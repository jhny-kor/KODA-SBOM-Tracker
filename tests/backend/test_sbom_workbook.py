import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET
import zipfile

import pytest
from sqlalchemy import func, select

from koda_tracker import main, sbom_workbook, services
from koda_tracker.models import Job, JobState, SbomRun
from koda_tracker.sbom_workbook import WORKBOOK_MEDIA_TYPE
from test_sbom_archives import context  # noqa: F401 - shared authenticated upload fixture


SS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def workbook_bytes(*, invalid=None):
    """Represent Excel's shared strings, merged labels, and numeric date."""
    sheet = ET.Element("worksheet", xmlns=SS)
    data = ET.SubElement(sheet, "sheetData")
    strings = ET.Element("sst", xmlns=SS)
    rows = [
        {"A": "솔루션명", "C": "Example Database"},
        {"A": "기준 버전", "C": "19.25.0.0.0 (RU 19.25)"},
        {"A": "운영 OS Platform", "C": "IBM AIX"},
        {"A": "작성일자", "C": 46275},
        {"A": "대상 서버", "C": "db-example-a, db-example-b"},
        dict(zip("ABCDEF", ("번호", "구분", "컴포넌트명", "버전", "라이선스 유형", "비고 / 상세 설명"))),
        {"A": 1, "B": "Third-Party / Java", "C": "Example JDK", "D": "1.8.0_201 (1.8.0.5.201)",
         "E": "Example license", "F": "구성요소 상세 설명"},
        {"A": 2, "C": "Example parser", "D": "02.01.0.4"},
    ]
    for number, values in enumerate(rows, 1):
        row = ET.SubElement(data, "row", r=str(number))
        for column, value in values.items():
            if invalid == "missing version" and (number, column) == (8, "D"):
                continue
            cell = ET.SubElement(row, "c", r=f"{column}{number}")
            if invalid == "formula" and (number, column) == (7, "D"):
                ET.SubElement(cell, "f").text = "1+1"
            if isinstance(value, str):
                cell.set("t", "s")
                index = len(strings)
                ET.SubElement(ET.SubElement(strings, "si"), "t").text = value
                value = index
            ET.SubElement(cell, "v").text = str(value)
    merged = ET.SubElement(sheet, "mergeCells")
    for row in range(1, 6):
        ET.SubElement(merged, "mergeCell", ref=f"A{row}:B{row}")
        ET.SubElement(merged, "mergeCell", ref=f"C{row}:F{row}")
    target = "../outside.xml" if invalid == "relationship" else "worksheets/sheet1.xml"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml",
                         '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                         '<Override PartName="/xl/workbook.xml" '
                         'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                         '</Types>')
        archive.writestr("xl/workbook.xml", f'<workbook xmlns="{SS}" xmlns:r="{REL}">'
                         '<sheets><sheet name="Inventory" sheetId="1" r:id="rId1"/></sheets></workbook>')
        archive.writestr("xl/_rels/workbook.xml.rels",
                         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                         f'<Relationship Id="rId1" Type="{REL}/worksheet" Target="{target}"/></Relationships>')
        archive.writestr("xl/worksheets/sheet1.xml", ET.tostring(sheet))
        archive.writestr("xl/sharedStrings.xml", ET.tostring(strings))
    return stream.getvalue()


def upload_workbook(context, raw):
    return context.client.post("/api/v1/sbom-runs", headers=context.headers,
                               data={"serviceId": context.service.id, "environmentId": context.environment.id,
                                     "releaseVersion": "deployment-1"},
                               files={"sbom": ("inventory.XLSX", raw, "application/octet-stream")})


def test_workbook_upload_preserves_original_and_uses_same_normalized_document_for_analysis(context, monkeypatch):
    # SQLite does not enforce VARCHAR lengths. Check the production schema contract.
    assert len(WORKBOOK_MEDIA_TYPE) <= SbomRun.__table__.c.media_type.type.length
    raw = workbook_bytes()
    response = upload_workbook(context, raw)
    assert response.status_code == 202, response.text
    run_id = response.json()["runId"]
    run = context.db.get(SbomRun, run_id)
    assert run.release.version == "deployment-1"
    assert run.sha256 == hashlib.sha256(raw).hexdigest()
    original = context.client.get(f"/api/v1/sbom-runs/{run_id}/artifact")
    assert original.content == raw
    assert original.headers["content-type"].endswith("spreadsheetml.sheet")
    detail = context.client.get(f"/api/v1/sbom-runs/{run_id}").json()
    assert detail["workbookMetadata"] == {
        "솔루션명": "Example Database", "기준 버전": "19.25.0.0.0 (RU 19.25)",
        "운영 OS Platform": "IBM AIX", "작성일자": "2026-09-10", "대상 서버": "db-example-a, db-example-b",
    }
    components = context.client.get(f"/api/v1/sbom-runs/{run_id}/components").json()["items"]
    assert {item["version"] for item in components} == {"1.8.0_201 (1.8.0.5.201)", "02.01.0.4"}
    jdk = next(item for item in components if item["name"] == "Example JDK")
    assert jdk["licenses"] == ["Example license"]
    assert {"name": "koda:xlsx:description", "value": "구성요소 상세 설명"} in jdk["properties"]

    original_run = services.subprocess.run
    selected_paths = []

    def scan(command, **kwargs):
        if command[0] != context.settings.grype_binary:
            return original_run(command, **kwargs)
        selected = Path(command[1].removeprefix("sbom:"))
        assert json.loads(selected.read_bytes()) == run.normalized_bom
        assert selected != Path(run.artifact_path)
        selected_paths.append(selected)
        return SimpleNamespace(returncode=0, stdout='{"matches":[]}', stderr="")

    monkeypatch.setattr(services.subprocess, "run", scan)
    revision = services.analyze_offline(context.db, run)
    assert revision.state == JobState.COMPLETED, revision.error
    assert revision.data_sources["sbomQuality"]["state"] == "completed"
    assert revision.data_sources["sbomQuality"]["originalSha256"] == run.sha256
    assert selected_paths and all(not path.exists() for path in selected_paths)


@pytest.mark.parametrize("invalid", ["missing version", "formula", "relationship", "upload size", "XML structure"])
def test_invalid_workbook_creates_no_run_or_job(context, monkeypatch, invalid):
    raw = workbook_bytes(invalid=invalid)
    if invalid == "upload size":
        monkeypatch.setattr(main, "MAX_WORKBOOK_BYTES", len(raw) - 1)
    if invalid == "XML structure":
        monkeypatch.setattr(sbom_workbook, "MAX_WORKBOOK_XML_NODES", 15)
    response = upload_workbook(context, raw)
    assert response.status_code == (413 if invalid == "upload size" else 422), response.text
    if invalid == "XML structure":
        assert "구조 복잡도" in response.json()["detail"]
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert context.db.scalar(select(func.count()).select_from(Job)) == 0
    assert not list(context.settings.artifact_dir.iterdir())
