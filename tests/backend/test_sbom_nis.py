import csv
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from koda_tracker import sbom, services
from koda_tracker.models import Job, JobState, SbomRun
from test_sbom_archives import archive_bytes, context, upload  # noqa: F401


HEADER = ('"SBOM Standard","SBOM Type","CycloneDXNo.","SPDX Doc. ID","SBOM ID",'
          '"Product Name","Product Version","Component Name","Component Alias","Component Version",'
          '"Component Supplier Name","Component Hash","Component Path","SBOM Author Name",'
          '"Unique Identifier","Dependency Relationship","Timestamp","License Name·Version","Vul. DB","Vul. Info"')
ROW = ("NIS 1.0", "Deployed", "", "", "KODA-20261117-100000", "한글, 제품", "3", "sample", "", "1.2",
       "Example Corp", f"alg : SHA-256\ncontent : {'a' * 64}", "lib/sample.jar", "KODA",
       "pkg:maven/org.example/sample@1.2", "", "2026-11-17T12:00:00Z", "MIT", "NVD/CVE", "CVE-2026-0001")


def document(*rows, header=HEADER):
    stream = io.StringIO(newline="")
    stream.write("\ufeff" + header + "\r\n")
    csv.writer(stream, quoting=csv.QUOTE_ALL).writerows(rows)
    return stream.getvalue().encode()


@pytest.mark.parametrize("archive", [None, "zip", "tar.gz"])
def test_nis_upload_validates_and_scans_cyclonedx_but_retains_original(context, monkeypatch, archive):
    raw_csv = document(ROW)
    expected, media_type = sbom.parse_sbom(raw_csv)
    assert media_type == "text/csv"
    assert expected["metadata"]["component"]["name"] == "한글, 제품"
    assert "vulnerabilities" not in expected
    assert expected["components"][0]["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    raw = archive_bytes(archive, [("inventory", raw_csv)]) if archive else raw_csv
    selected_paths = []

    def check_normalized(path):
        assert json.loads(path.read_bytes()) == expected
        selected_paths.append(path)

    def validate(command, **kwargs):
        assert command[command.index("--input-format") + 1] == "json"
        check_normalized(Path(command[command.index("--input-file") + 1]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(context.settings, "cyclonedx_cli_binary", "fixture-validator")
    monkeypatch.setattr(sbom, "_run_cyclonedx", validate)
    response = upload(context, raw)
    assert response.status_code == 202, response.text
    run = context.db.get(SbomRun, response.json()["runId"])
    assert run.normalized_bom == expected
    assert run.sha256 == hashlib.sha256(raw).hexdigest()
    artifact = context.client.get(f"/api/v1/sbom-runs/{run.id}/artifact")
    assert artifact.status_code == 200 and artifact.content == raw
    assert artifact.headers["content-type"].split(";", 1)[0] == {
        None: "text/csv", "zip": "application/zip", "tar.gz": "application/gzip",
    }[archive]
    components = context.client.get(f"/api/v1/sbom-runs/{run.id}/components").json()["items"]
    assert components[0]["purl"] == "pkg:maven/org.example/sample@1.2"
    assert components[0]["licenses"] == ["MIT"]
    subprocess_run = services.subprocess.run

    def scan(command, **kwargs):
        if command[0] != context.settings.grype_binary:
            return subprocess_run(command, **kwargs)
        check_normalized(Path(command[1].removeprefix("sbom:")))
        return SimpleNamespace(returncode=0, stdout='{"matches":[]}', stderr="")

    monkeypatch.setattr(services.subprocess, "run", scan)
    revision = services.analyze_offline(context.db, run)
    assert revision.state == JobState.COMPLETED, revision.error
    assert revision.data_sources["sbomQuality"]["originalSha256"] == run.sha256
    assert len(selected_paths) == 2
    assert all(not path.exists() for path in selected_paths)
    assert Path(run.artifact_path).read_bytes() == raw


@pytest.mark.parametrize("case", ["invalid header", "wrong version", "missing column", "row length", "component limit"])
def test_invalid_nis_csv_leaves_no_run_job_or_artifact(context, monkeypatch, case):
    documents = {
        "invalid header": document(ROW, header=HEADER.replace('"Vul. Info"', '"Vul. DB"')),
        "wrong version": document(("NIS 2.0", *ROW[1:])),
        "missing column": document(ROW[:-1]),
        "row length": document((*ROW[:-1], "x" * 65536)),
        "component limit": document(ROW, ROW),
    }
    if case == "component limit":
        monkeypatch.setattr(context.settings, "max_sbom_components", 1)
    response = upload(context, documents[case])
    assert response.status_code == 422, response.text
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert context.db.scalar(select(func.count()).select_from(Job)) == 0
    assert not list(context.settings.artifact_dir.iterdir())
