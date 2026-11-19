"""Exercise split-document upload through admission, storage and analysis."""
import hashlib
import json

import pytest
from sqlalchemy import delete, func, select

from koda_tracker import main, services
from koda_tracker.large_sbom import iter_large_records
from koda_tracker.models import Job, JobState, ProcessingState, SbomDocumentRecord, SbomRun
from test_sbom_archives import archive_bytes, context, upload


def cyclonedx():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"name": "host", "type": "application", "bom-ref": "host"}},
        "components": [{
            "type": "library", "name": "log4j-core", "version": "2.14.1", "bom-ref": "pkg",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "properties": [{"name": "koda:test:evidence", "value": "installation evidence " * 100}],
        }],
        "dependencies": [{"ref": "host", "dependsOn": ["pkg"]}, {"ref": "pkg", "dependsOn": []}],
    }


@pytest.mark.parametrize("compressed", [False, True])
def test_split_upload_preserves_original_records_and_reanalyzes(context, monkeypatch, compressed):
    monkeypatch.setattr(main, "LARGE_DOCUMENT_THRESHOLD", 512)
    payload = cyclonedx()
    document = json.dumps(payload).encode()
    original = archive_bytes("zip", [("sbom.cdx.json", document)]) if compressed else document
    result = upload(context, original)
    assert result.status_code == 202, result.text
    receipt = result.json()
    run = context.db.get(SbomRun, receipt["runId"])
    assert run.split_document and run.sha256 == hashlib.sha256(original).hexdigest()
    assert context.client.get(f"/api/v1/sbom-runs/{run.id}/artifact").content == original
    assert list(iter_large_records(context.db, run.id, "components")) == payload["components"]
    assert list(iter_large_records(context.db, run.id, "dependencies")) == payload["dependencies"]
    assert run.normalized_bom["dependencies"] == payload["dependencies"]
    assert run.normalized_bom["components"][0].get("properties") is None
    assert context.db.get(Job, receipt["jobId"]).state == JobState.QUEUED

    def scan(bom, records, *, binary, env, spool, on_match):
        assert list(records()) == payload["components"]
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        on_match({"artifact": {"id": "pkg", "name": "log4j-core", "version": "2.14.1"},
                  "vulnerability": {"id": "CVE-2021-44228", "severity": "Critical"}})
        return "test-scanner"

    monkeypatch.setattr(services, "scan_large_sbom", scan)
    for sequence in (1, 2):
        revision = services.analyze_offline(context.db, run)
        assert revision.sequence == sequence
        assert revision.state == JobState.COMPLETED and revision.policy_state == "completed", (
            revision.error, revision.policy_error
        )
        assert revision.findings[0]["bomRef"] == "pkg"
        assert revision.data_sources["sbomQuality"]["state"] == "completed"
        assert revision.data_sources["sbomQuality"]["edgeCount"] == 1
        assert revision.data_sources["sbomQuality"]["originalSha256"] == run.sha256
        assert run.state == ProcessingState.COMPLETED

    monkeypatch.setattr(main, "vulnerable_component_count", lambda *_args: pytest.fail("list reloaded compatibility JSON"))
    listing = context.client.get("/api/v1/sbom-runs")
    assert listing.status_code == 200 and listing.json()["items"][0]["vulnerableComponentCount"] == 1

    monkeypatch.setattr(services, "scan_large_sbom", lambda *_args, **_kwargs: pytest.fail("index incomplete"))
    context.db.execute(delete(SbomDocumentRecord).where(SbomDocumentRecord.section == "dependencies"))
    failed = services.analyze_offline(context.db, run)
    assert failed.state == JobState.FAILED
    assert "레코드 수" in failed.error
    assert failed.findings == []


def test_invalid_late_input_or_expanded_quota_leaves_no_split_rows(context, monkeypatch):
    monkeypatch.setattr(main, "LARGE_DOCUMENT_THRESHOLD", 512)
    document = json.dumps(cyclonedx()).encode()
    invalid = upload(context, document + b" trailing")
    assert invalid.status_code == 422, invalid.text
    duplicate = cyclonedx()
    duplicate["dependencies"].append(dict(reversed(list(duplicate["dependencies"][0].items()))))
    refused = upload(context, json.dumps(duplicate).encode())
    assert refused.status_code == 422 and "중복 항목" in refused.text
    archive = archive_bytes("zip", [("sbom.cdx.json", document)])
    monkeypatch.setattr(context.settings, "max_service_ingested_bytes", 2 * len(archive))
    assert 2 * len(archive) < len(document)
    refused = upload(context, archive)
    assert refused.status_code == 507, refused.text
    assert context.db.scalar(select(func.count()).select_from(SbomDocumentRecord)) == 0
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert not any(context.settings.artifact_dir.iterdir())
