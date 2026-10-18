from __future__ import annotations

import asyncio
import copy
import json
import uuid
from types import SimpleNamespace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, inspect, select, text

from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal, ensure_native_policy_columns
from koda_tracker.main import app
from koda_tracker.models import AnalysisRevision, Job, SbomRun
from koda_tracker.services import analyze_offline
from koda_tracker.sbom import licenses_for, parse_sbom
from koda_tracker.worker import process_one


@pytest.fixture
def admin():
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        assert login.status_code == 200
        headers = {"X-CSRF-Token": login.json()["csrfToken"]}
        original = client.get("/api/v1/sbom-policies").json()
        with SessionLocal() as db:
            existing_runs = set(db.scalars(select(SbomRun.id)))
        yield client, headers
        with SessionLocal() as db:
            for run in db.scalars(select(SbomRun)):
                if run.id not in existing_runs:
                    db.execute(delete(Job).where(Job.run_id == run.id))
                    db.delete(run)
            db.commit()
        current = client.get("/api/v1/sbom-policies").json()
        if current["version"] != original["version"]:
            restored = client.put("/api/v1/sbom-policies", json={"expectedVersion": current["version"], "rules": original["rules"], "exceptions": original["exceptions"]}, headers=headers)
            assert restored.status_code == 200


def test_policy_api_versions_validation_csrf_and_read_only_role(admin):
    client, headers = admin
    original = client.get("/api/v1/sbom-policies").json()
    request = {"expectedVersion": original["version"], "rules": original["rules"], "exceptions": []}
    assert client.put("/api/v1/sbom-policies", json=request).status_code == 403
    changed = client.put("/api/v1/sbom-policies", json=request, headers=headers)
    assert changed.status_code == 200, changed.text
    assert changed.json()["version"] == original["version"] + 1
    assert client.put("/api/v1/sbom-policies", json=request, headers=headers).status_code == 409
    invalid = {**request, "expectedVersion": changed.json()["version"], "rules": [original["rules"][0]] * 2}
    assert client.put("/api/v1/sbom-policies", json=invalid, headers=headers).status_code == 422
    assert client.put("/api/v1/sbom-policies", json={**request, "unexpected": True}, headers=headers).status_code == 422
    history = client.get("/api/v1/sbom-policies/history").json()["items"]
    assert next(row for row in history if row["version"] == original["version"]) == original
    events = client.get("/api/v1/audit-events").json()
    assert any(row["action"] == "sbom_policy.update" for row in events["items"])
    username = f"policy-viewer-{uuid.uuid4().hex[:8]}"
    assert client.post("/api/v1/users", json={"username": username, "password": "long-enough-password", "role": "viewer"}, headers=headers).status_code == 201
    with TestClient(app) as viewer:
        response = viewer.post("/api/v1/auth/login", json={"username": username, "password": "long-enough-password"})
        assert response.status_code == 200
        assert viewer.get("/api/v1/sbom-policies").status_code == 200
        assert viewer.put("/api/v1/sbom-policies", json=request, headers={"X-CSRF-Token": response.json()["csrfToken"]}).status_code == 403


def test_native_upload_analysis_metrics_policy_version_and_reanalysis(admin, monkeypatch):
    client, headers = admin
    settings = get_settings()
    monkeypatch.setattr(settings, "dependency_track_enabled", False)
    original = client.get("/api/v1/sbom-policies").json()
    rule = {"id": "test-high", "name": "High 취약점", "kind": "severity", "action": "fail", "enabled": True, "values": ["high"]}
    configured = client.put("/api/v1/sbom-policies", json={"expectedVersion": original["version"], "rules": [rule], "exceptions": []}, headers=headers).json()
    unique = uuid.uuid4().hex[:8]
    service = client.post("/api/v1/services", json={"slug": f"policy-{unique}", "name": "Native policy"}, headers=headers)
    assert service.status_code == 201, service.text
    environment_id = client.get("/api/v1/environments").json()[0]["id"]
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "name": "demo", "version": "1.0", "purl": "pkg:pypi/demo@1.0", "licenses": [{"license": {"id": "MIT"}}]}]}
    uploaded = client.post("/api/v1/sbom-runs", data={"serviceId": service.json()["id"], "environmentId": environment_id, "releaseVersion": unique}, files={"sbom": ("policy.cdx.json", json.dumps(bom), "application/json")}, headers=headers)
    assert uploaded.status_code == 202, uploaded.text
    run_id = uploaded.json()["runId"]
    pending = client.get(f"/api/v1/sbom-runs/{run_id}").json()
    assert pending["policyStatus"] == "not_evaluated"
    assert client.post(f"/api/v1/sbom-runs/{run_id}/retry-dependency-track", headers=headers).status_code == 409
    assert client.get("/api/v1/dependency-track/status").json()["enabled"] is False
    calls = []

    def grype(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"descriptor": {"version": "test-grype"}, "matches": [{"vulnerability": {"id": "GHSA-ABCD-1234-EFGH", "severity": "High", "fix": {"versions": ["2.0"]}}, "relatedVulnerabilities": [{"id": "CVE-2026-12345", "namespace": "nvd:cpe"}], "artifact": {"name": "demo", "version": "1.0", "purl": "pkg:pypi/demo@1.0"}}]}), stderr="")

    monkeypatch.setattr("koda_tracker.services.subprocess.run", grype)
    monkeypatch.setattr("koda_tracker.services.load_context", lambda _: SimpleNamespace(
        bundle=None, sources={"cisaKev": {"available": True}}, aliases={},
        nvd={"CVE-2026-12345": {"cvss": {"cvssV3": {"baseScore": 8.1}}}},
        kev={"CVE-2026-12345": {"dateAdded": "2026-10-17"}},
    ))
    with SessionLocal() as db:
        job = db.get(Job, uploaded.json()["jobId"])
        job.created_at = datetime(1970, 1, 1, tzinfo=UTC)
        db.commit()
    assert asyncio.run(process_one()) is True
    with SessionLocal() as db:
        assert db.get(Job, uploaded.json()["jobId"]).state.value == "completed"
        first = db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == run_id))
        first_id = first.id
        first_snapshot = copy.deepcopy(first.policy_snapshot)
    assert calls[0][0][0] == settings.grype_binary
    assert calls[0][1]["env"]["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert calls[0][1]["env"]["GRYPE_DB_CACHE_DIR"]
    result = client.get(f"/api/v1/sbom-runs/{run_id}").json()
    assert result["state"] == "completed"
    assert result["dependencyTrackEnabled"] is False
    assert result["policyStatus"] == "fail"
    assert result["policyViolationCount"] == result["analysisMetrics"]["policyFailCount"] == 1
    assert result["vulnerabilityCount"] == result["analysisMetrics"]["vulnerabilityCount"] == 1
    assert result["kevCount"] == result["analysisMetrics"]["kevCount"] == 1
    assert result["policyVersion"] == configured["version"]
    violations = client.get(f"/api/v1/sbom-runs/{run_id}/policy-violations", params={"size": 1}).json()
    assert violations["total"] == 1
    assert violations["items"][0]["vulnerabilityId"] == "CVE-2026-12345"
    assert client.get(f"/api/v1/sbom-runs/{run_id}/policy-violations", params={"page": 2, "size": 1}).json()["items"] == []
    assert client.get(f"/api/v1/sbom-runs/{run_id}/policy-violations", params={"analysisId": "other-run-analysis"}).status_code == 404
    listed = client.get("/api/v1/sbom-runs", params={"service_id": service.json()["id"]}).json()["items"][0]
    assert "policyViolations" not in listed and "policySnapshot" not in listed
    assert result["analyses"][0]["policySnapshot"] == first_snapshot
    changed = client.put("/api/v1/sbom-policies", json={"expectedVersion": configured["version"], "rules": [{**rule, "enabled": False}], "exceptions": []}, headers=headers)
    assert changed.status_code == 200
    assert client.post(f"/api/v1/sbom-runs/{run_id}/analyses", headers=headers).status_code == 202
    with SessionLocal() as db:
        run = db.get(SbomRun, run_id)
        analyze_offline(db, run)
        db.commit()
        first = db.get(AnalysisRevision, first_id)
        assert first.policy_snapshot == first_snapshot
        assert first.policy_version == configured["version"]
        assert len(first.policies) == 1
    updated = client.get(f"/api/v1/sbom-runs/{run_id}").json()
    assert updated["policyStatus"] == "pass"
    assert updated["policyViolationCount"] == 0
    assert updated["policyVersion"] == changed.json()["version"]
    comparison = client.get("/api/v1/comparisons", params={"baseRunId": run_id, "targetRunId": run_id, "baseAnalysisId": first_id, "targetAnalysisId": updated["analyses"][0]["id"]})
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["summary"]["policiesChanged"] == 1


def test_native_policy_migration_is_additive_and_repeatable():
    bind = create_engine("sqlite:///:memory:")
    with bind.begin() as connection:
        connection.execute(text("CREATE TABLE analysis_revisions (id TEXT PRIMARY KEY, policies JSON)"))
        connection.execute(text("INSERT INTO analysis_revisions VALUES ('old', '[{\"name\":\"legacy\"}]')"))
    ensure_native_policy_columns(bind)
    ensure_native_policy_columns(bind)
    assert {"policy_state", "policy_version", "policy_snapshot", "policy_error", "metrics"} <= {column["name"] for column in inspect(bind).get_columns("analysis_revisions")}
    with bind.connect() as connection:
        row = connection.execute(text("SELECT policies, policy_state, policy_version FROM analysis_revisions")).one()
        assert json.loads(row[0]) == [{"name": "legacy"}]
        assert row[1:] == ("not_evaluated", None)


def test_xml_and_json_license_expressions_are_preserved_for_native_policy():
    from koda_tracker.policies import PolicyDocument, evaluate_document

    payload, _ = parse_sbom(b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component type="library"><name>demo</name><version>1</version><licenses><expression>MIT OR GPL-3.0-only</expression></licenses></component><component type="library"><name>custom</name><licenses><license><name>Custom terms</name></license></licenses></component></components></bom>')
    assert licenses_for(payload["components"][0]) == ["MIT OR GPL-3.0-only"]
    assert payload["components"][1]["licenses"] == [{"license": {"name": "Custom terms"}}]
    document = PolicyDocument.model_validate({"rules": [{"id": "deny", "name": "금지 라이선스", "kind": "license_denied", "values": ["GPL-3.0-only"]}]})
    violations, _ = evaluate_document(document, payload["components"], [])
    assert violations == []


@pytest.mark.parametrize("kev_payload,available", [(None, False), ({}, False), ([{}], False), (["invalid"], False), ({"vulnerabilities": []}, True), ([], True), ({"vulnerabilities": [{"cveID": "CVE-2026-12345"}]}, True)])
def test_kev_source_availability_distinguishes_missing_feed_from_empty_feed(tmp_path, kev_payload, available):
    from koda_tracker.config import Settings
    from koda_tracker.vulnerability import load_context

    root = tmp_path / "vuln-data"
    release = root / "releases" / "kev-test"
    release.mkdir(parents=True)
    (release / "metadata.env").write_text("BUNDLE_VERSION=kev-test\nDATASET_DATE=2026-10-17\nKEV_CATALOG=kev.json\n")
    (release / "manifest.sha256").write_text("fixture  fixture.json\n")
    if kev_payload is not None:
        (release / "kev.json").write_text(json.dumps(kev_payload))
    (root / "current").symlink_to(release, target_is_directory=True)
    assert load_context(Settings(grype_db_dir=root / "current" / "grype-db")).sources["cisaKev"]["available"] is available


def test_advanced_cel_validation_scopes_and_csrf(admin):
    client, headers = admin
    body = {"expression": 'project.slug == "orders" && [1,2,3].exists(x, x > 2)', "target": "project"}
    assert client.post('/api/v1/sbom-policies/validate', json=body).status_code == 403
    valid = client.post('/api/v1/sbom-policies/validate', json=body, headers=headers)
    assert valid.status_code == 200 and valid.json()['runtime'] == 'cel-expr-python'
    invalid = client.post('/api/v1/sbom-policies/validate', json={**body, 'expression': 'project.'}, headers=headers)
    assert invalid.status_code == 422
    policy = client.get('/api/v1/sbom-policies').json()
    rule = {'id': 'scoped-cel', 'name': 'Scoped CEL', 'kind': 'cel', 'target': 'project', 'expression': 'true', 'serviceIds': ['missing-service']}
    rejected = client.put('/api/v1/sbom-policies', json={'expectedVersion': policy['version'], 'rules': [rule], 'exceptions': []}, headers=headers)
    assert rejected.status_code == 422
    rule['serviceIds'] = []
    rule['expression'] = 'project.'
    rejected = client.put('/api/v1/sbom-policies', json={'expectedVersion': policy['version'], 'rules': [rule], 'exceptions': []}, headers=headers)
    assert rejected.status_code == 422
    assert client.get('/api/v1/sbom-policies').json()['version'] == policy['version']


def test_schedule_api_rbac_csrf_versions_and_manual_empty_cycle(admin):
    client, headers = admin
    original = client.get('/api/v1/reanalysis-schedule').json()
    body = {key: original[key] for key in ('enabled', 'intervalMinutes', 'onDataUpdate', 'latestOnly', 'serviceIds', 'environmentIds')}
    body['expectedVersion'] = original['version']
    assert client.put('/api/v1/reanalysis-schedule', json=body).status_code == 403
    invalid = {**body, 'serviceIds': ['nonexistent']}
    assert client.put('/api/v1/reanalysis-schedule', json=invalid, headers=headers).status_code == 422
    invalid = {**body, 'intervalMinutes': 1}
    assert client.put('/api/v1/reanalysis-schedule', json=invalid, headers=headers).status_code == 422
    changed = client.put('/api/v1/reanalysis-schedule', json={**body, 'enabled': False}, headers=headers)
    assert changed.status_code == 200 and changed.json()['nextRunAt'] is None
    assert client.put('/api/v1/reanalysis-schedule', json=body, headers=headers).status_code == 409
    assert client.post('/api/v1/reanalysis-schedule/run-now', json={}).status_code == 403
    restored = client.put('/api/v1/reanalysis-schedule', json={**body, 'expectedVersion': changed.json()['version']}, headers=headers)
    assert restored.status_code == 200
