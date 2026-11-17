from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from koda_tracker import main as main_module
from koda_tracker.db import SessionLocal
from koda_tracker.main import app
from koda_tracker.models import AnalysisRevision, AuditEvent, Job, JobState, ProcessingState, RunComponent, SbomRun


def _admin(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "test-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrfToken"]}


def _sbom(component_name: str = "lifecycle") -> bytes:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "library", "name": component_name, "version": "1.0", "purl": f"pkg:pypi/{component_name}@1.0"}],
        }
    ).encode()


def _catalogs(client: TestClient, headers: dict[str, str], suffix: str) -> tuple[str, str]:
    service = client.post(
        "/api/v1/services",
        json={"slug": f"test-{suffix}", "name": f"테스트 서비스 {suffix}"},
        headers=headers,
    )
    environment = client.post(
        "/api/v1/environments",
        json={"slug": f"test-{suffix}", "name": f"테스트 환경 {suffix}", "sortOrder": 2000},
        headers=headers,
    )
    assert service.status_code == 201
    assert environment.status_code == 201
    return service.json()["id"], environment.json()["id"]


def test_inactive_catalogs_are_hidden_but_historical_run_names_remain() -> None:
    suffix = uuid.uuid4().hex[:10]
    with TestClient(app) as client:
        headers = _admin(client)
        service = client.post(
            "/api/v1/services",
            json={"slug": f"inactive-{suffix}", "name": "비활성 검증 서비스"},
            headers=headers,
        )
        assert service.status_code == 201
        environment = client.post(
            "/api/v1/environments",
            json={"slug": f"inactive-{suffix}", "name": "비활성 검증 환경", "sortOrder": 999},
            headers=headers,
        )
        assert environment.status_code == 201
        service_id = service.json()["id"]
        environment_id = environment.json()["id"]
        upload = client.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": "1.0.0"},
            files={"sbom": ("lifecycle.cdx.json", _sbom(), "application/json")},
            headers=headers,
        )
        assert upload.status_code == 202
        run_id = upload.json()["runId"]

        assert client.patch(f"/api/v1/services/{service_id}", json={"active": False}, headers=headers).status_code == 200
        assert client.patch(f"/api/v1/environments/{environment_id}", json={"active": False}, headers=headers).status_code == 200
        assert service_id not in {item["id"] for item in client.get("/api/v1/services").json()}
        assert environment_id not in {item["id"] for item in client.get("/api/v1/environments").json()}
        assert service_id in {item["id"] for item in client.get("/api/v1/services", params={"includeInactive": True}).json()}
        assert environment_id in {item["id"] for item in client.get("/api/v1/environments", params={"includeInactive": True}).json()}
        rejected = client.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": "1.0.1"},
            files={"sbom": ("lifecycle.cdx.json", _sbom(), "application/json")},
            headers=headers,
        )
        assert rejected.status_code == 409
        historical = client.get(f"/api/v1/sbom-runs/{run_id}")
        assert historical.status_code == 200
        assert historical.json()["service"]["name"] == "비활성 검증 서비스"
        assert historical.json()["environment"]["name"] == "비활성 검증 환경"


def test_audit_csv_is_filtered_redacted_kst_formula_safe_and_streamed(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = f"csv-{uuid.uuid4().hex}"
    with SessionLocal() as db:
        db.add(
            AuditEvent(
                actor=f"={marker}",
                action="audit.csv.test",
                target_type="test",
                target_id=marker,
                detail={"sha256": "secret-sha", "nested": {"sha-256": "nested-secret", "value": "=SUM(1,1)"}},
                created_at=datetime(2026, 8, 28, 0, 0, tzinfo=UTC),
            )
        )
        db.commit()
    with TestClient(app) as client:
        headers = _admin(client)
        real_factory = main_module.SessionLocal
        yield_sizes: list[int] = []

        class TrackingResult:
            def __init__(self, result):
                self.result = result

            def yield_per(self, size: int):
                yield_sizes.append(size)
                self.result = self.result.yield_per(size)
                return self

            def __iter__(self):
                return iter(self.result)

        class TrackingSession:
            def __init__(self):
                self.session = real_factory()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.session.close()

            def scalars(self, statement):
                return TrackingResult(self.session.scalars(statement))

        monkeypatch.setattr(main_module, "SessionLocal", TrackingSession)
        response = client.get("/api/v1/audit-events", params={"format": "csv", "q": marker}, headers=headers)
        assert response.status_code == 200
        body = response.content
        assert body.startswith("\ufeff".encode())
        text = body.decode("utf-8-sig")
        assert "2026-08-28 09:00:00" in text
        assert marker in text
        assert "secret-sha" not in text
        assert "nested-secret" not in text
        assert "'=SUM(1,1)" in text
        assert text.count("audit.csv.test") == 1
        assert yield_sizes == [100]


def test_completed_run_delete_requires_admin_and_removes_tracker_data_only(monkeypatch: pytest.MonkeyPatch) -> None:
    suffix = uuid.uuid4().hex[:10]
    with TestClient(app) as admin:
        headers = _admin(admin)
        deletion_sbom = _sbom(f"delete-{suffix}")
        service = admin.post(
            "/api/v1/services",
            json={"slug": f"delete-{suffix}", "name": "삭제 검증 서비스"},
            headers=headers,
        )
        environment = admin.post(
            "/api/v1/environments",
            json={"slug": f"delete-{suffix}", "name": "삭제 검증 환경", "sortOrder": 1000},
            headers=headers,
        )
        assert service.status_code == 201
        assert environment.status_code == 201
        service_id = service.json()["id"]
        environment_id = environment.json()["id"]
        uploaded = admin.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": f"delete-{suffix}"},
            files={"sbom": ("delete.cdx.json", deletion_sbom, "application/json")},
            headers=headers,
        )
        assert uploaded.status_code == 202
        run_id = uploaded.json()["runId"]
        shared = admin.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": f"shared-{suffix}"},
            files={"sbom": ("shared.cdx.json", deletion_sbom, "application/json")},
            headers=headers,
        )
        assert shared.status_code == 202
        shared_run_id = shared.json()["runId"]
        assert admin.delete(f"/api/v1/sbom-runs/{run_id}", headers=headers).status_code == 409
        with SessionLocal() as db:
            run = db.get(SbomRun, run_id)
            shared_run = db.get(SbomRun, shared_run_id)
            assert run is not None
            assert shared_run is not None
            artifact = Path(run.artifact_path)
            assert shared_run.artifact_path == run.artifact_path
            project_uuid = f"project-{suffix}"
            run.state = ProcessingState.PARTIAL
            shared_run.state = ProcessingState.COMPLETED
            for job in db.scalars(select(Job).where(Job.run_id.in_([run_id, shared_run_id]))):
                job.state = JobState.COMPLETED
            db.add(
                AnalysisRevision(
                    run_id=run_id,
                    sequence=1,
                    state=JobState.COMPLETED,
                    findings=[{"canonicalId": "CVE-2026-12345", "severity": "high"}],
                    policies=[],
                )
            )
            db.commit()
        assert artifact.exists()
        assert admin.delete(f"/api/v1/sbom-runs/{run_id}", headers=headers).status_code == 409
        with SessionLocal() as db:
            run = db.get(SbomRun, run_id)
            assert run is not None
            run.state = ProcessingState.COMPLETED
            db.commit()

        viewer = admin.post(
            "/api/v1/users",
            json={"username": f"delete-viewer-{suffix}", "password": "long-enough-password", "role": "viewer"},
            headers=headers,
        ).json()
        with TestClient(app) as viewer_client:
            viewer_login = viewer_client.post(
                "/api/v1/auth/login",
                json={"username": viewer["username"], "password": "long-enough-password"},
            )
            assert viewer_login.status_code == 200
            assert viewer_client.delete(f"/api/v1/sbom-runs/{run_id}", headers={"X-CSRF-Token": viewer_login.json()["csrfToken"]}).status_code == 403

        deleted = admin.delete(f"/api/v1/sbom-runs/{run_id}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json() == {"runId": run_id, "deleted": True, "artifactCleanupPending": False}
        assert artifact.exists()
        assert admin.get(f"/api/v1/sbom-runs/{shared_run_id}/artifact").status_code == 200
        assert admin.get(f"/api/v1/sbom-runs/{run_id}").status_code == 404
        assert admin.get(f"/api/v1/sbom-runs/{run_id}/artifact").status_code == 404
        assert admin.get("/api/v1/comparisons", params={"baseRunId": run_id, "targetRunId": run_id}).status_code == 404
        with SessionLocal() as db:
            assert db.scalar(select(RunComponent.id).where(RunComponent.run_id == run_id)) is None
            assert db.scalar(select(AnalysisRevision.id).where(AnalysisRevision.run_id == run_id)) is None
        assert admin.delete(f"/api/v1/sbom-runs/{shared_run_id}", headers=headers).status_code == 200
        assert not artifact.exists()


def test_cve_projection_counts_dates_and_comparison_stay_consistent() -> None:
    suffix = uuid.uuid4().hex[:10]
    with TestClient(app) as client:
        headers = _admin(client)
        service_id, environment_id = _catalogs(client, headers, f"projection-{suffix}")
        run_ids: list[str] = []
        for label in ("base", "target"):
            response = client.post(
                "/api/v1/sbom-runs",
                data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": f"projection-{label}-{suffix}"},
                files={"sbom": (f"{label}.cdx.json", _sbom("alpha"), "application/json")},
                headers=headers,
            )
            assert response.status_code == 202
            run_ids.append(response.json()["runId"])

        base_findings = [
            {"canonicalId": "CVE-2026-99999", "aliases": ["CVE-2026-00001"], "component": "alpha", "severity": "HIGH", "nvdCvss": {"cvssV31": {"baseScore": 8.8}}, "kev": True, "fixedIn": ["1.2.0", "1.3.0"]},
            {"id": "GHSA-abcd-1234-efgh", "aliases": ["CVE-2026-10002"], "component": "alpha", "severity": "MEDIUM"},
            {"id": "GHSA-only-1234-abcd", "component": "ignored", "severity": "LOW"},
        ]
        target_findings = [
            {"canonicalId": "CVE-2026-99999", "component": "alpha", "severity": "HIGH"},
            {"id": "GHSA-bbbb-1234-cccc", "aliases": ["CVE-2026-10003"], "component": "gamma", "severity": "LOW"},
            {"id": "GHSA-only-5678-abcd", "component": "ignored", "severity": "LOW"},
        ]
        with SessionLocal() as db:
            for run_id, findings, data_as_of, sources in (
                (run_ids[0], base_findings, "2026-08-20", {"nvd": {"dataAsOf": "2026-08-27"}}),
                (run_ids[1], target_findings, "2026-08-21", {}),
            ):
                run = db.get(SbomRun, run_id)
                run.state = ProcessingState.COMPLETED
                run.analysis_state = JobState.COMPLETED
                for job in db.scalars(select(Job).where(Job.run_id == run_id)):
                    job.state = JobState.COMPLETED
                db.add(AnalysisRevision(run_id=run_id, sequence=1, state=JobState.COMPLETED, data_as_of=data_as_of, data_sources=sources, findings=findings, policies=[]))
            db.commit()

        listed = client.get("/api/v1/sbom-runs", params={"q": run_ids[0]}, headers=headers).json()
        detail = client.get(f"/api/v1/sbom-runs/{run_ids[0]}", headers=headers).json()
        findings = client.get(f"/api/v1/sbom-runs/{run_ids[0]}/findings", headers=headers).json()
        comparison = client.get("/api/v1/comparisons", params={"baseRunId": run_ids[0], "targetRunId": run_ids[1]}, headers=headers).json()

        assert listed["items"][0]["vulnerabilityCount"] == detail["vulnerabilityCount"] == detail["analyses"][0]["findingCount"] == findings["total"] == 2
        assert listed["items"][0]["vulnerableComponentCount"] == detail["vulnerableComponentCount"] == 1
        assert detail["cveDataAsOf"] == detail["analyses"][0]["cveDataAsOf"] == "2026-08-27"
        assert findings["items"][0]["canonicalId"] == "CVE-2026-99999"
        assert findings["items"][0]["cvssScore"] == 8.8
        assert findings["items"][0]["fixedIn"] == ["1.2.0", "1.3.0"]
        assert comparison["summary"]["vulnerabilitiesAdded"] == 1
        assert comparison["summary"]["vulnerabilitiesRemoved"] == 1
        assert comparison["base"]["cveDataAsOf"] == "2026-08-27"
        assert comparison["target"]["cveDataAsOf"] == "2026-08-21"
        with SessionLocal() as db:
            assert len(db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == run_ids[0])).findings) == 3




def test_committed_run_delete_reports_pending_artifact_cleanup_instead_of_500(monkeypatch: pytest.MonkeyPatch) -> None:
    suffix = uuid.uuid4().hex[:10]
    with TestClient(app) as client:
        headers = _admin(client)
        service_id, environment_id = _catalogs(client, headers, f"cleanup-{suffix}")
        uploaded = client.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": f"cleanup-{suffix}"},
            files={"sbom": ("cleanup.cdx.json", _sbom(f"cleanup-{suffix}"), "application/json")},
            headers=headers,
        )
        run_id = uploaded.json()["runId"]
        with SessionLocal() as db:
            run = db.get(SbomRun, run_id)
            artifact = Path(run.artifact_path)
            run.state = ProcessingState.COMPLETED
            for job in db.scalars(select(Job).where(Job.run_id == run_id)):
                job.state = JobState.COMPLETED
            db.commit()

        original_unlink = Path.unlink
        failed_cleanup_paths: list[Path] = []

        def fail_quarantine_unlink(path: Path, *args, **kwargs):
            if path.parent.name == ".delete-quarantine":
                failed_cleanup_paths.append(path)
                raise OSError("simulated cleanup failure")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_quarantine_unlink)
        response = client.delete(f"/api/v1/sbom-runs/{run_id}", headers=headers)

        assert response.status_code == 200
        assert response.json()["artifactCleanupPending"] is True
        assert not artifact.exists()
        with SessionLocal() as db:
            assert db.get(SbomRun, run_id) is None
        quarantine = failed_cleanup_paths[0]
        assert quarantine.exists()
        original_unlink(quarantine)
        quarantine.parent.rmdir()


def test_rounds_count_distinct_registered_components_for_each_completed_revision() -> None:
    suffix = uuid.uuid4().hex[:10]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"type": "library", "name": "alpha", "version": "1", "bom-ref": "alpha-v1",
             "purl": "pkg:maven/org.example/alpha@1"},
            {"type": "library", "name": "alpha", "version": "2", "bom-ref": "alpha-v2",
             "purl": "pkg:maven/org.example/alpha@2"},
            {"type": "library", "name": "beta", "version": "1", "bom-ref": "beta",
             "components": [
                 {"type": "library", "name": "gamma", "version": "1", "bom-ref": "gamma"},
             ]},
        ],
    }
    findings = [
        {"id": "CVE-2026-5000", "component": "alpha", "bomRef": "alpha-v1", "version": "1"},
        {"id": "CVE-2026-5001", "component": "pkg:maven/org.example/alpha@1"},
        {"id": "CVE-2026-5000", "component": "pkg:maven/org.example/alpha", "version": "2"},
        {"id": "CVE-2026-5002", "component": "beta", "bomRef": "beta",
         "cpeEvidence": [{"bomRef": "gamma"}]},
        {"id": "CVE-2026-5003", "component": "not-in-sbom", "version": "1"},
        {"id": "CVE-2026-5004", "component": "alpha"},
    ]
    with TestClient(app) as client:
        headers = _admin(client)
        service_id, environment_id = _catalogs(client, headers, f"component-count-{suffix}")
        response = client.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": f"count-{suffix}"},
            files={"sbom": ("example.cdx.json", json.dumps(document).encode(), "application/json")},
            headers=headers,
        )
        assert response.status_code == 202
        run_id = response.json()["runId"]
        with SessionLocal() as db:
            run = db.get(SbomRun, run_id)
            run.state = ProcessingState.COMPLETED
            run.analysis_state = JobState.COMPLETED
            db.add_all([
                AnalysisRevision(run_id=run_id, sequence=1, state=JobState.COMPLETED, findings=[findings[1]]),
                AnalysisRevision(run_id=run_id, sequence=2, state=JobState.FAILED, findings=[findings[0]]),
                AnalysisRevision(run_id=run_id, sequence=3, state=JobState.COMPLETED, findings=[]),
                AnalysisRevision(run_id=run_id, sequence=4, state=JobState.COMPLETED, findings=findings),
            ])
            db.commit()

        listed = client.get("/api/v1/sbom-runs", params={"q": run_id}, headers=headers).json()["items"][0]
        detail = client.get(f"/api/v1/sbom-runs/{run_id}", headers=headers).json()
        assert listed["analysisAvailable"] is True
        assert listed["vulnerabilityCount"] == detail["vulnerabilityCount"] == len(findings)
        assert listed["vulnerableComponentCount"] == detail["vulnerableComponentCount"] == 4
        assert [row["vulnerableComponentCount"] for row in detail["analyses"]] == [4, 0, None, 1]
