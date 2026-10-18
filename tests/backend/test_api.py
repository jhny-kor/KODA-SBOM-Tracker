from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal
from koda_tracker.main import app
from koda_tracker.models import AnalysisRevision, JobState, ProcessingState, SbomRun


def test_authenticated_upload_idempotency_and_artifact_round_trip() -> None:
    sbom = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:api-test",
            "components": [
                {
                    "type": "library",
                    "name": "demo",
                    "version": "1.0",
                    "purl": "pkg:pypi/demo@1.0",
                    "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                }
            ],
        }
    ).encode()

    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "test-admin", "password": "correct-horse-battery-staple"},
        )
        assert login.status_code == 200
        csrf = login.json()["csrfToken"]
        headers = {"X-CSRF-Token": csrf}

        service_response = client.post(
            "/api/v1/services",
            json={"slug": "payment-api", "name": "결제 API"},
            headers=headers,
        )
        assert service_response.status_code == 201
        service_id = service_response.json()["id"]
        environment_id = next(
            item["id"] for item in client.get("/api/v1/environments").json() if item["slug"] == "prod"
        )

        upload = lambda key: client.post(  # noqa: E731
            "/api/v1/sbom-runs",
            data={
                "serviceId": service_id,
                "environmentId": environment_id,
                "releaseVersion": "1.4.2",
            },
            files={"sbom": ("payment.cdx.json", sbom, "application/json")},
            headers={**headers, "Idempotency-Key": key},
        )

        first = upload("deployment-42")
        assert first.status_code == 202
        assert first.json()["roundNumber"] == 1
        assert first.json()["sha256"] == hashlib.sha256(sbom).hexdigest()

        replay = upload("deployment-42")
        assert replay.status_code == 202
        assert replay.json()["runId"] == first.json()["runId"]
        assert replay.json()["idempotentReplay"] is True

        second = upload("deployment-43")
        assert second.status_code == 202
        assert second.json()["roundNumber"] == 2
        assert second.json()["runId"] != first.json()["runId"]

        artifact = client.get(f"/api/v1/sbom-runs/{first.json()['runId']}/artifact")
        assert artifact.status_code == 200
        assert hashlib.sha256(artifact.content).hexdigest() == first.json()["sha256"]

        listed = client.get("/api/v1/sbom-runs")
        assert listed.status_code == 200
        assert listed.json()["total"] == 2
        searched = client.get("/api/v1/sbom-runs", params={"q": "payment"})
        assert searched.status_code == 200
        assert searched.json()["total"] == 2
        component_searched = client.get("/api/v1/sbom-runs", params={"q": "pkg:pypi/demo"})
        assert component_searched.status_code == 200
        assert component_searched.json()["total"] == 2
        page = client.get("/api/v1/sbom-runs", params={"page": 2, "size": 1})
        assert page.status_code == 200
        assert page.json()["page"] == 2
        assert page.json()["total"] == 2
        assert len(page.json()["items"]) == 1

        detail = client.get(f"/api/v1/sbom-runs/{first.json()['runId']}")
        assert detail.status_code == 200
        assert detail.json()["components"] == []
        components = client.get(
            f"/api/v1/sbom-runs/{first.json()['runId']}/components",
            params={"q": "pkg:pypi/demo", "page": 1, "size": 1},
        )
        assert components.status_code == 200
        assert components.json()["total"] == 1
        assert components.json()["items"][0]["name"] == "demo"

        with SessionLocal() as db:
            db.add(
                AnalysisRevision(
                    run_id=first.json()["runId"],
                    sequence=1,
                    state=JobState.COMPLETED,
                    findings=[
                        {"canonicalId": "CVE-2026-0001", "severity": "critical", "component": "demo@1.0"},
                        {"canonicalId": "CVE-2026-0002", "severity": "medium", "component": "demo@1.0"},
                    ],
                    policies=[],
                )
            )
            db.commit()
        findings = client.get(
            f"/api/v1/sbom-runs/{first.json()['runId']}/findings",
            params={"page": 2, "size": 1},
        )
        assert findings.status_code == 200
        assert findings.json()["total"] == 2
        assert findings.json()["items"][0]["canonicalId"] == "CVE-2026-0002"

        audits = client.get("/api/v1/audit-events", params={"q": "sbom.upload", "page": 2, "size": 1})
        assert audits.status_code == 200
        assert audits.json()["total"] == 2
        assert audits.json()["page"] == 2
        assert len(audits.json()["items"]) == 1
        comparison = client.get(
            "/api/v1/comparisons",
            params={"baseRunId": first.json()["runId"], "targetRunId": second.json()["runId"]},
        )
        assert comparison.status_code == 200
        assert comparison.json()["components"] == []


def test_problem_details_and_authentication_boundary() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/sbom-runs")
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["status"] == 401


def test_koda_repository_provisioning_rotates_service_token_and_exposes_scoped_result() -> None:
    headers = {"Authorization": "Bearer test-koda-provisioning-secret"}
    repository = {
        "gitlabUrl": "https://gitlab.example.internal",
        "gitlabProjectId": 42,
        "pathWithNamespace": "group/demo",
    }
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    with TestClient(app) as client:
        assert client.post("/api/v1/integrations/koda/repositories", json=repository).status_code == 401
        first = client.post("/api/v1/integrations/koda/repositories", json=repository, headers=headers)
        second = client.post("/api/v1/integrations/koda/repositories", json=repository, headers=headers)
        assert first.status_code == second.status_code == 201
        assert first.json()["serviceCreated"] is True
        assert second.json()["serviceCreated"] is False
        assert first.json()["serviceId"] == second.json()["serviceId"]
        assert first.json()["environmentId"] == second.json()["environmentId"]
        upload_data = {
            "serviceId": second.json()["serviceId"],
            "environmentId": second.json()["environmentId"],
            "releaseVersion": "main@aaaaaaaaaaaa",
        }
        assert client.post(
            "/api/v1/sbom-runs", data=upload_data,
            files={"sbom": ("demo.cdx.json", sbom, "application/json")},
            headers={"Authorization": f"Bearer {first.json()['uploadToken']}"},
        ).status_code == 401
        uploaded = client.post(
            "/api/v1/sbom-runs", data=upload_data,
            files={"sbom": ("demo.cdx.json", sbom, "application/json")},
            headers={"Authorization": f"Bearer {second.json()['uploadToken']}"},
        )
        assert uploaded.status_code == 202
        with SessionLocal() as db:
            run = db.get(SbomRun, uploaded.json()["runId"])
            run.state = ProcessingState.COMPLETED
            run.analysis_state = JobState.COMPLETED
            db.add(AnalysisRevision(
                run_id=run.id, sequence=1, state=JobState.COMPLETED,
                findings=[
                    {"canonicalId": "CVE-2026-0001", "severity": "high", "component": "demo"},
                    {"canonicalId": "GHSA-only", "severity": "high", "component": "demo"},
                ],
                policies=[{"name": "critical-cve"}],
            ))
            db.commit()
        result = client.get(
            f"/api/v1/integrations/koda/runs/{uploaded.json()['runId']}",
            headers={"Authorization": f"Bearer {second.json()['uploadToken']}"},
        )
        assert result.status_code == 200
        assert result.json()["run"]["service"]["name"] == "group/demo"
        assert [item["canonicalId"] for item in result.json()["analysis"]["findings"]] == ["CVE-2026-0001"]
        assert result.json()["analysis"]["policyViolations"] == [{"name": "critical-cve"}]
        other = client.post(
            "/api/v1/integrations/koda/repositories",
            json={**repository, "gitlabProjectId": 43, "pathWithNamespace": "group/other"},
            headers=headers,
        ).json()
        assert client.get(
            f"/api/v1/integrations/koda/runs/{uploaded.json()['runId']}",
            headers={"Authorization": f"Bearer {other['uploadToken']}"},
        ).status_code == 404


def test_ldap_login_fails_closed_until_configured() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": "test-admin",
                "password": "correct-horse-battery-staple",
                "useLdap": True,
            },
        )
        assert response.status_code == 503
        assert response.json()["code"] == "ldap_not_configured"


def test_service_token_is_upload_only_and_can_read_only_its_job() -> None:
    sbom = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    ).encode()
    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "test-admin", "password": "correct-horse-battery-staple"},
        )
        csrf = login.json()["csrfToken"]
        admin_headers = {"X-CSRF-Token": csrf}
        services = client.get("/api/v1/services").json()
        if services:
            service_id = services[0]["id"]
        else:
            service_id = client.post(
                "/api/v1/services",
                json={"slug": "token-service", "name": "토큰 서비스"},
                headers=admin_headers,
            ).json()["id"]
        environment_id = client.get("/api/v1/environments").json()[0]["id"]
        token = client.post(
            "/api/v1/api-tokens",
            json={"name": "ci-one", "serviceId": service_id},
            headers=admin_headers,
        ).json()["token"]
        other_token = client.post(
            "/api/v1/api-tokens",
            json={"name": "ci-two", "serviceId": service_id},
            headers=admin_headers,
        ).json()["token"]
        listed_tokens = client.get("/api/v1/api-tokens")
        assert listed_tokens.status_code == 200
        token_id = next(item["id"] for item in listed_tokens.json() if item["name"] == "ci-one")
        revoked = client.post(f"/api/v1/api-tokens/{token_id}/revoke", headers=admin_headers)
        assert revoked.status_code == 200
        assert revoked.json()["active"] is False
        client.cookies.clear()

        upload = client.post(
            "/api/v1/sbom-runs",
            data={
                "serviceId": service_id,
                "environmentId": environment_id,
                "releaseVersion": "token-test",
            },
            files={"sbom": ("empty.cdx.json", sbom, "application/json")},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert upload.status_code == 401
        # A second token remains valid for the service-scoped upload path.
        upload = client.post(
            "/api/v1/sbom-runs",
            data={
                "serviceId": service_id,
                "environmentId": environment_id,
                "releaseVersion": "token-test",
            },
            files={"sbom": ("empty.cdx.json", sbom, "application/json")},
            headers={
                "Authorization": f"Bearer {other_token}",
                "Idempotency-Key": f"koda:run-42:{hashlib.sha256(sbom).hexdigest()}",
            },
        )
        assert upload.status_code == 202
        replay = client.post(
            "/api/v1/sbom-runs",
            data={
                "serviceId": service_id,
                "environmentId": environment_id,
                "releaseVersion": "token-test",
            },
            files={"sbom": ("empty.cdx.json", sbom, "application/json")},
            headers={
                "Authorization": f"Bearer {other_token}",
                "Idempotency-Key": f"koda:run-42:{hashlib.sha256(sbom).hexdigest()}",
            },
        )
        assert replay.status_code == 202
        assert replay.json()["runId"] == upload.json()["runId"]
        assert replay.json()["idempotentReplay"] is True
        job_id = upload.json()["jobId"]
        assert client.get(
            f"/api/v1/jobs/{job_id}",
            headers={"Authorization": f"Bearer {other_token}"},
        ).status_code == 200
        assert client.get(
            f"/api/v1/jobs/{job_id}",
            headers={"Authorization": f"Bearer {token}"},
        ).status_code == 401
        assert client.get(
            "/api/v1/sbom-runs",
            headers={"Authorization": f"Bearer {other_token}"},
        ).status_code == 403
        assert client.get("/api/v1/services", headers={"Authorization": f"Bearer {other_token}"}).status_code == 403
        assert client.get("/api/v1/environments", headers={"Authorization": f"Bearer {other_token}"}).status_code == 403


def test_service_token_rotation_preserves_idempotency_and_job_access(monkeypatch) -> None:
    repository = {
        "gitlabUrl": "https://gitlab.example.internal",
        "gitlabProjectId": 9001,
        "pathWithNamespace": "group/rotation",
    }
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    with TestClient(app) as client:
        provisioning_headers = {"Authorization": "Bearer test-koda-provisioning-secret"}
        first = client.post(
            "/api/v1/integrations/koda/repositories", json=repository, headers=provisioning_headers
        ).json()
        upload_data = {
            "serviceId": first["serviceId"],
            "environmentId": first["environmentId"],
            "releaseVersion": "main@rotation",
        }
        upload_headers = {"Authorization": f"Bearer {first['uploadToken']}", "Idempotency-Key": "rotation-key"}
        uploaded = client.post(
            "/api/v1/sbom-runs", data=upload_data,
            files={"sbom": ("rotation.cdx.json", sbom, "application/json")}, headers=upload_headers,
        )
        assert uploaded.status_code == 202

        rotated = client.post(
            "/api/v1/integrations/koda/repositories", json=repository, headers=provisioning_headers
        ).json()
        replay = client.post(
            "/api/v1/sbom-runs", data=upload_data,
            files={"sbom": ("rotation.cdx.json", sbom, "application/json")},
            headers={"Authorization": f"Bearer {rotated['uploadToken']}", "Idempotency-Key": "rotation-key"},
        )
        assert replay.status_code == 202
        assert replay.json()["runId"] == uploaded.json()["runId"]
        assert replay.json()["idempotentReplay"] is True
        assert client.get(
            f"/api/v1/jobs/{uploaded.json()['jobId']}",
            headers={"Authorization": f"Bearer {rotated['uploadToken']}"},
        ).status_code == 200

        result = client.get(
            f"/api/v1/integrations/koda/runs/{uploaded.json()['runId']}",
            headers={"Authorization": f"Bearer {rotated['uploadToken']}"},
        )
        assert result.status_code == 200
        assert result.json()["run"]["runUrl"] is None
        monkeypatch.setattr(get_settings(), "public_origin", "https://tracker.example.internal/base")
        result = client.get(
            f"/api/v1/integrations/koda/runs/{uploaded.json()['runId']}",
            headers={"Authorization": f"Bearer {rotated['uploadToken']}"},
        )
        assert result.status_code == 200
        assert result.json()["run"]["runUrl"] == (
            f"https://tracker.example.internal/base/?page=runs&runId={uploaded.json()['runId']}"
        )


def test_service_scoped_idempotency_is_distinct_between_services() -> None:
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    headers = {"Authorization": "Bearer test-koda-provisioning-secret"}
    with TestClient(app) as client:
        repositories = [
            {"gitlabUrl": "https://gitlab.example.internal", "gitlabProjectId": 9101, "pathWithNamespace": "group/one"},
            {"gitlabUrl": "https://gitlab.example.internal", "gitlabProjectId": 9102, "pathWithNamespace": "group/two"},
        ]
        provisioned = [client.post("/api/v1/integrations/koda/repositories", json=item, headers=headers).json() for item in repositories]
        uploads = []
        for item in provisioned:
            uploads.append(client.post(
                "/api/v1/sbom-runs",
                data={"serviceId": item["serviceId"], "environmentId": item["environmentId"], "releaseVersion": "main@same-key"},
                files={"sbom": ("same-key.cdx.json", sbom, "application/json")},
                headers={"Authorization": f"Bearer {item['uploadToken']}", "Idempotency-Key": "same-key"},
            ))
        assert [item.status_code for item in uploads] == [202, 202]
        assert uploads[0].json()["runId"] != uploads[1].json()["runId"]


def test_service_scoped_idempotency_concurrent_uploads_create_one_run() -> None:
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    headers = {"Authorization": "Bearer test-koda-provisioning-secret"}
    with TestClient(app) as client:
        item = client.post(
            "/api/v1/integrations/koda/repositories",
            json={"gitlabUrl": "https://gitlab.example.internal", "gitlabProjectId": 9201, "pathWithNamespace": "group/concurrent"},
            headers=headers,
        ).json()

        def upload() -> tuple[int, str]:
            response = client.post(
                "/api/v1/sbom-runs",
                data={"serviceId": item["serviceId"], "environmentId": item["environmentId"], "releaseVersion": "main@concurrent"},
                files={"sbom": ("concurrent.cdx.json", sbom, "application/json")},
                headers={"Authorization": f"Bearer {item['uploadToken']}", "Idempotency-Key": "concurrent-key"},
            )
            return response.status_code, response.json()["runId"]

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: upload(), range(2)))
    assert [status for status, _ in results] == [202, 202]
    assert len({run_id for _, run_id in results}) == 1


def test_api_token_requires_service_scope_and_admin_catalog_patches() -> None:
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        csrf = login.json()["csrfToken"]
        headers = {"X-CSRF-Token": csrf}
        assert client.post("/api/v1/api-tokens", json={"name": "global"}, headers=headers).status_code == 422
        user = client.post("/api/v1/users", json={"username": "  Patch-Me  ", "password": "long-enough-password", "role": "viewer"}, headers=headers).json()
        assert user["username"] == "patch-me"
        patched_user = client.patch(f"/api/v1/users/{user['id']}", json={"active": False}, headers=headers)
        assert patched_user.status_code == 200
        assert patched_user.json()["active"] is False
        service = client.get("/api/v1/services").json()[0]
        patched_service = client.patch(f"/api/v1/services/{service['id']}", json={"active": False}, headers=headers)
        assert patched_service.status_code == 200
        assert patched_service.json()["active"] is False
        assert client.patch(f"/api/v1/services/{service['id']}", json={"active": True}, headers=headers).status_code == 200
        environment = client.get("/api/v1/environments").json()[0]
        patched_environment = client.patch(
            f"/api/v1/environments/{environment['id']}",
            json={"name": "검증 환경", "slug": "운영 환경 / A", "sortOrder": 99},
            headers=headers,
        )
        assert patched_environment.status_code == 200
        assert patched_environment.json()["name"] == "검증 환경"
        assert patched_environment.json()["slug"] == "운영 환경 / A"
        assert patched_environment.json()["sortOrder"] == 99


def test_vulnerability_bundle_sync_is_admin_csrf_protected() -> None:
    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "test-admin", "password": "correct-horse-battery-staple"},
        )
        csrf = login.json()["csrfToken"]
        assert client.get("/api/v1/vulnerability-data-bundles").status_code == 200
        assert client.post("/api/v1/vulnerability-data-bundles/sync").status_code == 403
        synced = client.post("/api/v1/vulnerability-data-bundles/sync", headers={"X-CSRF-Token": csrf})
        assert synced.status_code == 200
        assert any(
            item["action"] == "vuln_data.sync"
            for item in client.get("/api/v1/audit-events").json()["items"]
        )


def test_vulnerability_bundle_sync_registers_current_release(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "vuln-data"
    release = root / "releases" / "bundle-a"
    release.mkdir(parents=True)
    (release / "metadata.env").write_text("BUNDLE_VERSION=bundle-a\nDATASET_DATE=2026-07-24\nGRYPE_DB_SCHEMA=6\n")
    (release / "manifest.sha256").write_text("fixture  fixture.json\n")
    (root / "current").symlink_to(release, target_is_directory=True)
    monkeypatch.setenv("TRACKER_GRYPE_DB_DIR", str(root / "current" / "grype-db"))
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            login = client.post(
                "/api/v1/auth/login",
                json={"username": "test-admin", "password": "correct-horse-battery-staple"},
            )
            csrf = login.json()["csrfToken"]
            headers = {"X-CSRF-Token": csrf}
            synced = client.post("/api/v1/vulnerability-data-bundles/sync", headers=headers)
            assert synced.status_code == 200
            assert synced.json()["items"][0]["version"] == "bundle-a"
            activated = client.post("/api/v1/vulnerability-data-bundles/bundle-a/activate", headers=headers)
            assert activated.status_code == 200
            assert activated.json()["active"] is True
    finally:
        get_settings.cache_clear()


def test_run_retry_reanalysis_and_logical_archive_keep_artifact(monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "dependency_track_enabled", True)
    sbom = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    with TestClient(app) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "test-admin", "password": "correct-horse-battery-staple"},
        )
        csrf = login.json()["csrfToken"]
        headers = {"X-CSRF-Token": csrf}
        service_id = client.get("/api/v1/services").json()[0]["id"]
        environment_id = client.get("/api/v1/environments").json()[0]["id"]
        upload = client.post(
            "/api/v1/sbom-runs",
            data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": "archive-test"},
            files={"sbom": ("archive.cdx.json", sbom, "application/json")},
            headers=headers,
        )
        assert upload.status_code == 202
        run_id = upload.json()["runId"]

        retry = client.post(f"/api/v1/sbom-runs/{run_id}/retry-dependency-track", headers=headers)
        assert retry.status_code == 202
        analysis = client.post(f"/api/v1/sbom-runs/{run_id}/analyses", headers=headers)
        assert analysis.status_code == 202
        archived = client.post(
            f"/api/v1/sbom-runs/{run_id}/archive",
            json={"reason": "보존 정책에 따른 QA 회차 보관"},
            headers=headers,
        )
        assert archived.status_code == 200
        assert archived.json()["state"] == "archived"
        assert client.post(
            f"/api/v1/sbom-runs/{run_id}/archive",
            json={"reason": "중복 보관 시도"},
            headers=headers,
        ).status_code == 409
        assert client.post(f"/api/v1/sbom-runs/{run_id}/retry-dependency-track", headers=headers).status_code == 409
        assert client.post(f"/api/v1/sbom-runs/{run_id}/analyses", headers=headers).status_code == 409
        detail = client.get(f"/api/v1/sbom-runs/{run_id}")
        assert detail.status_code == 200
        assert detail.json()["state"] == "archived"
        artifact = client.get(f"/api/v1/sbom-runs/{run_id}/artifact")
        assert artifact.status_code == 200
        assert hashlib.sha256(artifact.content).hexdigest() == hashlib.sha256(sbom).hexdigest()
