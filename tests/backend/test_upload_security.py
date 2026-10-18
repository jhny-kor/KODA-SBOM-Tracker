from __future__ import annotations

import json
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal
from koda_tracker.main import app
from koda_tracker.models import SbomRun


SBOM = json.dumps(
    {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
).encode()


def _admin(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "test-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrfToken"]}


def _service(client: TestClient, headers: dict[str, str]) -> tuple[str, str]:
    slug = f"quota-{uuid.uuid4().hex[:12]}"
    service = client.post(
        "/api/v1/services", json={"slug": slug, "name": slug}, headers=headers
    )
    assert service.status_code == 201, service.text
    environment_id = client.get("/api/v1/environments").json()[0]["id"]
    return service.json()["id"], environment_id


def _upload(
    client: TestClient,
    service_id: str,
    environment_id: str,
    headers: dict[str, str],
    release: str,
):
    return client.post(
        "/api/v1/sbom-runs",
        data={
            "serviceId": service_id,
            "environmentId": environment_id,
            "releaseVersion": release,
        },
        files={"sbom": ("empty.cdx.json", SBOM, "application/json")},
        headers=headers,
    )


def test_full_queue_rejects_upload_without_creating_run(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "max_queued_jobs", 0)
    with TestClient(app) as client:
        headers = _admin(client)
        service_id, environment_id = _service(client, headers)
        with SessionLocal() as db:
            before = db.scalar(select(func.count()).select_from(SbomRun))
        response = _upload(client, service_id, environment_id, headers, "queue-full")
        assert response.status_code == 429
        with SessionLocal() as db:
            assert db.scalar(select(func.count()).select_from(SbomRun)) == before


def test_service_storage_quota_fails_before_artifact_persistence(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "max_queued_jobs", 10_000)
    monkeypatch.setattr(settings, "max_service_storage_bytes", 1)
    with TestClient(app) as client:
        headers = _admin(client)
        service_id, environment_id = _service(client, headers)
        response = _upload(client, service_id, environment_id, headers, "storage-full")
        assert response.status_code == 507
        with SessionLocal() as db:
            assert db.scalar(
                select(func.count()).select_from(SbomRun).join(SbomRun.release).where(
                    SbomRun.release.has(service_id=service_id)
                )
            ) == 0


def test_duplicate_artifacts_still_count_toward_database_ingest_quota(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "max_queued_jobs", 10_000)
    monkeypatch.setattr(settings, "max_service_ingested_bytes", len(SBOM))
    with TestClient(app) as client:
        headers = _admin(client)
        service_id, environment_id = _service(client, headers)
        first = _upload(client, service_id, environment_id, headers, "ingest-first")
        assert first.status_code == 202, first.text
        duplicate = _upload(client, service_id, environment_id, headers, "ingest-duplicate")
        assert duplicate.status_code == 507


def test_service_token_rotation_does_not_reset_upload_rate_limit(monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "max_queued_jobs", 10_000)
    monkeypatch.setattr(settings, "upload_rate_limit", 1)
    with TestClient(app) as client:
        admin_headers = _admin(client)
        service_id, environment_id = _service(client, admin_headers)
        tokens = [
            client.post(
                "/api/v1/api-tokens",
                json={"name": f"quota-token-{index}", "serviceId": service_id},
                headers=admin_headers,
            ).json()["token"]
            for index in range(2)
        ]
        client.cookies.clear()
        first = _upload(
            client,
            service_id,
            environment_id,
            {"Authorization": f"Bearer {tokens[0]}", "Idempotency-Key": "quota-first"},
            "quota-first",
        )
        assert first.status_code == 202, first.text
        rotated = _upload(
            client,
            service_id,
            environment_id,
            {"Authorization": f"Bearer {tokens[1]}", "Idempotency-Key": "quota-second"},
            "quota-second",
        )
        assert rotated.status_code == 429
