from __future__ import annotations

import asyncio
import gzip
import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker import config, epss_snapshot, package_metadata, vulnerability_intelligence as intelligence, workflows
from koda_tracker.db import Base, get_db
from koda_tracker.models import AuditEvent, Role, User
from koda_tracker.security import current_principal, digest
from koda_tracker.vulnerability_intelligence_api import router
from koda_tracker.vulnerability_intelligence_models import VulnerabilityIntelligence

CVE = "CVE-2021-44228"
AT = datetime.now(UTC)


def snapshot(*, day=None, rows=None):
    day = day or AT.date()
    return (f"#model_version:v2025.03.14,score_date:{day.isoformat()}T00:00:00+0000\n"
            "cve,epss,percentile\n" + (rows if rows is not None else f"{CVE},0.94,0.99\n")).encode()


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(config.get_settings(), "offline_mode", True)
    monkeypatch.setattr(config.get_settings(), "epss_policy_max_age_days", 7)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    users = {"admin": User(id="offline-admin", username="offline-admin", password_hash="unused", role=Role.ADMIN),
             "viewer": User(id="offline-viewer", username="offline-viewer", password_hash="unused", role=Role.VIEWER)}
    db.add_all(users.values())
    db.commit()
    app = FastAPI()
    from koda_tracker.main import RequestBodyLimitMiddleware
    app.add_middleware(RequestBodyLimitMiddleware)
    app.include_router(router)

    def principal(request: Request):
        user = users.get(request.headers.get("X-Test-User"))
        if user is None:
            raise HTTPException(401, "authentication required")
        request.state.session = SimpleNamespace(csrf_hash=digest("csrf"))
        return user

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[current_principal] = principal
    with TestClient(app) as client:
        yield db, client
    db.close()
    engine.dispose()


def upload(client, raw, *, user="admin", csrf=True):
    return client.post("/api/v1/vulnerability-intelligence/import-csv", files={"file": ("epss.csv.gz", raw, "application/gzip")},
                       headers={"X-Test-User": user, **({"X-CSRF-Token": "csrf"} if csrf else {})})


def test_offline_is_production_default(monkeypatch):
    monkeypatch.delenv("TRACKER_OFFLINE_MODE", raising=False)
    assert config.Settings(_env_file=None).offline_mode is True




def test_snapshot_upload_auth_csrf_provenance_replay_and_policy(setup):
    db, client = setup
    raw = gzip.compress(snapshot(), mtime=0)
    assert upload(client, raw, user="unknown").status_code == 401
    assert upload(client, raw, user="viewer").status_code == 403
    assert upload(client, raw, csrf=False).status_code == 403
    response = upload(client, raw)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["imported"] == 1 and result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["modelVersion"] == "v2025.03.14" and result["policyEligible"] is True
    evidence = intelligence.intelligence_payload(db.get(VulnerabilityIntelligence, CVE), at=AT)
    assert evidence["date"] == AT.date().isoformat() and evidence["snapshotSha256"] == result["sha256"]
    assert evidence["modelVersion"] == "v2025.03.14" and evidence["policyEligible"] is True
    assert evidence["fetchedAt"].startswith(AT.date().isoformat())
    finding = intelligence.enrich_findings(db, [{"id": CVE}], at=AT)[0]
    assert finding["epssScore"] == .94 and finding["epssObservedScore"] == .94
    assert upload(client, raw).json()["skipped"] == 1
    audits = list(db.scalars(select(AuditEvent).where(AuditEvent.action == "vulnerability_intelligence.snapshot_import")))
    assert len(audits) == 2


def test_old_snapshot_is_historical_not_redated_and_cannot_drive_policy(setup):
    db, client = setup
    day = AT.date() - timedelta(days=30)
    response = upload(client, snapshot(day=day))
    assert response.status_code == 200 and response.json()["policyEligible"] is False
    finding = intelligence.enrich_findings(db, [{"id": CVE}], at=AT)[0]
    assert finding["epssStatus"] == "stale" and finding["epssObservedScore"] == .94
    assert finding["epssObservedDate"] == day.isoformat() and "epssScore" not in finding
    assert finding["epssEvidence"]["policyEligible"] is False
    assert finding["epssEvidence"]["fetchedAt"].startswith(day.isoformat())


def test_offline_policy_uses_configured_source_age_not_24h_import_ttl(setup):
    db, client = setup
    day = AT.date() - timedelta(days=6)
    assert upload(client, snapshot(day=day)).status_code == 200
    assert intelligence.enrich_findings(db, [{"id": CVE}], at=AT)[0]["epssScore"] == .94
    assert "epssScore" not in intelligence.enrich_findings(db, [{"id": CVE}], at=AT + timedelta(days=2))[0]


@pytest.mark.parametrize("rows", [f"{CVE},.2,.3\n{CVE},.4,.5\n", f"{CVE},.2,.3\nCVE-2024-12345,nan,.2\n",
                                  f"{CVE},.2,.3,extra\n", f"{CVE},.2\n", ""])
def test_invalid_snapshot_never_partially_updates_database(setup, rows):
    db, client = setup
    assert upload(client, snapshot()).status_code == 200
    response = upload(client, snapshot(rows=rows))
    assert response.status_code == 422
    db.expire_all()
    assert db.query(VulnerabilityIntelligence).count() == 1
    assert db.get(VulnerabilityIntelligence, CVE).document["epss"] == .94


def test_older_file_cannot_overwrite_newer_source_score(setup):
    db, client = setup
    assert upload(client, snapshot()).status_code == 200
    response = upload(client, snapshot(day=AT.date()-timedelta(days=1), rows=f"{CVE},.1,.2\n"))
    assert response.json()["skipped"] == 1 and db.get(VulnerabilityIntelligence, CVE).document["epss"] == .94


def test_full_snapshot_exceeds_legacy_10k_cache_and_updates_in_batches(setup):
    db, client = setup
    rows = "".join(f"CVE-2026-{10000+i},.1,.2\n" for i in range(10005))
    first = upload(client, gzip.compress(snapshot(day=AT.date()-timedelta(days=1), rows=rows)))
    assert first.status_code == 200 and first.json()["imported"] == 10005
    assert db.query(VulnerabilityIntelligence).count() == 10005
    second = upload(client, gzip.compress(snapshot(rows=rows.replace(",.1,.2", ",.8,.9"))))
    assert second.status_code == 200 and second.json()["imported"] == 10005
    db.expire_all()
    assert db.get(VulnerabilityIntelligence, "CVE-2026-10000").document["epss"] == .8
    assert db.get(VulnerabilityIntelligence, "CVE-2026-20004").document["date"] == AT.date().isoformat()


def test_snapshot_cache_export_can_be_reimported_with_hash_and_model(setup):
    db, client = setup
    assert upload(client, snapshot()).status_code == 200
    headers = {"X-Test-User": "admin", "X-CSRF-Token": "csrf"}
    export = client.get("/api/v1/vulnerability-intelligence/export", headers=headers)
    assert export.status_code == 200
    result = client.post("/api/v1/vulnerability-intelligence/import", json=export.json(), headers=headers)
    assert result.status_code == 200, result.text
    row = db.get(VulnerabilityIntelligence, CVE)
    assert row.document["snapshotSha256"] == hashlib.sha256(snapshot()).hexdigest()
    assert row.document["modelVersion"] == "v2025.03.14"


def test_snapshot_rejects_gzip_bomb_corruption_and_future_source_date(monkeypatch):
    monkeypatch.setattr(epss_snapshot, "MAX_EXPANDED_BYTES", 20)
    with pytest.raises(ValueError, match="128MiB"):
        epss_snapshot.parse_snapshot(gzip.compress(snapshot()))
    with pytest.raises(ValueError):
        epss_snapshot.parse_snapshot(b"\x1f\x8bcorrupt")
    monkeypatch.setattr(epss_snapshot, "MAX_EXPANDED_BYTES", 128*1024*1024)
    with pytest.raises(ValueError, match="미래"):
        epss_snapshot.parse_snapshot(snapshot(day=AT.date()+timedelta(days=5)))


def test_csv_upload_has_bounded_multipart_exception_not_unlimited_body(setup):
    _, client = setup
    response = client.post("/api/v1/vulnerability-intelligence/import-csv", content=b"", headers={"Content-Length": str(67 * 1024 * 1024)})
    assert response.status_code == 413


def test_future_reference_score_remains_observed_and_source_maximum_age_is_enforced(setup):
    db, client = setup
    assert upload(client, snapshot()).status_code == 200
    row = db.get(VulnerabilityIntelligence, CVE)
    row.document = {**row.document, 'date': (AT.date() + timedelta(days=1)).isoformat()}
    evidence = intelligence.intelligence_payload(row, at=AT)
    assert evidence['policyEligible'] is False and evidence['ageDays'] == -1
    finding = intelligence.enrich_findings(db, [{'id': CVE}], at=AT)[0]
    assert finding['epssObservedScore'] == .94 and 'epssScore' not in finding
    row.document = {**row.document, 'date': (AT.date() - timedelta(days=2)).isoformat(), 'maxAgeDays': 1}
    evidence = intelligence.intelligence_payload(row, at=AT)
    assert evidence['policyEligible'] is False and evidence['maxAgeDays'] == 1
