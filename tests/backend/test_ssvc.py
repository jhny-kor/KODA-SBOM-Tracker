from __future__ import annotations

import copy
import itertools
import socket
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker.db import Base, get_db
from koda_tracker.environment_admin_models import EnvironmentAdministrator
from koda_tracker.models import AnalysisRevision, ApiToken, AuditEvent, Environment, JobState, Release, Role, SbomRun, Service, User, UserSession
from koda_tracker.security import digest
from koda_tracker.ssvc import MODEL, OPTIONS, decision_table, evaluate
from koda_tracker.ssvc_api import router
from koda_tracker.ssvc_models import SsvcAssessment
from koda_tracker.vulnerability_intelligence_models import VulnerabilityIntelligence

FINDING = {"id": "CVE-2021-44228", "canonicalId": "CVE-2021-44228", "component": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "version": "2.14.1", "severity": "Critical", "kev": True}
INPUTS = {"exploitation": "active", "systemExposure": "open", "automatable": "yes", "humanImpact": "high"}


@pytest.fixture
def setup(monkeypatch):
    # API, calculations and evidence reads must work with all socket connects denied.
    def denied(*args, **kwargs):
        pytest.fail("SSVC attempted network access")
    monkeypatch.setattr(socket.socket, "connect", denied)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    db.add_all([Service(id="s", slug="ssvc", name="SSVC"), Environment(id="e", slug="ssvc-prod", name="운영"),
                Release(id="r", service_id="s", environment_id="e", version="1"),
                User(id="u", username="assessor", password_hash="unused", role=Role.ANALYST),
                User(id="v", username="reader", password_hash="unused", role=Role.VIEWER)])
    db.flush()
    run = SbomRun(id="run", release_id="r", round_number=1, analysis_state=JobState.COMPLETED, original_filename="a.json", media_type="application/json", spec_version="1.6", sha256="a"*64, size_bytes=12, artifact_path="unused", normalized_bom={})
    revision = AnalysisRevision(id="revision", run_id="run", sequence=1, state=JobState.COMPLETED, findings=[copy.deepcopy(FINDING)], data_as_of="2026-10-19")
    db.add_all([run, revision,
                EnvironmentAdministrator(environment_id="e", user_id="u", assigned_by="admin"),
                EnvironmentAdministrator(environment_id="e", user_id="v", assigned_by="admin"),
                UserSession(id_hash=digest("session"), user_id="u", csrf_hash=digest("csrf"), expires_at=datetime.now(UTC)+timedelta(hours=1)),
                UserSession(id_hash=digest("viewer"), user_id="v", csrf_hash=digest("csrf"), expires_at=datetime.now(UTC)+timedelta(hours=1)),
                ApiToken(id="token", name="other service", token_hash=digest("token"), service_id="elsewhere")])
    db.commit()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        client.cookies.set("koda_session", "session")
        yield db, client, run, revision
    db.close(); engine.dispose()


def body(**changes):
    result = {"component": FINDING["component"], "vulnerabilityId": FINDING["id"], "expectedRevisionId": "revision", "inputs": INPUTS.copy(), "rationale": "운영 서비스 노출과 안전·업무 영향 검토", "references": ["내부 검토 보고서 SEC-42"]}
    result.update(changes)
    return result


def post(client, value=None, headers=None):
    return client.post("/api/v1/sbom-runs/run/ssvc", json=body() if value is None else value, headers={"X-CSRF-Token": "csrf"} if headers is None else headers)


def test_official_complete_decision_table_and_boundaries():
    table, provenance = decision_table()
    assert len(table) == 72
    assert provenance["model"] == MODEL
    assert provenance["upstreamCommit"] == "fa6a3a4cb3943d76e3f0057d84dc57b5fe3e064a"
    # Official table row-order oracle, independent of dictionary lookup order.
    oracle = "DDSS DSSS DSSS SSSS DSSS SSSO DSSS SSSS DSSS SSSO SSSO SSOO SSOO SOOO SSOO OOOO SOOI OOII".replace(" ", "")
    labels = {"D": "defer", "S": "scheduled", "O": "out-of-cycle", "I": "immediate"}
    for combination, expected in zip(itertools.product(*OPTIONS.values()), oracle, strict=True):
        assert evaluate(dict(zip(OPTIONS, combination))) == labels[expected]
    for missing in OPTIONS:
        assert evaluate({**INPUTS, missing: None}) is None
    with pytest.raises(ValueError):
        evaluate({**INPUTS, "exploitation": "unknown"})
    with pytest.raises(ValueError):
        evaluate({})


def test_offline_roundtrip_append_only_context_and_audit(setup):
    db, client, run, revision = setup
    metadata = client.get("/api/v1/ssvc/model").json()
    assert metadata["runtimeNetworkRequired"] is False
    first = post(client)
    assert first.status_code == 201, first.text
    result = first.json()
    assert result["outcome"] == "immediate" and result["state"] == "assessed" and not result["stale"]
    assert (result["serviceId"], result["environmentId"], result["releaseId"], result["revisionId"]) == ("s", "e", "r", "revision")
    assert result["evidence"]["finding"]["kev"] is True
    assert len(result["tableSha256"]) == 64
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "ssvc.assess")).actor == "assessor"
    second = post(client, body(inputs={**INPUTS, "systemExposure": None}, rationale="노출 정보 확인 필요"))
    assert second.status_code == 201 and second.json()["outcome"] is None
    assert second.json()["state"] == "unassessed"
    db.expire_all()
    listing = client.get("/api/v1/sbom-runs/run/ssvc").json()
    assert listing["total"] == 2 and listing["items"][0]["state"] == "unassessed"
    assert listing["items"][1]["id"] == result["id"] and listing["items"][1]["outcome"] == "immediate"
    assert listing["items"][1]["superseded"] is True
    assert client.get("/api/v1/sbom-runs/run/ssvc?size=1&page=2").json()["items"][0]["id"] == result["id"]


def test_authentication_permission_service_token_and_csrf_boundaries(setup):
    db, client, run, revision = setup
    assert post(client, headers={}).status_code == 403
    client.cookies.set("koda_session", "viewer")
    assert client.get("/api/v1/sbom-runs/run/ssvc").status_code == 200
    assert post(client).status_code == 403
    assert client.get("/api/v1/sbom-runs/run/ssvc", headers={"Authorization": "Bearer token"}).status_code == 403
    assert post(client, headers={"Authorization": "Bearer token"}).status_code == 403
    client.cookies.clear()
    assert client.get("/api/v1/sbom-runs/run/ssvc").status_code == 401
    assert post(client).status_code == 401


def test_invalid_or_unconfirmed_target_cannot_create_decision(setup):
    db, client, run, revision = setup
    assert post(client, body(inputs={**INPUTS, "exploitation": "none"})).status_code == 422
    assert post(client, body(inputs={**INPUTS, "exploitation": "unknown"})).status_code == 422
    assert post(client, body(outcome="defer")).status_code == 422
    assert post(client, body(component="pkg:pypi/other@1")).status_code == 422
    assert post(client, body(vulnerabilityId="CVE-2026-0001")).status_code == 422
    assert post(client, body(rationale="  ")).status_code == 422
    assert post(client, body(references=["x"*2049])).status_code == 422
    assert post(client, body(reviewAt="2020-01-01T00:00:00Z")).status_code == 422
    assert post(client, body(expectedRevisionId="old")).status_code == 409
    assert db.scalar(select(SsvcAssessment)) is None


def test_revision_failure_archiving_and_review_due_require_reassessment(setup):
    db, client, run, revision = setup
    saved = post(client).json()
    row = db.get(SsvcAssessment, saved["id"])
    row.review_at = datetime.now(UTC)-timedelta(seconds=1)
    db.commit()
    assert "review_due" in client.get("/api/v1/sbom-runs/run/ssvc").json()["items"][0]["staleReasons"]
    row.review_at = None
    new = AnalysisRevision(id="new", run_id=run.id, sequence=2, state=JobState.FAILED, findings=[])
    db.add(new); db.commit(); db.expire_all()
    listing = client.get("/api/v1/sbom-runs/run/ssvc").json()
    assert not listing["analysisReady"] and listing["items"][0]["staleReasons"] == ["analysis_changed"]
    assert post(client).status_code == 409
    run.archived_at = datetime.now(UTC); db.commit()
    assert post(client).status_code == 409


def test_live_epss_evidence_changes_stale_saved_decision_without_mutating_revision(setup):
    db, client, run, revision = setup
    post(client)
    original = copy.deepcopy(revision.findings)
    at = datetime.now(UTC)
    db.add(VulnerabilityIntelligence(cve=FINDING["id"], state="completed", document={"epss": .9, "percentile": .99, "date": at.date().isoformat()}, fetched_at=at, expires_at=at+timedelta(hours=1)))
    db.commit()
    item = client.get("/api/v1/sbom-runs/run/ssvc").json()["items"][0]
    assert item["stale"] and item["staleReasons"] == ["evidence_changed"]
    assert revision.findings == original and "epssScore" not in revision.findings[0]


def test_finding_kev_change_invalidates_decision(setup):
    db, client, run, revision = setup
    post(client)
    revision.findings = [{**FINDING, "kev": False}]
    db.commit()
    assert client.get("/api/v1/sbom-runs/run/ssvc").json()["items"][0]["stale"]


def test_new_offline_data_requires_reanalysis_before_new_assessment(setup, monkeypatch):
    from types import SimpleNamespace
    from koda_tracker import ssvc_api
    db, client, run, revision = setup
    post(client)
    monkeypatch.setattr(ssvc_api, "active_bundle", lambda _: SimpleNamespace(version="new-data"))
    record = client.get("/api/v1/sbom-runs/run/ssvc").json()["items"][0]
    assert "analysis_data_outdated" in record["staleReasons"]
    assert post(client).status_code == 409
    revision.data_sources = {"bundleVersion": "new-data"}
    db.commit()
    assert post(client).status_code == 201


def test_queued_reanalysis_does_not_treat_previous_completed_result_as_current(setup):
    db, client, run, revision = setup
    post(client)
    run.analysis_state = JobState.QUEUED
    db.commit()
    result = client.get("/api/v1/sbom-runs/run/ssvc").json()
    assert not result["analysisReady"] and result["items"][0]["staleReasons"] == ["analysis_changed"]
    assert post(client).status_code == 409


def test_changed_decision_model_preserves_old_result_but_requires_review(setup):
    db, client, run, revision = setup
    saved = post(client).json()
    row = db.get(SsvcAssessment, saved["id"])
    row.table_sha256 = "0" * 64
    db.commit()
    item = client.get("/api/v1/sbom-runs/run/ssvc").json()["items"][0]
    assert item["outcome"] == "immediate" and item["staleReasons"] == ["model_changed"]


def test_non_purl_cpe_identity_and_evidence_are_scoped_and_rechecked(setup):
    db, client, run, revision = setup
    finding = {**FINDING, "component": "widget", "version": "1.2.0", "sourceKind": "nvd_cpe",
               "cpeEvidence": [{"cpe": "cpe:2.3:a:acme:widget:1.2.0:*:*:*:*:*:*:*", "status": "affected"}],
               "nvdCvss": {"cvssV3": {"baseScore": 9.8}}}
    revision.findings = [finding]
    db.commit()
    saved = post(client, body(component="widget@1.2.0"))
    assert saved.status_code == 201, saved.text
    result = saved.json()
    assert result["component"] == "widget@1.2.0" and result["componentVersion"] == "1.2.0"
    assert result["evidence"]["finding"]["sourceKind"] == "nvd_cpe"
    assert result["evidence"]["finding"]["cpeEvidence"] == finding["cpeEvidence"]
    assert result["evidence"]["finding"]["nvdCvss"] == finding["nvdCvss"]
    revision.findings = [{**finding, "cpeEvidence": [{**finding["cpeEvidence"][0], "reason": "new conditions"}]}]
    db.commit()
    assert client.get("/api/v1/sbom-runs/run/ssvc").json()["items"][0]["staleReasons"] == ["evidence_changed"]
