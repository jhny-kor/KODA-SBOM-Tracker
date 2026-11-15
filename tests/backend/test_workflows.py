from __future__ import annotations

import copy
import hashlib
import hmac
import json
import socket
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpcore
import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker import workflows
from koda_tracker.db import Base, get_db
from koda_tracker.models import (AnalysisRevision, Environment, JobState, Release, Role, RolePolicy,
                                 SbomRun, Service, User)
from koda_tracker.security import current_principal, digest
from koda_tracker.workflow_api import router
from koda_tracker.workflow_models import (FindingReview, NotificationDelivery, NotificationEvent,
                                          NotificationReceipt, ReviewEvent)

PURL = "pkg:pypi/demo@1.0"
CVE = "CVE-2026-10000"
FINDING = {"id": "GHSA-demo", "canonicalId": CVE, "aliases": [CVE, "GHSA-demo"], "component": PURL,
           "version": "1.0", "severity": "High", "kev": True}
BODY = {"component": PURL, "vulnerabilityId": CVE, "state": "not_affected",
        "justification": "code_not_reachable", "detail": "The vulnerable function is not reachable; call graph evidence attached.", "response": ["workaround_available"]}


def revision(run, sequence, findings=None):
    rows = [{"policyId": name, "component": PURL, "componentVersion": "1.0", "vulnerabilityId": CVE,
             "type": kind, "action": "fail", "suppressed": False, **extra}
            for name, kind, extra in [("high", "severity", {}), ("kev", "kev", {}),
                                      ("license", "license_denied", {}), ("project", "cel", {"target": "project"}),
                                      ("vuln", "cel", {"target": "vulnerability"}), ("missing", "data_unavailable", {})]]
    result = AnalysisRevision(run_id=run.id, sequence=sequence, state=JobState.COMPLETED,
                              findings=copy.deepcopy([FINDING] if findings is None else findings), policies=rows,
                              policy_state="completed", metrics={"vulnerabilityCount": 1, "severityCounts": {"high": 1}, "kevCount": 1})
    run.analyses.append(result)
    return result


@pytest.fixture
def setup(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False, autoflush=False)
    users = {name: User(id=name, username=name, password_hash="unused", role=Role.VIEWER if name == "viewer" else Role.ADMIN) for name in ["author", "reviewer", "viewer"]}
    db.add_all(users.values())
    db.add(RolePolicy(role=Role.ADMIN, permissions=["vex.view", "vex.manage", "vex.approve", "notifications.view", "notifications.manage"]))
    db.add(RolePolicy(role=Role.VIEWER, permissions=["vex.view", "notifications.view"]))
    service = Service(id="service", slug="workflow-service", name="Workflow")
    environment = Environment(id="env", slug="workflow-env", name="Test")
    release = Release(id="release", service=service, environment=environment, version="1")
    run = SbomRun(id="run", release=release, round_number=1, original_filename="demo.json", media_type="application/json",
                  spec_version="1.6", sha256="0" * 64, size_bytes=1, artifact_path="unused",
                  normalized_bom={"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "bom-ref": "demo-ref", "name": "demo", "version": "1.0", "purl": PURL}]})
    db.add(run)
    revision(run, 1)
    db.commit()
    settings = SimpleNamespace(notification_webhook_enabled=False, notification_webhook_url="", notification_webhook_secret="", notification_allowed_hosts="")
    monkeypatch.setattr(workflows, "get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(router)
    def database():
        yield db
    def principal(request: Request):
        user = users.get(request.headers.get("X-Test-User"))
        if not user:
            raise HTTPException(401, "authentication required")
        request.state.session = SimpleNamespace(csrf_hash=digest("csrf"))
        return user
    app.dependency_overrides[get_db] = database
    app.dependency_overrides[current_principal] = principal
    with TestClient(app) as client:
        yield SimpleNamespace(db=db, run=run, users=users, client=client, settings=settings)
    db.close()
    engine.dispose()


def headers(user="author", csrf=True):
    return {"X-Test-User": user, **({"X-CSRF-Token": "csrf"} if csrf else {})}


def submit(setup, body=None):
    response = setup.client.post("/api/v1/sbom-runs/run/reviews", json=body or BODY, headers=headers())
    assert response.status_code == 201, response.text
    return response.json()


def approve(setup, review):
    response = setup.client.post(f"/api/v1/reviews/{review['id']}/decision", json={"decision": "approved", "reason": "Evidence independently verified"}, headers=headers("reviewer"))
    assert response.status_code == 200, response.text
    return response.json()


def test_review_rbac_csrf_distinct_approval_append_only_and_audit(setup):
    client = setup.client
    assert client.get("/api/v1/sbom-runs/run/reviews").status_code == 401
    assert client.post("/api/v1/sbom-runs/run/reviews", json=BODY, headers=headers(csrf=False)).status_code == 403
    assert client.post("/api/v1/sbom-runs/run/reviews", json=BODY, headers=headers("viewer")).status_code == 403
    review = submit(setup)
    assert review["status"] == "submitted"
    url = f"/api/v1/reviews/{review['id']}/decision"
    body = {"decision": "approved", "reason": "self approval"}
    assert client.post(url, json=body, headers=headers()).status_code == 403
    assert client.post(url, json=body, headers=headers("viewer")).status_code == 403
    approve(setup, review)
    assert client.post(url, json={"decision": "rejected", "reason": "mutate approval"}, headers=headers("reviewer")).status_code == 409
    assert client.post(f"/api/v1/reviews/{review['id']}/events", json={"comment": "additional audit evidence"}, headers=headers()).status_code == 201
    events = client.get(f"/api/v1/reviews/{review['id']}/events", headers=headers()).json()["items"]
    assert {r["kind"] for r in events} == {"submitted", "approved", "comment"}
    listed = client.get("/api/v1/sbom-runs/run/reviews", headers=headers()).json()
    assert listed["total"] == 1 and listed["items"][0]["detail"] == BODY["detail"]
    assert setup.db.scalar(select(NotificationEvent).where(NotificationEvent.kind == "review_submitted"))
    assert setup.db.scalar(select(NotificationEvent).where(NotificationEvent.kind == "review_approved"))


def test_exact_target_evidence_expiry_validation(setup):
    for changes in [{"component": "pkg:pypi/demo@2.0"}, {"vulnerabilityId": "CVE-foreign"},
                    {"justification": ""}, {"detail": "   "}, {"state": "unknown"},
                    {"response": ["invented"]}, {"expiresAt": "2020-01-01T00:00:00Z"},
                    {"expiresAt": "2030-01-01T00:00:00"}, {"extra": "not allowed"}]:
        result = setup.client.post("/api/v1/sbom-runs/run/reviews", json={**BODY, **changes}, headers=headers())
        assert result.status_code == 422, result.text
    alias = submit(setup, {**BODY, "vulnerabilityId": "GHSA-demo"})
    assert alias["vulnerabilityId"] == CVE


def test_approved_vex_suppresses_only_security_preserves_raw_and_old_revision(setup):
    old = setup.run.analyses[0]
    snapshot = copy.deepcopy(old.findings)
    review = submit(setup)
    pending = revision(setup.run, 2)
    workflows.apply_vex_reviews(setup.db, setup.run, pending)
    assert not any(p["suppressed"] for p in pending.policies)
    approve(setup, review)
    current = revision(setup.run, 3)
    applied = workflows.apply_vex_reviews(setup.db, setup.run, current)
    assert applied == {"applied": 1, "suppressed": 1}
    assert {p["policyId"] for p in current.policies if p["suppressed"]} == {"high", "kev", "vuln"}
    assert current.metrics["effectiveVulnerabilityCount"] == 0
    assert current.metrics["vulnerabilityCount"] == 1 and current.metrics["severityCounts"] == {"high": 1} and current.metrics["kevCount"] == 1
    assert current.metrics["policyFailCount"] == 3 and current.metrics["policyStatus"] == "fail"
    assert old.findings == snapshot and "vex" not in old.findings[0]
    assert current.findings[0]["vex"]["reviewer"] == "reviewer"


def test_scope_version_revocation_and_expiry_do_not_restore_older_approval(setup):
    approve(setup, submit(setup))
    newer = approve(setup, submit(setup, {**BODY, "state": "exploitable", "justification": ""}))
    current = revision(setup.run, 2)
    workflows.apply_vex_reviews(setup.db, setup.run, current)
    assert current.metrics["vexSuppressedCount"] == 0
    row = setup.db.get(FindingReview, newer["id"])
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    setup.db.commit()
    assert workflows.approved_for_run(setup.db, setup.run) == {}
    row.expires_at = None
    row.environment_id = "other-environment"
    setup.db.commit()
    version2 = revision(setup.run, 3, [{**FINDING, "component": "pkg:pypi/demo@2.0", "version": "2.0"}])
    workflows.apply_vex_reviews(setup.db, setup.run, version2)
    assert version2.metrics["vexSuppressedCount"] == 0


def test_vex_export_import_bind_refs_and_require_local_approval(setup):
    approve(setup, submit(setup))
    exported = setup.client.get("/api/v1/sbom-runs/run/vex", headers=headers()).json()
    assert exported["bomFormat"] == "CycloneDX" and exported["specVersion"] == "1.6"
    item = exported["vulnerabilities"][0]
    assert item["affects"] == [{"ref": "demo-ref"}]
    assert item["analysis"]["state"] == "not_affected" and item["analysis"]["justification"] == "code_not_reachable"
    assert exported["components"][0]["bom-ref"] == "demo-ref"
    result = setup.client.post("/api/v1/sbom-runs/run/vex-import", json=exported, headers=headers())
    assert result.status_code == 201, result.text
    assert result.json()["imported"] == 1 and result.json()["items"][0]["status"] == "submitted"
    foreign = copy.deepcopy(exported)
    foreign["vulnerabilities"][0]["affects"] = [{"ref": "foreign-ref"}]
    assert setup.client.post("/api/v1/sbom-runs/run/vex-import", json=foreign, headers=headers()).status_code == 422
    assert setup.client.post("/api/v1/sbom-runs/run/vex-import", json=exported, headers=headers("viewer")).status_code == 403
    assert setup.client.post("/api/v1/sbom-runs/run/vex-import", json=exported, headers=headers(csrf=False)).status_code == 403
    huge = {**exported, "vulnerabilities": [item] * 101}
    assert setup.client.post("/api/v1/sbom-runs/run/vex-import", json=huge, headers=headers()).status_code == 422
    assert setup.client.post("/api/v1/sbom-runs/run/vex-import", content=b"x" * 65537, headers=headers()).status_code == 413


@pytest.mark.parametrize("change", [{"analysis": {"state": []}}, {"id": {}}, {"affects": ["bad"]},
                                     {"analysis": {"state": "not_affected", "detail": "text", "response": [["bad"]]}}])
def test_malformed_vex_never_causes_server_error_or_partial_insert(setup, change):
    vuln = {"id": CVE, "analysis": {"state": "not_affected", "detail": "evidence", "justification": "code_not_reachable"}, "affects": [{"ref": "demo-ref"}]}
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": [vuln, {**vuln, **change}]}
    response = setup.client.post("/api/v1/sbom-runs/run/vex-import", json=doc, headers=headers())
    assert response.status_code == 422, response.text
    assert setup.db.scalars(select(FindingReview)).all() == []


def test_notification_dedup_meaningful_change_and_per_user_read_receipts(setup):
    first = setup.run.analyses[0]
    assert workflows.notify_analysis(setup.db, setup.run, first)
    setup.db.commit()
    assert workflows.notify_analysis(setup.db, setup.run, first).id
    identical = revision(setup.run, 2)
    setup.db.add(identical)
    setup.db.flush()
    assert workflows.notify_analysis(setup.db, setup.run, identical) is None
    changed = revision(setup.run, 3, [])
    setup.db.add(changed)
    setup.db.flush()
    assert workflows.notify_analysis(setup.db, setup.run, changed)
    failure = revision(setup.run, 4, [])
    failure.state = JobState.FAILED
    setup.db.add(failure)
    setup.db.flush()
    assert workflows.notify_analysis(setup.db, setup.run, failure).kind == "analysis_failed"
    setup.db.commit()
    client = setup.client
    listed = client.get("/api/v1/notifications", headers=headers()).json()
    assert listed["total"] == listed["unreadCount"] == 3
    event = listed["items"][0]["id"]
    assert client.post(f"/api/v1/notifications/{event}/read", headers=headers(csrf=False)).status_code == 403
    assert client.post(f"/api/v1/notifications/{event}/read", headers=headers()).status_code == 200
    assert client.post(f"/api/v1/notifications/{event}/read", headers=headers()).status_code == 200
    assert client.get("/api/v1/notifications", headers=headers()).json()["unreadCount"] == 2
    assert client.get("/api/v1/notifications", headers=headers("reviewer")).json()["unreadCount"] == 3
    assert client.get("/api/v1/notification-deliveries", headers=headers("viewer")).status_code == 403


def webhook_resolution(monkeypatch, expect_host, expect_port, addresses):
    calls = []

    def resolve(host, port, *, type):
        calls.append((host, port))
        assert (host, port, type) == (expect_host, expect_port, socket.SOCK_STREAM)
        return [(socket.AF_INET6 if ":" in address else socket.AF_INET, type, socket.IPPROTO_TCP, "",
                 (address, port, 0, 0) if ":" in address else (address, port)) for address in addresses]

    monkeypatch.setattr(workflows.socket, "getaddrinfo", resolve)
    return calls


def test_webhook_signed_bounded_retry_no_redirect_and_manual_retry(setup, monkeypatch):
    settings = setup.settings
    settings.notification_webhook_enabled = True
    settings.notification_webhook_url = "http://collector.internal:8080/hook?message=a%20b"
    settings.notification_allowed_hosts = "collector.internal,10.20.30.40"
    settings.notification_webhook_secret = "do-not-leak-this-secret"
    resolutions = webhook_resolution(monkeypatch, "collector.internal", 8080, ["10.20.30.40"])
    event = workflows.notify_analysis(setup.db, setup.run, setup.run.analyses[0])
    setup.db.commit()
    deliveries = setup.db.scalars(select(NotificationDelivery)).all()
    assert len(deliveries) == 1
    requests = []
    def collector(request):
        requests.append(request)
        assert request.url.host == "10.20.30.40"
        assert request.url.port == 8080
        assert request.url.raw_path == b"/hook?message=a%20b"
        assert request.headers["Host"] == "collector.internal:8080"
        expected = hmac.new(settings.notification_webhook_secret.encode(), request.content, hashlib.sha256).hexdigest()
        assert request.headers["X-KODA-Signature"] == "sha256=" + expected
        assert request.headers["Idempotency-Key"] == event.id
        return httpx.Response(302, headers={"location": "http://forbidden.invalid/secret"})
    transport = httpx.MockTransport(collector)
    row = deliveries[0]
    for attempt in range(1, 6):
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        setup.db.commit()
        assert workflows.deliver_notifications(setup.db, transport=transport) == 0
        assert row.attempts == attempt
    assert len(requests) == 5 and row.status == "failed"
    assert "secret" not in row.last_error and "collector" not in row.last_error
    listed = setup.client.get("/api/v1/notification-deliveries", headers=headers()).json()
    assert listed["items"][0]["attempts"] == 5
    url = f"/api/v1/notification-deliveries/{row.id}/retry"
    assert setup.client.post(url, headers=headers("viewer")).status_code == 403
    assert setup.client.post(url, headers=headers(csrf=False)).status_code == 403
    assert setup.client.post(url, headers=headers()).status_code == 200
    assert row.status == "pending" and row.attempts == 0
    assert workflows.deliver_notifications(setup.db, transport=httpx.MockTransport(lambda request: httpx.Response(204))) == 1
    assert row.status == "delivered"
    assert workflows.deliver_notifications(setup.db, transport=transport) == 0
    assert len(resolutions) == 6
    config = setup.client.get("/api/v1/notification-settings", headers=headers()).json()
    assert config["webhookConfigured"] is True and "secret" not in json.dumps(config).lower().replace("secretconfigured", "")


@pytest.mark.parametrize("url,allowed", [("http://169.254.169.254/latest/meta-data", "collector.internal"),
                                          ("https://collector.internal.evil/hook", "collector.internal"),
                                          ("http://public.example/hook", "public.example"),
                                          ("https://user:password@collector.internal/hook", "collector.internal"),
                                          ("ftp://collector.internal/hook", "collector.internal"),
                                          ("https://collector.internal:invalid/hook", "collector.internal")])
def test_webhook_destination_rejection_never_uses_transport(setup, url, allowed):
    setup.settings.notification_webhook_enabled = True
    setup.settings.notification_webhook_url = url
    setup.settings.notification_allowed_hosts = allowed
    setup.settings.notification_webhook_secret = "secret"
    workflows.notify_analysis(setup.db, setup.run, setup.run.analyses[0])
    setup.db.commit()
    def forbidden(request):
        pytest.fail("unsafe destination attempted network I/O")
    assert workflows.deliver_notifications(setup.db, transport=httpx.MockTransport(forbidden)) == 0
    assert not workflows.webhook_settings()[-1]


def test_webhook_https_keeps_original_tls_name_on_validated_addresses(setup, monkeypatch):
    setup.settings.notification_webhook_enabled = True
    setup.settings.notification_webhook_url = "https://collector.example:8443/hook"
    setup.settings.notification_allowed_hosts = "collector.example,fd12::1"
    setup.settings.notification_webhook_secret = "secret"
    resolutions = webhook_resolution(monkeypatch, "collector.example", 8443, ["fd12::1", "93.184.216.34"])
    workflows.notify_analysis(setup.db, setup.run, setup.run.analyses[0])
    setup.db.commit()
    attempted = []
    sent = []

    class TLSStream(httpcore.MockStream):
        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            assert server_hostname == "collector.example"
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED and ssl_context.check_hostname
            return self

        def write(self, buffer, timeout=None):
            sent.append(buffer)

    def connect_tcp(self, host, port, **kwargs):
        attempted.append((host, port))
        if len(attempted) == 1:
            raise httpcore.ConnectError("fixture connection unavailable")
        return TLSStream([b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"])

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect_tcp)
    assert workflows.deliver_notifications(setup.db) == 1
    assert attempted == [("fd12::1", 8443), ("93.184.216.34", 8443)]
    assert resolutions == [("collector.example", 8443)]
    assert b"\r\nhost: collector.example:8443\r\n" in b"".join(sent).lower()


@pytest.mark.parametrize(("scheme", "address"), [("https", address) for address in (
    "10.20.30.41", "::ffff:127.0.0.1", "fe80::1", "::", "224.0.0.1", "240.0.0.1",
    "64:ff9b::c000:201", "64:ff9b:1::c000:201", "2002:c000:201::1", "2001:0:c000:201::1",
)] + [("http", "93.184.216.34")])
def test_webhook_rejects_mixed_dns_before_transport(setup, monkeypatch, scheme, address):
    setup.settings.notification_webhook_enabled = True
    setup.settings.notification_webhook_url = f"{scheme}://collector.internal/hook"
    setup.settings.notification_allowed_hosts = "collector.internal,10.20.30.40"
    setup.settings.notification_webhook_secret = "secret"
    port = 443 if scheme == "https" else 80
    resolutions = webhook_resolution(monkeypatch, "collector.internal", port, ["10.20.30.40", address])
    workflows.notify_analysis(setup.db, setup.run, setup.run.analyses[0])
    setup.db.commit()

    def forbidden(request):
        pytest.fail("address policy must reject the entire DNS answer before HTTP")

    assert workflows.deliver_notifications(setup.db, transport=httpx.MockTransport(forbidden)) == 0
    assert resolutions == [("collector.internal", port)]
    delivery = setup.db.scalar(select(NotificationDelivery))
    assert delivery.status == "pending" and delivery.last_error == "Webhook connection failed"


def test_webhook_private_literal_and_offline_mode_do_not_resolve(setup, monkeypatch):
    setup.settings.notification_webhook_enabled = True
    setup.settings.notification_webhook_url = "http://[fd12::1]/hook"
    setup.settings.notification_allowed_hosts = "fd12:0:0:0:0:0:0:1"
    setup.settings.notification_webhook_secret = "secret"
    workflows.notify_analysis(setup.db, setup.run, setup.run.analyses[0])
    setup.db.commit()

    def no_dns(*args, **kwargs):
        pytest.fail("numeric destinations and offline mode need no DNS")

    def collector(request):
        assert not setup.settings.offline_mode
        assert request.url.host == "fd12::1"
        assert request.headers["Host"] == "[fd12::1]"
        return httpx.Response(204)

    monkeypatch.setattr(workflows.socket, "getaddrinfo", no_dns)
    setup.settings.offline_mode = True
    assert workflows.deliver_notifications(setup.db, transport=httpx.MockTransport(collector)) == 0
    assert setup.db.scalar(select(NotificationDelivery)).attempts == 0
    setup.settings.offline_mode = False
    assert workflows.deliver_notifications(setup.db, transport=httpx.MockTransport(collector)) == 1


def test_review_carries_to_new_run_only_in_same_service_environment_and_component_version(setup):
    approve(setup, submit(setup))
    same_scope = SimpleNamespace(id="next-run", release=setup.run.release)
    changed_scope = SimpleNamespace(id="other-run", release=SimpleNamespace(service_id="different-service", environment_id="env"))
    other_environment = SimpleNamespace(id="other-run", release=SimpleNamespace(service_id="service", environment_id="other"))
    current = revision(setup.run, 2)
    assert workflows.apply_vex_reviews(setup.db, same_scope, current)["suppressed"] == 1
    assert workflows.approved_for_run(setup.db, changed_scope) == {}
    assert workflows.approved_for_run(setup.db, other_environment) == {}


@pytest.mark.parametrize("state,policy_state", [(JobState.FAILED, "not_evaluated"), (JobState.QUEUED, "not_evaluated"), (JobState.COMPLETED, "failed")])
def test_vex_does_not_mutate_incomplete_or_failed_policy_evidence(setup, state, policy_state):
    current = SimpleNamespace(state=state, policy_state=policy_state, findings=[], policies=[], metrics={})
    assert workflows.apply_vex_reviews(None, setup.run, current) == {"applied": 0, "suppressed": 0}
    assert current.metrics == {} and current.findings == []


@pytest.mark.parametrize("change", [{"severity": "Critical"}, {"kev": False}, {"fixedIn": ["2.0"]},
                                     {"cvssScore": 8.3}, {"nvdCvss": {"cvssV3": {"baseScore": 8.3}}},
                                     {"vex": {"state": "exploitable", "justification": ""}}])
def test_notification_detects_material_changes_to_existing_cve(setup, change):
    first = setup.run.analyses[0]
    workflows.notify_analysis(setup.db, setup.run, first)
    setup.db.commit()
    second = revision(setup.run, 2, [{**FINDING, **change}])
    setup.db.add(second)
    setup.db.flush()
    assert workflows.notify_analysis(setup.db, setup.run, second).kind == "analysis_changed"


def test_policy_failure_gets_explicit_durable_notification(setup):
    failed = setup.run.analyses[0]
    failed.policy_state = "failed"
    event = workflows.notify_analysis(setup.db, setup.run, failed)
    assert event.kind == "policy_failed" and "정책 평가 실패" in event.title


def test_import_rejects_same_bom_ref_with_foreign_component_identity(setup):
    approve(setup, submit(setup))
    document = workflows.export_vex(setup.db, setup.run)
    document["components"][0]["purl"] = "pkg:pypi/foreign@1.0"
    response = setup.client.post("/api/v1/sbom-runs/run/vex-import", json=document, headers=headers())
    assert response.status_code == 422
    assert len(setup.db.scalars(select(FindingReview)).all()) == 1


def test_terminal_job_failure_is_deduplicated_and_does_not_expose_exception_secrets(setup):
    job = SimpleNamespace(id="failed-job", run_id=setup.run.id, attempts=3, kind="analysis",
                          error="password=do-not-expose", payload={"secret": "also-not-exposed"})
    first = workflows.notify_job_failure(setup.db, job, setup.run)
    setup.db.commit()
    second = workflows.notify_job_failure(setup.db, job, setup.run)
    assert first.id == second.id and first.kind == "job_failed"
    assert first.payload == {"jobId": job.id, "attempts": 3, "kind": "analysis"}
    assert "do-not-expose" not in json.dumps(first.payload) + first.message


def test_manage_only_custom_grants_can_read_their_workflow_panels(setup):
    policy = setup.db.get(RolePolicy, Role.ADMIN)
    policy.permissions = ["vex.manage", "notifications.manage"]
    setup.db.commit()
    for path in ["/sbom-runs/run/reviews", "/sbom-runs/run/vex", "/notifications", "/notification-settings"]:
        assert setup.client.get("/api/v1" + path, headers=headers()).status_code == 200


def test_private_cve_alias_does_not_make_public_or_internal_vex_target_ambiguous():
    private = {**FINDING, "id": "INTERNAL-001", "canonicalId": "INTERNAL-001", "aliases": [CVE],
               "sourceKind": "private_vulnerability", "source": "KODA_PRIVATE", "privateAdvisoryId": "uuid"}
    run = SimpleNamespace(analyses=[SimpleNamespace(state=JobState.COMPLETED, sequence=1, findings=[FINDING, private])])
    assert workflows.resolve_target(run, PURL, CVE)[2] == CVE
    assert workflows.resolve_target(run, PURL, "INTERNAL-001")[2] == "INTERNAL-001"
    assert workflows.resolve_target(run, PURL, "GHSA-demo")[2] == CVE
