from __future__ import annotations

import asyncio
import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from koda_tracker import services
from koda_tracker.config import Settings
from koda_tracker.db import Base
from koda_tracker.models import AnalysisRevision, Environment, JobState, ProcessingState, Release, SbomPolicyRevision, SbomRun, Service
from koda_tracker.policies import DEFAULT_DOCUMENT, PolicyDocument, evaluate_document, evaluate_revision, get_policy_document
from koda_tracker.vulnerability import VulnerabilityContext


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def make_run(db, tmp_path, components=None):
    service = Service(slug="native", name="Native")
    environment = Environment(slug="native", name="Native")
    db.add_all([service, environment])
    db.flush()
    release = Release(service_id=service.id, environment_id=environment.id, version="1")
    db.add(release)
    db.flush()
    artifact = tmp_path / "bom.json"
    artifact.write_text("{}")
    run = SbomRun(release_id=release.id, round_number=1, original_filename="bom.json", media_type="application/json", spec_version="1.6", sha256="a" * 64, size_bytes=2, artifact_path=str(artifact), normalized_bom={"components": components or []})
    db.add(run)
    db.flush()
    return run


def rule(kind, values=None, **kwargs):
    return {"id": kind, "name": kind, "kind": kind, "values": values or [], **kwargs}


def test_default_policies_include_security_kev_review_and_canonical_metrics():
    document = PolicyDocument.model_validate(DEFAULT_DOCUMENT)
    policies, metrics = evaluate_document(document, [{"name": "a", "version": "1"}], [
        {"id": "CVE-2026-10000", "component": "a@1", "severity": "High", "kev": True},
        {"id": "GHSA-unmapped", "component": "a@1", "severity": "Low"},
    ])
    assert {row["policyId"] for row in policies} == {"severity-high", "kev", "license-unknown"}
    assert metrics["vulnerabilityCount"] == 1
    assert metrics["policyViolationCount"] == 3
    assert metrics["policyStatus"] == "fail"


@pytest.mark.parametrize(("expression", "denied", "review"), [
    ("MIT OR GPL-3.0-only", False, False),
    ("MIT AND GPL-3.0-only", True, False),
    ("(MIT OR GPL-3.0-only) AND Apache-2.0", False, False),
    ("GPL-3.0-only OR AGPL-3.0-only", True, False),
    ("GPL-3.0-only WITH Classpath-exception-2.0", True, True),
    ("MIT OR (GPL-3.0-only", False, True),
    ("LicenseRef-Custom", False, True),
    ("NOASSERTION", False, True),
    ("MIT AND", False, True),
])
def test_spdx_choice_obligation_exception_and_malformed_review(expression, denied, review):
    document = PolicyDocument(rules=[rule("license_denied", ["GPL-3.0-only", "AGPL-3.0-only"]), rule("license_unknown", action="warn")])
    rows, _ = evaluate_document(document, [{"name": "lib", "licenses": [{"expression": expression}]}], [])
    assert (any(row["type"] == "license_denied" for row in rows)) is denied
    assert (any(row["type"] == "license_unknown" for row in rows)) is review


def test_component_rules_are_exact_and_name_or_version_specific():
    document = PolicyDocument(rules=[rule("component_denied", ["unsafe@1", "pkg:pypi/exact@2"])])
    rows, _ = evaluate_document(document, [{"name": "unsafe", "version": "1", "purl": "pkg:pypi/unsafe@1"}, {"name": "unsafe", "version": "2"}, {"name": "exact", "purl": "pkg:pypi/exact@2"}], [])
    assert {row["component"] for row in rows} == {"pkg:pypi/unsafe@1", "pkg:pypi/exact@2"}


def test_multiple_vulnerabilities_on_one_component_have_distinct_stable_policy_keys():
    document = PolicyDocument(rules=[rule("severity", ["high"])])
    finding = {"id": "CVE-2026-10000", "component": "pkg:pypi/a@1", "severity": "High"}
    another = {**finding, "id": "CVE-2026-10001"}
    rows, metrics = evaluate_document(document, [], [finding, dict(finding), another])
    assert [(row["policyId"], row["component"], row["vulnerabilityId"]) for row in rows] == [("severity", "pkg:pypi/a@1", "CVE-2026-10000"), ("severity", "pkg:pypi/a@1", "CVE-2026-10001")]
    assert metrics["policyViolationCount"] == 2


def test_exceptions_are_narrow_expire_and_remain_in_audit_results():
    at = datetime(2026, 10, 17, tzinfo=UTC)
    base = {"id": "temporary", "ruleId": "severity", "component": "pkg:pypi/a@1", "vulnerabilityId": "CVE-2026-10000", "reason": "업그레이드 검증 중", "expiresAt": (at + timedelta(days=1)).isoformat()}
    document = PolicyDocument(rules=[rule("severity", ["high"])], exceptions=[base])
    findings = [{"id": "CVE-2026-10000", "component": "pkg:pypi/a@1", "severity": "High"}, {"id": "CVE-2026-10001", "component": "pkg:pypi/a@1", "severity": "High"}]
    rows, metrics = evaluate_document(document, [], findings, evaluated_at=at)
    assert metrics["policyViolationCount"] == 1
    assert metrics["policySuppressedCount"] == 1
    assert rows[0]["exception"]["reason"] == base["reason"]
    _, expired = evaluate_document(document, [], findings, evaluated_at=at + timedelta(days=1))
    assert expired["policyViolationCount"] == 2
    assert expired["policySuppressedCount"] == 0


@pytest.mark.parametrize("payload", [
    {"rules": [rule("severity", ["high"]), rule("severity", ["critical"])]},
    {"rules": [rule("severity", ["severe"])]},
    {"rules": [rule("license_denied", ["MIT OR GPL-3.0-only"])]},
    {"rules": [rule("kev", ["yes"])]},
    {"rules": [], "exceptions": [{"id": "x", "ruleId": "missing", "component": "a", "reason": "r", "expiresAt": "2026-10-17T00:00:00Z"}]},
    {"rules": [rule("kev")], "exceptions": [{"id": "x", "ruleId": "kev", "component": "a", "reason": "r", "expiresAt": "2026-10-17T00:00:00"}]},
])
def test_invalid_or_ambiguous_policy_documents_are_rejected(payload):
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(payload)


def test_native_grype_completion_requires_no_dependency_track(db, tmp_path, monkeypatch):
    run = make_run(db, tmp_path, [{"name": "safe", "licenses": [{"license": {"id": "MIT"}}]}])
    captured = {}
    settings = Settings(grype_db_dir=tmp_path / "current" / "grype-db", dependency_track_enabled=False)
    monkeypatch.setattr(services, "get_settings", lambda: settings)
    monkeypatch.setattr(services, "load_context", lambda _: VulnerabilityContext(None, {}, {}, {}, {}))
    def grype(*args, **kwargs):
        captured.update({"command": args[0], **kwargs["env"]})
        return SimpleNamespace(returncode=0, stdout=json.dumps({"matches": [], "descriptor": {"version": "0.109.1"}}), stderr="")
    monkeypatch.setattr(services.subprocess, "run", grype)
    def no_dtrack():
        raise AssertionError("Dependency-Track must not be called")
    monkeypatch.setattr(services, "DependencyTrackClient", no_dtrack)
    revision = services.analyze_offline(db, run)
    asyncio.run(services.sync_dependency_track(db, run))
    assert captured["command"][0] == settings.grype_binary
    assert captured["GRYPE_DB_CACHE_DIR"] == str(settings.grype_db_dir)
    assert captured["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert revision.policy_state == "completed"
    assert revision.metrics["policyStatus"] == "warn"
    assert revision.metrics["policyDataComplete"] is False
    assert run.state == ProcessingState.COMPLETED
    assert revision.policy_version == 1


def test_policy_evidence_is_immutable_across_configuration_changes(db, tmp_path):
    run = make_run(db, tmp_path)
    original = get_policy_document(db)
    revision = AnalysisRevision(run_id=run.id, sequence=1, state=JobState.COMPLETED, findings=[])
    db.add(revision)
    db.flush()
    evaluate_revision(db, run, revision)
    expected = copy.deepcopy(revision.policy_snapshot)
    db.add(SbomPolicyRevision(version=2, created_by="admin", document={"rules": [], "exceptions": []}))
    db.flush()
    assert get_policy_document(db).version == 2
    assert expected == revision.policy_snapshot
    assert original.document == {key: expected[key] for key in ("rules", "exceptions")}
    assert expected["projectScopeSnapshot"] is None
    assert revision.policy_version == 1
    second = AnalysisRevision(run_id=run.id, sequence=2, state=JobState.COMPLETED, findings=[])
    evaluate_revision(db, run, second)
    assert second.policy_version == 2


def test_grype_failure_does_not_claim_policy_pass(db, tmp_path, monkeypatch):
    run = make_run(db, tmp_path)
    monkeypatch.setattr(services, "load_context", lambda _: VulnerabilityContext(None, {}, {}, {}, {}))
    monkeypatch.setattr(services.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="missing DB"))
    revision = services.analyze_offline(db, run)
    assert revision.policy_state == "not_evaluated"
    assert revision.policy_error
    assert revision.policy_version is None
    assert revision.metrics == {}
    assert run.state == ProcessingState.FAILED


def test_invalid_stored_policy_is_explicit_partial_failure(db, tmp_path, monkeypatch):
    run = make_run(db, tmp_path)
    db.add(SbomPolicyRevision(version=1, document={"rules": [rule("severity", ["invalid"])]}, created_by="test"))
    db.flush()
    monkeypatch.setattr(services, "load_context", lambda _: VulnerabilityContext(None, {}, {}, {}, {}))
    monkeypatch.setattr(services.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout='{"matches": []}', stderr=""))
    revision = services.analyze_offline(db, run)
    assert revision.policy_state == "failed"
    assert revision.metrics["policyStatus"] == "error"
    assert run.state == ProcessingState.PARTIAL


def test_optional_dtrack_never_overwrites_native_policy_or_completion(db, tmp_path, monkeypatch):
    run = make_run(db, tmp_path)
    run.analysis_state = JobState.COMPLETED
    run.state = ProcessingState.COMPLETED
    revision = AnalysisRevision(run_id=run.id, sequence=1, state=JobState.COMPLETED, policy_state="completed", policies=[{"policyId": "native"}])
    db.add(revision)
    db.flush()
    class Client:
        configured = True
        async def ensure_collection(self, *args): return "collection"
        async def upload(self, **kwargs): return {"project": "project"}
        async def project_snapshot(self, *args): return ({"components": 4}, [{"uuid": "dtrack"}])
        async def promote_latest(self, *args): pass
    monkeypatch.setattr(services, "get_settings", lambda: SimpleNamespace(dependency_track_enabled=True))
    monkeypatch.setattr(services, "DependencyTrackClient", Client)
    asyncio.run(services.sync_dependency_track(db, run))
    assert revision.policies == [{"policyId": "native"}]
    assert run.dtrack_policies == [{"uuid": "dtrack"}]
    assert run.state == ProcessingState.COMPLETED
    class FailedClient(Client):
        async def upload(self, **kwargs): raise RuntimeError("offline")
    monkeypatch.setattr(services, "DependencyTrackClient", FailedClient)
    asyncio.run(services.sync_dependency_track(db, run))
    assert run.dtrack_state == JobState.FAILED
    assert run.state == ProcessingState.COMPLETED
    assert revision.policies == [{"policyId": "native"}]


def test_name_only_finding_versions_have_separate_metrics_policy_identity_and_exception():
    at = datetime(2026, 10, 17, tzinfo=UTC)
    document = PolicyDocument(rules=[rule("severity", ["high"])], exceptions=[{
        "id": "version-one", "ruleId": "severity", "component": "lib@1", "reason": "version-specific", "expiresAt": (at + timedelta(days=1)).isoformat(),
    }])
    findings = [{"id": "CVE-2026-10000", "component": "lib", "version": version, "severity": "High"} for version in ["1", "2"]]
    rows, metrics = evaluate_document(document, [], findings, evaluated_at=at)
    assert metrics["vulnerableComponentCount"] == 2
    assert metrics["policyViolationCount"] == 1
    assert [(row["component"], row["componentVersion"], row["suppressed"]) for row in rows] == [("lib@1", "1", True), ("lib@2", "2", False)]


@pytest.mark.parametrize(("available", "hit", "status", "row_type"), [
    (False, False, "warn", "data_unavailable"),
    (True, False, "pass", None),
    (True, True, "fail", "kev"),
])
def test_kev_missing_feed_empty_feed_and_hit_are_distinct(db, tmp_path, available, hit, status, row_type):
    run = make_run(db, tmp_path)
    db.add(SbomPolicyRevision(version=1, document={"rules": [rule("kev")]}, created_by="test"))
    revision = AnalysisRevision(run_id=run.id, sequence=1, state=JobState.COMPLETED, findings=[{"id": "CVE-2026-10000", "component": "lib", "severity": "Low", "kev": hit}], data_sources={"cisaKev": {"available": available}})
    db.add(revision)
    db.flush()
    evaluate_revision(db, run, revision)
    assert revision.policy_state == "completed"
    assert revision.metrics["policyStatus"] == status
    assert revision.metrics["policyDataComplete"] is available
    assert [row["type"] for row in revision.policies] == ([row_type] if row_type else [])
    if not available:
        assert revision.policies[0]["action"] == "warn"
        assert revision.metrics["policyDataWarnings"][0]["source"] == "cisaKev"


def test_result_limit_fails_explicitly_instead_of_claiming_partial_pass(db, tmp_path, monkeypatch):
    monkeypatch.setattr("koda_tracker.policies.MAX_POLICY_RESULTS", 2)
    run = make_run(db, tmp_path)
    db.add(SbomPolicyRevision(version=1, document={"rules": [rule("severity", ["high"])]}, created_by="test"))
    revision = AnalysisRevision(run_id=run.id, sequence=1, state=JobState.COMPLETED, findings=[{"id": f"CVE-2026-1000{n}", "component": "lib", "severity": "High"} for n in range(3)])
    db.add(revision)
    db.flush()
    evaluate_revision(db, run, revision)
    assert revision.policy_state == "failed"
    assert "한도를 초과" in revision.policy_error
    assert revision.metrics["policyStatus"] == "error"
    assert revision.policies == []


def test_context_loading_failure_updates_revision_and_run(db, tmp_path, monkeypatch):
    run = make_run(db, tmp_path)
    def failed_context(*args, **kwargs):
        raise OSError("unreadable offline context")
    monkeypatch.setattr(services, "load_context", failed_context)
    revision = services.analyze_offline(db, run)
    assert revision.state == JobState.FAILED
    assert revision.policy_state == "not_evaluated"
    assert "unreadable offline context" in revision.error
    assert run.analysis_state == JobState.FAILED
    assert run.state == ProcessingState.FAILED


def test_pending_source_reanalysis_remains_visible_after_older_job_completes(db, tmp_path):
    from koda_tracker.main import get_run, list_runs, koda_run_result
    from koda_tracker.project_catalog_models import NativeReanalysisPending
    run = make_run(db, tmp_path)
    run.state, run.analysis_state = ProcessingState.COMPLETED, JobState.COMPLETED
    db.add(NativeReanalysisPending(source_id="sample", run_id=run.id, reason="source_sync"))
    db.flush()
    result = get_run(run.id, db, None)
    assert result["nativeReanalysisPending"] is True
    assert result["state"] == "queued" and result["analysisState"] == "queued"
    result = list_runs(service_id=None, environment_id=None, state=None, source=None, q=None, page=1, size=50, db=db, _=None)
    assert result["items"][0]["nativeReanalysisPending"] is True
    result = koda_run_result(run.id, db, None)
    assert result["run"]["analysisState"] == "queued"
    assert run.state == ProcessingState.COMPLETED  # response overlay never rewrites evidence
