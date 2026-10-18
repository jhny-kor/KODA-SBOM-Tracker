"""Prove registry cache evidence reaches policies without registry I/O in analysis."""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from koda_tracker import package_metadata, policies, services, workflow_models, reanalysis  # noqa: F401
from koda_tracker.db import Base
from koda_tracker.models import AnalysisRevision, Environment, JobState, Release, SbomPolicyRevision, SbomRun, Service
from koda_tracker.package_metadata_models import PackageMetadataCache
from koda_tracker.workflow_models import FindingReview
from koda_tracker.workflows import apply_vex_reviews
from koda_tracker.vulnerability import VulnerabilityContext

PURL = "pkg:npm/example@1.0.0"
CVE = "CVE-2026-12345"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    service = Service(slug="metadata", name="Metadata")
    environment = Environment(slug="metadata", name="Test")
    db.add_all([service, environment])
    db.flush()
    release = Release(service=service, environment=environment, version="1")
    artifact = tmp_path / "bom.json"
    artifact.write_text("{}")
    component = {"type": "library", "name": "example", "version": "1.0.0", "purl": PURL, "licenses": [{"license": {"id": "MIT"}}]}
    run = SbomRun(release=release, round_number=1, original_filename="bom.json", media_type="application/json",
                  spec_version="1.6", sha256="0" * 64, size_bytes=2, artifact_path=str(artifact), normalized_bom={"components": [component]})
    db.add(run)
    db.flush()
    def no_network(*args, **kwargs):
        raise AssertionError("analysis/API must never construct a registry client")
    monkeypatch.setattr(package_metadata, "RegistryClient", no_network)
    yield db, run, component
    db.close()
    engine.dispose()


def rule(expression, *, target="component", action="fail"):
    return {"id": "operational", "name": "메타데이터 기반 정책", "kind": "cel", "target": target,
            "enabled": True, "action": action, "expression": expression}


def policy(db, expression, **kwargs):
    document = policies.PolicyDocument.model_validate({"rules": [rule(expression, **kwargs)], "exceptions": []})
    db.add(SbomPolicyRevision(version=1, document=document.model_dump(mode="json"), created_by="test"))
    db.flush()


def seed(db, *, state="completed", expired=False):
    at = datetime.now(UTC)
    target = package_metadata.parse_purl(PURL)
    row = PackageMetadataCache(id=target.id, package_key=target.package_key, current_version=target.version, purl=PURL,
                               ecosystem="npm", state=state, fetched_at=at - timedelta(hours=1),
                               expires_at=at + timedelta(days=-1 if expired else 1), next_attempt_at=at + timedelta(days=1),
                               document={"latestVersion": "2.0.0", "currentVersionPublishedAt": "2020-01-01T00:00:00Z",
                                         "latestPublishedAt": "2025-01-01T00:00:00Z", "versionDistance": 7,
                                         "versionDistanceBasis": "stable_semver_release_count", "sourceKind": "public_registry",
                                         "sourceUrls": ["https://registry.npmjs.org/example"],
                                         "fieldStatus": {"latestVersion": "available", "currentVersionPublishedAt": "available", "latestPublishedAt": "available", "versionDistance": "available"}})
    db.add(row)
    db.flush()
    return row


def revision(db, run, sequence=1, findings=None):
    value = AnalysisRevision(run_id=run.id, sequence=sequence, state=JobState.COMPLETED, tool_version="test",
                             data_as_of="2026-10-18", data_sources={}, findings=findings or [])
    run.analyses.append(value)
    db.flush()
    return value


def test_fresh_cache_contributes_actual_cel_fail_and_revision_provenance_without_io(setup):
    db, run, original = setup
    seed(db)
    policy(db, 'component.latestVersion != component.version && component.ageDays > 365 && component.versionDistance >= 5')
    current = revision(db, run)
    policies.evaluate_revision(db, run, current)
    assert current.policy_state == "completed", current.policy_error
    assert current.metrics["policyStatus"] == "fail"
    assert current.metrics["packageMetadataSummary"]["fresh"] == 1
    assert current.policies[0]["policyId"] == "operational"
    snapshot = current.policy_snapshot["packageMetadataSnapshot"][0]
    assert snapshot["latestVersion"] == "2.0.0"
    assert snapshot["sourceUrls"] == ["https://registry.npmjs.org/example"]
    assert snapshot["status"] == "fresh"
    assert "properties" not in original
    assert "packageMetadata" not in run.normalized_bom["components"][0]


@pytest.mark.parametrize("cache_state", ["missing", "stale", "error"])
def test_guarded_cel_cannot_report_clean_pass_when_required_metadata_is_missing_or_stale(setup, cache_state):
    db, run, _ = setup
    if cache_state != "missing":
        seed(db, state="failed" if cache_state == "error" else "completed", expired=cache_state == "stale")
    policy(db, "has(component.ageDays) && component.ageDays > 365")
    current = revision(db, run)
    policies.evaluate_revision(db, run, current)
    assert current.policy_state == "failed" or current.metrics.get("policyStatus") != "pass"
    if current.policy_state == "completed":
        assert any(row.get("type") == "data_unavailable" for row in current.policies)


def test_stale_cached_values_are_ui_evidence_but_not_available_to_cel(setup):
    db, run, _ = setup
    seed(db, expired=True)
    enriched = package_metadata.enrich_components(db, run.normalized_bom["components"])
    assert enriched[0]["packageMetadata"]["latestVersion"] == "2.0.0"
    assert enriched[0]["metadataStatus"] == "stale"
    context = policies.build_cel_contexts(enriched, [], targets={"component"})["component"][0]["component"]
    assert "latestVersion" not in context
    assert "latestVersion" not in context["packageMetadata"]


@pytest.mark.parametrize("field,expression", [
    ("currentVersionPublishedAt", "has(component.ageDays) && component.ageDays > 365"),
    ("versionDistance", "has(component.versionDistance) && component.versionDistance > 5"),
])
def test_fresh_cache_with_unavailable_field_is_not_clean_policy_pass(setup, field, expression):
    db, run, _ = setup
    cached = seed(db)
    cached.document = {**cached.document, field: None, "fieldStatus": {**cached.document["fieldStatus"], field: "unavailable"}}
    policy(db, expression)
    current = revision(db, run)
    policies.evaluate_revision(db, run, current)
    assert current.policy_state == "failed" or current.metrics.get("policyStatus") != "pass"


def test_literal_component_name_does_not_create_spurious_metadata_dependency(setup):
    db, run, _ = setup
    policy(db, 'component.name == "ageDays"')
    current = revision(db, run)
    policies.evaluate_revision(db, run, current)
    assert current.policy_state == "completed"
    assert current.metrics["policyStatus"] == "pass"
    assert not current.metrics["policyDataWarnings"]


def test_prior_revision_metadata_snapshot_is_immutable_after_cache_refresh(setup):
    db, run, _ = setup
    cached = seed(db)
    policy(db, "component.versionDistance >= 5")
    before = revision(db, run)
    policies.evaluate_revision(db, run, before)
    evidence = copy.deepcopy(before.policy_snapshot)
    cached.document = {**cached.document, "latestVersion": "3.0.0", "versionDistance": 20}
    db.flush()
    after = revision(db, run, sequence=2)
    policies.evaluate_revision(db, run, after)
    assert after.policy_snapshot["packageMetadataSnapshot"][0]["latestVersion"] == "3.0.0"
    assert before.policy_snapshot == evidence
    assert before.policy_snapshot["packageMetadataSnapshot"][0]["latestVersion"] == "2.0.0"


def test_existing_upload_and_grype_analysis_only_enqueue_metadata_without_network(setup, monkeypatch):
    db, run, _ = setup
    services.create_components(db, run)
    assert db.scalar(select(PackageMetadataCache)).state == "queued"
    monkeypatch.setattr(services, "active_bundle", lambda _: None)
    monkeypatch.setattr(services, "load_context", lambda _: VulnerabilityContext(None, {}, {}, {}, {}))
    original_subprocess = services.subprocess.run
    def grype_or_cel(args, **kwargs):
        if args[0] == services.get_settings().grype_binary:
            assert kwargs["env"]["GRYPE_DB_AUTO_UPDATE"] == "false"
            return SimpleNamespace(returncode=0, stdout=json.dumps({"matches": [], "descriptor": {"version": "test-grype"}}), stderr="")
        return original_subprocess(args, **kwargs)
    monkeypatch.setattr(services.subprocess, "run", grype_or_cel)
    current = services.analyze_offline(db, run)
    assert current.state == JobState.COMPLETED
    assert current.policy_state == "completed"
    assert db.scalar(select(PackageMetadataCache)).state == "queued"


def test_metadata_api_reads_and_refresh_only_touch_cache_without_registry_io(setup):
    from koda_tracker import package_metadata_api as api

    db, run, _ = setup
    services.create_components(db, run)
    listing = api.run_metadata(run.id, page=1, size=25, db=db, _=None)
    assert listing["total"] == 1
    assert listing["items"][0]["metadata"]["status"] == "pending"
    queued = api.refresh_run(run.id, db=db, principal=SimpleNamespace(username="admin"), _csrf=None)
    assert queued["queued"] == 1
    assert api.status(db=db, _=None)["counts"]["queued"] == 1


def test_approved_vex_is_annotated_before_aggregate_component_cel_and_raw_finding_retained(setup, monkeypatch):
    db, run, _ = setup
    policy(db, 'component.vulnerabilities.exists(v, v.severity == "high")')
    review = FindingReview(run_id=run.id, service_id=run.release.service_id, environment_id=run.release.environment_id,
                           component=PURL, component_version="1.0.0", vulnerability_id=CVE, state="not_affected",
                           justification="code_not_reachable", detail="Evidence confirms vulnerable code is unreachable.",
                           author_id="author", author="author", status="approved", reviewer="reviewer",
                           decision_reason="Independent evidence reviewed", decided_at=datetime.now(UTC))
    db.add(review)
    db.flush()
    monkeypatch.setattr(services, "active_bundle", lambda _: None)
    monkeypatch.setattr(services, "load_context", lambda _: VulnerabilityContext(None, {}, {}, {}, {}))
    real_subprocess = services.subprocess.run
    def grype_or_cel(args, **kwargs):
        if args[0] == services.get_settings().grype_binary:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"matches": [{"vulnerability": {"id": CVE, "severity": "High"}, "artifact": {"name": "example", "purl": PURL, "version": "1.0.0"}}]}), stderr="")
        return real_subprocess(args, **kwargs)
    monkeypatch.setattr(services.subprocess, "run", grype_or_cel)
    current = services.analyze_offline(db, run)
    assert current.state == JobState.COMPLETED
    assert current.policy_state == "completed", current.policy_error
    assert current.metrics["policyStatus"] == "pass"
    assert current.metrics["effectiveVulnerabilityCount"] == 0
    assert len(current.findings) == 1
    assert current.findings[0]["vex"]["suppressed"] is True
    assert current.policies == []
