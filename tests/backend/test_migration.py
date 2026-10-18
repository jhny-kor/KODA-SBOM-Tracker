from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import httpx
import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from koda_tracker.db import Base
from koda_tracker import migration, package_metadata_models
from koda_tracker.migration import LegacyExporter, MigrationError, apply_migration, make_report, stage_bundle, validate_source_url
from koda_tracker.migration_models import LegacyMigration, LegacyObjectMap
from koda_tracker.models import AnalysisRevision, JobState, SbomRun, SbomPolicyRevision, Service
from koda_tracker.policies import PolicyDocument, evaluate_document as evaluate_native_document, get_policy_document
from koda_tracker.workflow_models import FindingReview, ReviewEvent


def evaluate_document(document, components, findings, **kwargs):
    # Imported rules apply to their native source catalog, including global rules.
    # Supply a real source scope to isolate condition semantics from scope tests.
    context = kwargs.pop("project_context", {})
    context.setdefault("sourceProject", {"sourceId": "source-a", "projectId": uid("project"), "tags": ["prod"], "isLatest": True, "active": True, "ancestorIds": []})
    return evaluate_native_document(document, components, findings, project_context=context, **kwargs)


def uid(label):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, label))


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        get_policy_document(session)
        session.commit()
        yield session
    engine.dispose()


def policy(subject="SEVERITY", operator="IS", value="HIGH", **kwargs):
    return {"uuid": uid("policy"), "name": "Source policy", "operator": "ANY", "violationState": "FAIL", "policyConditions": [{"uuid": uid("condition"), "subject": subject, "operator": operator, "value": value}], **kwargs}


def bundle(policies=None, suppressed=False, analysis_state="NOT_AFFECTED"):
    component = {"uuid": uid("component"), "name": "sample", "version": "1", "purl": "pkg:pypi/sample@1"}
    vulnerability = {"uuid": uid("vulnerability"), "vulnId": "CVE-2026-12345", "severity": "HIGH", "source": "NVD", "cvssV3BaseScore": 8.1}
    return {"format": migration.FORMAT, "version": 1, "source": {"version": "5.0.3", "id": "source-a", "origin": "http://source.test", "exportedAt": "2026-10-18T00:00:00Z"}, "projects": [{"project": {"uuid": uid("project"), "name": "Original", "version": "1", "tags": [{"name": "prod"}], "isLatest": True}, "bom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [{"type": "library", "bom-ref": component["uuid"], "name": "sample", "version": "1", "purl": component["purl"], "licenses": [{"license": {"id": "MIT"}}]}]}, "components": [component], "findings": {"version": "1.2", "findings": [{"component": component, "vulnerability": vulnerability, "analysis": {"state": analysis_state, "isSuppressed": suppressed}}]}, "analyses": [{"componentUuid": component["uuid"], "vulnerabilityUuid": vulnerability["uuid"], "analysis": {"analysisState": analysis_state, "isSuppressed": suppressed, "analysisDetails": "Source analyst note", "analysisComments": [{"comment": "audit history"}]}}], "violations": [], "violationAnalyses": []}], "policies": policies if policies is not None else [policy()], "licenses": [], "licenseGroups": []}


def apply(db, staged, tmp_path, **kwargs):
    return apply_migration(db, staged.id, expected_digest=staged.digest, expected_policy_version=staged.report["currentPolicyVersion"], actor="admin", actor_id="admin-id", artifact_dir=tmp_path, **kwargs)


def test_stage_is_dry_run_and_blocks_unknown_conditions_without_dropping_them(db, tmp_path):
    raw = bundle([policy(subject="FUTURE_SUBJECT")])
    staged = stage_bundle(db, raw, "admin")
    assert staged.state == "blocked" and not staged.report["canApply"]
    assert staged.report["blockers"][0]["original"] == raw["policies"][0]
    assert db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert db.scalar(select(func.count()).select_from(Service)) == 0
    with pytest.raises(MigrationError, match="변환"):
        apply(db, staged, tmp_path)
    assert staged.bundle == raw


def test_apply_native_evidence_and_policies_preserve_source_history_and_idempotency(db, tmp_path):
    raw = bundle()
    staged = stage_bundle(db, raw, "admin")
    assert staged.report["canApply"]
    result = apply(db, staged, tmp_path)
    db.commit()
    assert result.state == "applied" and result.result["analysisRevisionsCreated"] == 1
    run = db.get(SbomRun, result.result["runIds"][0])
    assert Path(run.artifact_path).is_file()
    assert run.source_metadata["sourceProject"]["uuid"] == uid("project")
    revision = db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == run.id))
    assert revision.tool_version == "legacy-import" and revision.state == JobState.COMPLETED
    assert revision.policy_state == "completed"
    assert revision.data_sources["migration"]["original"]["analyses"] == raw["projects"][0]["analyses"]
    review = db.scalar(select(FindingReview))
    assert review.status == "submitted" and review.reviewer is None
    assert "audit history" in db.scalar(select(ReviewEvent.comment))
    assert not revision.findings[0].get("vex", {}).get("suppressed")
    assert apply(db, staged, tmp_path).id == result.id
    again = copy.deepcopy(raw)
    again["source"]["exportedAt"] = "2026-10-19T00:00:00Z"
    restaged = stage_bundle(db, again, "admin")
    apply(db, restaged, tmp_path)
    db.commit()
    assert db.scalar(select(func.count()).select_from(SbomRun)) == 1
    assert db.scalar(select(func.count()).select_from(AnalysisRevision)) == 1
    assert db.scalar(select(func.count()).select_from(FindingReview)) == 1


def test_source_approval_only_becomes_effective_with_explicit_trust(db, tmp_path):
    staged = stage_bundle(db, bundle(suppressed=True), "admin")
    apply(db, staged, tmp_path, trust_source_reviews=True)
    review = db.scalar(select(FindingReview))
    assert review.status == "approved" and review.reviewer == "admin"
    revision = db.scalar(select(AnalysisRevision))
    assert revision.findings[0]["vex"]["suppressed"] is True
    assert not any(row["policyId"].startswith("legacy-") for row in revision.policies)


def test_unsuppressed_false_positive_does_not_gain_suppression_from_trust(db, tmp_path):
    staged = stage_bundle(db, bundle(suppressed=False), "admin")
    apply(db, staged, tmp_path, trust_source_reviews=True)
    assert db.scalar(select(FindingReview.status)) == "submitted"
    assert any(row["policyId"].startswith("legacy-") for row in db.scalar(select(AnalysisRevision)).policies)


def test_ambiguous_source_suppression_trust_is_blocked_atomically(db, tmp_path):
    staged = stage_bundle(db, bundle(suppressed=True, analysis_state="NOT_SET"), "admin")
    original_version = get_policy_document(db).version
    with pytest.raises(MigrationError, match="임의 억제"):
        apply(db, staged, tmp_path, trust_source_reviews=True)
    assert db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert get_policy_document(db).version == original_version
    assert not list(tmp_path.rglob("*.json"))


def test_bom_change_creates_immutable_new_round_and_preserves_old_evidence(db, tmp_path):
    raw = bundle()
    first = stage_bundle(db, raw, "admin")
    apply(db, first, tmp_path)
    db.commit()
    changed = copy.deepcopy(raw)
    changed["projects"][0]["bom"]["components"].append({"type": "library", "name": "extra", "version": "1"})
    second = stage_bundle(db, changed, "admin")
    apply(db, second, tmp_path)
    db.commit()
    runs = list(db.scalars(select(SbomRun).order_by(SbomRun.round_number)))
    assert len(runs) == 2 and [run.round_number for run in runs] == [1, 2]
    assert len(runs[0].normalized_bom["components"]) == 1
    assert len(runs[1].normalized_bom["components"]) == 2
    assert db.get(LegacyObjectMap, ("source-a", "project", uid("project"))).target_id == runs[1].id


def test_all_security_conditions_match_different_vulnerabilities_on_same_component(db):
    raw = bundle([policy(value="HIGH")])
    raw["policies"][0]["operator"] = "ALL"
    raw["policies"][0]["policyConditions"] = [{"subject": "SEVERITY", "operator": "IS", "value": "HIGH"}, {"subject": "SEVERITY", "operator": "IS", "value": "CRITICAL"}]
    report = make_report(db, raw)
    assert report["canApply"]
    doc = PolicyDocument(rules=[report["convertedPolicies"][0]["rule"]])
    component = raw["projects"][0]["bom"]["components"][0]
    findings = [{"component": component["purl"], "version": "1", "severity": "HIGH", "id": "CVE-2026-10000"}, {"component": component["purl"], "version": "1", "severity": "CRITICAL", "id": "CVE-2026-10001"}]
    assert len(evaluate_document(doc, [component], findings)[0]) == 1
    assert evaluate_document(doc, [component], findings[:1])[0] == []


@pytest.mark.parametrize("operator,expected", [("MATCHES", True), ("NO_MATCH", False)])
def test_operational_java_wildcard_conversion_uses_real_cel(db, operator, expected):
    raw = bundle([policy("PACKAGE_URL", operator, "pkg:pypi/sample*")])
    report = make_report(db, raw)
    assert report["canApply"]
    rows, _ = evaluate_document(PolicyDocument(rules=[report["convertedPolicies"][0]["rule"]]), raw["projects"][0]["bom"]["components"], [])
    assert bool(rows) is expected


def test_project_tag_child_and_latest_scopes_are_dynamic_source_catalog_filters(db):
    raw = bundle([policy(tags=[{"name": "prod"}], onlyLatestProjectVersion=True)])
    first = raw["projects"][0]
    child = copy.deepcopy(first)
    child["project"] = {"uuid": uid("child"), "name": "Child", "version": "2", "isLatest": False, "parent": {"uuid": uid("project")}}
    raw["projects"].append(child)
    report = make_report(db, raw)
    assert report["canApply"]
    rule = report["convertedPolicies"][0]["rule"]
    assert rule["runIds"] == []
    assert rule["projectScope"] == {"sourceId":"source-a","projectIds":[],"tags":["prod"],"includeChildren":False,"onlyLatest":True}
    raw["policies"][0].update({"tags": [], "projects": [{"uuid": uid("project")}], "includeChildren": True, "onlyLatestProjectVersion": False})
    report = make_report(db, raw)
    scope=report["convertedPolicies"][0]["rule"]["projectScope"]
    assert scope["includeChildren"] and scope["projectIds"] == [uid("project")]
    from koda_tracker.project_catalog import project_scope_matches
    assert project_scope_matches(scope,{"sourceId":"source-a","projectId":uid("future-child"),"ancestorIds":[uid("project")],"active":True})


def test_license_group_is_converted_without_flattening_spdx_choices(db):
    raw = bundle([policy("LICENSE_GROUP", "IS", uid("group"))])
    raw["licenseGroups"] = [{"uuid": uid("group"), "licenses": [{"uuid": uid("license"), "licenseId": "GPL-3.0-only"}]}]
    report = make_report(db, raw)
    assert report["canApply"]
    doc = PolicyDocument(rules=[report["convertedPolicies"][0]["rule"]])
    for expression, violation in [("MIT OR GPL-3.0-only", False), ("MIT AND GPL-3.0-only", True)]:
        assert bool(evaluate_document(doc, [{"name": "x", "licenses": [{"expression": expression}]}], [])[0]) is violation


def test_mixed_license_and_security_conditions_preserve_source_all_semantics(db):
    raw=bundle([policy("LICENSE", "IS", uid("license"))])
    raw["licenses"]=[{"uuid":uid("license"),"licenseId":"MIT","name":"MIT License"}]
    raw["policies"][0]["operator"]="ALL"
    raw["policies"][0]["policyConditions"].append({"subject":"SEVERITY","operator":"IS","value":"HIGH"})
    report=make_report(db,raw)
    assert report["canApply"],report["blockers"]
    doc=PolicyDocument(rules=[report["convertedPolicies"][0]["rule"]])
    component=raw["projects"][0]["bom"]["components"][0]
    assert not evaluate_document(doc,[component],[])[0]
    assert evaluate_document(doc,[component],[{"id":"CVE-2026-12345","component":component["purl"],"version":"1","severity":"HIGH"}])[0]
    # Raw source5 regex is kept intact instead of applying the legacy wildcard rewrite.
    regex = make_report(db,bundle([policy("PACKAGE_URL","MATCHES",r"^pkg:pypi/[a-z]+@[0-9]+$")]))
    assert regex["canApply"] and "[a-z]+" in regex["convertedPolicies"][0]["rule"]["expression"]


def test_stale_policy_digest_and_partial_bundle_never_apply(db, tmp_path):
    staged = stage_bundle(db, bundle(), "admin")
    with pytest.raises(MigrationError, match="해시"):
        apply_migration(db, staged.id, expected_digest="a" * 64, expected_policy_version=1, actor="admin", actor_id="x", artifact_dir=tmp_path)
    db.add(SbomPolicyRevision(version=2, document=get_policy_document(db).document, created_by="other"))
    db.flush()
    with pytest.raises(MigrationError, match="버전"):
        apply(db, staged, tmp_path)
    partial = bundle()
    del partial["projects"][0]["analyses"]
    assert not stage_bundle(db, partial, "admin").report["canApply"]


def test_url_allowlist_redirects_proxies_and_errors_do_not_leak_secret(monkeypatch):
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    assert validate_source_url("http://source.test", ["http://source.test"]) == "http://source.test"
    for url in ("http://source.test/path", "http://key:secret@source.test", "http://source.test?key=secret"):
        with pytest.raises(MigrationError):
            validate_source_url(url, ["http://source.test"])
    with pytest.raises(MigrationError, match="허용"):
        validate_source_url("http://other.test", ["http://source.test"])
    exporter = LegacyExporter("http://source.test", "super-secret", ["http://source.test"], transport=httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": "http://metadata.invalid"}, text="super-secret")))
    with pytest.raises(MigrationError) as error:
        exporter.get("project")
    assert "super-secret" not in str(error.value) and "302" in str(error.value)
    exporter.close()
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 80))])
    with pytest.raises(MigrationError, match="메타데이터"):
        validate_source_url("http://source.test", ["http://source.test"])


def test_export_uses_official_paginated_endpoints_and_keeps_suppressed_history(monkeypatch):
    raw = bundle(suppressed=True)
    item = raw["projects"][0]
    called = []
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    def respond(request):
        called.append(str(request.url))
        path = request.url.path.removeprefix("/api/v1/")
        if path == "project": payload = [item["project"]]
        elif path == "project/" + uid("project"): payload = item["project"]
        elif path in {"license", "licenseGroup", "policy"}: payload = []
        elif path.startswith("bom/"): payload = item["bom"]
        elif path.endswith("/export"): payload = {"findings": []}
        elif path.startswith("finding/project/"): payload = item["findings"]["findings"]
        elif path == "analysis": payload = item["analyses"][0]["analysis"]
        elif path.startswith("component/project/"): payload = item["components"]
        elif path.startswith("violation/project/"): payload = []
        else: return httpx.Response(404)
        return httpx.Response(200, json=payload, headers={"X-Total-Count": str(len(payload))} if isinstance(payload, list) else {})
    exporter = LegacyExporter("http://source.test", "secret", ["http://source.test"], transport=httpx.MockTransport(respond))
    result = exporter.export()
    exporter.close()
    assert result["projects"][0]["analyses"] == item["analyses"]
    assert len(result["projects"][0]["findings"]["findings"]) == 1
    assert any("suppressed=true" in url for url in called)
    assert any("licenseGroup" in url for url in called)
    assert "secret" not in json.dumps(result)


def test_trusted_policy_suppression_is_indefinite_but_exact_project_scoped(db, tmp_path):
    raw = bundle()
    component = raw["projects"][0]["findings"]["findings"][0]["component"]
    violation = {"uuid": uid("violation"), "component": component, "policyCondition": {"uuid": uid("condition"), "policy": {"uuid": uid("policy")}}, "suppressed": True}
    raw["projects"][0]["violations"] = [violation]
    raw["projects"][0]["violationAnalyses"] = [{"violationUuid": violation["uuid"], "analysis": {"isSuppressed": True, "analysisState": "APPROVED", "analysisDetails": "Accepted source waiver"}}]
    staged = stage_bundle(db, raw, "admin")
    assert staged.report["counts"]["policyExceptions"] == 1 and not staged.report["trustReviewBlockers"]
    apply(db, staged, tmp_path, trust_source_reviews=True)
    document = PolicyDocument.model_validate(get_policy_document(db).document)
    exception = next(value for value in document.exceptions if value.id.startswith("legacy-exception-"))
    assert exception.expiresAt is None and exception.runId == staged.result["runIds"][0]
    rule = next(value for value in document.rules if value.id == exception.ruleId)
    component_bom = raw["projects"][0]["bom"]["components"][0]
    finding = {"id": "CVE-2026-12345", "severity": "HIGH", "component": component["purl"], "version": "1"}
    rows, _ = evaluate_document(PolicyDocument(rules=[rule], exceptions=[exception]), [component_bom], [finding], project_context={"run": {"id": exception.runId}})
    assert len(rows) == 1 and rows[0]["suppressed"]


def test_complex_condition_suppression_blocks_trusted_apply(db, tmp_path):
    raw = bundle()
    raw["policies"][0]["policyConditions"].append({"subject": "VULNERABILITY_ID", "operator": "IS", "value": "CVE-2026-12345"})
    raw["projects"][0]["violations"] = [{"uuid": uid("violation"), "component": raw["projects"][0]["findings"]["findings"][0]["component"], "policyCondition": {"policy": {"uuid": uid("policy")}}, "suppressed": True}]
    staged = stage_bundle(db, raw, "admin")
    assert staged.report["canApply"] and staged.report["trustReviewBlockers"]
    with pytest.raises(MigrationError, match="억제"):
        apply(db, staged, tmp_path, trust_source_reviews=True)
    assert db.scalar(select(func.count()).select_from(SbomRun)) == 0


def test_reexport_timestamp_and_fpf_meta_do_not_duplicate_analysis(db, tmp_path):
    raw = bundle()
    raw["projects"][0]["findings"]["meta"] = {"exportedAt": "one"}
    first = stage_bundle(db, raw, "admin")
    apply(db, first, tmp_path)
    db.commit()
    raw["projects"][0]["findings"]["meta"]["exportedAt"] = "two"
    again = stage_bundle(db, raw, "admin")
    apply(db, again, tmp_path)
    assert db.scalar(select(func.count()).select_from(AnalysisRevision)) == 1


def test_restage_refreshes_policy_version_for_review_without_changing_bundle(db):
    raw = bundle()
    staged = stage_bundle(db, raw, "admin")
    checksum = staged.digest
    db.add(SbomPolicyRevision(version=2, document=get_policy_document(db).document, created_by="other"))
    db.flush()
    refreshed = stage_bundle(db, raw, "admin")
    assert refreshed.id == staged.id and refreshed.digest == checksum
    assert refreshed.report["currentPolicyVersion"] == 2


def test_pinned_transport_connects_validated_address_without_resolving_again(monkeypatch):
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    transport = migration._PinnedTransport("http://source.test")
    assert transport.addresses[0][3] == ("127.0.0.1", 80)
    with pytest.raises(MigrationError, match="origin"):
        transport.handle_request(httpx.Request("GET", "http://other.test/"))
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 80))])
    with pytest.raises(MigrationError, match="금지"):
        migration._PinnedTransport("http://source.test")


@pytest.mark.parametrize(("operator", "expected"), [("NUMERIC_GREATER_THAN", False), ("NUMERIC_GREATER_THAN_OR_EQUAL", True), ("NUMERIC_EQUAL", True), ("NUMERIC_NOT_EQUAL", False), ("NUMERIC_LESS_THAN", False), ("NUMERIC_LESSER_THAN_OR_EQUAL", True)])
def test_age_utc_calendar_uses_latest_publication_not_elapsed_hours_or_installed_version(db, operator, expected):
    from datetime import UTC, datetime
    raw = bundle([policy("AGE", operator, "P1D")])
    raw["source"].update(version="4.12.7",timeZone="UTC")
    report = make_report(db, raw)
    assert report["canApply"]
    rule = report["convertedPolicies"][0]["rule"]
    component = copy.deepcopy(raw["projects"][0]["bom"]["components"][0])
    component.update({"metadataStatus": "fresh", "packageMetadata": {"status": "fresh", "latestPublishedAt": "2026-10-17T23:59:59Z", "currentVersionPublishedAt": "2020-01-01T00:00:00Z"}})
    # Two seconds elapsed, but the source compares UTC calendar dates (one day).
    rows, metrics = evaluate_document(PolicyDocument(rules=[rule]), [component], [], evaluated_at=datetime(2026, 10, 18, 0, 0, 1, tzinfo=UTC))
    assert bool(rows) is expected
    assert metrics["policyDataComplete"]
    assert any("달력 기간" in value["reason"] for value in report["warnings"])


def test_age_unknown_or_stale_latest_publication_is_explicit_data_warning(db):
    raw = bundle([policy("AGE", "NUMERIC_GREATER_THAN", "P30D")])
    raw["source"].update(version="4.12.7",timeZone="UTC")
    report = make_report(db, raw)
    component = copy.deepcopy(raw["projects"][0]["bom"]["components"][0])
    component.update({"metadataStatus": "stale", "packageMetadata": {"status": "stale", "latestPublishedAt": "2020-01-01T00:00:00Z"}})
    rows, metrics = evaluate_document(PolicyDocument(rules=[report["convertedPolicies"][0]["rule"]]), [component], [])
    assert len(rows) == 1 and rows[0]["type"] == "data_unavailable"
    assert not metrics["policyDataComplete"] and metrics["policyStatus"] == "warn"
    for source_zone, period in [(None, "P30D"), ("Unknown/Zone", "P30D"), ("UTC", "P0D")]:
        raw["source"]["timeZone"] = source_zone
        raw["policies"][0]["policyConditions"][0]["value"] = period
        assert not make_report(db, raw)["canApply"]


def test_bom_custom_mime_and_single_406_fallback_are_complete_or_explicit_failure(monkeypatch):
    raw = bundle()["projects"][0]["bom"]
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    accepts = []
    def respond(request):
        accepts.append(request.headers["accept"])
        if request.headers["accept"] != "*/*":
            return httpx.Response(406)
        return httpx.Response(200, json=raw, headers={"Content-Type": "application/vnd.cyclonedx+json"})
    exporter = LegacyExporter("http://source.test", "secret", ["http://source.test"], transport=httpx.MockTransport(respond))
    result, _ = exporter.get("bom/cyclonedx/project/" + uid("project"), {"format": "json"}, accept="application/vnd.cyclonedx+json")
    assert result == raw and accepts == ["application/vnd.cyclonedx+json", "*/*"]
    exporter.close()
    failed = LegacyExporter("http://source.test", "secret", ["http://source.test"], transport=httpx.MockTransport(lambda request: httpx.Response(406)))
    with pytest.raises(MigrationError, match="406"):
        failed.get("bom/cyclonedx/project/" + uid("project"), accept="application/vnd.cyclonedx+json")
    failed.close()


def test_licenses_with_exception_or_plus_are_never_silently_approximated(db):
    raw = bundle([policy("LICENSE_GROUP", "IS", uid("group"))])
    raw["licenseGroups"] = [{"uuid": uid("group"), "licenses": [{"licenseId": "GPL-2.0-only"}, {"licenseId": "GPL-2.0-or-later"}]}]
    for expression in ("GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0+"):
        raw["projects"][0]["bom"]["components"][0]["licenses"] = [{"expression": expression}]
        report = make_report(db, raw)
        assert report["canApply"],report["blockers"]
        doc=PolicyDocument(rules=[report["convertedPolicies"][0]["rule"]])
        rows,_=evaluate_document(doc,raw["projects"][0]["bom"]["components"],[])
        assert bool(rows) is (expression == "GPL-2.0+")


def test_real_source_unset_violation_analysis_is_optional_empty_200(monkeypatch):
    monkeypatch.setattr(migration.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b""))
    exporter = LegacyExporter("http://source.internal", "test-key", ["http://source.internal"], transport=transport)
    try:
        result, _ = exporter.get("violation/analysis", missing_ok=True)
        assert result is None
        with pytest.raises(MigrationError):
            exporter.get("policy")
    finally:
        exporter.close()


def test_postgres_review_author_width_and_source_not_set_enums(db, tmp_path):
    raw = bundle()
    raw["source"]["id"] = "a" * 64
    analysis = raw["projects"][0]["analyses"][0]["analysis"]
    analysis.update(analysisState="IN_TRIAGE", analysisJustification="NOT_SET", analysisResponse="NOT_SET")
    staged = stage_bundle(db, raw, "admin")
    apply(db, staged, tmp_path)
    review = db.scalar(select(FindingReview))
    assert len(review.author_id) == 36
    assert review.justification == "" and review.response == []
    event = db.scalar(select(ReviewEvent))
    assert "NOT_SET" in event.comment  # Preserve original enums in the audit evidence.


def test_source5_regex_preserves_raw_re2_and_rejects_invalid_patterns_during_stage(db):
    raw=bundle([policy('PACKAGE_URL','MATCHES',r'(?i)^PKG:PYPI/[a-z]+@\d+$')])
    report=make_report(db,raw)
    assert report['canApply'],report['blockers']
    assert evaluate_document(PolicyDocument(rules=[report['convertedPolicies'][0]['rule']]),raw['projects'][0]['bom']['components'],[])[0]
    for pattern in [r'(?<=pkg:)pypi',r'(pypi)\1','[unclosed']:
        raw['policies'][0]['policyConditions'][0]['value']=pattern
        invalid=make_report(db,raw)
        assert not invalid['canApply'] and invalid['blockers']


def test_converted_cwe_all_is_per_vulnerability_and_epss_is_score(db):
    cwe=policy('CWE','CONTAINS_ALL','CWE-79, 89')
    epss=policy('EPSS','NUMERIC_GREATER_THAN','0.5',uuid=uid('epss-policy'))
    raw=bundle([cwe,epss]);report=make_report(db,raw)
    assert report['canApply'],report['blockers']
    doc=PolicyDocument(rules=[row['rule'] for row in report['convertedPolicies']])
    component=raw['projects'][0]['bom']['components'][0]
    findings=[{'id':'CVE-2026-12345','component':component['purl'],'version':'1','cwes':[79],'cweStatus':'available','epssScore':0.8,'epssPercentile':0.95,'epssStatus':'fresh'}, {'id':'CVE-2026-99999','component':component['purl'],'version':'1','cwes':[89],'cweStatus':'available','epssScore':0.1,'epssStatus':'fresh'}]
    rows,metrics=evaluate_document(doc,[component],findings)
    assert len(rows)==1 and rows[0]['policyId']==doc.rules[1].id and metrics['policyDataComplete']
    findings[0]['cwes']=[79,89]
    assert len(evaluate_document(doc,[component],findings)[0])==2


def test_version_and_coordinate_comparison_import_use_generic_source_comparator(db):
    raw=bundle([policy('VERSION','NUMERIC_GREATER_THAN','0.9')])
    report=make_report(db,raw)
    assert report['canApply'],report['blockers']
    assert evaluate_document(PolicyDocument(rules=[report['convertedPolicies'][0]['rule']]),raw['projects'][0]['bom']['components'],[])[0]
    raw['policies']=[policy('COORDINATES','MATCHES',json.dumps({'name':'sample','version':'>= 1'}))]
    report=make_report(db,raw)
    assert report['canApply'],report['blockers']
    assert evaluate_document(PolicyDocument(rules=[report['convertedPolicies'][0]['rule']]),raw['projects'][0]['bom']['components'],[])[0]


def test_source5_age_uses_current_artifact_calendar_without_timezone_prompt(db):
    from datetime import UTC,datetime
    raw=bundle([policy('AGE','NUMERIC_EQUAL','P1M')]);report=make_report(db,raw)
    assert report['canApply'],report['blockers']
    component=raw['projects'][0]['bom']['components'][0]
    component.update(metadataStatus='fresh',packageMetadata={'currentVersionPublishedAt':'2024-01-31T12:00:00Z','latestPublishedAt':'2024-02-20T12:00:00Z'})
    rows,metrics=evaluate_document(PolicyDocument(rules=[report['convertedPolicies'][0]['rule']]),[component],[],evaluated_at=datetime(2024,2,29,tzinfo=UTC))
    assert rows and metrics['policyDataComplete']


def test_version_sensitive_import_requires_explicit_source_profile(db):
    raw=bundle([policy('PACKAGE_URL','MATCHES',r'(?i)^pkg:')]);raw['source'].pop('version')
    report=make_report(db,raw)
    assert not report['canApply'] and 'source.version' in report['blockers'][0]['reason']
    raw['policies']=[policy('SEVERITY','IS','HIGH')]
    assert make_report(db,raw)['canApply']


def test_exporter_timestamps_serials_and_repository_telemetry_do_not_create_rounds(db,tmp_path):
    raw=bundle();raw['projects'][0]['bom'].update(serialNumber='urn:uuid:'+uid('export1'),metadata={'timestamp':'2026-10-18T00:00:00Z','tools':[{'name':'original exporter'}]})
    raw['projects'][0]['components'][0].update(metrics={'critical':1},repositoryMeta={'latestVersion':'1','lastCheck':1})
    first=stage_bundle(db,raw,'admin');apply(db,first,tmp_path);db.commit()
    changed=copy.deepcopy(raw);changed['projects'][0]['bom'].update(serialNumber='urn:uuid:'+uid('export2'),metadata={'timestamp':'2026-10-19T00:00:00Z','tools':[{'name':'updated exporter'}]})
    changed['projects'][0]['components'][0].update(metrics={'critical':2},repositoryMeta={'latestVersion':'2','lastCheck':2})
    second=stage_bundle(db,changed,'admin');apply(db,second,tmp_path);db.commit()
    assert second.result['runIds']==first.result['runIds']
    assert db.scalar(select(func.count()).select_from(SbomRun))==1
    assert db.scalar(select(func.count()).select_from(AnalysisRevision))==1
    # Policy-relevant source annotations still create immutable inventory rounds.
    changed['projects'][0]['components'][0]['isInternal']=True
    third=stage_bundle(db,changed,'admin');apply(db,third,tmp_path)
    assert third.result['runIds']!=first.result['runIds']
    assert db.scalar(select(func.count()).select_from(SbomRun))==2
