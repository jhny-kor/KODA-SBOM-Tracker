"""Read-only project-to-run navigation uses the normal results access contract."""
from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker.db import Base, get_db
from koda_tracker.main import _run_payload
from koda_tracker.models import (
    AnalysisRevision, ApiToken, Environment, JobState, ProcessingState, Release,
    Role, RolePolicy, RunComponent, SbomRun, Service, User,
)
from koda_tracker.project_catalog import project_for_run
from koda_tracker.project_catalog_api import router
from koda_tracker.project_catalog_models import NativeProject, NativeReanalysisPending, ProjectRunLink
from koda_tracker.security import current_principal


@pytest.fixture
def context():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False, expire_on_commit=False) as db:
        service = Service(id="service", slug="service", name="Service")
        environment = Environment(id="environment", slug="environment", name="Environment")
        release = Release(id="release", service_id=service.id, environment_id=environment.id, version="1")
        principal = User(id="reader", username="reader", password_hash="unused", role=Role.MANAGER)
        policy = RolePolicy(role=Role.MANAGER, permissions=["catalog.manage", "runs.view"])
        db.add_all([service, environment, release, principal, policy])
        db.commit()
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        auth = {"principal": principal}
        app.dependency_overrides[current_principal] = lambda: auth["principal"]
        with TestClient(app) as client:
            yield SimpleNamespace(db=db, client=client, engine=engine, auth=auth, policy=policy, release=release)
    engine.dispose()


def project(context, identity="project", **overrides):
    values = dict(id=identity, source_id="native", source_project_id=identity,
                  name="same display name", service_id="service", environment_id="environment", version="1")
    values.update(overrides)
    item = NativeProject(**values)
    context.db.add(item)
    context.db.commit()
    return item


def run(context, identity, *, release=None, round_number=1, **overrides):
    values = dict(id=identity, release_id=(release or context.release).id, round_number=round_number,
                  state=ProcessingState.COMPLETED, analysis_state=JobState.COMPLETED,
                  original_filename=identity + ".json", media_type="application/json", spec_version="1.6",
                  sha256="a" * 64, size_bytes=2, artifact_path="/test/" + identity, normalized_bom={},
                  created_at=datetime(2026, 10, 25, tzinfo=UTC))
    values.update(overrides)
    item = SbomRun(**values)
    context.db.add(item)
    context.db.commit()
    return item


def get_runs(context, item, query=""):
    response = context.client.get(f"/api/v1/project-catalog/{item.id}/runs{query}")
    assert response.status_code == 200, response.text
    return response.json()


def test_explicit_historical_links_return_existing_summaries_and_no_writes(context):
    p = project(context)
    old = run(context, "old", archived_at=datetime(2026, 10, 24, tzinfo=UTC), state=ProcessingState.ARCHIVED)
    latest = run(context, "latest", round_number=2)
    p.current_run_id = latest.id
    findings = [{"id": "CVE-2026-10000", "severity": "High", "component": "example", "version": "1", "kev": True}]
    history = AnalysisRevision(id="history", run_id=old.id, sequence=1, state=JobState.COMPLETED,
                               findings=findings, policies=[{"action": "fail"}], policy_version=3,
                               policy_snapshot={"original": "evidence"}, metrics={"policyViolationCount": 1})
    context.db.add_all([history, ProjectRunLink(run_id=old.id, project_id=p.id),
                        ProjectRunLink(run_id=latest.id, project_id=p.id),
                        RunComponent(run_id=old.id, identity_key="example", name="example", component_type="library")])
    context.db.commit()
    before = copy.deepcopy((history.findings, history.policies, history.policy_snapshot, old.normalized_bom,
                            p.revision, p.current_run_id, context.auth["principal"].username))
    statements = []
    def record(_connection, _cursor, statement, _parameters, _execution, _many):
        statements.append(statement.lstrip().split(None, 1)[0].upper())
    event.listen(context.engine, "before_cursor_execute", record)
    try:
        body = get_runs(context, p)
    finally:
        event.remove(context.engine, "before_cursor_execute", record)
    assert {item["id"] for item in body["items"]} == {old.id, latest.id}
    summary = next(item for item in body["items"] if item["id"] == old.id)
    assert summary["vulnerabilityCount"] == summary["kevCount"] == summary["policyViolationCount"] == 1
    assert summary["severityCounts"] == {"high": 1}
    assert summary["componentCount"] == 1 and summary["componentTypeCounts"] == {"library": 1}
    assert summary["analysisId"] == history.id and summary["policyVersion"] == 3
    assert summary == _run_payload(old, component_count=1, component_type_counts={"library": 1})
    assert not {"INSERT", "UPDATE", "DELETE", "REPLACE"}.intersection(statements)
    context.db.expire_all()
    assert (history.findings, history.policies, history.policy_snapshot, old.normalized_bom,
            p.revision, p.current_run_id, context.auth["principal"].username) == before


def test_unique_coordinates_include_unlinked_runs_without_creating_links(context):
    p = project(context)
    item = run(context, "automatic")
    assert project_for_run(context.db, item.id).id == p.id
    body = get_runs(context, p)
    assert body["total"] == 1 and body["items"][0]["id"] == item.id
    assert context.db.scalar(select(ProjectRunLink)) is None
    assert p.current_run_id is None


@pytest.mark.parametrize("overrides", [{}, {"source_id": "other-source"}, {"active": False}])
def test_ambiguous_coordinates_require_explicit_links_even_across_sources(context, overrides):
    p = project(context)
    project(context, "collision", **overrides)
    explicit = run(context, "explicit")
    automatic = run(context, "automatic", round_number=2)
    context.db.add(ProjectRunLink(run_id=explicit.id, project_id=p.id))
    context.db.commit()
    assert project_for_run(context.db, automatic.id) is None
    body = get_runs(context, p)
    assert body["total"] == 1 and body["items"][0]["id"] == explicit.id


@pytest.mark.parametrize("coordinate", ["service", "environment", "version"])
def test_other_coordinates_and_matching_names_do_not_associate_runs(context, coordinate):
    p = project(context)
    values = dict(id="other-release", service_id="service", environment_id="environment", version="1")
    if coordinate == "service":
        context.db.add(Service(id="other-service", slug="other-service", name="Service"))
        values["service_id"] = "other-service"
    elif coordinate == "environment":
        context.db.add(Environment(id="other-environment", slug="other-environment", name="Environment"))
        values["environment_id"] = "other-environment"
    else:
        values["version"] = "2"
    release = Release(**values)
    context.db.add(release)
    context.db.commit()
    run(context, "unrelated", release=release)
    assert get_runs(context, p)["total"] == 0


def test_explicit_assignment_to_another_project_wins_over_coordinate_inference(context):
    p = project(context)
    other = project(context, "other", version="2")
    item = run(context, "legacy-explicit")
    # Explicit historical associations remain authoritative even if coordinates
    # in a legacy catalog differ from the current catalog entry.
    context.db.add(ProjectRunLink(run_id=item.id, project_id=other.id))
    context.db.commit()
    assert project_for_run(context.db, item.id).id == other.id
    assert get_runs(context, p)["total"] == 0
    assert get_runs(context, other)["items"][0]["id"] == item.id


def test_stable_pagination_and_pending_analysis_status(context):
    p = project(context)
    for number, identity in enumerate(("a", "c", "b"), 1):
        run(context, identity, round_number=number)
    context.db.add(NativeReanalysisPending(source_id="native", run_id="b"))
    context.db.commit()
    first = get_runs(context, p, "?page=1&size=1")
    second = get_runs(context, p, "?page=2&size=1")
    third = get_runs(context, p, "?page=3&size=1")
    assert first["items"][0]["id"] == "c" and second["items"][0]["id"] == "b"
    assert third["items"][0]["id"] == "a" and first["total"] == 3
    assert second["items"][0]["nativeReanalysisPending"] is True
    assert second["items"][0]["analysisAvailable"] is False
    assert get_runs(context, p, "?page=4&size=1")["items"] == []


@pytest.mark.parametrize("permissions", [["catalog.manage"], ["runs.view"], []])
def test_both_catalog_and_existing_results_permissions_are_required(context, permissions):
    p = project(context)
    context.policy.permissions = permissions
    context.db.commit()
    assert context.client.get(f"/api/v1/project-catalog/{p.id}/runs").status_code == 403


def test_service_tokens_are_not_allowed_into_user_result_navigation(context):
    p = project(context)
    context.auth["principal"] = ApiToken(id="token", service_id="other-service", name="token", token_hash="unused")
    assert context.client.get(f"/api/v1/project-catalog/{p.id}/runs").status_code == 403


def test_anonymous_and_invalid_token_requests_are_rejected(context):
    p = project(context)
    del context.client.app.dependency_overrides[current_principal]
    url = f"/api/v1/project-catalog/{p.id}/runs"
    assert context.client.get(url).status_code == 401
    assert context.client.get(url, headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_missing_project_and_invalid_pagination(context):
    assert context.client.get("/api/v1/project-catalog/missing/runs").status_code == 404
    p = project(context)
    for query in ("?page=0", "?size=0", "?size=101"):
        assert context.client.get(f"/api/v1/project-catalog/{p.id}/runs{query}").status_code == 422
