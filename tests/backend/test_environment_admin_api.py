from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker import environment_admin_api as api
from koda_tracker.db import Base, ensure_component_correction_removal_column, get_db
from koda_tracker.environment_admin_models import EnvironmentAdministrator
from koda_tracker.external_api import ExternalReadToken, router as external_router
from koda_tracker.library_api import router as library_router
from koda_tracker.main import compare_runs, download_artifact, get_run, get_run_components, list_runs
from koda_tracker.models import AnalysisRevision, ApiToken, AuditEvent, Environment, Job, JobState, ProcessingState, Release, Role, RolePolicy, RunComponent, RunComponentCorrection, RunManualComponent, SbomRun, Service, User, UserSession
from koda_tracker.project_catalog_models import NativeProject, NativeReanalysisPending, ProjectRunLink
from koda_tracker.security import digest


@pytest.fixture
def setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False, expire_on_commit=False) as db:
        users = [User(id=name, username=name, role=role, password_hash="unused", active=True, approval_state="approved")
                 for name, role in [("admin", Role.ADMIN), ("assigned", Role.VIEWER), ("other", Role.MANAGER)]]
        envs = [Environment(id="prod", slug="prod", name="운영"), Environment(id="test", slug="test", name="검증")]
        services = [Service(id="service", slug="service", name="결제 API"), Service(id="service2", slug="service2", name="회원 API")]
        db.add_all(users + envs + services)
        db.flush()
        release = Release(id="release", service_id="service", environment_id="prod", version="1.0")
        target = Release(id="target", service_id="service", environment_id="test", version="2.0")
        db.add_all([release, target])
        db.flush()
        for name, rel, number in [("run", release, 1), ("sibling", release, 2), ("existing", target, 7)]:
            run = SbomRun(id=name, release_id=rel.id, round_number=number, state=ProcessingState.COMPLETED,
                          analysis_state=JobState.COMPLETED, source="manual", original_filename="original.json",
                          media_type="application/json", spec_version="1.6", sha256="a" * 64,
                          size_bytes=42, artifact_path="/immutable/original.json", normalized_bom={"components": [{"name": "example", "version": "1"}]}, note="initial")
            db.add(run)
        db.flush()
        db.add(AnalysisRevision(id="analysis", run_id="run", sequence=1, state=JobState.COMPLETED,
                                policy_state="completed", findings=[{"id": "CVE-EXAMPLE"}], metrics={"policyViolationCount": 0}))
        db.add(RunComponent(id="component", run_id="run", identity_key="coord:library::example", name="example", version="1"))
        db.add(EnvironmentAdministrator(environment_id="prod", user_id="assigned", assigned_by="admin"))
        for user in users:
            db.add(UserSession(id_hash=digest(user.id + "-session"), user_id=user.id, csrf_hash=digest("csrf"), expires_at=datetime.now(UTC) + timedelta(hours=1)))
        db.add(ApiToken(id="token", token_hash=digest("token-secret"), name="integration", service_id="service"))
        db.commit()
        app = FastAPI()
        app.include_router(api.router)
        app.include_router(library_router)
        app.include_router(external_router)
        app.add_api_route("/api/v1/sbom-runs", list_runs)
        app.add_api_route("/api/v1/sbom-runs/{run_id}", get_run)
        app.add_api_route("/api/v1/sbom-runs/{run_id}/components", get_run_components)
        app.add_api_route("/api/v1/sbom-runs/{run_id}/artifact", download_artifact)
        app.add_api_route("/api/v1/comparisons", compare_runs)
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            client.cookies.set("koda_session", "admin-session")
            yield db, client
    engine.dispose()


def login(client, name):
    client.cookies.set("koda_session", name + "-session")


def patch(client, **body):
    return client.patch("/api/v1/sbom-runs/run/metadata", json=body, headers={"X-CSRF-Token": "csrf"})


def test_only_global_admin_can_replace_grants_and_replacement_is_audited(setup):
    db, client = setup
    response = client.get("/api/v1/environment-administrators")
    assert response.status_code == 200
    data = response.json()
    assert {item["id"] for item in data["users"]} == {"admin", "assigned", "other"}
    assert {item["status"] for item in data["users"]} == {"active"}
    assert next(item for item in data["environments"] if item["id"] == "prod")["administrators"][0]["id"] == "assigned"
    login(client, "assigned")
    assert client.get("/api/v1/environment-administrators").status_code == 403
    assert client.put("/api/v1/environment-administrators/test", json={"userIds": ["assigned"]}, headers={"X-CSRF-Token": "csrf"}).status_code == 403
    login(client, "other")
    assert client.put("/api/v1/environment-administrators/test", json={"userIds": ["other"]}, headers={"X-CSRF-Token": "csrf"}).status_code == 403
    login(client, "admin")
    assert client.put("/api/v1/environment-administrators/test", json={"userIds": ["assigned", "other"]}, headers={"X-CSRF-Token": "csrf"}).status_code == 200
    assert client.put("/api/v1/environment-administrators/test", json={"userIds": []}, headers={"X-CSRF-Token": "csrf"}).status_code == 200
    assert db.scalar(select(func.count()).select_from(EnvironmentAdministrator).where(EnvironmentAdministrator.environment_id == "test")) == 0
    event = db.scalars(select(AuditEvent).where(AuditEvent.action == "environment.administrators.update")).all()[-1]
    assert event.detail == {"before": ["assigned", "other"], "after": []}


def test_grant_validation_is_atomic_and_requires_csrf(setup):
    db, client = setup
    assert client.put("/api/v1/environment-administrators/prod", json={"userIds": []}).status_code == 403
    for invalid in [["missing"], ["assigned", "assigned"]]:
        assert client.put("/api/v1/environment-administrators/prod", json={"userIds": invalid}, headers={"X-CSRF-Token": "csrf"}).status_code == 422
        assert db.get(EnvironmentAdministrator, ("prod", "assigned")) is not None
    db.get(User, "other").approval_state = "pending"
    db.commit()
    assert client.put("/api/v1/environment-administrators/prod", json={"userIds": ["other"]}, headers={"X-CSRF-Token": "csrf"}).status_code == 422
    db.get(User, "other").approval_state = "approved"
    db.get(User, "other").active = False
    db.commit()
    assert client.put("/api/v1/environment-administrators/prod", json={"userIds": ["other"]}, headers={"X-CSRF-Token": "csrf"}).status_code == 422
    assert db.get(EnvironmentAdministrator, ("prod", "assigned")) is not None


def test_assigned_viewer_can_edit_notes_but_other_manager_cannot(setup):
    db, client = setup
    login(client, "assigned")
    permission = client.get("/api/v1/sbom-runs/run/edit-permission").json()
    assert permission["canEdit"] and permission["canChangeScope"]
    assert permission["editableEnvironmentIds"] == ["prod"]
    assert {item["id"] for item in permission["services"]} == {"service", "service2"}
    assert [item["id"] for item in permission["environments"]] == ["prod"]
    assert client.patch("/api/v1/sbom-runs/run/metadata", json={"note": "bad"}).status_code == 403
    assert patch(client, note="담당자가 검토함").status_code == 200
    assert db.get(SbomRun, "run").note == "담당자가 검토함"
    login(client, "other")
    assert client.get("/api/v1/sbom-runs/run/edit-permission").status_code == 404
    assert patch(client, note="unauthorized").status_code == 404
    assert db.get(SbomRun, "run").note == "담당자가 검토함"


def test_cross_environment_requires_both_grants_and_preserves_other_rows(setup):
    db, client = setup
    run = db.get(SbomRun, "run")
    original = (run.sha256, run.artifact_path, run.normalized_bom, run.created_at, run.original_filename, run.uploaded_by)
    login(client, "assigned")
    assert patch(client, environmentId="test", releaseVersion="2.0", note="denied").status_code == 403
    assert run.release_id == "release" and run.note == "initial"
    db.add(EnvironmentAdministrator(environment_id="test", user_id="assigned", assigned_by="admin"))
    db.commit()
    response = patch(client, environmentId="test", releaseVersion="2.0", note="moved")
    assert response.status_code == 200, response.text
    assert response.json()["roundNumber"] == 8 and response.json()["reanalysisPending"]
    assert run.release_id == "target" and run.note == "moved"
    assert db.get(SbomRun, "sibling").release_id == "release"
    assert db.get(Release, "release").version == "1.0"
    assert db.get(Release, "release").environment_id == "prod"
    assert (run.sha256, run.artifact_path, run.normalized_bom, run.created_at, run.original_filename, run.uploaded_by) == original
    assert db.get(AnalysisRevision, "analysis").policy_state == "completed"
    assert db.get(AnalysisRevision, "analysis").findings == [{"id": "CVE-EXAMPLE"}]
    assert db.get(RunComponent, "component").version == "1"
    assert run.analysis_state == JobState.QUEUED and run.state == ProcessingState.QUEUED
    assert db.get(NativeReanalysisPending, ("sbom-metadata-edit", "run")) is not None
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "sbom.metadata.update")).detail["originalPreserved"]


def test_source_grant_required_even_when_destination_is_granted(setup):
    db, client = setup
    db.delete(db.get(EnvironmentAdministrator, ("prod", "assigned")))
    db.add(EnvironmentAdministrator(environment_id="test", user_id="assigned", assigned_by="admin"))
    db.commit()
    login(client, "assigned")
    assert patch(client, environmentId="test").status_code == 404


def test_scope_move_to_new_release_does_not_mutate_shared_release(setup):
    db, client = setup
    response = patch(client, serviceId="service2", releaseVersion="new")
    assert response.status_code == 200
    run = db.get(SbomRun, "run")
    assert run.round_number == 1
    assert (run.release.service_id, run.release.environment_id, run.release.version) == ("service2", "prod", "new")
    assert db.get(SbomRun, "sibling").release_id == "release"


@pytest.mark.parametrize("field,value", [("sha256", "x"), ("normalized_bom", {}), ("state", "completed"), ("note", None), ("releaseVersion", "   ")])
def test_immutable_or_invalid_fields_rejected(setup, field, value):
    db, client = setup
    assert patch(client, **{field: value}).status_code == 422
    assert db.get(SbomRun, "run").note == "initial"


@pytest.mark.parametrize("reason", ["job", "archived", "linked", "pending"])
def test_scope_restrictions_allow_note_only_without_losing_original_state(setup, reason):
    db, client = setup
    run = db.get(SbomRun, "run")
    if reason == "job":
        db.add(Job(id="job", kind="analyze", run_id="run", state=JobState.RUNNING))
    elif reason == "archived":
        run.state = ProcessingState.ARCHIVED
        run.archived_at = datetime.now(UTC)
    elif reason == "linked":
        db.add(ProjectRunLink(run_id="run", project_id="project"))
    else:
        db.add(NativeReanalysisPending(source_id="other", run_id="run"))
    db.commit()
    db.refresh(run)
    before = (run.state, run.analysis_state, run.archived_at)
    permission = client.get("/api/v1/sbom-runs/run/edit-permission").json()
    assert permission["canEdit"] and not permission["canChangeScope"] and permission["scopeReason"]
    assert patch(client, releaseVersion="2.0").status_code == 409
    assert patch(client, serviceId="service", environmentId="prod", releaseVersion="1.0", note="allowed").status_code == 200
    assert run.note == "allowed" and run.release_id == "release"
    assert (run.state, run.analysis_state, run.archived_at) == before
    if reason == "archived":
        assert db.scalar(select(func.count()).select_from(NativeReanalysisPending)) == 0


def test_revocation_and_role_view_permission_take_effect_immediately(setup):
    db, client = setup
    login(client, "assigned")
    assert patch(client, note="first").status_code == 200
    db.add(RolePolicy(role=Role.VIEWER, permissions=[]))
    db.commit()
    assert patch(client, note="denied").status_code == 403
    db.get(RolePolicy, Role.VIEWER).permissions = ["runs.view"]
    db.delete(db.get(EnvironmentAdministrator, ("prod", "assigned")))
    db.commit()
    assert patch(client, note="still denied").status_code == 404


def test_api_tokens_and_pending_users_cannot_manage_or_edit(setup):
    db, client = setup
    token_headers = {"Authorization": "Bearer token-secret", "X-CSRF-Token": "csrf"}
    assert client.get("/api/v1/environment-administrators", headers=token_headers).status_code == 403
    assert client.patch("/api/v1/sbom-runs/run/metadata", json={"note": "token"}, headers=token_headers).status_code == 403
    db.get(User, "assigned").approval_state = "pending"
    db.commit()
    login(client, "assigned")
    assert patch(client, note="pending").status_code == 403


def test_inactive_target_is_rejected_but_existing_notes_are_editable(setup):
    db, client = setup
    db.get(Environment, "test").active = False
    db.commit()
    assert patch(client, environmentId="test").status_code == 409
    db.get(Environment, "prod").active = False
    db.commit()
    login(client, "assigned")
    permission = client.get("/api/v1/sbom-runs/run/edit-permission").json()
    assert permission["canEdit"] and permission["environments"][0]["active"] is False
    assert patch(client, note="retained history").status_code == 200
    assert patch(client, releaseVersion="2.0").status_code == 409


@pytest.mark.parametrize("approval,active,status", [("approved", True, "active"), ("approved", False, "inactive"), ("pending", False, "pending"), ("rejected", False, "rejected"), ("deleted", False, "deleted")])
def test_assigned_user_status_matches_existing_user_api(setup, approval, active, status):
    db, client = setup
    user = db.get(User, "assigned")
    user.approval_state, user.active = approval, active
    db.commit()
    response = client.get("/api/v1/environment-administrators")
    environment = next(item for item in response.json()["environments"] if item["id"] == "prod")
    assert environment["administrators"][0]["status"] == status


def test_stale_cached_admin_cannot_assign_after_role_revocation(setup):
    db, client = setup
    cached = db.get(User, "admin")
    db.execute(update(User).where(User.id == "admin").values(role=Role.VIEWER).execution_options(synchronize_session=False))
    db.commit()
    assert cached.role == Role.ADMIN  # Auth's identity-map instance is stale.
    response = client.put("/api/v1/environment-administrators/test", json={"userIds": ["assigned"]}, headers={"X-CSRF-Token": "csrf"})
    assert response.status_code == 403
    assert db.get(EnvironmentAdministrator, ("test", "assigned")) is None


def test_stale_cached_active_user_cannot_edit_after_approval_revocation(setup):
    db, client = setup
    cached = db.get(User, "assigned")
    db.execute(update(User).where(User.id == "assigned").values(approval_state="pending").execution_options(synchronize_session=False))
    db.commit()
    assert cached.approval_state == "approved"
    login(client, "assigned")
    assert patch(client, note="forbidden").status_code == 403
    assert db.get(SbomRun, "run").note == "initial"


@pytest.mark.parametrize("model,identity,changes", [(Environment, "test", {"environmentId": "test"}), (Service, "service2", {"serviceId": "service2"})])
def test_stale_cached_target_cannot_bypass_deactivation(setup, model, identity, changes):
    db, client = setup
    cached = db.get(model, identity)
    db.execute(update(model).where(model.id == identity).values(active=False).execution_options(synchronize_session=False))
    db.commit()
    assert cached.active is True
    assert patch(client, **changes).status_code == 409
    assert db.get(SbomRun, "run").release_id == "release"


def test_metadata_and_reanalysis_roll_back_together_on_database_failure(setup, monkeypatch):
    db, client = setup

    def fail_audit(*args, **kwargs):
        raise IntegrityError("simulated audit failure", {}, RuntimeError("conflict"))

    monkeypatch.setattr(api, "audit", fail_audit)
    assert patch(client, serviceId="service2", releaseVersion="new", note="not committed").status_code == 409
    run = db.get(SbomRun, "run")
    assert run.release_id == "release" and run.note == "initial"
    assert run.state == ProcessingState.COMPLETED and run.analysis_state == JobState.COMPLETED
    assert db.scalar(select(func.count()).select_from(Release)) == 2
    assert db.scalar(select(func.count()).select_from(NativeReanalysisPending)) == 0


def test_grant_replacement_rolls_back_on_database_failure(setup, monkeypatch):
    db, client = setup

    def fail_audit(*args, **kwargs):
        raise IntegrityError("simulated audit failure", {}, RuntimeError("conflict"))

    monkeypatch.setattr(api, "audit", fail_audit)
    assert client.put("/api/v1/environment-administrators/prod", json={"userIds": ["other"]}, headers={"X-CSRF-Token": "csrf"}).status_code == 409
    assert db.get(EnvironmentAdministrator, ("prod", "assigned")) is not None
    assert db.get(EnvironmentAdministrator, ("prod", "other")) is None


def test_run_scope_filters_search_and_relations_immediately_after_revocation(setup):
    db, client = setup
    db.add(RunComponent(run_id="existing", identity_key="prod-only", name="only-qa", search_text="only-qa"))
    db.commit()
    assert client.get("/api/v1/sbom-runs").json()["total"] == 3
    login(client, "other")
    assert client.get("/api/v1/sbom-runs").json()["total"] == 0
    assert client.get("/api/v1/sbom-runs/run").status_code == 404
    login(client, "assigned")
    assert {item["id"] for item in client.get("/api/v1/sbom-runs").json()["items"]} == {"run", "sibling"}
    assert client.get("/api/v1/sbom-runs?environment_id=test").json()["total"] == 0
    assert client.get("/api/v1/sbom-runs?q=only-qa").json()["total"] == 0
    assert client.get("/api/v1/libraries?q=only-qa").json()["total"] == 0
    assert client.get("/api/v1/sbom-runs/run/components").status_code == 200
    assert client.get("/api/v1/sbom-runs/existing/components").status_code == 404
    assert client.get("/api/v1/sbom-runs/existing/artifact").status_code == 404
    assert client.get("/api/v1/comparisons?baseRunId=run&targetRunId=existing").status_code == 404
    login(client, "admin")
    assert client.put("/api/v1/environment-administrators/prod", json={"userIds": []}, headers={"X-CSRF-Token": "csrf"}).status_code == 200
    login(client, "assigned")
    assert client.get("/api/v1/sbom-runs").json()["total"] == 0
    assert client.get("/api/v1/sbom-runs/run").status_code == 404


def test_component_correction_preserves_original_and_audits_optimistic_edits(setup):
    db, client = setup
    login(client, "assigned")
    url = "/api/v1/sbom-runs/run/components"
    body = {"name": "example corrected", "version": "2.0", "expectedRevision": 0}
    headers = {"X-CSRF-Token": "csrf"}
    assert client.patch(f"{url}/component", json=body).status_code == 403
    assert client.patch(f"{url}/component", json=body, headers=headers).json()["correctionRevision"] == 1
    assert client.patch(f"{url}/component", json=body, headers=headers).status_code == 409
    corrected = client.get(f"{url}?q=corrected").json()["items"][0]
    assert (corrected["name"], corrected["version"], corrected["originalName"], corrected["originalVersion"]) == (
        "example corrected", "2.0", "example", "1"
    )
    assert db.get(RunComponent, "component").version == "1"
    assert db.get(SbomRun, "run").normalized_bom["components"][0]["version"] == "1"
    assert db.get(AnalysisRevision, "analysis").findings == [{"id": "CVE-EXAMPLE"}]
    login(client, "other")
    assert client.patch(f"{url}/component", json={**body, "expectedRevision": 1}, headers=headers).status_code == 404
    login(client, "admin")
    reset = client.patch(f"{url}/component", json={"name": None, "version": None, "expectedRevision": 1}, headers=headers)
    assert reset.json() == {"name": "example", "version": "1", "correctionRevision": 2}
    correction = db.get(RunComponentCorrection, ("run", "coord:library::example"))
    assert correction.name is None and correction.version is None
    assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "sbom.component.correct")) == 2



def test_component_removal_is_scoped_reversible_and_preserves_original_analysis(setup):
    db, client = setup
    url = "/api/v1/sbom-runs/run/components"
    headers = {"X-CSRF-Token": "csrf"}
    removal = {"removed": True, "expectedRevision": 1}
    db.add(RunComponent(id="remaining", run_id="run", identity_key="coord:library::remaining", name="remaining", version="1"))
    db.add(RunComponent(id="sibling-comp", run_id="sibling", identity_key="coord:library::example", name="example", version="1"))
    db.commit()

    login(client, "other")
    assert client.patch(f"{url}/component", json=removal, headers=headers).status_code == 404
    assert client.get(f"{url}?removed=true").status_code == 404

    login(client, "assigned")
    edited = client.patch(f"{url}/component", json={"name": "renamed", "version": "2", "expectedRevision": 0}, headers=headers)
    assert edited.status_code == 200
    assert client.patch(f"{url}/component", json=removal).status_code == 403
    removed = client.patch(f"{url}/component", json=removal, headers=headers)
    assert removed.json() == {"name": "renamed", "version": "2", "correctionRevision": 2, "removed": True}
    assert client.patch(f"{url}/component", json=removal, headers=headers).status_code == 409
    assert client.patch(f"{url}/component", json={**removal, "expectedRevision": 2}, headers=headers).json() == removed.json()

    active = client.get(url).json()
    assert [item["id"] for item in active["items"]] == ["remaining"]
    assert (active["total"], active["removedTotal"]) == (1, 1)
    assert client.get(f"{url}?q=renamed").json()["total"] == 0
    deleted = client.get(f"{url}?removed=true&q=renamed").json()
    assert (deleted["items"][0]["id"], deleted["items"][0]["removed"], deleted["total"]) == ("component", True, 1)
    assert client.get(f"{url}?removed=true&q=missing").json()["removedTotal"] == 1
    assert client.get("/api/v1/sbom-runs/sibling/components").json()["total"] == 1
    assert db.get(RunComponent, "component").name == "example"
    assert db.get(SbomRun, "run").normalized_bom["components"] == [{"name": "example", "version": "1"}]
    assert db.get(AnalysisRevision, "analysis").findings == [{"id": "CVE-EXAMPLE"}]

    restored = client.patch(f"{url}/component", json={"removed": False, "expectedRevision": 2}, headers=headers)
    assert restored.json() == {"name": "renamed", "version": "2", "correctionRevision": 3, "removed": False}
    assert client.get(f"{url}?q=renamed").json()["total"] == 1
    assert client.get(f"{url}?removed=true").json()["total"] == 0
    events = db.scalars(select(AuditEvent).where(AuditEvent.action.in_(("sbom.component.remove", "sbom.component.restore")))).all()
    assert {event.action: event.detail["after"]["removed"] for event in events} == {
        "sbom.component.remove": True, "sbom.component.restore": False,
    }


def test_existing_component_correction_schema_keeps_old_edits(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.sqlite'}")
    with engine.begin() as db:
        db.execute(text("CREATE TABLE run_component_corrections (name TEXT, revision INTEGER)"))
        db.execute(text("INSERT INTO run_component_corrections (name, revision) VALUES ('renamed', 3)"))
    ensure_component_correction_removal_column(engine)
    ensure_component_correction_removal_column(engine)
    with engine.connect() as db:
        assert db.execute(text("SELECT name, revision, removed FROM run_component_corrections")).one() == ("renamed", 3, False)
    engine.dispose()



def test_manual_component_addition_is_scoped_and_keeps_original_inventory(setup):
    db, client = setup
    url = "/api/v1/sbom-runs/run/components"
    headers = {"X-CSRF-Token": "csrf"}
    payload = {"name": "   Local wrapper   ", "version": " 02.01 "}
    login(client, "other")
    assert client.post(url, json=payload, headers=headers).status_code == 404
    login(client, "assigned")
    assert client.post(url, json=payload).status_code == 403
    for invalid in ({"name": " ", "version": "1"}, {"name": "name", "version": " "}, {"name": "x", "version": "a\nb"}):
        assert client.post(url, json=invalid, headers=headers).status_code == 422

    added = client.post(url, json=payload, headers=headers)
    assert added.status_code == 201
    component_id = added.json()["id"]
    assert (added.json()["name"], added.json()["version"]) == ("Local wrapper", "02.01")
    assert client.post(url, json=payload, headers=headers).status_code == 409
    assert db.scalar(select(func.count()).select_from(RunManualComponent)) == 1

    first = client.get(f"{url}?size=1").json()
    assert first["total"] == 2
    assert [(item["id"], item["manual"]) for item in first["items"]] == [(component_id, True)]
    assert client.get(f"{url}?size=1&page=2").json()["items"][0]["id"] == "component"
    assert client.get(f"{url}?q=wrapper+02.01").json()["total"] == 1
    assert client.get("/api/v1/sbom-runs/sibling/components").json()["total"] == 0
    assert client.get("/api/v1/sbom-runs/run").json()["componentCount"] == 1
    assert db.get(SbomRun, "run").normalized_bom["components"] == [{"name": "example", "version": "1"}]
    assert db.get(AnalysisRevision, "analysis").findings == [{"id": "CVE-EXAMPLE"}]
    db.add(ExternalReadToken(name="fixture", token_hash=digest("koda_read_fixture"), service_id="service",
                             expires_at=datetime.now(UTC) + timedelta(hours=1)))
    db.commit()
    external = client.get("/api/v1/integrations/external/runs/run/components",
                          headers={"Authorization": "Bearer koda_read_fixture"})
    assert external.status_code == 200
    assert external.json()["total"] == 1
    assert [item["name"] for item in external.json()["items"]] == ["example"]
    event = db.scalar(select(AuditEvent).where(AuditEvent.action == "sbom.component.add"))
    assert event.detail == {"identityKey": component_id, "name": "Local wrapper", "version": "02.01"}

    component_url = f"{url}/{component_id}"
    edit = client.patch(component_url, json={"name": "renamed", "version": "03.00", "expectedRevision": 0}, headers=headers)
    assert edit.json()["correctionRevision"] == 1
    assert client.get(f"{url}?q=renamed").json()["items"][0]["version"] == "03.00"
    assert client.patch(component_url, json={"removed": True, "expectedRevision": 1}, headers=headers).status_code == 200
    assert client.get(url).json()["removedTotal"] == 1
    assert client.get(f"{url}?removed=true").json()["items"][0]["id"] == component_id
    assert client.post(url, json=payload, headers=headers).status_code == 409
    assert client.patch(component_url, json={"removed": False, "expectedRevision": 2}, headers=headers).status_code == 200
    assert client.get(f"{url}?q=renamed").json()["items"][0]["manual"] is True

    db.get(SbomRun, "run").state = ProcessingState.ARCHIVED
    db.commit()
    assert client.post(url, json={"name": "different", "version": "1"}, headers=headers).status_code == 409
