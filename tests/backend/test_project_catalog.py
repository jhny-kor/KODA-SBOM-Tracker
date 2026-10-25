from __future__ import annotations
import copy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
import uuid
from cryptography.fernet import Fernet
import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from fastapi import HTTPException
from koda_tracker import project_catalog as catalog, project_catalog_api as api
from koda_tracker.config import Settings
from koda_tracker.db import Base
from koda_tracker.models import Environment, Release, SbomRun, Service, ProcessingState, JobState, SbomPolicyRevision
from koda_tracker.project_catalog_models import NativeProject, ProjectRunLink
from koda_tracker import workflow_models, package_metadata_models


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, autoflush=False, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def identity(label):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, label))


def setup_runs(db):
    service = Service(id=identity("svc"), slug="test", name="Test")
    environment = Environment(id=identity("env"), slug="test", name="Test")
    db.add_all([service, environment]); db.flush()
    releases = [Release(id=identity("release"+str(i)), service_id=service.id, environment_id=environment.id, version=str(i)) for i in (1, 2)]
    db.add_all(releases); db.flush()
    runs = [SbomRun(id=identity("run"+str(i)), release_id=r.id, round_number=1, state=ProcessingState.COMPLETED, analysis_state=JobState.COMPLETED, source="upload", original_filename="test.json", media_type="application/json", spec_version="1.6", sha256="a"*64, size_bytes=2, artifact_path="/test", normalized_bom={}) for i, r in enumerate(releases)]
    db.add_all(runs); db.flush()
    return service, environment, releases, runs


def project(db, label="a", source="source", **kwargs):
    p = NativeProject(id=identity("project-"+source+"-"+label), source_id=source, source_project_id=label, name=kwargs.pop("name", label), version=kwargs.pop("version", "1"), service_id=identity("svc"), environment_id=identity("env"), tags=kwargs.pop("tags", []), is_latest=kwargs.pop("is_latest", True), active=True, **kwargs)
    db.add(p); db.flush(); return p


def test_dynamic_tags_parent_latest_and_cross_source_scope(db):
    _, _, _, runs = setup_runs(db)
    parent = project(db, "parent")
    child = project(db, "child", parent_project_id="parent", tags=["prod"])
    db.add(ProjectRunLink(run_id=runs[0].id, project_id=child.id)); db.flush()
    context = catalog.catalog_context_for_run(db, runs[0].id)
    assert context["ancestorIds"] == ["parent"]
    assert catalog.project_scope_matches({"sourceId":"source", "projectIds":["parent"], "includeChildren":True}, context)
    assert catalog.project_scope_matches({"sourceId":"source", "tags":["prod"], "onlyLatest":True}, context)
    assert not catalog.project_scope_matches({"sourceId":"other", "projectIds":["child"]}, context)
    child.tags=[]; child.is_latest=False; child.parent_project_id=None; db.flush()
    context2=catalog.catalog_context_for_run(db,runs[0].id)
    assert not catalog.project_scope_matches({"sourceId":"source", "tags":["prod"]},context2)
    assert not catalog.project_scope_matches({"sourceId":"source", "onlyLatest":True},context2)
    assert not catalog.project_scope_matches({"sourceId":"source", "projectIds":["parent"],"includeChildren":True},context2)
    assert context["tags"]==["prod"]  # previous snapshot is not rewritten


def test_ordinary_new_upload_uses_unique_catalog_release_and_historical_runs(db):
    _,_,releases,runs=setup_runs(db)
    p=project(db,"a",version="1")
    assert catalog.project_for_run(db,runs[0].id).id==p.id
    p.current_run_id=runs[1].id
    assert catalog.scoped_run_matches(db,runs[0].id,{"sourceId":"source","onlyLatest":True})
    duplicate=project(db,"ambiguous",version="1")
    assert catalog.project_for_run(db,runs[0].id) is None
    catalog.link_run(db,p,runs[0]);db.flush()
    assert catalog.project_for_run(db,runs[0].id).id==p.id
    with pytest.raises(catalog.CatalogError,match="다른 프로젝트"):
        catalog.link_run(db,duplicate,runs[0])
    with pytest.raises(catalog.CatalogError,match="서비스·환경·버전"):
        catalog.link_run(db,p,runs[1])


def test_latest_switch_is_atomic_within_name_and_source_group(db):
    a=project(db,"v1",name="Application",version="1")
    b=project(db,"v2",name="Application",version="2",is_latest=False)
    other=project(db,"v3",source="other",name="Application",version="3")
    previous=a.revision
    catalog.set_latest(db,b,True); db.flush()
    assert b.is_latest and not a.is_latest and other.is_latest and a.revision==previous+1




def test_catalog_native_api_create_edit_conflict_and_cycles(db):
    service,env,_,runs=setup_runs(db)
    user=SimpleNamespace(username="admin",id=identity("admin"))
    a=api.create_project(api.ProjectCreate(sourceProjectId="root",serviceId=service.id,environmentId=env.id,name="App",version="1",tags=["prod"],isLatest=True,runId=runs[0].id),db,user)
    b=api.create_project(api.ProjectCreate(sourceProjectId="child",serviceId=service.id,environmentId=env.id,name="Child",version="2",parentProjectId="root"),db,user)
    before=copy.deepcopy(runs[0].normalized_bom)
    changed=api.update_project(a["id"],api.ProjectUpdate(expectedRevision=a["revision"],tags=["qa"],isLatest=False),db,user)
    assert changed["tags"]==["qa"] and not changed["isLatest"]
    assert runs[0].normalized_bom==before
    with pytest.raises(HTTPException) as exc:
        api.update_project(a["id"],api.ProjectUpdate(expectedRevision=a["revision"],tags=[]),db,user)
    assert exc.value.status_code==409
    with pytest.raises(HTTPException) as exc:
        api.update_project(a["id"],api.ProjectUpdate(expectedRevision=changed["revision"],parentProjectId="child"),db,user)
    assert exc.value.status_code==422
    with pytest.raises(HTTPException) as exc:
        api.update_project(b["id"],api.ProjectUpdate(expectedRevision=b["revision"],parentProjectId="cross-source"),db,user)
    assert exc.value.status_code==422






def mock_exporter(monkeypatch, *, failure=None):
    class Exporter:
        closed=False
        def __init__(self,*args,**kwargs):pass
        def export(self,ids):
            if failure:raise failure
            return {"source":{"id":"source"}}
        def close(self):self.closed=True
    monkeypatch.setattr(catalog,"decrypt_key",lambda value:"sensitive-api-key")
    monkeypatch.setattr(migration,"LegacyExporter",Exporter)
    return Exporter


















def test_native_reanalysis_pending_survives_full_queue_and_drains_without_due_sources(db, monkeypatch):
    from koda_tracker.models import Job
    from koda_tracker.project_catalog_models import NativeReanalysisPending
    _, _, _, runs = setup_runs(db)
    monkeypatch.setattr(catalog, "get_settings", lambda: Settings(max_queued_jobs=1))
    blocker = Job(kind="analyze", run_id=runs[1].id, state=JobState.QUEUED)
    db.add(blocker); db.commit()
    assert catalog.request_native_reanalysis(db, "source", [runs[0].id]) == 1
    assert catalog.drain_native_reanalysis(db) == 0
    db.commit()
    assert db.get(NativeReanalysisPending, ("source", runs[0].id)) is not None
    assert runs[0].analysis_state == JobState.QUEUED
    # Free capacity and simulate a fresh process/session tick: no source is due,
    # but persisted intent must still become a durable real worker job.
    blocker.state = JobState.COMPLETED; db.commit(); db.expire_all()
    assert catalog.drain_native_reanalysis(db) == 1
    assert db.get(NativeReanalysisPending, ("source", runs[0].id)) is None
    job = db.scalar(select(Job).where(Job.run_id == runs[0].id))
    assert job.kind == "analyze" and job.state == JobState.QUEUED
    assert job.payload["sourceSync"]["sourceId"] == "source"


def test_native_reanalysis_waits_running_job_and_reuses_only_queued_job(db):
    from koda_tracker.models import Job
    from koda_tracker.project_catalog_models import NativeReanalysisPending
    _, _, _, runs = setup_runs(db)
    running = Job(kind="analyze", run_id=runs[0].id, state=JobState.RUNNING)
    db.add(running); db.commit()
    catalog.request_native_reanalysis(db, "source", [runs[0].id])
    assert catalog.drain_native_reanalysis(db) == 0
    assert db.get(NativeReanalysisPending, ("source", runs[0].id)) is not None
    assert runs[0].analysis_state == JobState.RUNNING
    running.state = JobState.COMPLETED; db.commit()
    assert catalog.drain_native_reanalysis(db) == 1
    queued = db.scalar(select(Job).where(Job.run_id == runs[0].id, Job.state == JobState.QUEUED))
    assert queued is not None and queued.id != running.id
    db.commit()
    catalog.request_native_reanalysis(db, "source", [runs[0].id])
    assert catalog.drain_native_reanalysis(db) == 1
    assert db.scalar(select(func.count()).select_from(Job).where(Job.run_id == runs[0].id)) == 2




def test_pending_multiple_sources_share_one_job_with_production_autoflush_disabled(db):
    from koda_tracker.models import Job
    from koda_tracker.project_catalog_models import NativeReanalysisPending
    _, _, _, runs = setup_runs(db)
    assert db.autoflush is False
    catalog.request_native_reanalysis(db, "source-a", [runs[0].id])
    catalog.request_native_reanalysis(db, "source-b", [runs[0].id])
    db.commit()
    assert catalog.drain_native_reanalysis(db) == 2
    assert db.scalar(select(func.count()).select_from(Job).where(Job.run_id == runs[0].id)) == 1
    assert db.scalar(select(func.count()).select_from(NativeReanalysisPending)) == 0
    job = db.scalar(select(Job))
    assert {item["sourceId"] for item in job.payload["sourceSyncRequests"]} == {"source-a", "source-b"}
