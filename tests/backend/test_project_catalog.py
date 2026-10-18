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
from koda_tracker import project_catalog as catalog, project_catalog_api as api, migration
from koda_tracker.config import Settings
from koda_tracker.db import Base
from koda_tracker.models import Environment, Release, SbomRun, Service, ProcessingState, JobState, SbomPolicyRevision
from koda_tracker.migration_models import LegacyObjectMap
from koda_tracker.project_catalog_models import NativeProject, ProjectRunLink, ProjectSyncSource, ProjectSyncEvent
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
    runs = [SbomRun(id=identity("run"+str(i)), release_id=r.id, round_number=1, state=ProcessingState.COMPLETED, analysis_state=JobState.COMPLETED, dtrack_state=JobState.COMPLETED, source="upload", original_filename="test.json", media_type="application/json", spec_version="1.6", sha256="a"*64, size_bytes=2, artifact_path="/test", normalized_bom={}) for i, r in enumerate(releases)]
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


def test_import_catalog_preserves_both_run_links_and_validates_cycles(db):
    _,_,_,runs=setup_runs(db)
    raw={"source":{"id":"source"},"projects":[{"project":{"uuid":"a","name":"Application","version":"1","tags":[{"name":"prod"}],"isLatest":True}}]}
    plan={"a":{"runId":runs[0].id,"serviceId":identity("svc"),"environmentId":identity("env")}}
    p=catalog.upsert_source_projects(db,raw,plan)[0]
    revision=p.revision
    catalog.upsert_source_projects(db,raw,plan)
    assert p.revision==revision
    new=copy.deepcopy(plan); new["a"]["runId"]=runs[1].id
    catalog.upsert_source_projects(db,raw,new)
    assert db.scalar(select(func.count()).select_from(ProjectRunLink))==2
    assert db.get(ProjectRunLink,runs[0].id).project_id==p.id
    assert p.current_run_id==runs[1].id
    invalid=copy.deepcopy(raw); invalid["projects"][0]["project"]["parent"]={"uuid":"a"}
    with pytest.raises(catalog.CatalogError,match="순환"):
        catalog.upsert_source_projects(db,invalid,new)


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


def test_credential_encrypted_no_key_in_public_payload(monkeypatch, db):
    settings=Settings(ldap_encryption_key=Fernet.generate_key().decode())
    monkeypatch.setattr(catalog,"get_settings",lambda:settings)
    secret="private-source-key-long-random"
    cipher=catalog.encrypt_key(secret)
    assert secret not in cipher and catalog.decrypt_key(cipher)==secret
    s=sync_source(db,cipher)
    assert secret not in str(catalog.sync_payload(s)) and cipher not in str(catalog.sync_payload(s))
    monkeypatch.setattr(catalog,"get_settings",lambda:Settings(ldap_encryption_key=""))
    with pytest.raises(catalog.CatalogError,match="암호화 키"):
        catalog.encrypt_key(secret)


def sync_source(db,cipher="cipher",**kwargs):
    s=ProjectSyncSource(id=identity("sync"),name="Source",base_url="http://source.test",allowed_origins=["http://source.test"],project_uuids=[],key_ciphertext=cipher,enabled=True,interval_minutes=5,next_run_at=datetime(2026,1,1,tzinfo=UTC),actor_id=identity("admin"),actor_name="admin",**kwargs)
    db.add(s);db.commit();return s


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


def test_sync_retry_backoff_redacts_key_and_stops_at_limit(db,monkeypatch):
    source=sync_source(db)
    mock_exporter(monkeypatch,failure=RuntimeError("sensitive-api-key upstream unavailable"))
    at=datetime(2026,1,1,tzinfo=UTC)
    for attempt in range(1,6):
        result=catalog.project_sync_tick(db,at=at)
        assert "sensitive-api-key" not in result["lastError"]
        assert result["attempts"]==attempt
        if attempt<5:
            assert result["state"]=="retrying"
            at=catalog.utc(source.next_run_at)
        else:assert result["state"]=="failed" and result["nextRunAt"] is None
    assert db.scalar(select(func.count()).select_from(ProjectSyncEvent))==5


def test_sync_claim_and_restart_recovers_lease_without_duplicate_exports(db,monkeypatch):
    at=datetime(2026,1,1,tzinfo=UTC)
    source=sync_source(db,state="running",attempts=1,lease_until=at+timedelta(minutes=1))
    event=ProjectSyncEvent(source_id=source.id,attempt=1,state="running",started_at=at-timedelta(minutes=10));db.add(event);db.commit()
    mock_exporter(monkeypatch,failure=RuntimeError("offline"))
    assert catalog.project_sync_tick(db,at=at) is None
    result=catalog.project_sync_tick(db,at=at+timedelta(minutes=2))
    assert result["state"]=="retrying" and result["attempts"]==2
    db.refresh(event);assert event.state=="failed" and "임대" in event.detail["error"]


def test_local_policy_edit_blocks_sync_instead_of_overwriting(db,monkeypatch):
    source=sync_source(db)
    db.add(SbomPolicyRevision(version=1,document={"rules":[{"id":"imported","name":"Local edit"}],"exceptions":[]},created_by="admin"))
    db.add(LegacyObjectMap(source_id="source",object_type="policy",object_id=identity("policy"),target_id="imported",content_hash="a"*64,provenance={"rule":{"id":"imported","name":"Original"}}));db.commit()
    mock_exporter(monkeypatch)
    result=catalog.project_sync_tick(db,at=datetime(2026,1,1,tzinfo=UTC))
    assert result["state"]=="blocked" and result["nextRunAt"] is None
    assert "덮어쓰기" in result["lastError"]
    assert db.scalar(select(SbomPolicyRevision.document))["rules"][0]["name"]=="Local edit"


def test_sync_success_uses_safe_untrusted_apply_and_schedules_next(db,monkeypatch):
    source=sync_source(db)
    mock_exporter(monkeypatch)
    batch=SimpleNamespace(id=identity("batch"),digest="a"*64,report={"canApply":True},result={"runIds":[]})
    monkeypatch.setattr(migration,"stage_bundle",lambda *args:batch)
    captured={}
    def apply(*args,**kwargs):captured.update(kwargs);return batch
    monkeypatch.setattr(migration,"apply_migration",apply)
    result=catalog.project_sync_tick(db,at=datetime(2026,1,1,tzinfo=UTC))
    assert result["state"]=="idle" and result["attempts"]==0
    assert result["sourceId"]=="source" and result["lastMigrationId"]==batch.id
    assert captured["trust_source_reviews"] is False and result["nextRunAt"].startswith("2026-01-01T00:05")
    assert db.scalar(select(ProjectSyncEvent.state))=="completed"


def test_sync_failed_semantic_conversion_preserves_block_report(db,monkeypatch):
    source=sync_source(db);mock_exporter(monkeypatch)
    batch=SimpleNamespace(id=identity("batch"),report={"canApply":False,"blockers":[{"reason":"unsupported"}]})
    monkeypatch.setattr(migration,"stage_bundle",lambda *args:batch)
    result=catalog.project_sync_tick(db,at=datetime(2026,1,1,tzinfo=UTC))
    assert result["state"]=="blocked" and result["lastMigrationId"]==batch.id
    assert db.scalar(select(ProjectSyncEvent.detail))["blockers"]==batch.report["blockers"]


def test_real_migration_sync_updates_catalog_version_and_sbom_without_rewriting_history(db, monkeypatch, tmp_path):
    from test_migration import bundle, uid
    from koda_tracker.models import AnalysisRevision
    from koda_tracker.policies import evaluate_revision
    raw = bundle()
    raw["policies"][0].update({"tags": [{"name": "prod"}], "onlyLatestProjectVersion": True})
    settings = Settings(artifact_dir=tmp_path)
    monkeypatch.setattr(migration, "get_settings", lambda: settings)
    monkeypatch.setattr(catalog, "decrypt_key", lambda value: "sample-key")
    class Exporter:
        def __init__(self, *args, **kwargs): pass
        def export(self, ids): return copy.deepcopy(raw)
        def close(self): pass
    monkeypatch.setattr(migration, "LegacyExporter", Exporter)
    source = sync_source(db)
    at = datetime(2026, 1, 1, tzinfo=UTC)
    first = catalog.project_sync_tick(db, at=at)
    assert first["state"] == "idle", first
    first_run_id = db.get(LegacyObjectMap, ("source-a", "project", uid("project"))).target_id
    first_run = db.get(SbomRun, first_run_id)
    first_revision = db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == first_run_id))
    old_evidence = {"bom": copy.deepcopy(first_run.normalized_bom), "source": copy.deepcopy(first_run.source_metadata), "policies": copy.deepcopy(first_revision.policies), "snapshot": copy.deepcopy(first_revision.policy_snapshot)}
    assert any(p["policyId"].startswith("legacy-") for p in first_revision.policies)

    # A metadata-only source update changes future dynamic applicability, while
    # reusing the immutable run when source version and BOM are unchanged.
    raw["projects"][0]["project"].update({"tags": [{"name": "qa"}], "isLatest": False})
    parent = copy.deepcopy(raw["projects"][0])
    parent["project"].update({"uuid": uid("parent"), "name": "Root", "isLatest": True, "tags": []})
    parent["findings"] = {"version": "1.2", "findings": []}
    parent["analyses"] = []
    parent["bom"]["components"] = []
    parent["components"] = []
    raw["projects"].append(parent)
    raw["projects"][0]["project"]["parent"] = {"uuid": uid("parent")}
    second = catalog.project_sync_tick(db, at=at + timedelta(minutes=5))
    assert second["state"] == "idle", second
    assert db.get(LegacyObjectMap, ("source-a", "project", uid("project"))).target_id == first_run_id
    context = catalog.catalog_context_for_run(db, first_run_id)
    assert context["tags"] == ["qa"] and not context["isLatest"] and context["ancestorIds"] == [uid("parent")]
    new_revision = AnalysisRevision(run_id=first_run_id, sequence=first_revision.sequence+1, state=JobState.COMPLETED, findings=copy.deepcopy(first_revision.findings), tool_version="test-reanalysis")
    db.add(new_revision); db.flush(); evaluate_revision(db, first_run, new_revision); db.commit()
    assert new_revision.policy_state == "completed"
    assert not any(p["policyId"].startswith("legacy-") for p in new_revision.policies)
    assert first_revision.policies == old_evidence["policies"] and first_revision.policy_snapshot == old_evidence["snapshot"]

    # A changed source version gets a new release/run even when BOM bytes match.
    raw["projects"][0]["project"].update({"version": "2", "isLatest": True, "tags": [{"name": "prod"}]})
    third = catalog.project_sync_tick(db, at=at + timedelta(minutes=10))
    assert third["state"] == "idle", third
    second_run_id = db.get(LegacyObjectMap, ("source-a", "project", uid("project"))).target_id
    assert second_run_id != first_run_id
    assert db.get(SbomRun, second_run_id).release.version == "2"
    assert first_run.release.version == "1" and first_run.normalized_bom == old_evidence["bom"]
    old_context = catalog.catalog_context_for_run(db, first_run_id)
    current_context = catalog.catalog_context_for_run(db, second_run_id)
    assert old_context["version"] == "1" and old_context["catalogVersion"] == "2" and not old_context["isLatest"]
    assert current_context["version"] == "2" and current_context["isLatest"]
    assert not catalog.project_scope_matches({"sourceId": "source-a", "onlyLatest": True}, old_context)
    assert catalog.project_scope_matches({"sourceId": "source-a", "onlyLatest": True}, current_context)
    assert first_run.source_metadata == old_evidence["source"]
    assert catalog.project_for_run(db, first_run_id).id == catalog.project_for_run(db, second_run_id).id

    # Changed source BOM appends another round in the same source version.
    raw["projects"][0]["bom"]["components"].append({"type": "library", "name": "extra", "version": "1"})
    fourth = catalog.project_sync_tick(db, at=at + timedelta(minutes=15))
    assert fourth["state"] == "idle", fourth
    third_run_id = db.get(LegacyObjectMap, ("source-a", "project", uid("project"))).target_id
    assert third_run_id not in {first_run_id, second_run_id}
    assert db.get(SbomRun, third_run_id).round_number == 2
    assert len(db.get(SbomRun, second_run_id).normalized_bom["components"]) == 1
    assert len(db.get(SbomRun, third_run_id).normalized_bom["components"]) == 2
    count = db.scalar(select(func.count()).select_from(SbomRun))
    fifth = catalog.project_sync_tick(db, at=at + timedelta(minutes=20))
    assert fifth["state"] == "idle" and db.scalar(select(func.count()).select_from(SbomRun)) == count


def test_complete_source_snapshot_retires_deleted_projects_but_partial_preserves_them(db):
    _, _, _, runs = setup_runs(db)
    parent = {"project": {"uuid": "parent", "name": "Parent", "version": "1", "isLatest": True}}
    child = {"project": {"uuid": "child", "name": "Child", "version": "2", "parent": {"uuid": "parent"}, "isLatest": True}}
    raw = {"source": {"id": "source", "projectSnapshotComplete": True}, "projects": [parent, child]}
    plan = {"parent": {"runId": runs[0].id, "serviceId": identity("svc"), "environmentId": identity("env")}, "child": {"runId": runs[1].id, "serviceId": identity("svc"), "environmentId": identity("env")}}
    projects = catalog.upsert_source_projects(db, raw, plan)
    parent_row = next(p for p in projects if p.source_project_id == "parent")
    child_row = next(p for p in projects if p.source_project_id == "child")
    assert catalog.catalog_context_for_run(db, runs[1].id)["ancestorIds"] == ["parent"]
    partial = copy.deepcopy(raw); partial["projects"] = [child]; partial["source"]["projectSnapshotComplete"] = False
    catalog.upsert_source_projects(db, partial, plan)
    assert parent_row.active and parent_row.is_latest and child_row.parent_project_id == "parent"
    # Complete source deletion retires the parent and removes effective dangling
    # edges, preserving imported raw evidence and historical run links.
    full = copy.deepcopy(partial); full["source"]["projectSnapshotComplete"] = True
    catalog.upsert_source_projects(db, full, plan)
    assert not parent_row.active and not parent_row.is_latest
    assert child_row.parent_project_id is None
    context = catalog.catalog_context_for_run(db, runs[1].id)
    assert context["parentProjectId"] is None and context["ancestorIds"] == []
    assert not catalog.project_scope_matches({"sourceId": "source", "projectIds": ["parent"], "includeChildren": True}, context)
    assert db.get(ProjectRunLink, runs[0].id).project_id == parent_row.id


def test_real_sync_upstream_policy_deletion_and_repeat_are_not_local_conflicts(db, monkeypatch, tmp_path):
    from test_migration import bundle, uid
    from koda_tracker.models import AnalysisRevision
    from koda_tracker.policies import get_policy_document
    raw = bundle()
    raw["source"]["projectSnapshotComplete"] = True
    settings = Settings(artifact_dir=tmp_path)
    monkeypatch.setattr(migration, "get_settings", lambda: settings)
    monkeypatch.setattr(catalog, "decrypt_key", lambda value: "sample-key")
    class Exporter:
        def __init__(self, *args, **kwargs): pass
        def export(self, ids): return copy.deepcopy(raw)
        def close(self): pass
    monkeypatch.setattr(migration, "LegacyExporter", Exporter)
    source = sync_source(db)
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert catalog.project_sync_tick(db, at=at)["state"] == "idle"
    original_revision = db.scalar(select(AnalysisRevision))
    evidence = copy.deepcopy(original_revision.policy_snapshot)
    mapping = db.get(LegacyObjectMap, ("source-a", "policy", uid("policy")))
    imported_rule_id = mapping.target_id
    original_rule = copy.deepcopy(mapping.provenance["rule"])
    assert any(r["id"] == imported_rule_id for r in get_policy_document(db).document["rules"])
    raw["policies"] = []
    deleted = catalog.project_sync_tick(db, at=at + timedelta(minutes=5))
    assert deleted["state"] == "idle", deleted
    assert mapping.provenance["retired"] and mapping.provenance["rule"] is None
    assert mapping.provenance["retiredRule"] == original_rule
    assert not any(r["id"] == imported_rule_id for r in get_policy_document(db).document["rules"])
    repeated = catalog.project_sync_tick(db, at=at + timedelta(minutes=10))
    assert repeated["state"] == "idle", repeated
    assert original_revision.policy_snapshot == evidence
    # Restoring source policy clears tombstone and uses its existing native ID.
    raw["policies"] = bundle()["policies"]
    raw["source"]["exportedAt"] = "2026-10-18T00:15:00Z"
    restored = catalog.project_sync_tick(db, at=at + timedelta(minutes=15))
    assert restored["state"] == "idle", restored
    assert mapping.target_id == imported_rule_id and mapping.provenance["rule"] == original_rule
    assert not mapping.provenance.get("retired")
    # A subsequent genuine local deletion must still block automatic overwrite.
    current = get_policy_document(db)
    modified = copy.deepcopy(current.document)
    modified["rules"] = [r for r in modified["rules"] if r["id"] != imported_rule_id]
    db.add(SbomPolicyRevision(version=current.version+1, document=modified, created_by="local-admin")); db.commit()
    conflict = catalog.project_sync_tick(db, at=at + timedelta(minutes=20))
    assert conflict["state"] == "blocked" and "덮어쓰기" in conflict["lastError"]


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
    assert catalog.project_sync_tick(db) is None
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


def test_real_sync_requests_native_jobs_only_when_source_effective_state_changes(db, monkeypatch, tmp_path):
    from test_migration import bundle
    from koda_tracker.models import Job
    raw = bundle()
    monkeypatch.setattr(migration, "get_settings", lambda: Settings(artifact_dir=tmp_path))
    monkeypatch.setattr(catalog, "decrypt_key", lambda value: "sample-key")
    class Exporter:
        def __init__(self, *args, **kwargs): pass
        def export(self, ids): return copy.deepcopy(raw)
        def close(self): pass
    monkeypatch.setattr(migration, "LegacyExporter", Exporter)
    source = sync_source(db)
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert catalog.project_sync_tick(db, at=at)["state"] == "idle"
    first_job = db.scalar(select(Job))
    assert first_job is not None and first_job.kind == "analyze" and first_job.state == JobState.QUEUED
    run = db.get(SbomRun, first_job.run_id)
    assert run.analysis_state == JobState.QUEUED
    # Finish the job, export identical effective evidence with a fresh timestamp.
    first_job.state = JobState.COMPLETED; run.analysis_state = JobState.COMPLETED; run.state = ProcessingState.COMPLETED; db.commit()
    raw["source"]["exportedAt"] = "2026-10-18T00:05:00Z"
    assert catalog.project_sync_tick(db, at=at+timedelta(minutes=5))["state"] == "idle"
    assert db.scalar(select(func.count()).select_from(Job)) == 1
    # Catalog-only changes also need a new native evaluation after synchronization.
    raw["projects"][0]["project"]["tags"] = [{"name": "changed"}]
    raw["source"]["exportedAt"] = "2026-10-18T00:10:00Z"
    assert catalog.project_sync_tick(db, at=at+timedelta(minutes=10))["state"] == "idle"
    assert db.scalar(select(func.count()).select_from(Job)) == 2
    assert run.analysis_state == JobState.QUEUED and run.state == ProcessingState.QUEUED
    event = db.scalar(select(ProjectSyncEvent).order_by(ProjectSyncEvent.started_at.desc()))
    assert event.detail["nativeReanalysisRequested"] == 1 and event.detail["nativeReanalysisEnqueued"] == 1


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


def test_unchanged_explicit_source_resync_restores_mutable_catalog_and_queues_once(db, monkeypatch, tmp_path):
    from test_migration import bundle, uid
    from koda_tracker.models import Job
    raw = bundle()
    monkeypatch.setattr(migration, "get_settings", lambda: Settings(artifact_dir=tmp_path))
    monkeypatch.setattr(catalog, "decrypt_key", lambda value: "sample-key")
    class Exporter:
        def __init__(self, *args, **kwargs): pass
        def export(self, ids): return copy.deepcopy(raw)
        def close(self): pass
    monkeypatch.setattr(migration, "LegacyExporter", Exporter)
    source = sync_source(db)
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assert catalog.project_sync_tick(db, at=at)["state"] == "idle"
    p = db.scalar(select(NativeProject).where(NativeProject.source_project_id == uid("project")))
    first_job = db.scalar(select(Job))
    first_job.state = JobState.COMPLETED; db.commit()
    # Byte-identical source and unchanged local catalog is a no-op.
    assert catalog.project_sync_tick(db, at=at+timedelta(minutes=5))["state"] == "idle"
    assert db.scalar(select(func.count()).select_from(Job)) == 1
    p.tags = ["local-edit"]; p.is_latest = False; p.parent_project_id = "local-parent"; p.revision += 1; db.commit()
    # An explicit poll of that same source restores its authoritative metadata,
    # without mutating the already-applied migration record or creating a run.
    assert catalog.project_sync_tick(db, at=at+timedelta(minutes=10))["state"] == "idle"
    assert p.tags == ["prod"] and p.is_latest and p.parent_project_id is None
    assert db.scalar(select(func.count()).select_from(Job)) == 2
    assert db.scalar(select(func.count()).select_from(SbomRun)) == 1
    assert catalog.project_sync_tick(db, at=at+timedelta(minutes=15))["state"] == "idle"
    assert db.scalar(select(func.count()).select_from(Job)) == 2
