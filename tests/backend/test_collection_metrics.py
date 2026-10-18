from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from koda_tracker.db import Base
from koda_tracker.models import AnalysisRevision, Environment, JobState, ProcessingState, Release, RunComponent, SbomRun, Service, now
from koda_tracker.project_catalog_models import NativeProject, NativeReanalysisPending, ProjectRunLink
from koda_tracker.collection_metrics import collection_metrics, configure_collection
from koda_tracker import project_catalog, project_catalog_api


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        session.add_all([Service(id="s", slug="s", name="S"), Environment(id="e", slug="e", name="E")])
        session.flush()
        yield session
    engine.dispose()


def project(db, identity, parent=None, logic="NONE", tag=None, **kw):
    p = NativeProject(id=identity, source_id="sample", source_project_id=identity, service_id="s", environment_id="e", name=identity, version=kw.pop("version", identity), parent_project_id=parent, tags=kw.pop("tags", []), is_latest=kw.pop("latest", True), active=kw.pop("active", True), **kw)
    configure_collection(p, logic, tag)
    db.add(p); db.flush()
    return p


def analysis(db, p, label=None, sequence=1, suppressed=False, analysis_state=JobState.COMPLETED):
    label = label or p.id
    r = Release(id=label, service_id="s", environment_id="e", version=p.version)
    db.add(r); db.flush()
    run = SbomRun(id=label, release_id=r.id, round_number=1, state=ProcessingState.COMPLETED, analysis_state=analysis_state, dtrack_state=JobState.COMPLETED, original_filename="sample.json", media_type="application/json", spec_version="1.6", sha256="a"*64, size_bytes=2, artifact_path="/sample", normalized_bom={}, created_at=now())
    db.add(run); db.flush()
    db.add(ProjectRunLink(run_id=run.id, project_id=p.id))
    db.add(RunComponent(run_id=run.id, identity_key=label, name="sample", version="1"))
    rev = AnalysisRevision(run_id=run.id, sequence=sequence, state=JobState.COMPLETED, policy_state="completed", findings=[{"id":"CVE-2026-1234", "component":"pkg:npm/sample@1", "version":"1", "severity":"High", "kev":True, "vex":{"suppressed":suppressed}}], policies=[{"action":"fail", "suppressed":False}, {"action":"warn", "suppressed":True}])
    db.add(rev); db.flush()
    return run, rev


def test_direct_nested_latest_tag_descendants_and_parent_own_evidence(db):
    root=project(db,"root",logic="AGGREGATE_DIRECT_CHILDREN")
    child=project(db,"child","root",tags=["prod"])
    nested=project(db,"nested","root",logic="AGGREGATE_LATEST_VERSION_CHILDREN",tags=["prod"])
    a=project(db,"a","nested"); b=project(db,"b","nested",latest=False)
    project(db,"inactive","root",active=False)
    analysis(db,root); analysis(db,child); analysis(db,a,suppressed=True); analysis(db,b)
    result=collection_metrics(db,root)
    assert {p["projectId"] for p in result["projects"]}=={"child","a"}
    assert result["totals"]["componentCount"]==2
    assert result["totals"]["vulnerabilityCount"]==1
    assert result["totals"]["rawVulnerabilityCount"]==2
    assert result["totals"]["suppressedVulnerabilityCount"]==1
    assert result["totals"]["uniqueVulnerabilityCount"]==1
    assert result["totals"]["policyFailCount"]==2
    assert result["totals"]["policySuppressedCount"]==2
    configure_collection(root,"AGGREGATE_DIRECT_CHILDREN_WITH_TAG","prod")
    assert collection_metrics(db,root)["coverage"]["selectedProjectCount"]==2
    configure_collection(root,"AGGREGATE_ALL_DESCENDANTS",None)
    assert collection_metrics(db,root)["coverage"]["selectedProjectCount"]==3
    configure_collection(root,"AGGREGATE_DIRECT_CHILDREN_WITH_TAG","absent")
    empty=collection_metrics(db,root)
    assert empty["coverage"]["complete"] and empty["totals"]["vulnerabilityCount"]==0


def test_missing_failed_pending_and_archived_coverage_does_not_report_complete(db):
    root=project(db,"root",logic="AGGREGATE_DIRECT_CHILDREN")
    a=project(db,"a","root"); b=project(db,"b","root"); project(db,"missing","root")
    run,rev=analysis(db,a)
    failed=AnalysisRevision(run_id=run.id,sequence=2,state=JobState.FAILED,error="test")
    db.add(failed); run.analysis_state=JobState.FAILED
    rb,_=analysis(db,b); rb.archived_at=now()
    db.flush()
    result=collection_metrics(db,root)
    assert result["coverage"]=={"selectedProjectCount":3,"analyzedProjectCount":1,"missingProjectCount":2,"staleProjectCount":1,"policyIncompleteProjectCount":0,"ambiguousProjectCount":0,"complete":False}
    assert result["projects"][0]["analysisId"]==rev.id
    db.delete(failed); run.analysis_state=JobState.COMPLETED
    db.add(NativeReanalysisPending(source_id="private",run_id=run.id)); db.flush()
    assert collection_metrics(db,root)["coverage"]["staleProjectCount"]==1
    rev.metrics={"policyDataComplete":False}
    assert collection_metrics(db,root)["coverage"]["policyIncompleteProjectCount"]==1


def test_newest_unarchived_round_and_latest_completed_revision_selected(db):
    root=project(db,"root",logic="AGGREGATE_DIRECT_CHILDREN")
    a=project(db,"a","root"); run,old=analysis(db,a)
    new=SbomRun(id="new",release_id=run.release_id,round_number=2,state=ProcessingState.COMPLETED,analysis_state=JobState.COMPLETED,dtrack_state=JobState.COMPLETED,original_filename="new.json",media_type="application/json",spec_version="1.6",sha256="b"*64,size_bytes=2,artifact_path="/new",normalized_bom={},created_at=run.created_at+timedelta(seconds=1))
    db.add(new); db.flush()
    revision=AnalysisRevision(run_id=new.id,sequence=1,state=JobState.COMPLETED,policy_state="completed",findings=[],policies=[])
    db.add(revision);db.flush()
    out=collection_metrics(db,root)
    assert out["projects"][0]["runId"]=="new" and out["projects"][0]["analysisId"]==revision.id
    assert out["totals"]["vulnerabilityCount"]==0
    new.archived_at=now();db.flush()
    assert collection_metrics(db,root)["projects"][0]["runId"]==run.id


def test_import_collection_config_and_native_revision_validation(db):
    root=project(db,"root")
    run,_=analysis(db,root)
    bundle={"source":{"id":"sample"},"projects":[{"project":{"uuid":"root","name":"root","version":"root","collectionLogic":"AGGREGATE_DIRECT_CHILDREN_WITH_TAG","collectionTag":{"name":"prod"}}}]}
    plan={"root":{"runId":run.id,"serviceId":"s","environmentId":"e"}}
    project_catalog.upsert_source_projects(db,bundle,plan)
    assert project_catalog.project_payload(root)["collectionTag"]=="prod"
    version=root.revision
    project_catalog.upsert_source_projects(db,bundle,plan)
    assert root.revision==version
    user=SimpleNamespace(username="admin")
    with pytest.raises(Exception) as exc:
        project_catalog_api.update_project(root.id,project_catalog_api.ProjectUpdate(expectedRevision=version,collectionTag=" "),db,user)
    assert exc.value.status_code==422


def test_deep_hierarchy_is_iterative_and_cycle_rejected(db):
    root=project(db,"root",logic="AGGREGATE_ALL_DESCENDANTS")
    parent="root"
    for i in range(1000):
        node=NativeProject(id=f"node{i}",source_id="sample",source_project_id=f"node{i}",service_id="s",environment_id="e",name=f"node{i}",version=f"node{i}",parent_project_id=parent,tags=[],active=True,is_latest=True)
        db.add(node);parent=node.id
    db.flush()
    with pytest.raises(ValueError,match="깊이"):
        collection_metrics(db,root)
    root.parent_project_id="node999";db.flush()
    with pytest.raises(ValueError):
        collection_metrics(db,root)


def test_cross_source_unlinked_coordinate_is_ambiguous_not_owned_by_each_collection(db):
    root_a = project(db, "root-a", logic="AGGREGATE_DIRECT_CHILDREN")
    child_a = project(db, "child-a", "root-a")
    root_b = project(db, "root-b", logic="AGGREGATE_DIRECT_CHILDREN")
    child_b = project(db, "child-b", "root-b", version=child_a.version)
    root_b.source_id = child_b.source_id = "other-source"
    run, _ = analysis(db, child_a)
    db.delete(db.get(ProjectRunLink, run.id)); db.flush()
    assert project_catalog.project_for_run(db, run.id) is None
    for root in (root_a, root_b):
        result = collection_metrics(db, root)
        assert result["projects"][0]["runId"] is None
        assert result["projects"][0]["state"] == "ambiguous"
        assert result["coverage"]["ambiguousProjectCount"] == 1
        assert result["coverage"]["missingProjectCount"] == 1
        assert result["coverage"]["complete"] is False
        assert result["totals"]["vulnerabilityCount"] == 0


@pytest.mark.parametrize("explicit_other_source", [False, True])
def test_explicit_link_wins_over_cross_source_coordinate_and_never_leaks(db, explicit_other_source):
    root = project(db, "root", logic="AGGREGATE_DIRECT_CHILDREN")
    child = project(db, "child", "root")
    foreign = project(db, "foreign", version=child.version)
    foreign.source_id = "other-source"
    run, revision = analysis(db, child)
    if explicit_other_source:
        db.get(ProjectRunLink, run.id).project_id = foreign.id
    db.flush()
    result = collection_metrics(db, root)
    if explicit_other_source:
        assert result["projects"][0]["runId"] is None
        assert result["coverage"]["complete"] is False
        assert result["totals"]["componentCount"] == 0
    else:
        assert result["projects"][0]["runId"] == run.id
        assert result["projects"][0]["analysisId"] == revision.id
        assert result["coverage"]["complete"] is True
        assert result["totals"]["componentCount"] == 1
    assert result["coverage"]["ambiguousProjectCount"] == 0


def test_globally_unique_unlinked_coordinate_inherits_but_archived_runs_do_not(db):
    root = project(db, "root", logic="AGGREGATE_DIRECT_CHILDREN")
    child = project(db, "child", "root")
    foreign = project(db, "foreign", version="different-version")
    foreign.source_id = "other-source"
    run, _ = analysis(db, child)
    db.delete(db.get(ProjectRunLink, run.id)); db.flush()
    assert project_catalog.project_for_run(db, run.id).id == child.id
    result = collection_metrics(db, root)
    assert result["projects"][0]["runId"] == run.id and result["coverage"]["complete"]
    run.archived_at = now(); foreign.version = child.version; db.flush()
    result = collection_metrics(db, root)
    assert result["projects"][0]["runId"] is None
    assert result["projects"][0]["state"] == "missing"
    assert result["coverage"]["ambiguousProjectCount"] == 0
