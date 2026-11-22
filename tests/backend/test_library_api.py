from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker.db import Base, get_db
from koda_tracker.library_api import library_key, package_coordinate, router
from koda_tracker.models import AnalysisRevision, ApiToken, Environment, JobState, ProcessingState, Release, Role, RolePolicy, RunComponent, SbomRun, Service, User
from koda_tracker.environment_admin_models import EnvironmentAdministrator
from koda_tracker.security import current_principal
from koda_tracker.project_catalog_models import NativeReanalysisPending


@pytest.fixture
def context():
    engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine,expire_on_commit=False) as db:
        db.add_all([Service(id="service",slug="service",name="결제 API"),Environment(id="prod",slug="prod",name="운영"),Environment(id="qa",slug="qa",name="검증"),Release(id="release",service_id="service",environment_id="prod",version="2026.10.1"),RolePolicy(role=Role.VIEWER,permissions=["runs.view"])])
        viewer = User(id="viewer", username="viewer", role=Role.VIEWER, password_hash="unused", active=True)
        db.add(viewer)
        db.flush()
        db.add_all([EnvironmentAdministrator(environment_id=env, user_id=viewer.id, assigned_by="admin") for env in ("prod", "qa")])
        db.commit()
        app=FastAPI();app.include_router(router)
        auth={"principal":viewer}
        app.dependency_overrides[get_db]=lambda:db
        app.dependency_overrides[current_principal]=lambda:auth["principal"]
        with TestClient(app) as client:
            yield SimpleNamespace(db=db,client=client,auth=auth,engine=engine)
    engine.dispose()


def add_run(context, number, versions=("1.4.0",), *, state=ProcessingState.COMPLETED, complete=False, archived=False, release="release", name="sample-json", purl=None):
    run=SbomRun(id=f"run-{number}",release_id=release,round_number=number,state=state,analysis_state=JobState.COMPLETED,
        original_filename="original.json",media_type="application/json",spec_version="1.6",sha256="a"*64,size_bytes=2,artifact_path="/test/original.json",
        normalized_bom={"compositions":[{"aggregate":"complete"}]} if complete else {},
        created_at=datetime(2026,10,1,tzinfo=UTC)+timedelta(days=number),archived_at=datetime(2026,10,29,tzinfo=UTC) if archived else None)
    context.db.add(run);context.db.flush()
    for index,version in enumerate(versions):
        component_purl=purl or f"pkg:npm/{name}@{version}"
        context.db.add(RunComponent(run_id=run.id,identity_key=f"purl:pkg:npm/{name}|bom-ref:{index}",name=name,version=version,purl=component_purl,bom_ref=str(index)))
    context.db.commit()
    return run


def detail(context,coordinate="pkg:npm/sample-json",**params):
    response=context.client.get("/api/v1/libraries/detail",params={"key":library_key(coordinate),**params})
    assert response.status_code==200,response.text
    return response.json()


def test_coordinate_keeps_distribution_architecture_subpath_and_scoped_namespace():
    a=package_coordinate("pkg:deb/debian/openssl@3.0?distro=debian-12&arch=amd64#lib")
    assert a==package_coordinate("pkg:deb/debian/openssl@3.1?arch=amd64&distro=debian-12#lib")
    assert a!=package_coordinate("pkg:deb/debian/openssl@3.0?arch=arm64&distro=debian-12#lib")
    assert a!=package_coordinate("pkg:deb/debian/openssl@3.0?arch=amd64&distro=debian-12#other")
    assert package_coordinate("pkg:npm/%40angular/core@17.0.0")=="pkg:npm/@angular/core"
    assert package_coordinate("pkg:npm/example@1")!=package_coordinate("pkg:pypi/example@1")


def test_group_duplicates_across_runs_and_keep_current_snapshot_separate(context):
    add_run(context,1,("1.4.0","1.3.0"))
    add_run(context,2,("1.4.2",))
    add_run(context,3,("9.0",),state=ProcessingState.PARTIAL)
    add_run(context,4,("99",),state=ProcessingState.ARCHIVED,archived=True)
    result=context.client.get("/api/v1/libraries").json()
    assert result["total"]==1
    item=result["items"][0]
    assert item["versions"]==["1.3.0","1.4.0","1.4.2","9.0","99"]
    assert item["currentVersions"]==["1.4.2"]
    assert item["currentServiceCount"]==1
    body=detail(context)
    assert [item["runId"] for item in body["observations"]]==["run-2"]
    assert body["observationsTotal"]==5
    assert body["observations"][0]["releaseVersion"]=="2026.10.1"
    assert body["observations"][0]["libraryVersion"]=="1.4.2"


def test_no_current_inventory_for_only_archived_observations(context):
    add_run(context,1,archived=True,state=ProcessingState.ARCHIVED)
    body=context.client.get("/api/v1/libraries").json()["items"][0]
    assert body["currentVersions"]==[] and body["currentServiceCount"]==0
    body=detail(context)
    assert body["observations"]==[]
    assert body["history"]["total"]==1


def test_unknown_or_partial_absence_never_becomes_removed(context):
    add_run(context,1)
    add_run(context,2,(),complete=False)
    add_run(context,3,(),complete=True,state=ProcessingState.PARTIAL)
    add_run(context,4,("1.4.2",))
    history=detail(context)["history"]["items"]
    assert [event["kind"] for event in history]==["version_changed","first_seen"]
    assert history[0]["previousVersions"]==["1.4.0"]


def test_complete_absence_and_return_preserve_evidence_and_history_paginates(context):
    add_run(context,1)
    add_run(context,2,(),complete=True)
    add_run(context,3,("1.4.2",))
    response=detail(context,size=2)
    assert response["history"]["total"]==3
    assert [item["kind"] for item in response["history"]["items"]]==["reappeared","removed"]
    assert response["history"]["items"][1]["runId"]=="run-2"
    assert detail(context,page=2,size=2)["history"]["items"][0]["kind"]=="first_seen"


def test_scoped_complete_composition_does_not_prove_service_removal(context):
    add_run(context,1)
    item=add_run(context,2,(),complete=True)
    item.normalized_bom={"compositions":[{"aggregate":"complete","assemblies":["one-submodule"]}]}
    context.db.commit()
    assert [item["kind"] for item in detail(context)["history"]["items"]]==["first_seen"]


def test_filters_pagination_and_literal_search(context):
    add_run(context,1,name="sample-json")
    add_run(context,2,name="sample-http")
    context.db.add(Release(id="qa-release",service_id="service",environment_id="qa",version="test"));context.db.commit()
    add_run(context,3,name="other",release="qa-release")
    response=context.client.get("/api/v1/libraries",params={"environmentId":"prod","ecosystem":"npm","version":"1.4.0","page":2,"size":1})
    assert response.status_code==200
    assert response.json()["total"]==2 and len(response.json()["items"])==1
    assert context.client.get("/api/v1/libraries",params={"q":"%"}).json()["total"]==0
    assert context.client.get("/api/v1/libraries",params={"q":"sample-http"}).json()["total"]==1
    assert context.client.get("/api/v1/libraries",params={"size":101}).status_code==422


def test_related_cves_use_latest_revision_and_exact_purl_without_write(context):
    run=add_run(context,1)
    context.db.add_all([AnalysisRevision(run_id=run.id,sequence=1,state=JobState.COMPLETED,findings=[{"id":"CVE-OLD","component":"pkg:npm/sample-json@1.4.0"}]),
        AnalysisRevision(run_id=run.id,sequence=2,state=JobState.COMPLETED,findings=[{"id":"CVE-2026-12345","component":"pkg:npm/sample-json@1.4.0","severity":"High"},{"id":"CVE-WRONG","component":"pkg:pypi/sample-json@1.4.0"}])])
    context.db.commit()
    statements=[]
    def capture(_c,_cu,statement,_p,_e,_m):statements.append(statement.lstrip().split()[0].upper())
    event.listen(context.engine,"before_cursor_execute",capture)
    try:
        body=detail(context)
        context.client.get("/api/v1/libraries")
    finally:event.remove(context.engine,"before_cursor_execute",capture)
    assert [value["id"] for value in body["vulnerabilities"]]==["CVE-2026-12345"]
    assert body["vulnerabilities"][0]["matchBasis"]=="purl"
    assert not {"INSERT","UPDATE","DELETE"}.intersection(statements)


def test_permissions_invalid_keys_and_missing_library(context):
    assert context.client.get("/api/v1/libraries/detail",params={"key":"not-base64!"}).status_code==422
    for coordinate in ("coordinate:bad", 'coordinate:["only"]', 'coordinate:[1,2,3]', 'coordinate:{"name":"bad"}'):
        assert context.client.get("/api/v1/libraries/detail",params={"key":library_key(coordinate)}).status_code==422
    assert context.client.get("/api/v1/libraries/detail",params={"key":library_key("pkg:npm/none")}).status_code==404
    context.db.get(RolePolicy,Role.VIEWER).permissions=[];context.db.commit()
    assert context.client.get("/api/v1/libraries").status_code==403
    context.auth["principal"]=ApiToken(id="token",name="token",service_id="service",token_hash="x",active=True)
    assert context.client.get("/api/v1/libraries").status_code==403


def test_detail_preserves_pypi_normalization_and_subpath_boundaries(context):
    add_run(context,1,name="Foo_Bar",purl="pkg:pypi/Foo_Bar@1.4.0#one")
    add_run(context,2,name="Foo_Bar",purl="pkg:pypi/foo.bar@1.4.2#two")
    body=context.client.get("/api/v1/libraries").json()
    assert body["total"]==2
    assert detail(context,"pkg:pypi/foo-bar#one")["observationsTotal"]==1
    assert detail(context,"pkg:pypi/foo-bar#two")["observationsTotal"]==1


def test_encoded_purl_leaf_with_friendly_display_name_remains_openable(context):
    add_run(context,1,name="Friendly display name",purl="pkg:generic/hello%2Bworld@1.0")
    listed=context.client.get("/api/v1/libraries").json()
    assert listed["total"]==1
    response=context.client.get("/api/v1/libraries/detail",params={"key":listed["items"][0]["key"]})
    assert response.status_code==200,response.text
    assert response.json()["coordinate"]=="pkg:generic/hello%2Bworld"
    assert response.json()["observations"][0]["name"]=="Friendly display name"


def test_findings_without_purl_include_actual_observed_name_as_review_evidence(context):
    run=add_run(context,1,name="Friendly Display Name")
    component=context.db.scalar(select(RunComponent).where(RunComponent.run_id==run.id))
    component.purl=""
    context.db.add(AnalysisRevision(run_id=run.id,sequence=1,state=JobState.COMPLETED,findings=[{"id":"CVE-2026-12345","component":"Friendly Display Name"}]))
    context.db.commit()
    coordinate=package_coordinate("",name="Friendly Display Name")
    finding=detail(context,coordinate)["vulnerabilities"][0]
    assert finding["id"]=="CVE-2026-12345"
    assert finding["matchBasis"]=="name_review_required"


@pytest.mark.parametrize("run_limit",[2,10])
def test_related_evidence_bounds_recent_runs_and_records_without_cutting_history(context,monkeypatch,run_limit):
    from koda_tracker import library_api
    monkeypatch.setattr(library_api,"RELATED_RUN_LIMIT",run_limit)
    monkeypatch.setattr(library_api,"RELATED_RECORD_LIMIT",2)
    for number in range(1,5):
        run=add_run(context,number)
        context.db.add(AnalysisRevision(run_id=run.id,sequence=1,state=JobState.COMPLETED,findings=[{"id":f"CVE-2026-{number}{index:04d}","component":"pkg:npm/sample-json@1.4.0"} for index in range(3)]))
    context.db.commit()
    body=detail(context)
    assert body["vulnerabilitiesTruncated"] is True
    assert body["vulnerabilityCoverage"]=={"runLimit":run_limit,"recordLimit":2,"matchingRuns":4,"runsInScope":min(4,run_limit)}
    assert len(body["vulnerabilities"])==2
    assert {item["runId"] for item in body["vulnerabilities"]}=={"run-4"}
    assert body["history"]["total"]==4
    assert body["observationsTotal"]==4


@pytest.mark.parametrize("pending",[False,True])
def test_preserve_old_findings_without_claiming_current_evaluation_after_scope_move(context,pending):
    run=add_run(context,1)
    run.analysis_state=JobState.QUEUED if not pending else JobState.COMPLETED
    context.db.add(AnalysisRevision(run_id=run.id,sequence=1,state=JobState.COMPLETED,findings=[{"id":"CVE-2026-12345","component":"pkg:npm/sample-json@1.4.0"}]))
    if pending:
        context.db.add(NativeReanalysisPending(source_id="native",run_id=run.id))
    else:
        context.db.add(AnalysisRevision(run_id=run.id,sequence=2,state=JobState.QUEUED))
    context.db.commit()
    finding=detail(context)["vulnerabilities"][0]
    assert finding["current"] is False and finding["analysisCurrent"] is False
    assert finding["evaluationState"]=="reanalysis_required"
    assert finding["id"]=="CVE-2026-12345"
