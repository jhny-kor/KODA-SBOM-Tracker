from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from koda_tracker.db import Base
from koda_tracker.models import ApiToken, Environment, Release, Role, RolePolicy, SbomRun, Service, now
from koda_tracker.project_catalog_models import NativeProject, ProjectRunLink, NativeReanalysisPending
from koda_tracker.quality import DEFAULT_PROFILE, QualityIssue, QualityProfile, diagnose, effective_profile, evaluate_quality, latest_quality
from koda_tracker.quality_api import ProfileInput, checked_run, export_quality, list_issues, read_profile, rerun_quality, write_profile


def good_bom():
    return {'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:sample',
            'metadata':{'timestamp':now().isoformat(),'tools':[{'name':'generator'}],'authors':[{'name':'Author'}],
                        'component':{'bom-ref':'root','name':'app','supplier':{'name':'Vendor'}}},
            'components':[{'name':'a','version':'1','bom-ref':'a','purl':'pkg:npm/a@1','licenses':[{'license':{'id':'MIT'}}],
                           'hashes':[{'alg':'SHA-256','content':'a'*64}]}],
            'dependencies':[{'ref':'root','dependsOn':['a']},{'ref':'a','dependsOn':[]}]}


@pytest.fixture
def db():
    engine=create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine,expire_on_commit=False) as db:
        db.add_all([Service(id='s',slug='s',name='S'),Environment(id='e',slug='e',name='E'),RolePolicy(role=Role.ADMIN,permissions=[])])
        db.flush()
        release=Release(id='r',service_id='s',environment_id='e',version='1');db.add(release);db.flush()
        run=SbomRun(id='run',release_id='r',round_number=1,original_filename='bom.json',media_type='application/json',spec_version='1.6',sha256='a'*64,size_bytes=2,artifact_path='/missing',normalized_bom=good_bom())
        db.add(run);db.flush()
        yield db
    engine.dispose()


def test_good_bom_no_issues_and_empty_denominator_is_not_success():
    issues,summary=diagnose(good_bom(),DEFAULT_PROFILE,now())
    assert issues==[] and summary['qualityStatus']=='pass'
    issues,summary=diagnose({'components':[]},{**DEFAULT_PROFILE,'mode':'enforce'},now())
    assert summary['qualityStatus']=='fail' and summary['missingIdentityRatio'] is None
    assert summary['fieldStatus']['graph']=='missing'


def test_nested_invalid_fields_original_paths_and_ratios():
    bom=good_bom(); child={'name':'bad','version':'2','bom-ref':'a','purl':'nonsense','cpe':'cpe:bad','swid':{'patch':'maybe'},'licenses':[{'expression':'MIT OR'}],'hashes':[{'alg':'SHA-256','content':'no'}]}
    bom['components'][0]['components']=[child];bom['dependencies'][0]['dependsOn'].append('missing')
    issues,summary=diagnose(bom,{**DEFAULT_PROFILE,'mode':'enforce'},now())
    rules={i['ruleId'] for i in issues}
    assert {'identity.purl_invalid','identity.cpe_invalid','identity.swid_invalid','graph.duplicate_ref','graph.unresolved_ref','license.expression_invalid','integrity.hash_invalid'} <= rules
    assert summary['componentCount']==2 and summary['missingIdentityRatio']==0.5 and summary['qualityStatus']=='fail'
    assert any(i['path']=='$.components[0].components[0].purl' for i in issues)


def test_distinct_package_versions_are_not_duplicates_and_cycles_warn():
    bom=good_bom(); other=deepcopy(bom['components'][0]);other.update({'version':'2','purl':'pkg:npm/a@2','bom-ref':'b'});bom['components'].append(other)
    bom['dependencies']=[{'ref':'a','dependsOn':['b']},{'ref':'b','dependsOn':['a']}]
    issues,summary=diagnose(bom,DEFAULT_PROFILE,now())
    assert 'identity.duplicate' not in {i['ruleId'] for i in issues}
    assert 'graph.cycle' in {i['ruleId'] for i in issues}


def test_timestamp_and_empty_provenance_not_claimed_present():
    bom=good_bom();bom['metadata'].update(timestamp=(now()-timedelta(days=400)).isoformat(),tools={},authors=[{}])
    issues,_=diagnose(bom,DEFAULT_PROFILE,now())
    assert {'provenance.stale','provenance.tools_missing','provenance.authors_missing'} <= {i['ruleId'] for i in issues}


def test_revisions_immutable_cached_history_diff_and_filtered_export(db):
    run=db.get(SbomRun,'run');first=evaluate_quality(db,run);document=deepcopy(first.summary)
    assert evaluate_quality(db,run).id==first.id
    run.normalized_bom={'components':[{'name':'=FORMULA','version':'1'}]}
    second=evaluate_quality(db,run,force=True)
    assert first.summary==document and second.sequence==2 and second.comparison['warningDelta']>0
    result=list_issues(run.id,revisionId=second.id,ruleId='identity.missing',severity=None,page=1,size=1,db=db,principal=SimpleNamespace())
    assert result['total']==1 and len(result['items'])==1
    assert export_quality(run.id,revisionId=second.id,format='csv',db=db,principal=SimpleNamespace()).body.find(b"'=FORMULA")>=0
    assert latest_quality(db,run.id)['id']==second.id


def test_malformed_or_missing_xml_records_failed_not_zero(db):
    run=db.get(SbomRun,'run');run.media_type='application/xml'
    result=evaluate_quality(db,run)
    assert result.state=='failed' and result.summary['errorCount'] is None and result.error


def project(db,identity,source='native'):
    p=NativeProject(id=identity,source_id=source,source_project_id=identity,service_id='s',environment_id='e',version='1',name=identity)
    db.add(p);db.flush();return p


def test_project_profiles_versioning_ownership_and_reanalysis(db):
    project(db,'p');run=db.get(SbomRun,'run');actor=SimpleNamespace(username='admin')
    profile=write_profile(ProfileInput(expectedVersion=0,name='strict',mode='enforce'),projectId='p',db=db,principal=actor)
    assert profile['version']==1 and profile['reanalysisRequested']==1
    assert effective_profile(db,run)['projectId']=='p'
    assert db.scalar(select(NativeReanalysisPending.run_id))==run.id
    with pytest.raises(HTTPException) as exc:
        write_profile(ProfileInput(expectedVersion=0,name='stale'),projectId='p',db=db,principal=actor)
    assert exc.value.status_code==409
    project(db,'other','source2')
    failed=evaluate_quality(db,run,force=True)
    assert failed.state=='failed' and '모호' in failed.error
    db.add(ProjectRunLink(run_id=run.id,project_id='p'));db.flush()
    assert evaluate_quality(db,run,force=True).state=='completed'


def test_previous_round_comparison_and_scoped_tokens(db):
    run=db.get(SbomRun,'run');first=evaluate_quality(db,run)
    second=SbomRun(id='run2',release_id='r',round_number=2,original_filename='bom.json',media_type='application/json',spec_version='1.6',sha256='b'*64,size_bytes=2,artifact_path='/missing',normalized_bom=good_bom())
    db.add(second);db.flush();latest=evaluate_quality(db,second)
    assert latest.comparison['previousRunId']=='run' and latest.comparison['previousRevisionId']==first.id
    for token in [ApiToken(id='x',service_id='other'),ApiToken(id='x',service_id=None)]:
        with pytest.raises(HTTPException) as exc:checked_run(db,'run',token)
        assert exc.value.status_code==403
    assert checked_run(db,'run',ApiToken(id='x',service_id='s')).id=='run'
    run.idempotency_actor='token:x'
    assert checked_run(db,'run',ApiToken(id='x',service_id=None)).id=='run'


def test_archived_rerun_rejected_and_revision_cross_run_hidden(db):
    run=db.get(SbomRun,'run');evaluate_quality(db,run);run.archived_at=now();db.commit()
    with pytest.raises(HTTPException) as exc:rerun_quality(run.id,db=db,principal=SimpleNamespace(username='admin'))
    assert exc.value.status_code==409
    from koda_tracker.quality_api import checked_revision
    with pytest.raises(HTTPException) as exc:checked_revision(db,'different',latest_quality(db,run.id)['id'])
    assert exc.value.status_code==404


def test_invalid_identifier_does_not_hide_missing_and_hex_case_not_conflict():
    bom=good_bom();c=bom['components'][0];c['purl']='pkg:npm/a@';c['hashes']=[{'alg':'SHA-256','content':'A'*64},{'alg':'SHA-256','content':'a'*64}]
    issues,summary=diagnose(bom,DEFAULT_PROFILE,now());rules={i['ruleId'] for i in issues}
    assert summary['missingIdentityRatio']==1 and 'identity.purl_invalid' in rules
    assert 'integrity.hash_duplicate' in rules and 'integrity.hash_conflict' not in rules
    c['cpe']='cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*'
    assert diagnose(bom,DEFAULT_PROFILE,now())[1]['missingIdentityRatio']==0
    c['cpe']='cpe:2.3:x:vendor:product:1:*:*:*:*:*:*:*'
    assert diagnose(bom,DEFAULT_PROFILE,now())[1]['missingIdentityRatio']==1


def test_original_json_hash_is_checked_and_reported(db,tmp_path):
    import hashlib,json
    run=db.get(SbomRun,'run');artifact=tmp_path/'bom.json';raw=json.dumps(good_bom()).encode();artifact.write_bytes(raw)
    run.artifact_path=str(artifact);run.sha256=hashlib.sha256(raw).hexdigest()
    row=evaluate_quality(db,run)
    assert row.summary['sourceBasis']=='verified_original_artifact'
    artifact.write_text('{}')
    row=evaluate_quality(db,run,force=True)
    assert row.state=='failed' and 'SHA-256' in row.error and row.summary['qualityStatus']=='failed'


def test_empty_identity_enforced_but_unrelated_project_not_applied(db):
    p=project(db,'p');p.version='another'
    row=QualityProfile(scope_key='p',version=1,document={**DEFAULT_PROFILE,'name':'strict','mode':'enforce'},created_by='admin')
    db.add(row);db.flush();run=db.get(SbomRun,'run')
    assert effective_profile(db,run)['projectId'] is None
    # A default warning profile keeps previous upload behavior while reporting issues.
    run.normalized_bom={'components':[{'name':'x','version':'1'}]}
    result=evaluate_quality(db,run)
    assert result.summary['criteriaViolated'] and result.summary['qualityStatus']=='warn'
    assert read_profile(projectId='p',db=db)['version']==1
    with pytest.raises(HTTPException) as exc:read_profile(projectId='missing',db=db)
    assert exc.value.status_code==404
