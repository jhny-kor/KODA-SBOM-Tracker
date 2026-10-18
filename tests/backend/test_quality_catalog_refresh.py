from copy import deepcopy
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from koda_tracker.db import Base
from koda_tracker.models import Environment, JobState, ProcessingState, Release, SbomRun, Service, now
from koda_tracker.project_catalog_api import ProjectCreate, ProjectUpdate, RunLinkRequest, attach_run, create_project, update_project
from koda_tracker.project_catalog_models import NativeProject, NativeReanalysisPending
from koda_tracker.quality import DEFAULT_PROFILE, QualityProfile, current_profile, effective_profile, evaluate_quality, profile_scope_key


@pytest.fixture
def sample():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine,autoflush=False,expire_on_commit=False) as db:
        db.add_all([Service(id='s',slug='s',name='S'),Environment(id='e',slug='e',name='E')]);db.flush()
        db.add(Release(id='r',service_id='s',environment_id='e',version='child'));db.flush()
        for id,parent in [('parent',None),('child','parent')]:
            db.add(NativeProject(id=id,source_id='source',source_project_id=id,service_id='s',environment_id='e',version=id,name=id,parent_project_id=parent,tags=[]))
        bom={'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:sample','metadata':{'timestamp':now().isoformat(),'tools':[{'name':'generator'}],'authors':[{'name':'Author'}],'component':{'name':'root','bom-ref':'root','supplier':{'name':'Sample'}}},'components':[{'type':'library','name':'a','version':'1','purl':'pkg:generic/a@1','bom-ref':'a','licenses':[{'license':{'id':'MIT'}}]}],'dependencies':[{'ref':'root','dependsOn':['a']},{'ref':'a','dependsOn':[]}]}
        run=SbomRun(id='run',release_id='r',round_number=1,state=ProcessingState.COMPLETED,analysis_state=JobState.COMPLETED,original_filename='bom.json',media_type='application/json',spec_version='1.6',sha256='a'*64,size_bytes=2,artifact_path='/missing',normalized_bom=bom)
        db.add(run);db.flush()
        yield db,run,SimpleNamespace(username='admin')
    engine.dispose()


def put(db,key,**values):
    db.add(QualityProfile(scope_key=key,version=1,document={**deepcopy(DEFAULT_PROFILE),**values},created_by='test'));db.flush()


def test_tag_catalog_edit_reanalyzes_descendants_without_rewriting_previous_evidence(sample):
    db,run,actor=sample
    put(db,'parent',mode='enforce',minScore=95)
    key=profile_scope_key(source_id='source',tag='relaxed')
    put(db,key,mode='enforce',minScore=85,scopeSourceId='source',scopeTag='relaxed')
    before=evaluate_quality(db,run);snapshot=deepcopy(before.profile_snapshot);oldsummary=deepcopy(before.summary)
    assert before.summary['score']==90 and before.summary['qualityStatus']=='fail'
    p=db.get(NativeProject,'child')
    update_project(p.id,ProjectUpdate(expectedRevision=p.revision,tags=['relaxed']),db=db,principal=actor)
    assert db.scalar(select(NativeReanalysisPending.run_id))==run.id
    assert before.profile_snapshot==snapshot and before.summary==oldsummary
    fresh=evaluate_quality(db,run,force=True)
    assert fresh.profile_snapshot['resolution']['kind']=='tag' and fresh.summary['qualityStatus']=='warn'
    assert fresh.summary['minScore']==85


def test_creating_cross_source_candidate_invalidates_inherited_owner_then_explicit_link_recovers(sample):
    db,run,actor=sample
    put(db,'parent',mode='enforce',minScore=95)
    evaluate_quality(db,run)
    create_project(ProjectCreate(sourceId='other',sourceProjectId='other-child',serviceId='s',environmentId='e',name='Other',version='child'),db=db,principal=actor)
    assert db.scalar(select(NativeReanalysisPending.run_id))==run.id
    with pytest.raises(ValueError,match='모호'):
        effective_profile(db,run)
    child=db.get(NativeProject,'child')
    attach_run(child.id,RunLinkRequest(expectedRevision=child.revision,runId=run.id),db=db,principal=actor)
    assert effective_profile(db,run)['resolution']['kind']=='parent'
    assert effective_profile(db,run)['resolution']['projectId']=='child'


def test_unrelated_catalog_name_edit_does_not_enqueue_but_parent_replacement_does(sample):
    db,run,actor=sample
    put(db,'parent',mode='enforce',minScore=95)
    evaluate_quality(db,run)
    parent=db.get(NativeProject,'parent')
    update_project(parent.id,ProjectUpdate(expectedRevision=parent.revision,name='Renamed'),db=db,principal=actor)
    assert db.scalar(select(NativeReanalysisPending.run_id)) is None
    child=db.get(NativeProject,'child')
    update_project(child.id,ProjectUpdate(expectedRevision=child.revision,parentProjectId=None),db=db,principal=actor)
    assert db.scalar(select(NativeReanalysisPending.run_id))==run.id
    assert effective_profile(db,run)['resolution']['kind']=='global'


def test_min_score_and_core_errors_remain_independent_of_weight_and_error_allowances(sample):
    from koda_tracker.quality import diagnose
    db,run,_=sample
    config={**DEFAULT_PROFILE,'mode':'enforce','maxErrors':100,'maxUnresolvedRefs':100,'minScore':100,'scoreWeights':{'identity':100,'graph':0,'license':0,'provenance':0,'integrity':0}}
    bom=deepcopy(run.normalized_bom);bom['dependencies'][0]['dependsOn'].append('missing')
    _,summary=diagnose(bom,config,now())
    assert summary['score']==100 and summary['blockingIssueCount']==1 and not summary['scoreThresholdViolated']
    assert summary['qualityStatus']=='fail'
    config['minScore']=95;config['scoreWeights']=dict(DEFAULT_PROFILE['scoreWeights'])
    _,summary=diagnose(run.normalized_bom,config,now())
    assert summary['score']==90 and summary['scoreThresholdViolated'] and summary['qualityStatus']=='fail'


def test_cel_score_context_does_not_repeat_full_ancestor_evidence():
    import json
    from koda_tracker.policies import PolicyDocument, build_cel_contexts, evaluate_document
    quality={'state':'completed','score':90.0,'errorCount':0,'profileSnapshot':{'mode':'enforce','minScore':95.0,'resolution':{'chain':[{'projectId':str(i),'tags':['x'*200]*10} for i in range(256)]}},'scoreDetails':{'domains':{'integrity':{'score':0.0,'checks':[{'id':'components','numerator':0,'denominator':1}]}}}}
    before=deepcopy(quality)
    components=[{'name':'sample-'+str(i),'version':'1'} for i in range(80)]
    contexts=build_cel_contexts(components,[],{'sbomQuality':quality},targets={'component'})
    assert len(json.dumps(contexts).encode()) < 1024*1024
    value=contexts['component'][0]['sbomQuality']
    assert value['score']==90 and value['domainScores']['integrity']==0
    assert value['profileSnapshot']['minScore']==95 and 'resolution' not in value['profileSnapshot']
    assert quality==before
    rules=PolicyDocument(rules=[{'id':'score','name':'Score','kind':'cel','target':'project','expression':'sbomQuality.score < 95.0 && sbomQuality.domainScores.integrity < 100.0'}])
    rows,metrics=evaluate_document(rules,components,[],project_context={'sbomQuality':quality})
    assert len(rows)==1 and metrics['policyStatus']=='fail'
