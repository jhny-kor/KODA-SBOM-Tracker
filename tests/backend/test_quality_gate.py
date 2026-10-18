from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from koda_tracker.ci_gate import gate_result, read_gate
from koda_tracker.db import Base
from koda_tracker.models import (AnalysisRevision, ApiToken, Environment, Job, JobState, ProcessingState, Release, SbomRun, Service)
from koda_tracker.policies import PolicyDocument, evaluate_document, get_policy_document
from koda_tracker.quality import QualityProfile, evaluate_quality, revision_payload


@pytest.fixture
def sample(tmp_path):
    import json,hashlib
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Service(id='s',slug='s',name='S'),Environment(id='e',slug='e',name='E')]);db.flush()
        db.add(Release(id='r',service_id='s',environment_id='e',version='1'));db.flush()
        bom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[{'type':'library','name':'demo','version':'1','purl':'pkg:pypi/demo@1'}]}
        raw=json.dumps(bom).encode();artifact=tmp_path/'bom.json';artifact.write_bytes(raw)
        run = SbomRun(id='run',release_id='r',round_number=1,state=ProcessingState.COMPLETED,analysis_state=JobState.COMPLETED,
                      original_filename='sample.json',media_type='application/json',spec_version='1.6',sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),
                      artifact_path=str(artifact),normalized_bom=bom)
        db.add(run);db.flush()
        q=revision_payload(evaluate_quality(db,run))
        analysis=AnalysisRevision(run_id=run.id,sequence=1,state=JobState.COMPLETED,policy_state='completed',policy_version=get_policy_document(db).version,
                                  metrics={'policyStatus':'pass','policyDataComplete':True},data_sources={'sbomQuality':{'revisionId':q['id']}})
        db.add(analysis);db.flush()
        yield db,run,analysis
    engine.dispose()


def test_warn_profile_keeps_gate_usable_but_quality_is_separate(sample):
    db,run,analysis=sample
    result=gate_result(db,run)
    assert result['allowed'] and result['status']=='pass' and result['qualityStatus']=='warn'
    # CEL conditions can explicitly reject quality warnings independently of Grype findings.
    rows,metrics=evaluate_document(PolicyDocument(rules=[{'id':'quality','name':'Quality','kind':'cel','target':'project','expression':'sbomQuality.state != "completed" || sbomQuality.warningCount > 0'}]),[],[],project_context={'sbomQuality':{'state':'completed','warningCount':3}})
    assert metrics['policyStatus']=='fail' and len(rows)==1


@pytest.mark.parametrize('change,reason',[
    ('policy_fail','policy_violation'),('data_incomplete','policy_data_incomplete'),('policy_failed','policy_incomplete'),
    ('analysis_failed','analysis_incomplete'),('profile_changed','quality_profile_stale'),('quality_rerun','quality_analysis_mismatch'),
    ('archived','run_archived'),('quality_failed','quality_failed'),('policy_stale','policy_stale'),
    ('original_missing','quality_original_unverified'),('engine_stale','quality_engine_stale')])
def test_gate_never_passes_incomplete_failed_or_stale_evidence(sample,change,reason):
    db,run,a=sample
    if change=='policy_fail':a.metrics={'policyStatus':'fail','policyDataComplete':True}
    elif change=='data_incomplete':a.metrics={'policyStatus':'pass','policyDataComplete':False}
    elif change=='policy_failed':a.policy_state='failed'
    elif change=='analysis_failed':a.state=JobState.FAILED
    elif change=='profile_changed':db.add(QualityProfile(scope_key='default',version=1,document={'name':'Changed','mode':'enforce','maxErrors':0,'maxWarnings':0,'maxMissingIdentityRatio':0,'maxUnresolvedRefs':0,'maxAgeDays':365},created_by='test'))
    elif change=='quality_rerun':evaluate_quality(db,run,force=True)
    elif change=='archived':run.state=ProcessingState.ARCHIVED
    elif change=='quality_failed':
        Path(run.artifact_path).write_text('corrupt');evaluate_quality(db,run,force=True)
    elif change=='policy_stale':a.policy_version=0
    elif change in {'original_missing','engine_stale'}:
        from koda_tracker.quality import latest_revision
        q=latest_revision(db,run.id)
        if change=='original_missing':q.summary={**q.summary,'sourceBasis':'stored_normalized_json'}
        else:q.engine_version='old'
    db.flush()
    result=gate_result(db,run)
    assert result['status']=='blocked' and not result['allowed'] and reason in result['reasons']


def test_pending_job_cannot_reuse_previous_pass_and_foreign_service_cannot_read(sample):
    from fastapi import HTTPException,Response
    db,run,a=sample
    db.add(Job(run_id=run.id,kind='analyze',state=JobState.QUEUED));db.flush()
    assert gate_result(db,run)['status']=='pending'
    for token in (ApiToken(id='foreign',service_id='other'),ApiToken(id='global',service_id=None)):
        with pytest.raises(HTTPException) as error:
            read_gate(run.id,Response(),db,token)
        assert error.value.status_code==404
    assert read_gate(run.id,Response(),db,ApiToken(service_id='s'))['status']=='pending'


def test_ci_cli_nonzero_on_blocked_unknown_timeout_and_pending_to_pass():
    spec=importlib.util.spec_from_file_location('gate_script',Path(__file__).parents[2]/'scripts/check-sbom-gate.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for result,code in [({'status':'blocked','allowed':False},1),({'status':'error'},2),({'status':'pass','allowed':False},2)]:
        assert module.wait_for_gate(lambda:result,timeout=1,interval=.1)[0]==code
    values=iter([{'status':'pending'},{'status':'pass','allowed':True,'reasons':[]}])
    assert module.wait_for_gate(lambda:next(values),timeout=1,interval=.1,sleep=lambda _:None)[0]==0
    clock=iter([0,2])
    assert module.wait_for_gate(lambda:{'status':'pending'},timeout=1,interval=.1,clock=lambda:next(clock))[0]==2
