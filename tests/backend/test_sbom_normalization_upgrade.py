from __future__ import annotations
import hashlib,json
from sqlalchemy import create_engine,select
from sqlalchemy.orm import Session
from koda_tracker.db import Base
from koda_tracker.models import AnalysisRevision,FeatureUpgrade,Environment,JobState,ProcessingState,Release,RunComponent,SbomRun,Service
from koda_tracker.sbom_normalization import RunNormalization,normalization_tick,prepare_run
from koda_tracker.project_catalog_models import NativeReanalysisPending


def make(db,tmp_path,*,xml=False,archived=False):
 db.add_all([Service(id='s',slug='s',name='S'),Environment(id='e',slug='e',name='E')]);db.flush();db.add(Release(id='r',service_id='s',environment_id='e',version='1'));db.flush()
 child={'type':'library','name':'child','version':'1','purl':'pkg:generic/child@1','licenses':[{'license':{'id':'GPL-3.0-only'}}]};parent={'type':'library','name':'parent','version':'1','purl':'pkg:generic/parent@1','components':[child]};bom={'bomFormat':'CycloneDX','specVersion':'1.6','components':[parent]}
 raw=b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component type="library"><name>parent</name><version>1</version><purl>pkg:generic/parent@1</purl><components><component type="library"><name>child</name><version>1</version><purl>pkg:generic/child@1</purl></component></components></component></components></bom>' if xml else json.dumps(bom).encode()
 path=tmp_path/'bom';path.write_bytes(raw)
 run=SbomRun(id='run',release_id='r',round_number=1,state=ProcessingState.ARCHIVED if archived else ProcessingState.COMPLETED,analysis_state=JobState.COMPLETED,original_filename='bom',media_type='application/xml' if xml else 'application/json',spec_version='1.6',sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw),artifact_path=str(path),normalized_bom={'bomFormat':'CycloneDX','specVersion':'1.6','components':[{k:v for k,v in parent.items() if k!='components'}]} if xml else bom)
 db.add(run);db.flush();db.add(RunComponent(run_id=run.id,name='parent',version='1',purl='pkg:generic/parent@1',identity_key='purl:pkg:generic/parent',identity_status='identified',licenses=[],properties=[]));revision=AnalysisRevision(run_id=run.id,sequence=1,state=JobState.COMPLETED,policy_state='completed',metrics={'componentCount':1},findings=[],policies=[]);db.add(revision);db.commit();return run,revision


def test_existing_json_reindexes_then_durably_reanalyzes_without_rewriting_history(tmp_path):
 engine=create_engine('sqlite://');Base.metadata.create_all(engine)
 with Session(engine,expire_on_commit=False) as db:
  run,old=make(db,tmp_path);result=normalization_tick(db);db.commit()
  assert result=={'processed':1,'changed':1,'reanalyzes':1,'failed':0}
  assert len(run.components)==2 and old.metrics=={'componentCount':1}
  assert db.get(NativeReanalysisPending,('sbom-normalization-v2',run.id))
  assert db.get(RunNormalization,run.id).version==2
  assert normalization_tick(db)['processed']==0
  assert db.get(FeatureUpgrade,'sbom-normalization-v2-backfill') is not None
  assert prepare_run(db,run) is False
 engine.dispose()


def test_archived_xml_recovers_children_but_never_queues_analysis(tmp_path):
 engine=create_engine('sqlite://');Base.metadata.create_all(engine)
 with Session(engine,expire_on_commit=False) as db:
  run,old=make(db,tmp_path,xml=True,archived=True);result=normalization_tick(db);db.commit()
  assert result['changed']==1 and result['reanalyzes']==0
  assert len(run.components)==2 and run.state==ProcessingState.ARCHIVED
  assert old.metrics=={'componentCount':1}
  assert run.normalized_bom['components'][0]['components'][0]['name']=='child'
 engine.dispose()


def test_xml_hash_mismatch_fails_without_deleting_old_rows_and_can_retry(tmp_path):
 engine=create_engine('sqlite://');Base.metadata.create_all(engine)
 with Session(engine,expire_on_commit=False) as db:
  run,_=make(db,tmp_path,xml=True);original=(tmp_path/'bom').read_bytes();(tmp_path/'bom').write_bytes(b'tampered')
  result=normalization_tick(db);db.commit()
  assert result['failed']==1 and len(run.components)==1
  assert db.get(RunNormalization,run.id).state=='failed' and run.analysis_state==JobState.FAILED
  assert normalization_tick(db)['processed']==0
  (tmp_path/'bom').write_bytes(original);result=normalization_tick(db,retry_failed=True);db.commit()
  assert result['failed']==0 and result['reanalyzes']==1 and len(run.components)==2
 engine.dispose()


def test_reanalysis_request_failure_rolls_back_reindex_and_success_counters(tmp_path,monkeypatch):
 from koda_tracker import project_catalog
 engine=create_engine('sqlite://');Base.metadata.create_all(engine)
 with Session(engine,expire_on_commit=False) as db:
  run,_=make(db,tmp_path)
  def failed(*args,**kwargs):raise RuntimeError('queue transaction failed')
  monkeypatch.setattr(project_catalog,'request_native_reanalysis',failed)
  result=normalization_tick(db);db.commit()
  assert result=={'processed':0,'changed':0,'reanalyzes':0,'failed':1}
  assert len(run.components)==1 and db.get(RunNormalization,run.id).state=='failed'
 engine.dispose()


def test_prepare_failure_can_be_committed_as_failed_job_without_losing_old_components(tmp_path):
 import pytest
 from koda_tracker.sbom import SbomValidationError
 engine=create_engine('sqlite://');Base.metadata.create_all(engine)
 with Session(engine,expire_on_commit=False) as db:
  run,_=make(db,tmp_path)
  run.normalized_bom={'components':[{'name':'parent','components':{}}]};db.commit()
  with pytest.raises(SbomValidationError):prepare_run(db,run)
  run.analysis_state=JobState.FAILED;db.commit()
  assert len(run.components)==1 and run.components[0].name=='parent'
 engine.dispose()
