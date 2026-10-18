"""Versioned repair of derived SBOM rows; original artifacts/revisions are kept.

Workers repair one old run per maintenance tick, outside API startup. Active
changed runs receive durable reanalysis intents; archived runs are reindexed only.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
from sqlalchemy import ForeignKey,Integer,String,Text,or_,select
from sqlalchemy.orm import Mapped,Session,mapped_column
from .db import Base
from .models import AnalysisRevision,AuditEvent,FeatureUpgrade,JobState,ProcessingState,SbomRun
from .sbom import parse_sbom_file

NORMALIZATION_VERSION=2

class RunNormalization(Base):
    __tablename__='run_normalizations'
    run_id: Mapped[str]=mapped_column(ForeignKey('sbom_runs.id',ondelete='CASCADE'),primary_key=True)
    version: Mapped[int]=mapped_column(Integer,default=0)
    state: Mapped[str]=mapped_column(String(16),default='completed')
    error: Mapped[str|None]=mapped_column(Text,nullable=True)


def mark_current(db:Session,run:SbomRun):
    row=db.get(RunNormalization,run.id)
    if row is None:
        row=RunNormalization(run_id=run.id);db.add(row)
    row.version,row.state,row.error=NORMALIZATION_VERSION,'completed',None


def _components_snapshot(run):
    return sorted((r.identity_key,r.identity_status,r.purl,r.version,r.name,json_value(r.licenses),json_value(r.properties)) for r in run.components)


def json_value(value):
    import json
    return json.dumps(value,sort_keys=True,ensure_ascii=False)


def prepare_run(db:Session,run:SbomRun)->bool:
    # Worker exceptions are committed as failed jobs. Reindexing must roll back
    # separately so an invalid legacy document cannot commit deleted old rows.
    with db.begin_nested():
        return _prepare_run(db,run)


def _prepare_run(db:Session,run:SbomRun)->bool:
    row=db.get(RunNormalization,run.id)
    if row and row.version==NORMALIZATION_VERSION and row.state=='completed':
        return False
    before=_components_snapshot(run)
    old_bom=run.normalized_bom or {}
    payload=old_bom
    if 'xml' in run.media_type.lower():
        path=Path(run.artifact_path)
        with path.open('rb') as source:
            if hashlib.file_digest(source,'sha256').hexdigest()!=run.sha256:
                raise ValueError('정규화 복구 중 원본 SBOM SHA-256 불일치')
        payload,_=parse_sbom_file(path)
    # JSON preserved the hierarchy. XML must be recovered from the exact original.
    run.normalized_bom=payload
    from .services import create_components
    create_components(db,run,refresh=True)
    changed=payload!=old_bom or before!=_components_snapshot(run)
    mark_current(db,run);db.flush()
    if changed:
        db.add(AuditEvent(actor='normalization-upgrade',action='sbom.normalization_rebuild',target_type='sbom_run',target_id=run.id,detail={'version':NORMALIZATION_VERSION,'componentCount':len(run.components),'historicalAnalysesPreserved':True}))
    return changed


def normalization_tick(db:Session,*,batch_size:int=1,retry_failed:bool=False)->dict:
    result={'processed':0,'changed':0,'reanalyzes':0,'failed':0}
    completed_key='sbom-normalization-v2-backfill'
    if not retry_failed and db.get(FeatureUpgrade,completed_key) is not None:
        return result
    needs=or_(RunNormalization.run_id.is_(None),RunNormalization.version<NORMALIZATION_VERSION)
    query=select(SbomRun).outerjoin(RunNormalization,RunNormalization.run_id==SbomRun.id).where(needs)
    if not retry_failed:
        query=query.where(or_(RunNormalization.state.is_(None),RunNormalization.state!='failed'))
    runs=list(db.scalars(query.order_by(SbomRun.created_at,SbomRun.id).limit(batch_size).with_for_update(of=SbomRun,skip_locked=True)))
    if not runs and db.get(FeatureUpgrade,completed_key) is None and db.scalar(query.with_only_columns(SbomRun.id).limit(1)) is None:
        db.add(FeatureUpgrade(name=completed_key))
    for run in runs:
        try:
            with db.begin_nested():
                changed=prepare_run(db,run)
                reanalyzes=0
                if changed and run.archived_at is None and run.state!=ProcessingState.ARCHIVED and db.scalar(select(AnalysisRevision.id).where(AnalysisRevision.run_id==run.id).limit(1)):
                    from .project_catalog import request_native_reanalysis
                    reanalyzes=request_native_reanalysis(db,'sbom-normalization-v2',[run.id],reason='sbom_normalization_upgrade')
            result['processed']+=1;result['changed']+=int(changed);result['reanalyzes']+=reanalyzes
        except Exception as exc:
            row=db.get(RunNormalization,run.id)
            if row is None:
                row=RunNormalization(run_id=run.id,version=0);db.add(row)
            row.state,row.error='failed',str(exc)[-2000:]
            if run.archived_at is None and run.state!=ProcessingState.ARCHIVED:
                run.state,run.analysis_state=ProcessingState.FAILED,JobState.FAILED
            db.add(AuditEvent(actor='normalization-upgrade',action='sbom.normalization_failed',target_type='sbom_run',target_id=run.id,detail={'error':row.error,'version':NORMALIZATION_VERSION}))
            result['failed']+=1
    db.flush();return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--limit',type=int,default=100);parser.add_argument('--retry-failed',action='store_true');args=parser.parse_args()
    if not 1<=args.limit<=10000:parser.error('--limit must be 1..10000')
    from .db import SessionLocal
    import json
    with SessionLocal() as db:
        result=normalization_tick(db,batch_size=args.limit,retry_failed=args.retry_failed);db.commit();print(json.dumps(result))

if __name__=='__main__':main()
