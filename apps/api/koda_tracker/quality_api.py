"""Versioned quality policy administration and run-scoped immutable evidence."""
from __future__ import annotations

import csv
import io
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import get_db
from .models import ApiToken, AuditEvent, ProcessingState, Release, SbomRun
from .project_catalog_models import NativeProject, ProjectRunLink
from .quality import QualityIssue, QualityProfile, QualityRevision, current_profile, evaluate_quality, latest_revision, revision_payload
from .security import require_csrf, require_permission

router = APIRouter(prefix='/api/v1', tags=['SBOM quality'])


def checked_run(db, run_id, principal, for_update=False):
    run = db.scalar(select(SbomRun).where(SbomRun.id == run_id).with_for_update().execution_options(populate_existing=True)) if for_update else db.get(SbomRun, run_id)
    if run is None:
        raise HTTPException(404, 'SBOM 회차가 없습니다')
    if isinstance(principal, ApiToken):
        allowed = principal.service_id == run.release.service_id if principal.service_id else run.idempotency_actor == f'token:{principal.id}'
        if not allowed:
            raise HTTPException(403, '서비스 범위 권한이 없습니다')
    return run


def checked_revision(db, run_id, revision_id):
    row = db.get(QualityRevision, revision_id) if revision_id else latest_revision(db, run_id)
    if row is None or row.run_id != run_id:
        raise HTTPException(404, '품질 진단 결과가 없습니다')
    return row


@router.get('/sbom-runs/{run_id}/quality-revisions')
def list_revisions(run_id: str, page: int = Query(1, ge=1), size: int = Query(25, ge=1, le=100),
                   db: Session = Depends(get_db), principal=Depends(require_permission('runs.view', allow_service_token=True))):
    checked_run(db, run_id, principal)
    query = select(QualityRevision).where(QualityRevision.run_id == run_id)
    return {'items':[revision_payload(r) for r in db.scalars(query.order_by(QualityRevision.sequence.desc()).offset((page-1)*size).limit(size))],
            'total':db.scalar(select(func.count()).select_from(query.subquery())) or 0,'page':page,'size':size}


@router.post('/sbom-runs/{run_id}/quality-revisions', status_code=201)
def rerun_quality(run_id: str, db: Session = Depends(get_db), principal=Depends(require_permission('analysis.create')),
                  _csrf=Depends(require_csrf)):
    run = checked_run(db,run_id,principal,for_update=True)
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        raise HTTPException(409, '보관된 회차는 품질 재진단할 수 없습니다')
    row = evaluate_quality(db,run,actor=principal.username,force=True)
    db.add(AuditEvent(actor=principal.username,action='sbom_quality.evaluate',target_type='sbom_run',target_id=run.id,detail={'qualityRevisionId':row.id,'state':row.state}))
    db.commit()
    return revision_payload(row)


@router.get('/sbom-runs/{run_id}/quality-issues')
def list_issues(run_id: str, revisionId: str | None = None, ruleId: str | None = None,
                severity: Literal['error','warning'] | None = None, page: int = Query(1, ge=1), size: int = Query(25, ge=1, le=100),
                db: Session = Depends(get_db), principal=Depends(require_permission('runs.view', allow_service_token=True))):
    checked_run(db,run_id,principal);rev=checked_revision(db,run_id,revisionId)
    query=select(QualityIssue).where(QualityIssue.revision_id==rev.id)
    if ruleId:
        query=query.where(QualityIssue.rule_id==ruleId)
    if severity:
        query=query.where(QualityIssue.severity==severity)
    return {'items':[{'id':i.id,**i.document} for i in db.scalars(query.order_by(QualityIssue.ordinal).offset((page-1)*size).limit(size))],
            'revisionId':rev.id,'total':db.scalar(select(func.count()).select_from(query.subquery())) or 0,'page':page,'size':size}


@router.get('/sbom-runs/{run_id}/quality-export')
def export_quality(run_id: str, revisionId: str | None = None, format: Literal['json','csv']='json',
                   db: Session = Depends(get_db), principal=Depends(require_permission('runs.view', allow_service_token=True))):
    checked_run(db,run_id,principal);rev=checked_revision(db,run_id,revisionId)
    rows=list(db.scalars(select(QualityIssue).where(QualityIssue.revision_id==rev.id).order_by(QualityIssue.ordinal)))
    if format=='json':
        return {'revision':revision_payload(rev),'issues':[r.document for r in rows]}
    stream=io.StringIO();fields=['ruleId','severity','path','bomRef','componentName','message','observed','expected','remediation']
    writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
    for row in rows:
        values={k: json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else '' if v is None else str(v) for k,v in row.document.items()}
        # Excel formula injection is unsafe even in an authenticated export.
        writer.writerow({k:("'"+v if v.lstrip().startswith(('=','+','-','@','\t','\r')) else v) for k,v in values.items()})
    return Response('\ufeff'+stream.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="sbom-quality.csv"'})


class ProfileInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    expectedVersion: int=Field(ge=0)
    name: str=Field(min_length=1,max_length=255)
    mode: Literal['warn','enforce']='warn'
    maxErrors: int=Field(default=0,ge=0,le=1000000)
    maxWarnings: int | None=Field(default=None,ge=0,le=1000000)
    maxMissingIdentityRatio: float=Field(default=0,ge=0,le=1,allow_inf_nan=False)
    maxUnresolvedRefs: int=Field(default=0,ge=0,le=1000000)
    maxAgeDays: int=Field(default=365,ge=1,le=36500)


def check_project(db,project_id):
    if project_id and db.get(NativeProject,project_id) is None:
        raise HTTPException(404,'프로젝트가 없습니다')


@router.get('/quality-profiles')
def read_profile(projectId: str | None=None, db: Session=Depends(get_db),
                 _=Depends(require_permission('policies.view','policies.manage'))):
    check_project(db,projectId)
    return current_profile(db,projectId)


@router.put('/quality-profiles')
def write_profile(body: ProfileInput, projectId: str | None=None, db: Session=Depends(get_db),
                  principal=Depends(require_permission('policies.manage')), _csrf=Depends(require_csrf)):
    check_project(db,projectId)
    # A stable parent row also serializes the first version where no profile row exists.
    if projectId:
        db.scalar(select(NativeProject.id).where(NativeProject.id==projectId).with_for_update())
    else:
        from .models import RolePolicy, Role
        db.scalar(select(RolePolicy.role).where(RolePolicy.role==Role.ADMIN).with_for_update())
    current=current_profile(db,projectId)
    if current['version']!=body.expectedVersion:
        raise HTTPException(409,'품질 기준이 변경되었습니다. 다시 조회하세요')
    row=QualityProfile(scope_key=projectId or 'default',version=current['version']+1,document=body.model_dump(exclude={'expectedVersion'}),created_by=principal.username)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback();raise HTTPException(409,'품질 기준이 변경되었습니다. 다시 조회하세요') from exc
    from .project_catalog import request_native_reanalysis
    from .quality import effective_profile
    # Rebind quality/policies to the new profile without rewriting old evidence.
    run_query = select(SbomRun).where(SbomRun.archived_at.is_(None), SbomRun.state != ProcessingState.ARCHIVED)
    if projectId:
        project = db.get(NativeProject, projectId)
        run_query = run_query.join(Release, Release.id == SbomRun.release_id).where(or_(
            SbomRun.id.in_(select(ProjectRunLink.run_id).where(ProjectRunLink.project_id == projectId)),
            (Release.service_id == project.service_id) & (Release.environment_id == project.environment_id) & (Release.version == project.version)))
    active_runs = db.scalars(run_query)
    affected = []
    for run in active_runs:
        try:
            effective = effective_profile(db,run)
            if effective['projectId'] == projectId:
                affected.append(run.id)
        except ValueError:
            if projectId:
                affected.append(run.id)
    requested = request_native_reanalysis(db, 'quality-profile-' + (projectId or 'default'), affected, reason='quality_profile_changed')
    db.add(AuditEvent(actor=principal.username,action='sbom_quality.profile',target_type='project' if projectId else 'quality_profile',target_id=projectId or 'default',detail={'version':row.version}))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback();raise HTTPException(409,'품질 기준이 변경되었습니다. 다시 조회하세요') from exc
    return {**current_profile(db,projectId), 'reanalysisRequested': requested}
