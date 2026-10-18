"""Versioned quality policy administration and run-scoped immutable evidence."""
from __future__ import annotations

import csv
import io
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import get_db
from .models import ApiToken, AuditEvent, ProcessingState, Release, SbomRun
from .project_catalog_models import NativeProject, ProjectRunLink
from .quality import QualityIssue, QualityProfile, QualityRevision, current_profile, effective_profile, evaluate_quality, latest_revision, profile_scope_key, queue_quality_changes, revision_payload
from .security import require_csrf, require_permission
from .quality_scoring import DEFAULT_SCORE_WEIGHTS, validate_score_weights

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
    scoreWeights: dict[str, int]=Field(default_factory=lambda: dict(DEFAULT_SCORE_WEIGHTS))
    minScore: float | None=Field(default=None,ge=0,le=100,allow_inf_nan=False)
    inherit: bool=False
    priority: int=Field(default=0,ge=-1000000,le=1000000)

    @field_validator('scoreWeights', mode='before')
    @classmethod
    def score_weights(cls, value):
        return validate_score_weights(value)


def check_scope(db, project_id, source_id, tag):
    try:
        key = profile_scope_key(project_id, source_id=source_id, tag=tag)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if project_id and db.get(NativeProject, project_id) is None:
        raise HTTPException(404, '프로젝트가 없습니다')
    return key


@router.get('/quality-profiles')
def read_profile(projectId: str | None=None, sourceId: str | None=None, tag: str | None=None,
                 db: Session=Depends(get_db), _=Depends(require_permission('policies.view','policies.manage'))):
    check_scope(db, projectId, sourceId, tag)
    return current_profile(db, projectId, source_id=sourceId, tag=tag)


@router.get('/quality-tag-profiles')
def read_tag_profiles(sourceId: str | None=None, page: int=Query(1,ge=1), size: int=Query(25,ge=1,le=100),
                      db: Session=Depends(get_db), _=Depends(require_permission('policies.view','policies.manage'))):
    # Aggregate in SQL before pagination so a rule's old version never reappears.
    latest = select(QualityProfile.scope_key, func.max(QualityProfile.version).label('version')).where(
        QualityProfile.scope_key.like('tag:%')).group_by(QualityProfile.scope_key).subquery()
    query = select(QualityProfile).join(latest, (QualityProfile.scope_key == latest.c.scope_key) & (QualityProfile.version == latest.c.version))
    if sourceId:
        query = query.where(QualityProfile.document['scopeSourceId'].as_string() == sourceId)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(QualityProfile.scope_key).offset((page-1)*size).limit(size))
    return {'items': [profile_payload_for_tag(row) for row in rows], 'total': total, 'page': page, 'size': size}


def profile_payload_for_tag(row):
    from .quality import profile_payload
    return profile_payload(row, source_id=row.document.get('scopeSourceId'), tag=row.document.get('scopeTag'))


@router.get('/sbom-runs/{run_id}/quality-profile')
def resolved_run_profile(run_id: str, db: Session=Depends(get_db),
                         principal=Depends(require_permission('runs.view',allow_service_token=True))):
    run = checked_run(db, run_id, principal)
    try:
        profile = effective_profile(db, run)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    owner = (profile.get('resolution') or {}).get('projectId')
    project = db.get(NativeProject, owner) if owner else None
    return {'profile': profile, 'project': None if project is None else {
        'id': project.id, 'sourceId': project.source_id, 'sourceProjectId': project.source_project_id,
        'parentProjectId': project.parent_project_id, 'tags': project.tags}}


@router.put('/quality-profiles')
def write_profile(body: ProfileInput, projectId: str | None=None, sourceId: str | None=None, tag: str | None=None,
                  db: Session=Depends(get_db), principal=Depends(require_permission('policies.manage')), _csrf=Depends(require_csrf)):
    from .quality import quality_write_lock
    quality_write_lock(db)
    key = check_scope(db, projectId, sourceId, tag)
    if body.inherit and key == 'default':
        raise HTTPException(422, '공통 기본 기준은 상속 모드로 해제할 수 없습니다')
    if body.priority != 0 and tag is None:
        raise HTTPException(422, '우선순위는 태그 기준에서만 지정할 수 있습니다')
    # Stable parent locks serialize the first version as well as later updates.
    if projectId:
        db.scalar(select(NativeProject.id).where(NativeProject.id==projectId).with_for_update())
    else:
        from .models import RolePolicy, Role
        db.scalar(select(RolePolicy.role).where(RolePolicy.role==Role.ADMIN).with_for_update())
    current = current_profile(db, projectId, source_id=sourceId, tag=tag)
    if current['version'] != body.expectedVersion:
        raise HTTPException(409, '품질 기준이 변경되었습니다. 다시 조회하세요')
    document = body.model_dump(exclude={'expectedVersion'})
    if tag is not None:
        document.update(scopeSourceId=sourceId, scopeTag=tag)
    row = QualityProfile(scope_key=key, version=current['version']+1, document=document, created_by=principal.username)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback(); raise HTTPException(409, '품질 기준이 변경되었습니다. 다시 조회하세요') from exc
    requested = queue_quality_changes(db, project_id=projectId, source_id=sourceId)
    db.add(AuditEvent(actor=principal.username, action='sbom_quality.profile',
                     target_type='project' if projectId else 'quality_tag' if tag else 'quality_profile',
                     target_id=key, detail={'version': row.version, 'sourceId': sourceId, 'tag': tag,
                                           'inherit': body.inherit, 'priority': body.priority}))
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback(); raise HTTPException(409, '품질 기준이 변경되었습니다. 다시 조회하세요') from exc
    return {**current_profile(db, projectId, source_id=sourceId, tag=tag), 'reanalysisRequested': requested}
