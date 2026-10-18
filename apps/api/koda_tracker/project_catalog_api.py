"""Administrator-managed native catalog and read-only legacy synchronization."""
from __future__ import annotations
from datetime import timedelta
import re
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .db import get_db
from .models import Environment, Release, SbomRun, Service, now
from .project_catalog_models import NativeProject, ProjectRunLink, ProjectSyncSource, ProjectSyncEvent
from .project_catalog import CatalogError, encrypt_key, link_run, project_payload, set_latest, sync_payload, tags_of, validate_hierarchy
from .security import require_admin, require_csrf, require_permission
from .services import audit

router = APIRouter(prefix="/api/v1", tags=["Project catalog"])


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sourceId: str = Field(default="native", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    sourceProjectId: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    serviceId: str
    environmentId: str
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(default="", max_length=255)
    parentProjectId: str | None = Field(default=None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=100)
    isLatest: bool = False
    active: bool = True
    runId: str | None = None


class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedRevision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    parentProjectId: str | None = Field(default=None, max_length=128)
    tags: list[str] | None = Field(default=None, max_length=100)
    isLatest: bool | None = None
    active: bool | None = None


class RunLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedRevision: int = Field(ge=1)
    runId: str


def _parent_check(db: Session, source_id: str, identity: str, parent: str | None):
    rows = list(db.scalars(select(NativeProject).where(NativeProject.source_id == source_id).with_for_update()))
    if parent is not None and not any(p.source_project_id == parent for p in rows):
        raise CatalogError("같은 원본 범위의 부모 프로젝트가 없습니다")
    values = [{"id": p.source_project_id, "parent": parent if p.source_project_id == identity else p.parent_project_id} for p in rows]
    if not any(p["id"] == identity for p in values):
        values.append({"id": identity, "parent": parent})
    validate_hierarchy(values)


@router.get("/project-catalog")
def list_projects(sourceId: str | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), _=Depends(require_permission("migrations.manage"))):
    query = select(NativeProject)
    if sourceId:
        query = query.where(NativeProject.source_id == sourceId)
    count = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    return {"items": [project_payload(p) for p in db.scalars(query.order_by(NativeProject.source_id, NativeProject.name, NativeProject.version, NativeProject.id).offset((page - 1) * size).limit(size))], "total": count, "page": page, "size": size}


@router.post("/project-catalog", status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    try:
        if db.get(Service, body.serviceId) is None or db.get(Environment, body.environmentId) is None:
            raise CatalogError("서비스 또는 환경이 없습니다")
        if db.scalar(select(NativeProject.id).where(NativeProject.source_id == body.sourceId, NativeProject.source_project_id == body.sourceProjectId)):
            raise HTTPException(409, "동일한 원본 프로젝트가 이미 있습니다")
        _parent_check(db, body.sourceId, body.sourceProjectId, body.parentProjectId)
        p = NativeProject(source_id=body.sourceId, source_project_id=body.sourceProjectId, service_id=body.serviceId, environment_id=body.environmentId, name=body.name, version=body.version, parent_project_id=body.parentProjectId, tags=tags_of(body.tags), is_latest=False, active=body.active)
        db.add(p); db.flush()
        set_latest(db, p, body.isLatest)
        if body.runId:
            run = db.get(SbomRun, body.runId)
            if not run:
                raise CatalogError("연결할 회차가 없습니다")
            link_run(db, p, run)
        audit(db, principal.username, "project_catalog.create", "project", p.id, body.model_dump())
        db.commit()
        return project_payload(p)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.patch("/project-catalog/{project_id}")
def update_project(project_id: str, body: ProjectUpdate, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    p = db.scalar(select(NativeProject).where(NativeProject.id == project_id).with_for_update())
    if p is None:
        raise HTTPException(404, "프로젝트가 없습니다")
    if p.revision != body.expectedRevision:
        raise HTTPException(409, "프로젝트가 변경되었습니다. 다시 조회하세요")
    try:
        if "parentProjectId" in body.model_fields_set:
            _parent_check(db, p.source_id, p.source_project_id, body.parentProjectId)
            p.parent_project_id = body.parentProjectId
        if "tags" in body.model_fields_set:
            p.tags = tags_of(body.tags)
        for name in ("name", "active"):
            if name in body.model_fields_set:
                if getattr(body, name) is None:
                    raise CatalogError("이름·활성 상태는 null일 수 없습니다")
                setattr(p, name, getattr(body, name))
        if "isLatest" in body.model_fields_set:
            if body.isLatest is None:
                raise CatalogError("최신 버전 상태는 null일 수 없습니다")
            set_latest(db, p, body.isLatest)
        p.revision += 1
        audit(db, principal.username, "project_catalog.update", "project", p.id, body.model_dump(exclude_unset=True))
        db.commit()
        return project_payload(p)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.post("/project-catalog/{project_id}/runs")
def attach_run(project_id: str, body: RunLinkRequest, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    p = db.scalar(select(NativeProject).where(NativeProject.id == project_id).with_for_update())
    if p is None:
        raise HTTPException(404, "프로젝트가 없습니다")
    if p.revision != body.expectedRevision:
        raise HTTPException(409, "프로젝트가 변경되었습니다. 다시 조회하세요")
    run = db.get(SbomRun, body.runId)
    if run is None:
        raise HTTPException(404, "회차가 없습니다")
    try:
        link_run(db, p, run); p.revision += 1
        audit(db, principal.username, "project_catalog.link_run", "project", p.id, body.model_dump())
        db.commit()
        return project_payload(p)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


class SyncCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    baseUrl: str = Field(max_length=2048)
    allowedOrigins: list[str] = Field(min_length=1, max_length=20)
    apiKey: SecretStr
    projectUuids: list[str] = Field(default_factory=list, max_length=10000)
    sourceTimeZone: str | None = Field(default=None, max_length=64)
    enabled: bool = False
    intervalMinutes: int = Field(default=1440, ge=5, le=10080)


class SyncUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedVersion: int = Field(ge=1)
    enabled: bool | None = None
    intervalMinutes: int | None = Field(default=None, ge=5, le=10080)
    apiKey: SecretStr | None = None


@router.get("/project-sync-sources")
def list_sources(page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), _=Depends(require_permission("migrations.manage"))):
    return {"items": [sync_payload(s) for s in db.scalars(select(ProjectSyncSource).order_by(ProjectSyncSource.name, ProjectSyncSource.id).offset((page - 1) * size).limit(size))], "total": db.scalar(select(func.count()).select_from(ProjectSyncSource)) or 0, "page": page, "size": size}


@router.post("/project-sync-sources", status_code=201)
def create_source(body: SyncCreate, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    from .migration import validate_source_url
    try:
        origin = validate_source_url(body.baseUrl, body.allowedOrigins)
        if not body.apiKey.get_secret_value().strip():
            raise CatalogError("원본 API 키가 필요합니다")
        s = ProjectSyncSource(name=body.name, base_url=origin, allowed_origins=body.allowedOrigins, project_uuids=body.projectUuids, source_timezone=body.sourceTimeZone, key_ciphertext=encrypt_key(body.apiKey.get_secret_value()), enabled=body.enabled, interval_minutes=body.intervalMinutes, actor_id=principal.id, actor_name=principal.username, next_run_at=now() if body.enabled else None)
        db.add(s); db.flush()
        audit(db, principal.username, "project_sync.create", "project_sync_source", s.id, {"baseUrl": origin, "enabled": s.enabled})
        db.commit()
        return sync_payload(s)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.patch("/project-sync-sources/{source_id}")
def update_source(source_id: str, body: SyncUpdate, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    s = db.scalar(select(ProjectSyncSource).where(ProjectSyncSource.id == source_id).with_for_update())
    if not s:
        raise HTTPException(404, "동기화 원본이 없습니다")
    if s.version != body.expectedVersion:
        raise HTTPException(409, "동기화 설정이 변경되었습니다")
    if s.state == "running":
        raise HTTPException(409, "동기화 실행 중에는 설정을 변경할 수 없습니다")
    try:
        if body.apiKey:
            if not body.apiKey.get_secret_value().strip():
                raise CatalogError("원본 API 키가 비었습니다")
            s.key_ciphertext = encrypt_key(body.apiKey.get_secret_value())
        if body.enabled is not None:
            s.enabled = body.enabled
        if body.intervalMinutes is not None:
            s.interval_minutes = body.intervalMinutes
        s.version += 1
        s.next_run_at = now() if s.enabled else None
        s.state, s.attempts, s.last_error = "idle", 0, None
        audit(db, principal.username, "project_sync.update", "project_sync_source", s.id, {"enabled": s.enabled, "intervalMinutes": s.interval_minutes, "credentialReplaced": body.apiKey is not None})
        db.commit()
        return sync_payload(s)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.post("/project-sync-sources/{source_id}/run-now", status_code=202)
def run_source(source_id: str, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    s = db.scalar(select(ProjectSyncSource).where(ProjectSyncSource.id == source_id).with_for_update())
    if not s:
        raise HTTPException(404, "동기화 원본이 없습니다")
    if s.state == "running":
        return sync_payload(s)
    if not s.enabled:
        raise HTTPException(409, "동기화를 활성화한 뒤 실행하세요")
    s.next_run_at, s.attempts, s.state, s.last_error = now(), 0, "idle", None
    audit(db, principal.username, "project_sync.enqueue", "project_sync_source", s.id)
    db.commit()
    return sync_payload(s)


@router.get("/project-sync-sources/{source_id}/events")
def source_events(source_id: str, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), _=Depends(require_permission("migrations.manage"))):
    query = select(ProjectSyncEvent).where(ProjectSyncEvent.source_id == source_id)
    events = list(db.scalars(query.order_by(ProjectSyncEvent.started_at.desc()).offset((page - 1) * size).limit(size)))
    return {"items": [{"id": e.id, "attempt": e.attempt, "state": e.state, "startedAt": e.started_at.isoformat(), "finishedAt": e.finished_at.isoformat() if e.finished_at else None, "migrationId": e.migration_id, "detail": e.detail} for e in events], "total": db.scalar(select(func.count()).select_from(query.subquery())) or 0, "page": page, "size": size}
