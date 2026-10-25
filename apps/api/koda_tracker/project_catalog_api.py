"""Administrator-managed native project catalog."""
from __future__ import annotations
import re
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, selectinload
from .collection_metrics import CollectionLogic, collection_config, collection_metrics, configure_collection
from .db import get_db
from .models import AnalysisRevision, Environment, Release, RunComponent, SbomRun, Service, now
from .project_catalog_models import NativeProject, NativeReanalysisPending, ProjectRunLink
from .project_catalog import CatalogError, link_run, project_payload, set_latest, tags_of, validate_hierarchy
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
    collectionLogic: CollectionLogic = CollectionLogic.NONE
    collectionTag: str | None = Field(default=None, max_length=255)


class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedRevision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    parentProjectId: str | None = Field(default=None, max_length=128)
    tags: list[str] | None = Field(default=None, max_length=100)
    isLatest: bool | None = None
    active: bool | None = None
    collectionLogic: CollectionLogic | None = None
    collectionTag: str | None = Field(default=None, max_length=255)


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


def _refresh_quality_scope(db: Session, source_id: str) -> int:
    # Parent/tag edits may change descendants and ordinary uploads in the same
    # coordinates. Persist reanalysis in this transaction; keep old evidence.
    from .quality import queue_quality_changes
    db.flush()
    return queue_quality_changes(db, source_id=source_id)


@router.get("/project-catalog")
def list_projects(sourceId: str | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), _=Depends(require_permission("catalog.manage"))):
    query = select(NativeProject)
    if sourceId:
        query = query.where(NativeProject.source_id == sourceId)
    count = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    return {"items": [project_payload(p) for p in db.scalars(query.order_by(NativeProject.source_id, NativeProject.name, NativeProject.version, NativeProject.id).offset((page - 1) * size).limit(size))], "total": count, "page": page, "size": size}


@router.post("/project-catalog", status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("catalog.manage")), _csrf=Depends(require_csrf)):
    from .quality import quality_write_lock
    quality_write_lock(db)
    try:
        if db.get(Service, body.serviceId) is None or db.get(Environment, body.environmentId) is None:
            raise CatalogError("서비스 또는 환경이 없습니다")
        if db.scalar(select(NativeProject.id).where(NativeProject.source_id == body.sourceId, NativeProject.source_project_id == body.sourceProjectId)):
            raise HTTPException(409, "동일한 원본 프로젝트가 이미 있습니다")
        _parent_check(db, body.sourceId, body.sourceProjectId, body.parentProjectId)
        p = NativeProject(source_id=body.sourceId, source_project_id=body.sourceProjectId, service_id=body.serviceId, environment_id=body.environmentId, name=body.name, version=body.version, parent_project_id=body.parentProjectId, tags=tags_of(body.tags), is_latest=False, active=body.active)
        configure_collection(p, body.collectionLogic, body.collectionTag)
        db.add(p); db.flush()
        set_latest(db, p, body.isLatest)
        if body.runId:
            run = db.get(SbomRun, body.runId)
            if not run:
                raise CatalogError("연결할 회차가 없습니다")
            link_run(db, p, run)
        audit(db, principal.username, "project_catalog.create", "project", p.id, body.model_dump())
        _refresh_quality_scope(db, p.source_id)
        db.commit()
        return project_payload(p)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.patch("/project-catalog/{project_id}")
def update_project(project_id: str, body: ProjectUpdate, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("catalog.manage")), _csrf=Depends(require_csrf)):
    from .quality import quality_write_lock
    quality_write_lock(db)
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
        if {"collectionLogic", "collectionTag"} & body.model_fields_set:
            current = collection_config(p)
            logic = body.collectionLogic if "collectionLogic" in body.model_fields_set else current["collectionLogic"]
            if logic is None:
                raise CatalogError("Collection 방식은 null일 수 없습니다")
            tag = body.collectionTag if "collectionTag" in body.model_fields_set else current["collectionTag"]
            configure_collection(p, logic, tag)
        p.revision += 1
        audit(db, principal.username, "project_catalog.update", "project", p.id, body.model_dump(exclude_unset=True))
        _refresh_quality_scope(db, p.source_id)
        db.commit()
        return project_payload(p)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.post("/project-catalog/{project_id}/runs")
def attach_run(project_id: str, body: RunLinkRequest, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("catalog.manage")), _csrf=Depends(require_csrf)):
    from .quality import quality_write_lock
    quality_write_lock(db)
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
        _refresh_quality_scope(db, p.source_id)
        db.commit()
        return project_payload(p)
    except ValueError as exc:
        db.rollback(); raise HTTPException(422, str(exc)) from exc


@router.get("/project-catalog/{project_id}/runs")
def list_project_runs(
    project_id: str,
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    _catalog=Depends(require_permission("catalog.manage")),
    _runs=Depends(require_permission("runs.view")),
):
    # Reuse the normal results summary, including current analysis availability.
    # Import lazily because main registers this router during module loading.
    from .main import _run_payload

    project = db.get(NativeProject, project_id)
    if project is None:
        raise HTTPException(404, "프로젝트가 없습니다")
    linked = select(ProjectRunLink.run_id).where(
        ProjectRunLink.run_id == SbomRun.id,
        ProjectRunLink.project_id == project.id,
    ).exists()
    association = linked
    coordinates = (
        NativeProject.service_id == project.service_id,
        NativeProject.environment_id == project.environment_id,
        NativeProject.version == project.version,
    )
    # Exactly mirror project_for_run: explicit links win, and an unlinked run
    # inherits a catalog project only when its coordinates identify one project
    # across all sources, including inactive projects. Do not persist new links.
    candidates = db.scalar(select(func.count()).select_from(NativeProject).where(*coordinates))
    if candidates == 1:
        unlinked = ~select(ProjectRunLink.run_id).where(ProjectRunLink.run_id == SbomRun.id).exists()
        association = or_(linked, and_(
            unlinked,
            Release.service_id == project.service_id,
            Release.environment_id == project.environment_id,
            Release.version == project.version,
        ))
    query = select(SbomRun).join(Release).where(association)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = list(db.scalars(query.options(
        selectinload(SbomRun.release).selectinload(Release.service),
        selectinload(SbomRun.release).selectinload(Release.environment),
        selectinload(SbomRun.analyses).defer(AnalysisRevision.policies).defer(AnalysisRevision.policy_snapshot),
    ).order_by(SbomRun.created_at.desc(), SbomRun.id.desc()).offset((page - 1) * size).limit(size)))
    run_ids = [item.id for item in items]
    pending_ids = set(db.scalars(select(NativeReanalysisPending.run_id).where(
        NativeReanalysisPending.run_id.in_(run_ids),
    ))) if run_ids else set()
    component_counts, type_counts = {}, {}
    if run_ids:
        for run_id, kind, count in db.execute(select(
            RunComponent.run_id, RunComponent.component_type, func.count(),
        ).where(RunComponent.run_id.in_(run_ids)).group_by(RunComponent.run_id, RunComponent.component_type)):
            component_counts[run_id] = component_counts.get(run_id, 0) + count
            type_counts.setdefault(run_id, {})[kind or "library"] = count
    return {
        "items": [_run_payload(
            item,
            component_count=component_counts.get(item.id, 0),
            component_type_counts=type_counts.get(item.id, {}),
            native_reanalysis_pending=item.id in pending_ids,
        ) for item in items],
        "total": total, "page": page, "size": size,
    }


@router.get("/project-catalog/{project_id}/metrics")
def get_collection_metrics(project_id: str, db: Session = Depends(get_db), _=Depends(require_permission("catalog.manage"))):
    p = db.get(NativeProject, project_id)
    if p is None:
        raise HTTPException(404, "프로젝트가 없습니다")
    try:
        return collection_metrics(db, p)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
