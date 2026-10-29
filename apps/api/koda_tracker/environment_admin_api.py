"""Environment administrator assignments and provenance-preserving SBOM edits."""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .db import get_db
from .environment_admin_models import EnvironmentAdministrator
from .models import ApiToken, Environment, Job, JobState, ProcessingState, Release, Role, RolePolicy, SbomRun, Service, User
from .project_catalog_models import NativeProject, NativeReanalysisPending, ProjectRunLink
from .security import DEFAULT_ROLE_PERMISSIONS, current_principal, require_csrf
from .services import audit

router = APIRouter(prefix="/api/v1", tags=["Environment administration"])


class EnvironmentAdministratorsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userIds: list[str] = Field(max_length=200)


class RunMetadataRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    serviceId: str | None = Field(default=None, min_length=1, max_length=36)
    environmentId: str | None = Field(default=None, min_length=1, max_length=36)
    releaseVersion: str | None = Field(default=None, min_length=1, max_length=255)
    note: str | None = Field(default=None, max_length=4000)


def _human(principal: User | ApiToken) -> User:
    if not isinstance(principal, User) or not principal.active or principal.approval_state != "approved":
        raise HTTPException(403, "승인된 활성 사용자만 사용할 수 있습니다")
    return principal


def _global_admin(principal: User | ApiToken) -> User:
    user = _human(principal)
    if user.role != Role.ADMIN:
        raise HTTPException(403, "환경 관리자 지정은 시스템 관리자만 할 수 있습니다")
    return user


def _can_view(db: Session, user: User) -> bool:
    policy = db.scalar(select(RolePolicy).where(RolePolicy.role == user.role).execution_options(populate_existing=True))
    permissions = policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(user.role, ())
    return user.role == Role.ADMIN or "runs.view" in permissions


def _editable_environments(db: Session, user: User) -> list[str]:
    query = select(Environment.id).where(Environment.active.is_(True))
    if user.role != Role.ADMIN:
        query = query.join(EnvironmentAdministrator, EnvironmentAdministrator.environment_id == Environment.id).where(EnvironmentAdministrator.user_id == user.id)
    return list(db.scalars(query.order_by(Environment.id)))


def _authorized(db: Session, user: User, environment_id: str) -> bool:
    return user.role == Role.ADMIN or (_can_view(db, user) and db.get(EnvironmentAdministrator, (environment_id, user.id)) is not None)


def _user_payload(user: User) -> dict:
    status = user.approval_state if user.approval_state != "approved" else ("active" if user.active else "inactive")
    return {"id": user.id, "username": user.username, "role": user.role.value, "active": user.active,
            "status": status}


@router.get("/environment-administrators")
def list_environment_administrators(db: Session = Depends(get_db), principal=Depends(current_principal)):
    _global_admin(principal)
    users = list(db.scalars(select(User).order_by(User.username, User.id)))
    by_id = {user.id: user for user in users}
    grants: dict[str, list[dict]] = {}
    for item in db.scalars(select(EnvironmentAdministrator).order_by(EnvironmentAdministrator.user_id)):
        if item.user_id in by_id:
            grants.setdefault(item.environment_id, []).append(_user_payload(by_id[item.user_id]))
    return {"environments": [{"id": item.id, "name": item.name, "slug": item.slug, "active": item.active,
                              "administrators": grants.get(item.id, [])}
                             for item in db.scalars(select(Environment).order_by(Environment.sort_order, Environment.name, Environment.id))],
            "users": [_user_payload(user) for user in users if user.active and user.approval_state == "approved"]}


@router.put("/environment-administrators/{environment_id}")
def replace_environment_administrators(environment_id: str, body: EnvironmentAdministratorsRequest,
                                      db: Session = Depends(get_db), principal=Depends(current_principal),
                                      _csrf=Depends(require_csrf)):
    user = _global_admin(principal)
    try:
        environment = db.scalar(select(Environment).where(Environment.id == environment_id).with_for_update().execution_options(populate_existing=True))
        if environment is None:
            raise HTTPException(404, "환경을 찾을 수 없습니다")
        if len(body.userIds) != len(set(body.userIds)):
            raise HTTPException(422, "관리자 사용자가 중복되었습니다")
        if not environment.active and body.userIds:
            raise HTTPException(409, "비활성 환경에는 관리자를 새로 지정할 수 없습니다")
        locked_users = {item.id: item for item in db.scalars(select(User).where(User.id.in_(sorted(set(body.userIds + [user.id])))).order_by(User.id).with_for_update().execution_options(populate_existing=True))}
        user = _global_admin(locked_users.get(user.id))
        selected = [locked_users[user_id] for user_id in body.userIds if user_id in locked_users]
        if len(selected) != len(body.userIds) or any(not item.active or item.approval_state != "approved" for item in selected):
            raise HTTPException(422, "승인된 활성 사용자만 환경 관리자로 지정할 수 있습니다")
        before = list(db.scalars(select(EnvironmentAdministrator.user_id).where(EnvironmentAdministrator.environment_id == environment_id)))
        db.execute(delete(EnvironmentAdministrator).where(EnvironmentAdministrator.environment_id == environment_id))
        db.add_all([EnvironmentAdministrator(environment_id=environment_id, user_id=user_id, assigned_by=user.username) for user_id in body.userIds])
        audit(db, user.username, "environment.administrators.update", "environment", environment_id,
              {"before": sorted(before), "after": sorted(body.userIds)})
        db.commit()
        return {"environmentId": environment_id, "userIds": sorted(body.userIds)}
    except (HTTPException, IntegrityError) as exc:
        db.rollback()
        if isinstance(exc, IntegrityError):
            raise HTTPException(409, "환경 또는 사용자가 변경되었습니다. 다시 조회하세요") from exc
        raise


def _run(db: Session, run_id: str, *, lock: bool = False) -> SbomRun:
    query = select(SbomRun).where(SbomRun.id == run_id).options(selectinload(SbomRun.release))
    if lock:
        query = query.with_for_update(of=SbomRun).execution_options(populate_existing=True)
    run = db.scalar(query)
    if run is None:
        raise HTTPException(404, "회차를 찾을 수 없습니다")
    return run


def _scope_restriction(db: Session, run: SbomRun) -> str | None:
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        return "보관된 회차는 메모만 수정할 수 있습니다"
    if db.scalar(select(Job.id).where(Job.run_id == run.id, Job.state.in_([JobState.QUEUED, JobState.RUNNING])).limit(1)) or db.scalar(select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id == run.id).limit(1)) or run.analysis_state in {JobState.QUEUED, JobState.RUNNING} or run.state in {ProcessingState.QUEUED, ProcessingState.PROCESSING}:
        return "처리 중인 회차는 분석 완료 후 서비스·환경·릴리스를 변경하세요"
    if db.get(ProjectRunLink, run.id) is not None or db.scalar(select(NativeProject.id).where(NativeProject.current_run_id == run.id).limit(1)):
        return "프로젝트에 연결된 회차는 메모만 수정할 수 있습니다. 서비스·환경·릴리스는 연결 관계를 먼저 확인하세요"
    return None


@router.get("/sbom-runs/{run_id}/edit-permission")
def run_edit_permission(run_id: str, db: Session = Depends(get_db), principal=Depends(current_principal)):
    user = _human(principal)
    if not _can_view(db, user):
        raise HTTPException(403, "SBOM 조회 권한이 필요합니다")
    run = _run(db, run_id)
    allowed = _authorized(db, user, run.release.environment_id)
    editable_ids = _editable_environments(db, user) if allowed else []
    scope_reason = _scope_restriction(db, run) if allowed else None
    metadata = {"serviceId": run.release.service_id, "environmentId": run.release.environment_id,
                "releaseVersion": run.release.version, "note": run.note or ""}
    return {"canEdit": allowed, "reason": scope_reason if allowed else "이 환경의 관리자만 수정할 수 있습니다",
            "canChangeScope": allowed and scope_reason is None, "scopeReason": scope_reason,
            "editableEnvironmentIds": editable_ids, **metadata, "metadata": metadata,
            "services": [{"id": item.id, "name": item.name, "slug": item.slug, "active": item.active}
                         for item in db.scalars(select(Service).where((Service.active.is_(True)) | (Service.id == run.release.service_id)).order_by(Service.name, Service.id))] if allowed else [],
            "environments": [{"id": item.id, "name": item.name, "slug": item.slug, "active": item.active}
                             for item in db.scalars(select(Environment).where(Environment.id.in_(sorted(set(editable_ids + [run.release.environment_id])))).order_by(Environment.sort_order, Environment.name, Environment.id))] if allowed else []}


@router.patch("/sbom-runs/{run_id}/metadata")
def update_run_metadata(run_id: str, body: RunMetadataRequest, db: Session = Depends(get_db),
                        principal=Depends(current_principal), _csrf=Depends(require_csrf)):
    user = _human(principal)
    if not _can_view(db, user):
        raise HTTPException(403, "SBOM 조회 권한이 필요합니다")
    if not body.model_fields_set or any(getattr(body, field) is None for field in body.model_fields_set):
        raise HTTPException(422, "수정할 항목을 입력하세요. null 값은 사용할 수 없습니다")
    if body.releaseVersion is not None and not body.releaseVersion.strip():
        raise HTTPException(422, "릴리스 버전은 비어 있을 수 없습니다")
    try:
        # Project linking/profile writes use this lock before inspecting runs.
        # Holding it prevents a concurrent project link from being committed
        # with coordinates that a metadata edit has just changed.
        from .quality import quality_write_lock
        quality_write_lock(db)
        # Same transaction lock as upload admission: release creation and next
        # round assignment cannot race a simultaneous PostgreSQL SBOM upload.
        if db.bind and db.bind.dialect.name == "postgresql":
            key = int.from_bytes(hashlib.sha256(b"sbom-upload-admission").digest()[:8], "big", signed=True)
            db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
        initial = _run(db, run_id)
        initial_environment = initial.release.environment_id
        destination_environment = body.environmentId or initial_environment
        # Grant replacement locks the same environment rows, so revocation and
        # cross-environment edits have a serial, server-enforced order.
        environments = {item.id: item for item in db.scalars(select(Environment).where(Environment.id.in_(sorted({initial_environment, destination_environment}))).order_by(Environment.id).with_for_update().execution_options(populate_existing=True))}
        fresh_user = db.scalar(select(User).where(User.id == user.id).with_for_update().execution_options(populate_existing=True))
        user = _human(fresh_user)
        if not _can_view(db, user):
            raise HTTPException(403, "SBOM 조회 권한이 필요합니다")
        run = _run(db, run_id, lock=True)
        if run.release.environment_id != initial_environment:
            raise HTTPException(409, "회차 환경이 변경되었습니다. 다시 조회하세요")
        if not _authorized(db, user, initial_environment) or not _authorized(db, user, destination_environment):
            raise HTTPException(403, "현재 환경과 변경할 환경 모두의 관리자 권한이 필요합니다")
        service_id = body.serviceId or run.release.service_id
        version = body.releaseVersion.strip() if body.releaseVersion is not None else run.release.version
        before = {"serviceId": run.release.service_id, "environmentId": initial_environment,
                  "releaseVersion": run.release.version, "roundNumber": run.round_number, "note": run.note or ""}
        scope_changed = (service_id, destination_environment, version) != (run.release.service_id, initial_environment, run.release.version)
        if scope_changed:
            service = db.scalar(select(Service).where(Service.id == service_id).with_for_update().execution_options(populate_existing=True))
            target_environment = environments.get(destination_environment)
            if service is None or target_environment is None:
                raise HTTPException(422, "서비스 또는 환경을 찾을 수 없습니다")
            if not service.active or not target_environment.active:
                raise HTTPException(409, "활성 서비스와 환경으로만 변경할 수 있습니다")
            restriction = _scope_restriction(db, run)
            if restriction:
                raise HTTPException(409, restriction)
            release = db.scalar(select(Release).where(Release.service_id == service_id, Release.environment_id == destination_environment, Release.version == version).with_for_update())
            if release is None:
                release = Release(service_id=service_id, environment_id=destination_environment, version=version)
                db.add(release)
                db.flush()
            run.release = release
            run.release_id = release.id
            run.round_number = int(db.scalar(select(func.max(SbomRun.round_number)).where(SbomRun.release_id == release.id)) or 0) + 1
        if "note" in body.model_fields_set:
            run.note = body.note or ""
        db.flush()
        reanalysis_pending = False
        if scope_changed:
            from .project_catalog import request_native_reanalysis
            reanalysis_pending = bool(request_native_reanalysis(db, "sbom-metadata-edit", [run.id], reason="sbom_metadata_scope_changed"))
        after = {"serviceId": service_id, "environmentId": destination_environment, "releaseVersion": version,
                 "roundNumber": run.round_number, "note": run.note or ""}
        if before != after:
            audit(db, user.username, "sbom.metadata.update", "sbom_run", run.id,
                  {"before": before, "after": after, "reanalysisPending": reanalysis_pending, "originalPreserved": True})
        db.commit()
        return {"runId": run.id, **after, "reanalysisPending": reanalysis_pending}
    except (HTTPException, IntegrityError) as exc:
        db.rollback()
        if isinstance(exc, IntegrityError):
            raise HTTPException(409, "회차 또는 릴리스가 변경되었습니다. 다시 조회하세요") from exc
        raise
