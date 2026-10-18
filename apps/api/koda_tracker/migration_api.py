from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import get_db
from .migration import LegacyExporter, MigrationError, apply_migration, migration_payload, stage_bundle
from .migration_models import LegacyMigration
from .security import require_admin, require_csrf, require_permission

router = APIRouter(prefix="/api/v1/legacy-migrations", tags=["Legacy migration"])


class StageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundle: dict


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    baseUrl: str = Field(max_length=2048)
    apiKey: SecretStr
    allowedOrigins: list[str] = Field(min_length=1, max_length=20)
    projectUuids: list[str] = Field(default_factory=list, max_length=10000)
    sourceTimeZone: str | None = Field(default=None, max_length=64)


class ApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expectedDigest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expectedPolicyVersion: int = Field(ge=1)
    trustSourceReviews: bool = False


@router.post("/stage", status_code=201)
def stage(body: StageRequest, db: Session = Depends(get_db), principal=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    try:
        item = stage_bundle(db, body.bundle, principal.username)
        db.commit()
        return migration_payload(item)
    except (ValueError, KeyError, TypeError) as exc:
        db.rollback()
        raise HTTPException(422, str(exc)[:2000]) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "동일한 이관 번들이 동시에 준비되었습니다. 목록에서 다시 확인하세요") from exc


@router.post("/export-stage", status_code=201)
def export_stage(body: ExportRequest, db: Session = Depends(get_db), principal=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    exporter = None
    try:
        exporter = LegacyExporter(body.baseUrl, body.apiKey.get_secret_value(), body.allowedOrigins, source_timezone=body.sourceTimeZone)
        bundle = exporter.export(body.projectUuids)
        item = stage_bundle(db, bundle, principal.username)
        db.commit()
        return migration_payload(item)
    except (ValueError, KeyError, TypeError) as exc:
        db.rollback()
        raise HTTPException(422, str(exc)[:2000]) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "동일한 이관 번들이 동시에 준비되었습니다. 목록에서 다시 확인하세요") from exc
    finally:
        if exporter:
            exporter.close()


@router.get("")
def list_migrations(page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), _=Depends(require_permission("migrations.manage"))):
    return {"items": [migration_payload(item) for item in db.scalars(select(LegacyMigration).order_by(LegacyMigration.created_at.desc()).offset((page - 1) * size).limit(size))], "total": db.scalar(select(func.count()).select_from(LegacyMigration)) or 0, "page": page, "size": size}


@router.get("/{migration_id}")
def get_migration(migration_id: str, db: Session = Depends(get_db), _=Depends(require_permission("migrations.manage"))):
    item = db.get(LegacyMigration, migration_id)
    if item is None:
        raise HTTPException(404, "이관 작업이 없습니다")
    return migration_payload(item)


@router.get("/{migration_id}/bundle")
def download_bundle(migration_id: str, db: Session = Depends(get_db), _=Depends(require_permission("migrations.manage"))):
    item = db.get(LegacyMigration, migration_id)
    if item is None:
        raise HTTPException(404, "이관 작업이 없습니다")
    return JSONResponse(item.bundle, headers={"Content-Disposition": f'attachment; filename="legacy-export-{item.id}.json"', "Cache-Control": "no-store"})


@router.post("/{migration_id}/apply")
def apply(migration_id: str, body: ApplyRequest, db: Session = Depends(get_db), principal=Depends(require_admin), _=Depends(require_permission("migrations.manage")), _csrf=Depends(require_csrf)):
    try:
        item = apply_migration(db, migration_id, expected_digest=body.expectedDigest, expected_policy_version=body.expectedPolicyVersion, actor=principal.username, actor_id=principal.id, trust_source_reviews=body.trustSourceReviews)
        db.commit()
        return migration_payload(item)
    except MigrationError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "이관 중 원본 또는 정책이 동시에 변경되었습니다. 다시 검토하세요") from exc
