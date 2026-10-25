"""Read/refresh/export optional registry metadata without performing network I/O."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import get_db
from .data_updates import reference_access
from .models import RunComponent, SbomRun
from .package_metadata import (BACKFILL_BATCH, MAX_CACHE_IMPORT, MAX_RESPONSE_BYTES, SUPPORTED_ECOSYSTEMS,
                               enqueue_components, enrich_components, iso, metadata_payload, metadata_summary,
                               parse_date, parse_purl, setting, utc)
from .version_ordering import numeric_version_distance
from .package_metadata_models import PackageMetadataCache
from .security import require_csrf, require_permission
from .services import audit
from .sbom import iter_components

router = APIRouter(prefix="/api/v1")


@router.get("/package-metadata/status")
def status(db: Session = Depends(get_db), _=Depends(require_permission("metadata.view", "metadata.manage"))):
    counts = dict(db.execute(select(PackageMetadataCache.state, func.count()).group_by(PackageMetadataCache.state)).all())
    return {"enabled": bool(setting("enabled", True)), "supportedEcosystems": list(SUPPORTED_ECOSYSTEMS),
            "counts": {state: counts.get(state, 0) for state in ("queued", "running", "completed", "failed", "unsupported")},
            "ttlSeconds": int(setting("ttl_seconds", 86400)),
            "limits": {"requestTimeoutSeconds": float(setting("request_timeout_seconds", 10)), "maxResponseBytes": MAX_RESPONSE_BYTES,
                       "maxAttempts": int(setting("max_attempts", 3)), "backfillBatch": BACKFILL_BATCH}}


@router.get("/sbom-runs/{run_id}/package-metadata")
def run_metadata(run_id: str, page: int = Query(1, ge=1), size: int = Query(25, ge=1, le=100),
                 db: Session = Depends(get_db), _=Depends(require_permission("runs.view", "metadata.view", "metadata.manage"))):
    run = db.get(SbomRun, run_id)
    if run is None:
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    query = select(RunComponent).where(RunComponent.run_id == run_id)
    total = int(db.scalar(select(func.count()).select_from(query.subquery())) or 0)
    rows = list(db.scalars(query.order_by(RunComponent.name, RunComponent.id).offset((page - 1) * size).limit(size)))
    enriched = enrich_components(db, [{"purl": row.purl, "name": row.name, "version": row.version} for row in rows])
    return {"items": [{"component": {"identityKey": row.identity_key, "name": row.name, "version": row.version, "purl": row.purl},
                       "metadata": value["packageMetadata"]} for row, value in zip(rows, enriched)],
            "total": total, "page": page, "size": size}


@router.post("/sbom-runs/{run_id}/package-metadata/refresh", status_code=202)
def refresh_run(run_id: str, db: Session = Depends(get_db), principal=Depends(require_permission("metadata.manage")),
                _csrf=Depends(require_csrf)):
    run = db.get(SbomRun, run_id)
    if run is None:
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    result = enqueue_components(db, list(iter_components((run.normalized_bom or {}).get("components", []))), force=True)
    audit(db, principal.username, "package_metadata.refresh", "sbom_run", run_id, result)
    db.commit()
    return result


@router.get("/package-metadata/export")
def export_metadata(page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=MAX_CACHE_IMPORT),
                    db: Session = Depends(get_db), _=Depends(require_permission("metadata.manage"))):
    rows = db.scalars(select(PackageMetadataCache).where(PackageMetadataCache.fetched_at.is_not(None)).order_by(PackageMetadataCache.id).offset((page - 1) * size).limit(size))
    return {"format": "koda-package-metadata-v1", "exportedAt": iso(datetime.now(UTC)),
            "items": [metadata_payload(row) for row in rows], "page": page, "size": size,
            "total": int(db.scalar(select(func.count()).select_from(PackageMetadataCache).where(PackageMetadataCache.fetched_at.is_not(None))) or 0)}


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str = Field(pattern=r"^koda-package-metadata-v1$")
    exportedAt: str
    items: list[dict] = Field(max_length=MAX_CACHE_IMPORT)
    page: int | None = None
    size: int | None = None
    total: int | None = None


@router.post("/package-metadata/import", dependencies=[Depends(reference_access)])
def import_metadata(body: ImportRequest, db: Session = Depends(get_db), principal=Depends(require_permission("metadata.manage")),
                    _csrf=Depends(require_csrf)):
    from .data_updates import reference_import_allowed
    from .config import get_settings
    try: reference_import_allowed(get_settings())
    except ValueError as exc: raise HTTPException(409,str(exc)) from exc
    # An administrator explicitly imports an offline snapshot. It is labelled
    # as imported, never misrepresented as a fresh live-registry observation.
    from .package_metadata import allowed_registry_url

    now = datetime.now(UTC)
    accepted = []
    for document in body.items:
        try:
            target = parse_purl(document.get("purl", ""), str(document.get("currentVersion") or ""))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        fetched, expires = parse_date(document.get("fetchedAt")), parse_date(document.get("expiresAt"))
        if target.ecosystem not in SUPPORTED_ECOSYSTEMS or fetched is None or expires is None or fetched > now + timedelta(minutes=5) or expires <= fetched:
            raise HTTPException(422, "메타데이터 ecosystem 또는 관측 시각이 올바르지 않습니다")
        if (expires - fetched).total_seconds() > int(setting("ttl_seconds", 86400)):
            expires = fetched + timedelta(seconds=int(setting("ttl_seconds", 86400)))
        for field in ("currentVersionPublishedAt", "latestPublishedAt"):
            if document.get(field) is not None and parse_date(document[field]) is None:
                raise HTTPException(422, "릴리스 시각에는 시간대가 필요합니다")
        latest = document.get("latestVersion")
        if not isinstance(latest, str) or not latest or len(latest) > 255:
            raise HTTPException(422, "최신 버전이 올바르지 않습니다")
        distance = document.get("versionDistance")
        if distance is not None and (type(distance) is not int or not 0 <= distance <= 1000000):
            raise HTTPException(422, "버전 거리가 올바르지 않습니다")
        parts = numeric_version_distance(target.version, latest)
        supplied_parts = document.get("versionDistanceParts")
        if supplied_parts is not None and (not isinstance(supplied_parts, dict) or any(type(value) is not int for value in supplied_parts.values()) or supplied_parts != parts):
            raise HTTPException(422, "단위별 버전 거리가 원본 버전과 일치하지 않습니다")
        field_status = document.get("fieldStatus") or {}
        if not isinstance(field_status, dict):
            raise HTTPException(422, "메타데이터 필드 상태가 올바르지 않습니다")
        document = {**document, "versionDistanceParts": parts, "versionDistancePartsBasis": "first_numeric_difference_absolute",
                    "fieldStatus": {**field_status, "versionDistanceParts": "available" if parts is not None else "unavailable"}}
        urls = document.get("sourceUrls")
        if not isinstance(urls, list) or not urls or len(urls) > 16 or any(not isinstance(url, str) or len(url) > 4096 or not allowed_registry_url(url) for url in urls):
            raise HTTPException(422, "출처 URL은 허용된 HTTPS registry여야 합니다")
        accepted.append((target, document, fetched, expires))
    imported, skipped = 0, 0
    for target, document, fetched, expires in accepted:
        row = db.scalar(select(PackageMetadataCache).where(PackageMetadataCache.id == target.id).with_for_update())
        if row and row.fetched_at and utc(row.fetched_at) > fetched:
            skipped += 1
            continue
        if row is None:
            row = PackageMetadataCache(id=target.id, package_key=target.package_key, current_version=target.version,
                                       purl=target.purl, ecosystem=target.ecosystem)
            db.add(row)
        row.document = {key: value for key, value in document.items() if key not in {"status", "error", "ageDays", "attempts"}}
        row.document = {**row.document, "sourceKind": "offline_import", "importedAt": iso(now), "importedBy": principal.username}
        row.state, row.error, row.attempts = "completed", None, 0
        row.fetched_at, row.expires_at, row.next_attempt_at = fetched, expires, expires
        imported += 1
    audit(db, principal.username, "package_metadata.import", "package_metadata", "cache", {"imported": imported, "skipped": skipped})
    db.commit()
    return {"imported": imported, "skipped": skipped}
