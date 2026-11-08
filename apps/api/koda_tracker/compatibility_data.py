"""Authenticated storage for public reference material imported into Tracker."""
from datetime import UTC, datetime
import hashlib
import re
from threading import BoundedSemaphore
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from sqlalchemy import DateTime, JSON, LargeBinary, String, column, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column, load_only

from .compatibility_bundle import parse_compatibility_bundle
from .compatibility_sources import AUTHORITIES, MAX_ARCHIVE_BYTES
from .db import Base, get_db
from .models import new_id, now
from .security import has_any_permission, require_csrf, require_permission
from .services import audit
from .upgrade_native_versions import rpm_version_key
from .upgrade_python import python_version_key

router = APIRouter(prefix="/api/v1/compatibility-data", tags=["Official compatibility reference"])
_view_permissions = ("metadata.view", "metadata.manage")
_view = require_permission(*_view_permissions)
_manage = require_permission("metadata.manage")
_import_slot = BoundedSemaphore(1)


class CompatibilityBundle(Base):
    __tablename__ = "compatibility_bundles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    item_count: Mapped[int] = mapped_column()
    items: Mapped[list] = mapped_column(JSON, deferred=True)
    archive: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)


def can_view_references(db: Session, user) -> bool:
    return has_any_permission(db, user, *_view_permissions)


def _oracle_scope(coordinate: str):
    package_path, _, query = coordinate.removeprefix("pkg:rpm/").partition("?")
    namespace, _, package = package_path.rpartition("/")
    qualifiers = dict(parse_qsl(query))
    distro = qualifiers.get("distro", "")
    architecture = qualifiers.get("arch")
    oracle_names = {"ol", "oracle", "oraclelinux", "oracle-linux"}
    distro_match = re.fullmatch(r"(?:ol|oraclelinux|oracle-linux)-?(8|9|10)(?:\.(\d{1,2}))?", distro)
    if (architecture not in {"x86_64", "aarch64"} or (namespace and namespace not in oracle_names)
            or (distro and not distro_match) or not (namespace or distro_match)):
        return None
    return package, architecture, distro_match.groups() if distro_match else (None, None)


def matching_references(db: Session, ecosystem: str, coordinate: str, versions: set[str]) -> dict[str, list[dict]]:
    """Look up imported declarations for exact coordinates, with no external requests."""
    if not versions or "#" in coordinate:
        return {}
    architecture = major = minor = None
    if ecosystem == "maven":
        package = coordinate.removeprefix("pkg:maven/").replace("/", ":", 1)
        def version_key(value):
            return value
    elif ecosystem == "python":
        package = coordinate.removeprefix("pkg:pypi/")
        version_key = python_version_key
    elif coordinate.startswith("pkg:rpm/") and (scope := _oracle_scope(coordinate)):
        package, architecture, (major, minor) = scope
        version_key = rpm_version_key
    else:
        return {}
    expected = {version: version_key(version) for version in versions}
    expected_keys = {key for key in expected.values() if key is not None}
    if not expected_keys:
        return {}

    # Both supported databases expand JSON without loading archived bytes or unrelated packages.
    expand = func.json_each if db.get_bind().dialect.name == "sqlite" else func.json_array_elements
    item = expand(CompatibilityBundle.items).table_valued(column("value", JSON), joins_implicitly=True).c.value
    query = select(CompatibilityBundle.id, CompatibilityBundle.collected_at, item).where(
        item["ecosystem"].as_string() == ecosystem, item["package"].as_string() == package)
    if architecture:
        query = query.where(item["architecture"].as_string() == architecture)
    if ecosystem == "maven":
        query = query.where(item["version"].as_string().in_(versions))
    query = query.order_by(CompatibilityBundle.collected_at.desc(), CompatibilityBundle.imported_at.desc(),
                           CompatibilityBundle.id.desc()).execution_options(yield_per=50)
    hits: dict[object, list[dict]] = {}
    seen: dict[object, set[str]] = {}
    for bundle_id, collected_at, reference in db.execute(query):
        key = version_key(reference["version"])
        if key not in expected_keys or len(hits.get(key, ())) >= 3:
            continue
        if architecture and major:
            path = urlsplit(reference["files"][0]["url"]).path
            repo = re.match(r"/repo/OracleLinux/OL(\d+)/(?:([0-9]+)/)?", path)
            if not repo or repo[1] != major or (minor and repo[2] != minor):
                continue
        # A repeated bundle or a refreshed PyPI API response can contain the same artifact.
        artifact = next(file for file in reference["files"] if file["kind"] != "pypi_release")
        digest = artifact["sha256"]
        if digest in seen.setdefault(key, set()):
            continue
        seen[key].add(digest)
        hits.setdefault(key, []).append({**reference, "bundleId": bundle_id, "collectedAt": _utc_iso(collected_at)})
    return {version: hits[key] for version, key in expected.items() if key in hits}


def _utc_iso(timestamp: datetime) -> str:
    return timestamp.astimezone(UTC).isoformat() if timestamp.tzinfo else timestamp.replace(tzinfo=UTC).isoformat()


def _summary(row: CompatibilityBundle):
    return {"id": row.id, "sha256": row.sha256, "collectedAt": _utc_iso(row.collected_at),
            "importedAt": _utc_iso(row.imported_at), "itemCount": row.item_count}


def _get_bundle(db: Session, bundle_id: str):
    row = db.get(CompatibilityBundle, bundle_id)
    if row is None:
        raise HTTPException(404, "공식 호환성 자료를 찾을 수 없습니다")
    return row


@router.get("", dependencies=[Depends(_view)])
def list_bundles(db: Session = Depends(get_db)):
    query = select(CompatibilityBundle).options(load_only(
        CompatibilityBundle.id, CompatibilityBundle.sha256, CompatibilityBundle.collected_at,
        CompatibilityBundle.imported_at, CompatibilityBundle.item_count,
    )).order_by(CompatibilityBundle.imported_at.desc(), CompatibilityBundle.id.desc()).limit(50)
    return {"bundles": [_summary(row) for row in db.scalars(query)], "authorities": list(AUTHORITIES.values())}


@router.get("/{bundle_id}", dependencies=[Depends(_view)])
def get_bundle(bundle_id: str, db: Session = Depends(get_db)):
    row = _get_bundle(db, bundle_id)
    return {**_summary(row), "items": row.items}


@router.get("/{bundle_id}/archive", dependencies=[Depends(_view)])
def download_bundle(bundle_id: str, db: Session = Depends(get_db)):
    row = _get_bundle(db, bundle_id)
    return Response(row.archive, media_type="application/gzip", headers={
        "Content-Disposition": f'attachment; filename="compatibility-{row.sha256[:12]}.tar.gz"',
        "Cache-Control": "no-store",
    })


@router.post("/import", dependencies=[Depends(_manage), Depends(require_csrf)])
def import_bundle(file: UploadFile = File(...), db: Session = Depends(get_db), user=Depends(_manage)):
    if not file.filename or not file.filename.lower().endswith(".tar.gz"):
        raise HTTPException(422, "공식 호환성 자료의 tar.gz 파일을 선택하세요")
    if not _import_slot.acquire(blocking=False):
        raise HTTPException(429, "다른 호환성 자료를 검증하고 있습니다. 잠시 후 다시 시도하세요")
    try:
        raw = file.file.read(MAX_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise HTTPException(413, "호환성 자료 압축은 최대 16 MiB입니다")
        digest = hashlib.sha256(raw).hexdigest()
        lookup = select(CompatibilityBundle).where(CompatibilityBundle.sha256 == digest)
        row = db.scalar(lookup)
        if row is not None:
            return {**_summary(row), "items": row.items}
        try:
            parsed = parse_compatibility_bundle(raw)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        row = CompatibilityBundle(sha256=digest, collected_at=datetime.fromisoformat(parsed["collectedAt"]),
                                  item_count=len(parsed["items"]), items=parsed["items"], archive=raw)
        db.add(row)
        try:
            db.flush()
            audit(db, user.username, "compatibility_bundle.import", "compatibility_bundle", row.id,
                  {"sha256": digest, "itemCount": row.item_count, "profile": parsed["profile"]})
            db.commit()
        except IntegrityError:
            db.rollback()
            row = db.scalar(lookup)
            if row is None:
                raise
        return {**_summary(row), "items": row.items}
    finally:
        _import_slot.release()
