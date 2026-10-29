"""Safe, offline vulnerability-data package lifecycle.

The API can use this module without knowing the on-disk layout.  Consumers only
read ``current``; this module is the sole writer and switches that symlink
atomically after a complete composite release has been built.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
import re
import sys
from contextlib import contextmanager
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import Depends
from .security import require_permission
from .config import Settings
from .offline_intelligence import load_intelligence, normalize_source
from .streaming_nvd import NvdShapeError, read_nvd

DataType = Literal["grype-db", "vuln-data", "unified"]
VULN_FILES = ("nvd.json", "nvd-data.json", "kev.json", "cisa-kev.json", "alias-index.json", "aliases.json", "epss.csv", "epss.csv.gz", "intelligence.json", "intelligence-sources")
INTELLIGENCE_KEYS = {"EPSS_SNAPSHOT", "EPSS_SHA256", "EPSS_DATASET_DATE", "INTELLIGENCE_INDEX", "INTELLIGENCE_SHA256"}


class DataUpdateError(ValueError):
    """A package or lifecycle operation failed validation."""


@dataclass(frozen=True)
class Package:
    kind: DataType
    version: str
    root: Path
    metadata: dict[str, str]
    manifest_sha256: str


@dataclass(frozen=True)
class Release:
    version: str
    path: Path
    kind: DataType | None = None


@dataclass(frozen=True)
class Limits:
    max_members: int = 100_000
    max_file_bytes: int = 4 * 1024 * 1024 * 1024
    max_total_bytes: int = 12 * 1024 * 1024 * 1024


def _root(settings: Settings) -> Path:
    return settings.grype_db_dir.parent.parent


def managed_state(settings: Settings) -> dict | None:
    if not getattr(settings, "grype_db_dir", None): return None
    path = _root(settings) / ".managed.json"
    if not path.exists() and not path.is_symlink(): return None
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {"state": "unavailable"}
    except (OSError, ValueError): return {"state": "unavailable"}


def approval_required(settings: Settings) -> bool:
    return managed_state(settings) is not None or (getattr(settings,"offline_mode",False) and sys.platform.startswith("linux"))


def reference_import_allowed(settings: Settings) -> None:
    state = managed_state(settings)
    if (state is not None and state.get("state") != "active") or (approval_required(settings) and state is None):
        raise DataUpdateError("승인된 통합 데이터가 없습니다. 서명된 통합 파일을 먼저 반입·적용하십시오")


@contextmanager
def release_read_lease(settings: Settings):
    root = _root(settings)
    path = root / ".release.lock"
    if not path.is_file():
        if managed_state(settings) is not None:
            raise DataUpdateError("승인된 자료의 읽기 잠금이 없습니다. 관리자 확인이 필요합니다")
        yield
        return
    handle = path.open("rb")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield
    except BlockingIOError as exc:
        raise DataUpdateError("취약점 데이터 적용·삭제가 진행 중입니다. 완료 후 다시 점검하십시오") from exc
    finally:
        handle.close()


def release_busy(settings):
    lock = _root(settings) / ".release.lock"
    if not lock.is_file(): return False
    try:
        with lock.open("rb") as handle:
            try: fcntl.flock(handle.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: return True
            finally: fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
        return False
    except OSError: return True


def reference_access(_principal=Depends(require_permission("metadata.manage"))):
    """FastAPI yield dependency: hold a reader lease through import commit."""
    from .config import get_settings
    from fastapi import HTTPException
    try:
        with release_read_lease(get_settings()):
            reference_import_allowed(get_settings())
            yield
    except DataUpdateError as exc:
        raise HTTPException(409,str(exc)) from exc


def _file_identity(path):
    if path.is_symlink() or not path.is_file(): raise DataUpdateError("승인된 데이터 파일이 없거나 링크로 변경되었습니다")
    stat = path.stat()
    return (str(path),stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns)


@lru_cache(maxsize=8)
def _verify_approved_files(release_name, key_name, file_identities):
    # The cache key includes inode, size, mtime and ctime for EVERY signed file,
    # original metadata, proof/signature, runtime metadata and registered key.
    # A changed file is hashed again; unchanged multi-GB DBs need no polling I/O.
    release = Path(release_name); key = Path(key_name)
    metadata = release / "approved-metadata.env"
    manifest = release / "approved-manifest.sha256"
    signature = release / "approved-manifest.sha256.sig"
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature), str(manifest)], capture_output=True,timeout=30,check=False)
    if result.returncode != 0: raise DataUpdateError("승인된 데이터의 서명 근거가 변경되었습니다")
    for line in manifest.read_text().splitlines():
        checksum, name = line.split()
        name = name.removeprefix("./")
        path = metadata if name == "metadata.env" else release / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink() or not path.is_file() or _sha256(path) != checksum:
            raise DataUpdateError("승인된 데이터 파일이 변경되었거나 없습니다: " + name)
    approved = _metadata(metadata)
    actual = _metadata(release / "metadata.env")
    if _dataset_metadata(approved, "unified") != {key: actual.get(key) for key in _dataset_metadata(approved, "unified")}:
        # BUNDLE_VERSION can change when importing the same source version again.
        expected = _dataset_metadata(approved, "unified"); expected.pop("BUNDLE_VERSION", None)
        if any(actual.get(key) != value for key,value in expected.items()): raise DataUpdateError("승인 데이터 메타데이터가 변경되었습니다")


def assert_approved_release(settings: Settings, release: Path | None) -> None:
    if not approval_required(settings): return
    state = managed_state(settings)
    if not state or state.get("state") != "active" or release is None or state.get("currentVersion") != release.name:
        raise DataUpdateError("승인된 통합 취약점 데이터가 없습니다. 반입·검증·적용 후 다시 점검하십시오")
    key = settings.data_update_verify_key or os.environ.get("KODA_RELEASE_VERIFY_KEY")
    if not key or not Path(key).is_file(): raise DataUpdateError("등록된 검증키를 찾을 수 없습니다")
    if not (release.parent.parent / ".release.lock").is_file(): raise DataUpdateError("승인된 데이터의 읽기 잠금이 없습니다")
    manifest = release / "approved-manifest.sha256"
    if not manifest.is_file() or manifest.stat().st_size > 16 * 1024 * 1024: raise DataUpdateError("승인된 manifest가 없거나 제한을 초과합니다")
    paths = [manifest,release / "approved-metadata.env",release / "approved-manifest.sha256.sig",release / "metadata.env",Path(key)]
    for line in manifest.read_text().splitlines():
        parts = line.split()
        if len(parts) != 2: raise DataUpdateError("승인 manifest 형식이 잘못되었습니다")
        _, name = parts; name = name.removeprefix("./")
        if Path(name).is_absolute() or ".." in Path(name).parts: raise DataUpdateError("승인 manifest 경로가 잘못되었습니다")
        paths.append(release / "approved-metadata.env" if name == "metadata.env" else release / name)
    expected = {str(path.relative_to(release)) for path in paths if path != Path(key)}
    expected.add("manifest.sha256")  # runtime composite manifest, not a publisher input
    for path in release.rglob("*"):
        if path.is_symlink(): raise DataUpdateError("승인된 릴리스에 링크가 추가되었습니다")
        if path.is_file() and path.relative_to(release).as_posix() not in expected:
            raise DataUpdateError("승인되지 않은 파일이 추가되었습니다: " + path.relative_to(release).as_posix())
    identities = tuple(_file_identity(path) for path in paths)
    _verify_approved_files(str(release),str(key),identities)


def purge_reference_database(db, *, job_id):
    """Delete external reference contents; operational history stays immutable."""
    from sqlalchemy import delete, select
    from .models import Job, JobState, ProcessingState, SbomRun, VulnerabilityDataBundle
    from .offline_intelligence_models import OfflineReferenceCurrent, OfflineReferenceSnapshot
    from .package_metadata_models import PackageMetadataCache, PackageMetadataCursor
    from .vulnerability_intelligence_models import VulnerabilityIntelligence, IntelligenceCursor
    from .project_catalog_models import NativeReanalysisPending
    summary = {}
    for model in (OfflineReferenceCurrent, OfflineReferenceSnapshot, PackageMetadataCache, PackageMetadataCursor, VulnerabilityIntelligence, IntelligenceCursor, NativeReanalysisPending):
        result = db.execute(delete(model)); summary[model.__tablename__] = result.rowcount
    for bundle in db.scalars(select(VulnerabilityDataBundle)):
        bundle.active = False
    for queued in db.scalars(select(Job).where(Job.id != job_id, Job.state == JobState.QUEUED)):
        if queued.kind in {"analyze", "process_run", "data_update", "vulnerability_data_update"}:
            queued.state, queued.error = JobState.FAILED, "취약점 데이터 전체 삭제로 취소됨. 통합 파일 반입·적용 후 다시 요청하십시오"
            if queued.run_id:
                run = db.get(SbomRun, queued.run_id)
                if run and run.archived_at is None:
                    run.analysis_state, run.state = JobState.FAILED, ProcessingState.FAILED
    for prior in db.scalars(select(Job).where(Job.id != job_id, Job.kind.in_(["data_update","vulnerability_data_update"]))):
        if (prior.payload or {}).get("phase") == "validated":
            prior.payload = {**prior.payload,"phase":"purged"}
            prior.error = "참조 자료 전체 삭제로 검증 파일이 제거되었습니다. 통합 파일을 다시 반입하십시오"
    db.flush()
    return summary


def _safe_version(version: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", version)) and version not in {".", ".."}


def _dataset_metadata(metadata: dict[str, str], kind: DataType) -> dict[str, str]:
    common = {"DATASET_DATE", "BUNDLE_VERSION"}
    allowed = common | ({"GRYPE_DB_SCHEMA", "GRYPE_DATASET_DATE"} if kind == "grype-db" else {
        "NVD_INDEX", "NVD_DATASET_DATE", "NVD_SHA256", "KEV_CATALOG", "KEV_DATASET_DATE", "KEV_SHA256", "ALIAS_INDEX", "ALIAS_SHA256", *INTELLIGENCE_KEYS
    })
    if kind == "unified":
        allowed |= {"GRYPE_DB_SCHEMA", "GRYPE_DATASET_DATE"}
    return {key: value for key, value in metadata.items() if key in allowed}


def _validate_intelligence(root: Path, metadata: dict[str, str]) -> set[str]:
    allowed = set()
    try:
        if any((root / name).exists() for name in ("epss.csv", "epss.csv.gz")) and "EPSS_SNAPSHOT" not in metadata:
            raise DataUpdateError("undeclared EPSS snapshot")
        if any((root / name).exists() for name in ("intelligence.json", "intelligence-sources")) and "INTELLIGENCE_INDEX" not in metadata:
            raise DataUpdateError("undeclared intelligence index")
        if "EPSS_SNAPSHOT" in metadata:
            name = metadata["EPSS_SNAPSHOT"]
            path = root / name
            if name not in {"epss.csv", "epss.csv.gz"} or not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
                raise DataUpdateError("invalid EPSS_SNAPSHOT")
            raw = path.read_bytes()
            normalized = normalize_source("epss", raw, {"id": "epss"})
            if hashlib.sha256(raw).hexdigest() != metadata.get("EPSS_SHA256") or normalized["sources"][0]["dataDate"] != metadata.get("EPSS_DATASET_DATE"):
                raise DataUpdateError("EPSS source metadata mismatch")
            allowed.add(name)
        if "INTELLIGENCE_INDEX" in metadata:
            if metadata["INTELLIGENCE_INDEX"] != "intelligence.json":
                raise DataUpdateError("invalid INTELLIGENCE_INDEX")
            path = root / "intelligence.json"
            if _sha256(path) != metadata.get("INTELLIGENCE_SHA256"):
                raise DataUpdateError("INTELLIGENCE_SHA256 mismatch")
            document = load_intelligence(root)
            allowed.add("intelligence.json")
            allowed.update(source["sourceFile"] for dataset in document["datasets"].values() for source in dataset["sources"])
        return allowed
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise DataUpdateError(f"offline intelligence validation failed: {exc}") from exc


def _metadata(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def _manifest(root: Path) -> tuple[str, dict[str, str]]:
    manifest = root / "manifest.sha256"
    if not manifest.is_file():
        raise DataUpdateError("manifest.sha256 is required")
    expected: dict[str, str] = {}
    if manifest.stat().st_size > 16 * 1024 * 1024:
        raise DataUpdateError("manifest is too large")
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            raise DataUpdateError("invalid manifest entry")
        digest, name = parts
        name = name.removeprefix("./")
        if not name or name.startswith("/") or "\\" in name or "//" in name or any(part in {"", ".", ".."} for part in name.split("/")):
            raise DataUpdateError("invalid manifest path")
        if len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise DataUpdateError("invalid manifest digest")
        path = (root / name).resolve()
        if root.resolve() not in path.parents or not path.is_file() or name in {"manifest.sha256", "manifest.sha256.sig"}:
            raise DataUpdateError("manifest path escapes package")
        if name in expected:
            raise DataUpdateError("duplicate manifest entry")
        expected[name] = digest.lower()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {"manifest.sha256", "manifest.sha256.sig"}:
            continue
        rel = path.relative_to(root).as_posix()
        if rel not in expected:
            raise DataUpdateError(f"manifest missing entry: {rel}")
        digest = _sha256(path)
        if digest != expected[rel]:
            raise DataUpdateError(f"manifest checksum mismatch: {rel}")
    return hashlib.sha256(manifest.read_bytes()).hexdigest(), expected


def _validate_tree(root: Path, kind: DataType, *, allow_legacy: bool = False) -> tuple[dict[str, str], str]:
    metadata_file = root / "metadata.env"
    if not metadata_file.is_file():
        raise DataUpdateError("metadata.env is required")
    if metadata_file.stat().st_size > 65536:
        raise DataUpdateError("metadata is too large")
    metadata = _metadata(metadata_file)
    for key, allowed_names in {"NVD_INDEX": {"nvd.json", "nvd-data.json"}, "KEV_CATALOG": {"kev.json", "cisa-kev.json"}, "ALIAS_INDEX": {"alias-index.json", "aliases.json"}}.items():
        if key in metadata and metadata[key] not in allowed_names:
            raise DataUpdateError(f"invalid {key}")
    declared = metadata.get("DATASET_TYPE")
    if not declared and not allow_legacy:
        raise DataUpdateError("DATASET_TYPE is required")
    if declared and declared != kind:
        raise DataUpdateError(f"package DATASET_TYPE is {declared!r}, expected {kind!r}")
    version = metadata.get("BUNDLE_VERSION", "")
    if not _safe_version(version):
        raise DataUpdateError("invalid BUNDLE_VERSION")
    allowed: set[str] = {"metadata.env", "manifest.sha256", "manifest.sha256.sig", "collection.json"}
    if kind in {"grype-db", "unified"}:
        schema = metadata.get("GRYPE_DB_SCHEMA", "")
        if not schema.isdigit():
            raise DataUpdateError("invalid GRYPE_DB_SCHEMA")
        db = root / "grype-db" / schema / "vulnerability.db"
        if not db.is_file():
            raise DataUpdateError("grype-db schema database is missing")
        if not (db.parent / "import.json").is_file():
            raise DataUpdateError("grype-db schema import metadata is missing")
        allowed.add("grype-db")
    if kind in {"vuln-data", "unified"}:
        nvd = next((root / name for name in ("nvd.json", "nvd-data.json") if (root / name).is_file()), None)
        if nvd is None:
            raise DataUpdateError("vuln-data requires nvd.json")
        try:
            read_nvd(nvd)
            kev = root / metadata.get("KEV_CATALOG", "kev.json")
            if kev.parent != root or not kev.is_file():
                raise DataUpdateError("vuln-data requires kev.json")
            payload = json.loads(kev.read_text(encoding="utf-8"))
        except NvdShapeError as exc:
            raise DataUpdateError("NVD data must contain vulnerabilities") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DataUpdateError("invalid vulnerability JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise DataUpdateError("KEV catalog must contain vulnerabilities")
        allowed.update({nvd.name, kev.name, "alias-index.json", "aliases.json"})
        allowed.update(_validate_intelligence(root, metadata))
        if kind == "unified" and not metadata.get("EPSS_SNAPSHOT"):
            raise DataUpdateError("통합 자료에 공식 EPSS 원본이 필요합니다")
    for path in root.rglob("*"):
        if path.is_file() and path.relative_to(root).parts[0] not in allowed and path.relative_to(root).as_posix() not in allowed:
            raise DataUpdateError(f"unexpected package file: {path.relative_to(root)}")
    digest, _ = _manifest(root)
    return metadata, digest


def _write_manifest(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in {"manifest.sha256", "manifest.sha256.sig"}:
            lines.append(f"{_sha256(path)}  {path.relative_to(root).as_posix()}")
    manifest = root / "manifest.sha256"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


def _publish_permissions(root: Path) -> None:
    # Public CVE data is shared read-only by different container UIDs.
    for path in root.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    root.chmod(0o755)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(archive: Path, destination: Path, limits: Limits) -> None:
    try:
        handle = tarfile.open(archive, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise DataUpdateError("invalid gzip tar package") from exc
    with handle:
        members = handle.getmembers()
        if len(members) > limits.max_members:
            raise DataUpdateError("package has too many members")
        names: set[str] = set()
        total = 0
        for member in members:
            name = member.name
            if not name or name.startswith("/") or "\\" in name or any(part in {"", ".", ".."} for part in name.split("/")):
                raise DataUpdateError("package path traversal")
            if name in names:
                raise DataUpdateError("duplicate package member")
            names.add(name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise DataUpdateError("links and special files are not allowed")
            target = (destination / name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise DataUpdateError("package path traversal")
            if member.isfile():
                if member.size > limits.max_file_bytes:
                    raise DataUpdateError("package member exceeds size limit")
                total += member.size
                if total > limits.max_total_bytes:
                    raise DataUpdateError("package exceeds size limit")
        try:
            handle.extractall(destination, filter="data")
        except (OSError, tarfile.TarError) as exc:
            raise DataUpdateError("package extraction failed") from exc


def _expanded_size(archive: Path, limits: Limits) -> int:
    try:
        with tarfile.open(archive, "r:gz") as handle:
            total = 0
            count = 0
            for member in handle:
                count += 1
                if count > limits.max_members:
                    raise DataUpdateError("package has too many members")
                if member.isfile():
                    if member.size > limits.max_file_bytes:
                        raise DataUpdateError("package member exceeds size limit")
                    total += member.size
                    if total > limits.max_total_bytes:
                        raise DataUpdateError("package exceeds size limit")
            return total
    except (OSError, tarfile.TarError) as exc:
        raise DataUpdateError("invalid gzip tar package") from exc


def validate_package(archive: str | Path, kind: DataType, *, limits: Limits | None = None) -> Package:
    """Validate without touching the runtime data directory."""
    limits = limits or Limits()
    archive = Path(archive)
    if not archive.is_file():
        raise DataUpdateError("package does not exist")
    with tempfile.TemporaryDirectory(prefix="koda-data-validate-") as temporary:
        root = Path(temporary)
        _extract(archive, root, limits)
        # Builders may wrap files in one directory; accept that only when the
        # wrapper contains no competing paths.
        entries = list(root.iterdir())
        if len(entries) == 1 and entries[0].is_dir() and not (root / "metadata.env").exists():
            root = entries[0]
        metadata, digest = _validate_tree(root, kind)
        return Package(kind, metadata["BUNDLE_VERSION"], root, metadata, digest)


class DataUpdateEngine:
    def __init__(self, settings: Settings, *, limits: Limits | None = None, runner: Callable[..., subprocess.CompletedProcess] | None = None, read_only: bool = False):
        self.settings = settings
        self.root = _root(settings)
        self.limits = limits or Limits()
        self.runner = runner or subprocess.run
        if read_only: return
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(self.root.stat().st_mode | 0o055)
        lease = self.root / ".release.lock"
        lease.touch(exist_ok=True)
        lease.chmod(0o644)

    @contextmanager
    def exclusive_access(self):
        if getattr(self, "_writer_lease", None) is not None:
            yield
            return
        handle = (self.root / ".release.lock").open("a+b")
        try:
            try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc: raise DataUpdateError("분석 또는 데이터 작업이 진행 중입니다. 완료 후 재시도하십시오") from exc
            self._writer_lease = handle
            yield
        finally:
            self._writer_lease = None
            handle.close()

    def write_managed(self, state, *, version=None, job_id=None):
        marker = self.root / ".managed.json"
        temporary = self.root / (".managed-" + uuid.uuid4().hex)
        document = {"format": "koda-managed-vulnerability-data-v1", "state": state, "currentVersion": version, "jobId": job_id, "updatedAt": datetime.now(timezone.utc).isoformat()}
        try:
            with temporary.open("w") as handle:
                json.dump(document, handle); handle.flush(); os.fsync(handle.fileno())
            temporary.chmod(0o644)
            os.replace(temporary, marker)
            descriptor = os.open(self.root, os.O_RDONLY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        finally: temporary.unlink(missing_ok=True)

    def _verify_signature(self, root):
        key = self.settings.data_update_verify_key or os.environ.get("KODA_RELEASE_VERIFY_KEY")
        signature = root / "manifest.sha256.sig"
        if not key or not Path(key).is_file() or not signature.is_file() or signature.stat().st_size > 65536:
            raise DataUpdateError("등록된 검증키와 manifest.sha256.sig 서명이 필요합니다")
        result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature), str(root / "manifest.sha256")], capture_output=True, timeout=30, check=False)
        if result.returncode != 0: raise DataUpdateError("통합 자료의 서명 검증에 실패했습니다")

    def purge_files(self, *, expected_base_version=None, job_id=None):
        with self.exclusive_access():
            lock = self._lock()
            try:
                current = self.current()
                if expected_base_version is not None and (current is None or current.version != expected_base_version):
                    raise DataUpdateError("현재 데이터가 변경되었습니다. 상태를 새로 조회하십시오")
                self.write_managed("purging", job_id=job_id)
                for name in ("current", "previous"):
                    path = self.root / name
                    if path.is_symlink(): path.unlink()
                    elif path.exists(): shutil.rmtree(path) if path.is_dir() else path.unlink()
                for name in ("releases", "staging"):
                    path = self.root / name
                    if path.is_symlink(): path.unlink()
                    elif path.exists(): shutil.rmtree(path)
                for path in self.root.glob("legacy-source-*"):
                    if path.is_dir() and not path.is_symlink(): shutil.rmtree(path)
                    else: path.unlink(missing_ok=True)
                self.write_managed("purged", job_id=job_id)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN); lock.close()

    def _ensure_space(self, required: int) -> None:
        if shutil.disk_usage(self.root).free < required:
            raise DataUpdateError("insufficient disk space for offline data update")

    def _lock(self):
        self.root.mkdir(parents=True, exist_ok=True)
        handle = open(self.root / ".update.lock", "a+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def current(self) -> Release | None:
        pointer = self.root / "current"
        if not pointer.is_symlink():
            return None
        target = pointer.resolve()
        releases = (self.root / "releases").resolve()
        return Release(target.name, target) if target.is_dir() and releases in target.parents else None

    def status(self) -> dict[str, object]:
        current = self.current()
        previous = (self.root / "previous").resolve() if (self.root / "previous").is_symlink() else None
        return {"current": current.version if current else None, "previous": previous.name if previous and previous.is_dir() else None}

    def migrate_legacy(self, *, version: str = "legacy") -> Release:
        """Import an existing complete ``current`` tree into immutable releases."""
        if not _safe_version(version):
            raise DataUpdateError("invalid migration version")
        lock = self._lock()
        try:
            current_link = self.root / "current"
            if not current_link.exists():
                raise DataUpdateError("legacy current data is unavailable")
            current = current_link.resolve()
            releases = (self.root / "releases").resolve()
            if releases in current.parents:
                existing = _metadata(current / "metadata.env")
                if existing.get("DATASET_TYPE") == "composite" and existing.get("GRYPE_DB_VERSION") and existing.get("VULN_DATA_VERSION") and all(p.stat().st_mode & 0o004 for p in current.rglob("*") if p.is_file()):
                    self._validate_composite(current)
                    return Release(current.name, current)
            staging = self.root / "staging"
            staging.mkdir(exist_ok=True)
            migrated = staging / f"migration-{uuid.uuid4().hex}"
            shutil.copytree(current, migrated, symlinks=False)
            metadata = _metadata(migrated / "metadata.env")
            metadata["BUNDLE_VERSION"] = version
            metadata["DATASET_TYPE"] = "composite"
            metadata.setdefault("GRYPE_DATASET_DATE", metadata.get("DATASET_DATE", "unknown"))
            metadata.setdefault("GRYPE_DB_VERSION", metadata.get("BUNDLE_VERSION", version))
            metadata.setdefault("VULN_DATA_VERSION", metadata.get("BUNDLE_VERSION", version))
            (migrated / "metadata.env").write_text("".join(f"{key}={value}\n" for key, value in sorted(metadata.items())), encoding="utf-8")
            _write_manifest(migrated)
            self._validate_composite(migrated)
            releases_dir = self.root / "releases"
            releases_dir.mkdir(exist_ok=True)
            final = releases_dir / version
            if final.exists():
                raise DataUpdateError("migration release already exists")
            _publish_permissions(migrated)
            os.replace(migrated, final)
            if current.is_dir() and releases in current.parents:
                self._swap_pointer("previous", current)
            if current_link.is_dir() and not current_link.is_symlink():
                os.replace(current_link, self.root / f"legacy-source-{uuid.uuid4().hex}")
            self._swap_pointer("current", final)
            return Release(version, final)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def stage(self, archive: str | Path, kind: DataType, *, expected_base_version: str | None = None) -> Package:
        current = self.current()
        if approval_required(self.settings) and kind != "unified":
            raise DataUpdateError("통합 관리 모드에서는 통합 파일만 반입할 수 있습니다")
        if current is None and kind != "unified":
            raise DataUpdateError("immutable base release is required; migrate legacy data first")
        if expected_base_version is not None and (current is None or current.version != expected_base_version):
            raise DataUpdateError("current release changed; retry with a fresh base version")
        expanded = _expanded_size(Path(archive), self.limits)
        # Keep room for the staged tree and the immutable composite copy.
        self._ensure_space(max(expanded * 2 + 64 * 1024 * 1024, 64 * 1024 * 1024))
        staging = self.root / "staging"
        staging.mkdir(exist_ok=True)
        destination = staging / f"package-{uuid.uuid4().hex}"
        destination.mkdir()
        try:
            # Re-extract into an owned staging directory; Package.root is temporary.
            _extract(Path(archive), destination, self.limits)
            entries = list(destination.iterdir())
            if len(entries) == 1 and entries[0].is_dir() and not (destination / "metadata.env").exists():
                wrapped = entries[0]
                for item in wrapped.iterdir():
                    shutil.move(str(item), destination / item.name)
                wrapped.rmdir()
            if kind == "unified":
                self._verify_signature(destination)
            metadata, digest = _validate_tree(destination, kind)
            if kind in {"grype-db", "unified"}:
                self._validate_grype(destination)
            return Package(kind, metadata["BUNDLE_VERSION"], destination, metadata, digest)
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise

    def _validate_grype(self, package_root: Path) -> None:
        env = os.environ.copy()
        env.update(GRYPE_DB_CACHE_DIR=str(package_root / "grype-db"), GRYPE_DB_AUTO_UPDATE="false", GRYPE_DB_VALIDATE_AGE="false", GRYPE_CHECK_FOR_APP_UPDATE="false", GRYPE_EXTERNAL_SOURCES_ENABLE="false")
        binaries = [self.settings.grype_binary]
        if self.settings.data_update_koda_grype_binary and self.settings.data_update_koda_grype_binary not in binaries:
            binaries.append(self.settings.data_update_koda_grype_binary)
        for binary in binaries:
            result = self.runner([binary, "db", "status", "-o", "json"], env=env, capture_output=True, text=True, timeout=60, check=False)
            if result.returncode != 0:
                raise DataUpdateError((result.stderr or f"Grype database validation failed: {binary}")[-1000:])
            try:
                status = json.loads(getattr(result, "stdout", ""))
            except (TypeError, json.JSONDecodeError) as exc:
                raise DataUpdateError(f"invalid Grype status response: {binary}") from exc
            if not isinstance(status, dict):
                raise DataUpdateError(f"invalid Grype status response: {binary}")
            if status.get("valid") is not True:
                raise DataUpdateError(f"Grype database is invalid: {binary}")
            expected_schema = _metadata(package_root / "metadata.env").get("GRYPE_DB_SCHEMA")
            actual_schema = str(status.get("schemaVersion", ""))
            if not expected_schema or not actual_schema or actual_schema.lstrip("v").split(".", 1)[0] != expected_schema:
                raise DataUpdateError(f"Grype schema mismatch: {binary}")
            status_path = status.get("path")
            if not status_path or Path(status_path).resolve().parent != (package_root / "grype-db" / expected_schema).resolve():
                raise DataUpdateError(f"Grype status path mismatch: {binary}")
            smoke_dir = self.root / "staging"
            smoke_dir.mkdir(parents=True, exist_ok=True)
            smoke = smoke_dir / f".smoke-{uuid.uuid4().hex}.cdx.json"
            try:
                smoke.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [{"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}), encoding="utf-8")
                result = self.runner([binary, f"sbom:{smoke}", "-o", "json"], env=env, capture_output=True, text=True, timeout=60, check=False)
                if result.returncode != 0:
                    raise DataUpdateError((result.stderr or f"Grype smoke scan failed: {binary}")[-1000:])
                try:
                    smoke_payload = json.loads(getattr(result, "stdout", ""))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise DataUpdateError(f"invalid Grype smoke response: {binary}") from exc
                if not isinstance(smoke_payload, dict) or "matches" not in smoke_payload:
                    raise DataUpdateError(f"invalid Grype smoke response: {binary}")
            finally:
                smoke.unlink(missing_ok=True)

    def apply(self, package: Package, *, expected_base_version: str | None = None, job_id: str | None = None) -> Release:
        lock = self._lock()
        try:
            with self.exclusive_access():
                return self._apply_locked(package, expected_base_version=expected_base_version, job_id=job_id)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def compensate_activation(self, *, release_version: str, job_id: str) -> bool:
        """Restore preactivation pointers after a failed DB projection.

        A concurrent successful activation owns current and is never overwritten.
        Files remain immutable for audit/recovery; only this job's pointers move.
        """
        lock = self._lock()
        try:
            current = self.current()
            if current is None or current.version != release_version:
                return False
            metadata = _metadata(current.path / "metadata.env")
            if metadata.get("DATA_UPDATE_JOB_ID") != job_id:
                return False
            base = metadata.get("DATA_UPDATE_BASE_RELEASE", "")
            if not _safe_version(base):
                (self.root / "current").unlink(missing_ok=True)
                (self.root / "previous").unlink(missing_ok=True)
                self.write_managed("unavailable", job_id=job_id)
                return True
            target = self.root / "releases" / base
            if target.is_symlink() or not target.is_dir():
                raise DataUpdateError("activation compensation base is invalid")
            self._validate_composite(target)
            prior = metadata.get("DATA_UPDATE_PREVIOUS_RELEASE", "")
            if prior:
                if not _safe_version(prior) or not (self.root / "releases" / prior).is_dir():
                    raise DataUpdateError("activation compensation previous is invalid")
                self._swap_pointer("previous", self.root / "releases" / prior)
            else:
                (self.root / "previous").unlink(missing_ok=True)
            self._swap_pointer("current", target)
            if managed_state(self.settings) is not None:
                self.write_managed("active", version=target.name, job_id=job_id)
            return True
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def _apply_locked(self, package: Package, *, expected_base_version: str | None = None, job_id: str | None = None) -> Release:
        if approval_required(self.settings) and package.kind != "unified":
            raise DataUpdateError("통합 관리 모드에서는 서명된 통합 파일만 적용할 수 있습니다")
        current = self.current()
        if expected_base_version is not None and (current is None or current.version != expected_base_version):
            raise DataUpdateError("current release changed; retry with a fresh base version")
        staging_root = (self.root / "staging").resolve()
        package_root = package.root.resolve()
        if staging_root not in package_root.parents or not package_root.is_dir():
            raise DataUpdateError("staged package is outside the update spool")
        if package.kind == "unified":
            self._verify_signature(package_root)
        metadata, package_manifest = _validate_tree(package_root, package.kind)
        if package_manifest != package.manifest_sha256:
            raise DataUpdateError("staged package changed after validation")
        releases = self.root / "releases"
        staging = self.root / "staging"
        releases.mkdir(exist_ok=True)
        version = package.version
        if (releases / version).exists():
            version = f"{version}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        composite = staging / f"composite-{uuid.uuid4().hex}"
        if package.kind != "unified" and current and current.path.is_dir():
            shutil.copytree(current.path, composite, symlinks=False)
        else:
            composite.mkdir()
        names = ["grype-db"] if package.kind == "grype-db" else (["grype-db", "collection.json", *VULN_FILES] if package.kind == "unified" else VULN_FILES)
        for stale in names:
            stale_path = composite / stale
            if stale_path.exists():
                if stale_path.is_dir():
                    shutil.rmtree(stale_path)
                else:
                    stale_path.unlink()
        for name in names:
            item = package.root / name
            if not item.exists():
                continue
            destination = composite / name
            if item.is_dir():
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(item, destination, symlinks=False)
            else:
                shutil.copy2(item, destination)
        if package.kind == "unified":
            (composite / "approved-metadata.env").write_bytes((package.root / "metadata.env").read_bytes())
            (composite / "approved-manifest.sha256").write_bytes((package.root / "manifest.sha256").read_bytes())
            (composite / "approved-manifest.sha256.sig").write_bytes((package.root / "manifest.sha256.sig").read_bytes())
        metadata = _metadata(composite / "metadata.env") if (composite / "metadata.env").is_file() else {}
        if package.kind == "vuln-data":
            for key in INTELLIGENCE_KEYS:
                metadata.pop(key, None)
        metadata.update(_dataset_metadata(package.metadata, package.kind))
        metadata["BUNDLE_VERSION"] = version
        metadata["DATASET_TYPE"] = "composite"
        metadata[f"{package.kind.upper().replace('-', '_')}_VERSION"] = package.version
        metadata["DATA_UPDATE_BASE_RELEASE"] = current.version if current else ""
        previous = self.root / "previous"
        prior = previous.resolve() if previous.is_symlink() else None
        metadata["DATA_UPDATE_PREVIOUS_RELEASE"] = prior.name if prior and prior.is_dir() and prior.parent == releases.resolve() else ""
        if job_id:
            metadata["DATA_UPDATE_JOB_ID"] = job_id
        (composite / "metadata.env").write_text("".join(f"{key}={value}\n" for key, value in sorted(metadata.items())), encoding="utf-8")
        _write_manifest(composite)
        self._validate_composite(composite)
        final = releases / version
        _publish_permissions(composite)
        os.replace(composite, final)
        if current:
            self._swap_pointer("previous", current.path)
        current_pointer = self.root / "current"
        if current_pointer.exists() and not current_pointer.is_symlink():
            # A first unified import replaces an old in-place installation;
            # quarantine it without granting it any fallback authority.
            os.replace(current_pointer, self.root / ("legacy-source-" + uuid.uuid4().hex))
        self._swap_pointer("current", final)
        if package.kind == "unified":
            self.write_managed("active", version=version, job_id=job_id)
        shutil.rmtree(package.root, ignore_errors=True)
        return Release(version, final, package.kind)

    def _validate_composite(self, root: Path) -> None:
        metadata = _metadata(root / "metadata.env")
        schema = metadata.get("GRYPE_DB_SCHEMA", "")
        if not schema.isdigit() or not (root / "grype-db" / schema / "vulnerability.db").is_file():
            raise DataUpdateError("composite Grype database is incomplete")
        if not (root / "grype-db" / schema / "import.json").is_file():
            raise DataUpdateError("composite Grype import metadata is missing")
        nvd = next((root / name for name in ("nvd.json", "nvd-data.json") if (root / name).is_file()), None)
        kev = root / metadata.get("KEV_CATALOG", "kev.json")
        if nvd is None or kev.parent != root or not kev.is_file():
            raise DataUpdateError("composite vulnerability data is incomplete")
        try:
            read_nvd(nvd)
            payload = json.loads(kev.read_text(encoding="utf-8"))
        except NvdShapeError as exc:
            raise DataUpdateError("composite NVD data is invalid") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DataUpdateError("composite vulnerability JSON is invalid") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise DataUpdateError("composite KEV catalog is invalid")
        _validate_intelligence(root, metadata)
        _manifest(root)
        self._validate_grype(root)

    def rollback(self, kind: DataType, *, version: str | None = None, job_id: str | None = None) -> Release:
        with self.exclusive_access():
            return self._rollback(kind,version=version,job_id=job_id)

    def _rollback(self, kind: DataType, *, version: str | None = None, job_id: str | None = None) -> Release:
        lock = self._lock()
        try:
            current = self.current()
            if current is None:
                raise DataUpdateError("no active release")
            if version is not None and not _safe_version(version):
                raise DataUpdateError("invalid rollback version")
            target = self.root / "releases" / version if version else None
            if target is None:
                current_marker = _metadata(current.path / "metadata.env").get(f"{kind.upper().replace('-', '_')}_VERSION")
                for candidate in sorted((self.root / "releases").iterdir(), key=lambda item: item.stat().st_mtime, reverse=True):
                    if candidate.is_dir() and candidate != current.path:
                        marker = _metadata(candidate / "metadata.env").get(f"{kind.upper().replace('-', '_')}_VERSION")
                        if marker and marker != current_marker:
                            target = candidate
                            break
            releases = (self.root / "releases").resolve()
            if target is None or not target.is_dir() or releases not in target.resolve().parents:
                raise DataUpdateError("rollback release is unavailable")
            if approval_required(self.settings) and kind != "unified":
                raise DataUpdateError("통합 관리 모드에서는 통합 롤백만 허용됩니다")
            if kind == "unified":
                original_manifest = target / "approved-manifest.sha256"
                original_metadata = target / "approved-metadata.env"
                original_signature = target / "approved-manifest.sha256.sig"
                if not all(path.is_file() for path in (original_manifest,original_metadata,original_signature)):
                    raise DataUpdateError("서명된 통합 롤백 근거가 없습니다")
                package_root = self.root / "staging" / ("rollback-" + uuid.uuid4().hex)
                package_root.mkdir(parents=True)
                for line in original_manifest.read_text().splitlines():
                    checksum, name = line.split(); name = name.removeprefix("./")
                    if Path(name).is_absolute() or ".." in Path(name).parts: raise DataUpdateError("잘못된 롤백 경로")
                    source = original_metadata if name == "metadata.env" else target / name
                    destination = package_root / name; destination.parent.mkdir(parents=True,exist_ok=True)
                    shutil.copy2(source,destination)
                shutil.copy2(original_manifest,package_root/"manifest.sha256")
                shutil.copy2(original_signature,package_root/"manifest.sha256.sig")
                self._verify_signature(package_root)
                metadata, checksum = _validate_tree(package_root,"unified")
                with self.exclusive_access():
                    return self._apply_locked(Package("unified",metadata["BUNDLE_VERSION"],package_root,metadata,checksum),job_id=job_id)
            # A rollback is an ordinary typed update from an earlier immutable release.
            # Copy only that dataset so its metadata and files stay together.
            package_root = self.root / "staging" / f"rollback-{uuid.uuid4().hex}"
            package_root.mkdir(parents=True)
            names = ("grype-db",) if kind == "grype-db" else VULN_FILES
            for name in names:
                source = target / name
                if source.is_dir():
                    shutil.copytree(source, package_root / name)
                elif source.is_file():
                    shutil.copy2(source, package_root / name)
            target_metadata = _metadata(target / "metadata.env")
            marker = target_metadata.get(f"{kind.upper().replace('-', '_')}_VERSION") or target_metadata.get("BUNDLE_VERSION", target.name)
            metadata = _dataset_metadata(target_metadata, kind)
            metadata.update(BUNDLE_VERSION=marker, DATASET_TYPE=kind)
            (package_root / "metadata.env").write_text("".join(f"{key}={value}\n" for key, value in sorted(metadata.items())), encoding="utf-8")
            manifest_sha256 = _write_manifest(package_root)
            try:
                return self._apply_locked(Package(kind, marker, package_root, metadata, manifest_sha256), job_id=job_id)
            finally:
                shutil.rmtree(package_root, ignore_errors=True)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    @staticmethod
    def _swap_pointer(name: str, target: Path) -> None:
        pointer = target.parent.parent / name
        temporary = pointer.with_name(f".{name}.{uuid.uuid4().hex}.tmp")
        temporary.symlink_to(os.path.relpath(target, pointer.parent))
        os.replace(temporary, pointer)
