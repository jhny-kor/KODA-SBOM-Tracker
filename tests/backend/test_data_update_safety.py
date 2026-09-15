from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from koda_tracker.config import Settings
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, validate_package


def _runner(command, **kwargs):
    if any(str(item).startswith("sbom:") for item in command):
        output = '{"matches": []}'
    else:
        cache = kwargs["env"]["GRYPE_DB_CACHE_DIR"]
        output = json.dumps({"valid": True, "schemaVersion": "v5.1.9", "path": f"{cache}/5/vulnerability.db"})
    return type("Result", (), {"returncode": 0, "stderr": "", "stdout": output})()


def _archive(tmp_path: Path, kind: str, version: str) -> Path:
    root = tmp_path / f"{kind}-{version}"
    root.mkdir()
    (root / "metadata.env").write_text(f"BUNDLE_VERSION={version}\nDATASET_TYPE={kind}\nNVD_DATASET_DATE=2026-09-14\nKEV_DATASET_DATE=2026-09-14\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\n", encoding="utf-8")
    if kind == "grype-db":
        (root / "grype-db" / "5").mkdir(parents=True)
        (root / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
        (root / "grype-db" / "5" / "import.json").write_text("{}")
    else:
        (root / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
        (root / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    entries = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}" for p in sorted(root.rglob("*")) if p.is_file()]
    (root / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
    archive = tmp_path / f"{kind}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        for path in root.rglob("*"):
            if path.is_file():
                out.add(path, arcname=path.relative_to(root))
    return archive


def _engine(tmp_path: Path) -> DataUpdateEngine:
    return DataUpdateEngine(Settings(grype_db_dir=tmp_path / "runtime" / "current" / "grype-db"), runner=_runner)


def _base(engine: DataUpdateEngine) -> None:
    path = engine.root / "releases" / "legacy"
    (path / "grype-db" / "5").mkdir(parents=True)
    (path / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (path / "grype-db" / "5" / "import.json").write_text("{}")
    (path / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (path / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (path / "metadata.env").write_text("BUNDLE_VERSION=legacy\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\n", encoding="utf-8")
    engine._swap_pointer("current", path)


def test_rejects_links_duplicates_and_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "bad.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        info = tarfile.TarInfo("../escape")
        info.size = 1
        out.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(DataUpdateError, match="traversal"):
        validate_package(archive, "vuln-data")
    valid = _archive(tmp_path, "vuln-data", "one")
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(valid, "r:gz") as source, tarfile.open(tampered, "w:gz") as out:
        for member in source.getmembers():
            data = source.extractfile(member).read() if member.isfile() else None
            if member.name == "nvd.json":
                data = b'{"vulnerabilities": [1]}'
                member.size = len(data)
            out.addfile(member, io.BytesIO(data) if data is not None else None)
    with pytest.raises(DataUpdateError):
        validate_package(tampered, "vuln-data")


def test_status_schema_path_and_smoke_are_required(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    _base(engine)
    bad = lambda command, **kwargs: type("R", (), {"returncode": 0, "stderr": "", "stdout": "{}"})()
    engine.runner = bad
    with pytest.raises(DataUpdateError, match="status|schema|invalid"):
        engine.stage(_archive(tmp_path, "grype-db", "two"), "grype-db", expected_base_version="legacy")
    assert engine.current().version == "legacy"


def test_stale_base_and_legacy_migration_preserve_source(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    legacy = engine.root / "current"
    (legacy / "grype-db" / "5").mkdir(parents=True)
    (legacy / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (legacy / "grype-db" / "5" / "import.json").write_text("{}")
    (legacy / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (legacy / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (legacy / "metadata.env").write_text("BUNDLE_VERSION=old\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\n", encoding="utf-8")
    migrated = engine.migrate_legacy(version="base")
    assert migrated.version == "base"
    assert any(path.name.startswith("legacy-source-") for path in engine.root.iterdir())
    with pytest.raises(DataUpdateError, match="current release changed"):
        engine.stage(_archive(tmp_path, "vuln-data", "new"), "vuln-data", expected_base_version="wrong")


def test_migrate_release_pointer_normalizes_without_mutating_old_release(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    old = engine.root / "releases" / "old"
    old.mkdir(parents=True)
    (old / "grype-db" / "5").mkdir(parents=True)
    (old / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (old / "grype-db" / "5" / "import.json").write_text("{}")
    (old / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (old / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (old / "metadata.env").write_text("BUNDLE_VERSION=old\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\n", encoding="utf-8")
    entries = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(old).as_posix()}" for p in sorted(old.rglob("*")) if p.is_file()]
    (old / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
    engine._swap_pointer("current", old)
    migrated = engine.migrate_legacy(version="normalized")
    assert migrated.version == "normalized"
    assert "DATASET_TYPE" not in (old / "metadata.env").read_text()
    metadata = (migrated.path / "metadata.env").read_text()
    assert "DATASET_TYPE=composite" in metadata and "GRYPE_DB_VERSION=" in metadata and "VULN_DATA_VERSION=" in metadata
    assert engine.status()["previous"] == "old"

@pytest.mark.parametrize('member_type', [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_archive_links_rejected(tmp_path, member_type):
    archive = tmp_path / 'link.tar.gz'
    with tarfile.open(archive, 'w:gz') as out:
        item = tarfile.TarInfo('escape'); item.type = member_type; item.linkname = '/etc/passwd'
        out.addfile(item)
    with pytest.raises(DataUpdateError, match='links'):
        validate_package(archive, 'vuln-data')


def test_duplicate_and_expansion_limits(tmp_path):
    from koda_tracker.data_updates import Limits
    archive = tmp_path / 'duplicate.tar.gz'
    with tarfile.open(archive, 'w:gz') as out:
        for _ in range(2):
            item = tarfile.TarInfo('same'); item.size = 1
            out.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(DataUpdateError, match='duplicate'):
        validate_package(archive, 'vuln-data')
    with pytest.raises(DataUpdateError, match='size limit'):
        validate_package(archive, 'vuln-data', limits=Limits(max_file_bytes=0))


def test_rollback_restores_dates_and_preserves_other_dataset(tmp_path):
    engine = _engine(tmp_path); _base(engine)
    old_metadata = engine.current().path / 'metadata.env'
    old_metadata.write_text(old_metadata.read_text() + 'NVD_DATASET_DATE=2026-09-01\nKEV_DATASET_DATE=2026-09-01\n')
    base = engine.migrate_legacy(version='normalized')
    # New data carries a different effective date, which must revert with the bytes.
    package_path = _archive(tmp_path, 'vuln-data', 'new-data')
    staged = engine.stage(package_path, 'vuln-data')
    original_db = (base.path / 'grype-db/5/vulnerability.db').read_bytes()
    engine.apply(staged)
    rolled = engine.rollback('vuln-data')
    from koda_tracker.data_updates import _metadata
    metadata = _metadata(rolled.path / 'metadata.env')
    assert metadata['VULN_DATA_VERSION'] == 'normalized'
    assert metadata['NVD_DATASET_DATE'] == '2026-09-01'
    assert metadata['KEV_DATASET_DATE'] == '2026-09-01'
    assert metadata['GRYPE_DB_VERSION'] == 'normalized'
    assert (rolled.path / 'grype-db/5/vulnerability.db').read_bytes() == original_db


def test_worker_ownership_lock_does_not_deadlock_activation(tmp_path, monkeypatch):
    import asyncio
    import fcntl
    from koda_tracker import worker
    from koda_tracker.config import get_settings
    monkeypatch.setenv('TRACKER_GRYPE_DB_DIR', str(tmp_path / 'runtime/current/grype-db'))
    get_settings.cache_clear()
    monkeypatch.setattr(worker, 'recover_data_update_jobs', lambda: 0)
    class Done(Exception): pass
    async def process():
        engine = DataUpdateEngine(get_settings())
        with (engine.root / '.update.lock').open('a+') as activation:
            fcntl.flock(activation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (engine.root / '.updater-worker.lock').open('a+') as ownership:
            with pytest.raises(BlockingIOError):
                fcntl.flock(ownership, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raise Done()
    monkeypatch.setattr(worker, 'process_data_update_one', process)
    with pytest.raises(Done): worker.run(data_updates=True)
    get_settings.cache_clear()


def test_published_data_readable_across_container_uids(tmp_path):
    engine = _engine(tmp_path); _base(engine)
    old = engine.current().path
    (old / 'nvd.json').chmod(0o600)
    migrated = engine.migrate_legacy(version='readable')
    assert (migrated.path / 'nvd.json').stat().st_mode & 0o777 == 0o644
    assert (old / 'nvd.json').stat().st_mode & 0o777 == 0o600


def test_import_metadata_and_composite_nvd_required(tmp_path):
    from koda_tracker.data_updates import _validate_tree
    engine = _engine(tmp_path); _base(engine)
    archive = _archive(tmp_path, "grype-db", "missing-import")
    root = tmp_path / "grype-db-missing-import"
    (root / "grype-db/5/import.json").unlink()
    with pytest.raises(DataUpdateError, match="import metadata"):
        _validate_tree(root, "grype-db")
    current = engine.current().path
    (current / "nvd.json").write_text('{"unexpected": []}')
    with pytest.raises(DataUpdateError, match="NVD data"):
        engine._validate_composite(current)
