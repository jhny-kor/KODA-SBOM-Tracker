from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from koda_tracker.config import Settings
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, validate_package


def _package(tmp_path: Path, kind: str, version: str) -> Path:
    root = tmp_path / f"{kind}-{version}"
    root.mkdir(parents=True)
    if kind == "grype-db":
        (root / "grype-db" / "5").mkdir(parents=True)
        (root / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
        (root / "grype-db" / "5" / "import.json").write_text("{}")
    if kind == "vuln-data":
        (root / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
        (root / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (root / "metadata.env").write_text(
        f"BUNDLE_VERSION={version}\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\nDATASET_TYPE={kind}\n",
        encoding="utf-8",
    )
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}")
    (root / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
    archive = tmp_path / f"{kind}-{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in root.rglob("*"):
            if path.is_file():
                tar.add(path, arcname=path.relative_to(root))
    return archive


def test_validate_rejects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "bad.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("../escape")
        data = b"x"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(DataUpdateError, match="traversal"):
        validate_package(archive, "grype-db")


def test_apply_builds_composite_and_keeps_previous(tmp_path: Path, monkeypatch) -> None:
    settings = Settings(grype_db_dir=tmp_path / "runtime" / "current" / "grype-db")
    def runner(command, **kwargs):
        if any(str(item).startswith("sbom:") for item in command):
            output = '{"matches": []}'
        else:
            cache = kwargs["env"]["GRYPE_DB_CACHE_DIR"]
            output = '{"valid": true, "schemaVersion": "v5.1.9", "path": "' + cache + '/5/vulnerability.db"}'
        return type("Result", (), {"returncode": 0, "stderr": "", "stdout": output})()
    engine = DataUpdateEngine(settings, runner=runner)
    # A complete legacy base is required before independent dataset updates.
    grype_archive = _package(tmp_path, "grype-db", "one")
    vuln_archive = _package(tmp_path, "vuln-data", "two")
    base = tmp_path / "runtime" / "releases" / "base"
    base.mkdir(parents=True)
    for name in ("grype-db", "metadata.env", "nvd.json", "kev.json"):
        source = (tmp_path / "grype-db-one" / name) if name != "nvd.json" and name != "kev.json" else (tmp_path / "vuln-data-two" / name)
        if source.is_dir():
            import shutil
            shutil.copytree(source, base / name)
        else:
            base.joinpath(name).write_bytes(source.read_bytes())
    (base / "metadata.env").write_text("BUNDLE_VERSION=base\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\n", encoding="utf-8")
    engine._swap_pointer("current", base)
    second = engine.stage(vuln_archive, "vuln-data", expected_base_version="base")
    engine.apply(second, expected_base_version="base")
    assert engine.status()["current"] == "two"
    assert engine.status()["previous"] == "base"
    assert (engine.current().path / "grype-db" / "5" / "vulnerability.db").read_bytes() == b"db"
