"""Analysis caches need artifact writes, never data-updater spool access."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tarfile
from types import SimpleNamespace

import pytest

from koda_tracker import cve_catalog_api as catalog
from koda_tracker import vulnerability as vuln
from koda_tracker.config import Settings
from koda_tracker.nvd_record_index import NvdRecordIndex, cache_directory
from test_installed_backup_paths import EXAMPLE, _environment, _installed
from test_streaming_vulnerability_context import context_source


ROOT = Path(__file__).resolve().parents[2]
ALPINE = "alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"


@pytest.mark.parametrize("value", [None, "", "   ", "relative cache"])
def test_optional_cache_environment_empty_values_and_default(monkeypatch, value):
    monkeypatch.delenv("TRACKER_NVD_CACHE_DIR", raising=False)
    if value is not None:
        monkeypatch.setenv("TRACKER_NVD_CACHE_DIR", value)
    settings = Settings(_env_file=None)
    expected = Path(value) if value and value.strip() else None
    assert settings.nvd_cache_dir == expected
    assert cache_directory(settings) == (expected or settings.data_update_spool_dir).resolve()


@pytest.mark.parametrize("extra", [{}, {"nvd_cache_dir": None}, {"nvd_cache_dir": ""}])
def test_legacy_namespace_keeps_existing_spool_default(tmp_path, extra):
    spool = tmp_path / "legacy spool"
    settings = SimpleNamespace(data_update_spool_dir=spool, **extra)
    assert cache_directory(settings) == spool.resolve()
    assert not spool.exists(), "selecting a location must not create a directory"


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the file mode permission boundary")
def test_read_only_worker_cwd_and_source_use_only_writable_artifact_cache(context_source, tmp_path, monkeypatch):
    settings, _root, source, record = context_source
    app = tmp_path / "read-only-app"
    app.mkdir(mode=0o555)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(mode=0o700)
    settings.artifact_dir = artifacts
    settings.data_update_spool_dir = Path("data/vuln-data/staging")
    settings.nvd_cache_dir = artifacts / ".nvd-cache"
    source.chmod(0o444)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.chdir(app)
    monkeypatch.setattr(catalog, "get_settings", lambda: settings)
    catalog._search_index.cache_clear()
    try:
        # Reproduce the old failure with the ordinary worker's unwritable cwd.
        with pytest.raises(PermissionError):
            NvdRecordIndex(source, cache_directory(SimpleNamespace(data_update_spool_dir=settings.data_update_spool_dir)), vuln._nvd_details)
        context = vuln.load_context(settings)
        assert context.nvd[record["id"]] == record
        assert context.nvd.path.parent.parent == artifacts / ".nvd-cache"
        assert context.nvd.path.stat().st_mode & 0o777 == 0o400
        # Catalog and analysis use the same normalized location and factory.
        search = catalog._search_index(str(source), vuln._source_identity(source), context.bundle.manifest_sha256)
        assert search is context.nvd
        assert not (app / "data").exists()
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
        assert set(artifacts.iterdir()) == {artifacts / ".nvd-cache"}
    finally:
        app.chmod(0o755)
        catalog._search_index.cache_clear()


def test_compose_regular_worker_has_private_cache_without_updater_writes():
    compose = (ROOT / "compose.yaml").read_text()
    worker = compose.split("\n  portal-worker:\n", 1)[1].split("\n  portal-metadata-collector:\n", 1)[0]
    declaration = "TRACKER_NVD_CACHE_DIR: ${ARTIFACT_ROOT:-/var/lib/sbom-tracker/artifacts}/.nvd-cache"
    assert declaration in worker and compose.count(declaration) == 1
    assert "TRACKER_DATA_UPDATE_SPOOL_DIR" not in worker
    assert "- data-updates:" not in worker
    assert "- tracker-artifacts:${ARTIFACT_ROOT:-/var/lib/sbom-tracker/artifacts}" in worker
    assert "- vuln-data:${VULN_DATA_ROOT:-/var/lib/sbom-tracker/vuln-data}:ro" in worker


def test_backup_excludes_only_reserved_root_cache_and_preserves_other_files(tmp_path):
    # BSD tar strips ./ in exclude patterns. Exercise the actual Linux tar on
    # macOS; other hosts can execute the emitted command locally. No pulls.
    real_docker = shutil.which("docker") if sys.platform == "darwin" else ""
    if sys.platform == "darwin":
        if not real_docker or subprocess.run([real_docker, "image", "inspect", ALPINE], capture_output=True, timeout=10).returncode:
            pytest.skip("Linux backup tar requires the cached pinned Alpine image on macOS")
    installed = _installed(tmp_path)
    (installed / ".env").write_text(EXAMPLE)
    (installed / "compose.yaml").write_text("services: {}\n")
    (installed / "deploy").mkdir()
    volumes = tmp_path / "volumes"
    artifact = volumes / "fixture-artifacts"
    preserved = {
        "original.json": b"original SBOM",
        "run-uuid/analysis.json": b"analysis revision",
        ".other-cache/user.json": b"unrelated hidden file",
        "nested/.nvd-cache/user.json": b"nested user artifact",
        ".nvd-cache-other/user.json": b"similarly named user artifact",
        "cve-records-user.json": b"unrelated user artifact",
    }
    for name, content in preserved.items():
        target = artifact / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    cache = artifact / ".nvd-cache/cve-records-private/records.sqlite3"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"disposable index")
    vuln_volume = volumes / "fixture-vuln"
    (vuln_volume / ".nvd-cache").mkdir(parents=True)
    (vuln_volume / ".nvd-cache/approved-source.json").write_bytes(b"preserve entire source volume")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text('''#!/usr/bin/env python3
import os, shlex, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
if args[0] == 'compose':
    if 'pg_dump' in args:
        sys.stdout.write('fixture database dump')
elif args[0] == 'run':
    mounts = [args[n + 1] for n, value in enumerate(args) if value == '-v']
    source_name = next(value[:-len(':/from:ro')] for value in mounts if value.endswith(':/from:ro'))
    destination = next(value[:-len(':/backup')] for value in mounts if value.endswith(':/backup'))
    source = Path(os.environ['FIXTURE_VOLUMES']) / source_name
    if os.environ.get('FIXTURE_REAL_DOCKER'):
        # Own fixture binds only; no product container or named volume access.
        command = [os.environ['FIXTURE_REAL_DOCKER'], 'run', '--rm', '--pull', 'never',
                   '--platform', 'linux/amd64', '--label', 'io.koda.verification=nvd-cache-backup-test',
                   '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt',
                   'no-new-privileges', '--memory', '64m', '--pids-limit', '32',
                   '--user', f'{os.getuid()}:{os.getgid()}',
                   '-v', f'{source}:/from:ro', '-v', f'{destination}:/backup',
                   os.environ['FIXTURE_ALPINE'], 'sh', '-c', args[-1]]
        raise SystemExit(subprocess.run(command, timeout=15).returncode)
    # Execute the real tar command emitted by lib.sh, replacing only mounts.
    command = args[-1].replace('cd /from', 'cd ' + shlex.quote(str(source)))
    command = command.replace('/backup/', shlex.quote(destination) + '/')
    raise SystemExit(subprocess.run(['sh', '-c', command]).returncode)
else:
    raise SystemExit('unexpected Docker operation')
''')
    docker.chmod(0o755)
    env = _environment(installed, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                       BACKUP_ROOT=str(tmp_path / "backups"), FIXTURE_VOLUMES=str(volumes),
                       FIXTURE_REAL_DOCKER=real_docker or "", FIXTURE_ALPINE=ALPINE,
                       KODA_ALLOW_UNSIGNED_ARTIFACTS="1", KODA_BACKUP_SIGNING_KEY="",
                       KODA_BACKUP_VERIFY_KEY="", INCLUDE_ENV_IN_BACKUP="0", COPYFILE_DISABLE="1")
    result = subprocess.run(["bash", installed / "scripts/backup-system.sh"], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    backup = next((tmp_path / "backups").iterdir())
    with tarfile.open(backup / "tracker-artifacts.tar.gz") as archive:
        files = {member.name.removeprefix("./"): archive.extractfile(member).read() for member in archive if member.isfile()}
    assert files == preserved
    with tarfile.open(backup / "vuln-data.tar.gz") as archive:
        assert archive.extractfile("./.nvd-cache/approved-source.json").read() == b"preserve entire source volume"
    assert cache.read_bytes() == b"disposable index", "backup must not delete a live cache"
    verified = subprocess.run(["bash", installed / "scripts/verify-backup.sh", backup], env=env, capture_output=True, text=True, timeout=30)
    assert verified.returncode == 0, verified.stderr
