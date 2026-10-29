"""The packaged layout keeps its example env under config, unlike a source checkout."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = """TRACKER_MARKER=packaged
COMPOSE_PROJECT_NAME=installed-fixture
POSTGRES_SUPERUSER=postgres
TRACKER_DB_NAME=tracker
TRACKER_ARTIFACTS_VOLUME_NAME=fixture-artifacts
VULN_DATA_VOLUME_NAME=fixture-vuln
ALPINE_BASE_IMAGE=alpine:fixture
"""


def _installed(tmp_path: Path) -> Path:
    installed = tmp_path / "installed tracker"
    (installed / "scripts").mkdir(parents=True)
    (installed / "config").mkdir()
    for name in ("lib.sh", "backup-system.sh", "verify-backup.sh"):
        shutil.copy2(ROOT / "scripts" / name, installed / "scripts" / name)
    (installed / "config/.env.example").write_text(EXAMPLE)
    return installed


def _environment(installed: Path, **values: str) -> dict[str, str]:
    return {**os.environ, "ENV_FILE": str(installed / ".env"),
            "TRACKER_DATA_UPDATE_VERIFY_KEY_FILE": "", **values}


@pytest.mark.parametrize("root_example", [False, True])
def test_example_lookup_loads_packaged_env_and_keeps_source_root_precedence(tmp_path: Path, root_example: bool) -> None:
    installed = _installed(tmp_path)
    if root_example:
        (installed / ".env.example").write_text("TRACKER_MARKER=source\n")
    result = subprocess.run(
        ["bash", "-c", 'source "$1/scripts/lib.sh"; load_env; printf "%s\\n" "$EXAMPLE_ENV_FILE" "$TRACKER_MARKER"',
         "bash", str(installed)], env=_environment(installed), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    expected = installed / (".env.example" if root_example else "config/.env.example")
    assert result.stdout.splitlines() == [str(expected), "source" if root_example else "packaged"]


def test_runtime_env_stays_authoritative_and_resolves_its_relative_trust_key(tmp_path: Path) -> None:
    installed = _installed(tmp_path)
    (installed / ".env").write_text("TRACKER_MARKER=runtime\nTRACKER_DATA_UPDATE_VERIFY_KEY_FILE=trust/data.pub\n")
    result = subprocess.run(
        ["bash", "-c", 'source "$1/scripts/lib.sh"; load_env; printf "%s\\n" "$TRACKER_MARKER" "$TRACKER_DATA_UPDATE_VERIFY_KEY_FILE"',
         "bash", str(installed)], env=_environment(installed), capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["runtime", str(installed / "trust/data.pub")]


def test_installed_backup_completes_manifest_and_verifies_without_root_example(tmp_path: Path) -> None:
    installed = _installed(tmp_path)
    (installed / ".env").write_text(EXAMPLE.replace("TRACKER_MARKER=packaged", "TRACKER_MARKER=runtime"))
    (installed / "compose.yaml").write_text("services: {}\n")
    (installed / "deploy").mkdir()
    (installed / "deploy/fixture.txt").write_text("deployment configuration\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text('''#!/usr/bin/env python3
import io
from pathlib import Path
import sys
import tarfile

arguments = sys.argv[1:]
if arguments[0] == "compose":
    if "pg_dump" in arguments:
        sys.stdout.write("fixture database dump")
elif arguments[0] == "run":
    mounts = [arguments[index + 1] for index, item in enumerate(arguments) if item == "-v"]
    destination = next(mount[:-len(":/backup")] for mount in mounts if mount.endswith(":/backup"))
    archive_name = arguments[-1].split("/backup/", 1)[1].split(" ", 1)[0]
    payload = b"preserved volume data"
    with tarfile.open(Path(destination) / archive_name, "w:gz") as archive:
        item = tarfile.TarInfo("original.json")
        item.size = len(payload)
        archive.addfile(item, io.BytesIO(payload))
else:
    raise SystemExit("unexpected Docker operation")
''')
    docker.chmod(0o755)
    environment = _environment(installed, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
                               BACKUP_ROOT=str(tmp_path / "backups"), KODA_ALLOW_UNSIGNED_ARTIFACTS="1",
                               KODA_BACKUP_SIGNING_KEY="", KODA_BACKUP_VERIFY_KEY="", INCLUDE_ENV_IN_BACKUP="1")
    result = subprocess.run(["bash", installed / "scripts/backup-system.sh"], env=environment,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    backup = next((tmp_path / "backups").iterdir())
    assert (backup / ".env.example").read_text() == EXAMPLE
    assert (backup / ".env").read_text() == (installed / ".env").read_text()
    assert (backup / "tracker.dump").read_text() == "fixture database dump"
    assert "tracker-artifacts.tar.gz" in (backup / "manifest.sha256").read_text()
    verified = subprocess.run(["bash", installed / "scripts/verify-backup.sh", backup],
                              env=environment, capture_output=True, text=True)
    assert verified.returncode == 0, verified.stderr
    assert "Backup verified:" in verified.stdout
