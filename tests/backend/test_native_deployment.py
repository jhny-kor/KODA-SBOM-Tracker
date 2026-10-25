"""Exercise native-only deployment boundaries without a Docker daemon."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _native_env(tmp_path: Path, **updates: str) -> Path:
    values = {
        "COMPOSE_PROJECT_NAME": "native-test",
        "POSTGRES_PASSWORD": "strong-postgres-secret",
        "TRACKER_DB_USER": "sbom_tracker",
        "TRACKER_DB_NAME": "sbom_tracker",
        "TRACKER_DB_PASSWORD": "strong-tracker-secret",
        "TRACKER_DATABASE_URL": "postgresql+psycopg://sbom_tracker:strong-tracker-secret@postgres:5432/sbom_tracker",
        "TRACKER_BOOTSTRAP_ADMIN_PASSWORD": "strong-bootstrap-secret",
        "TRACKER_ARTIFACTS_VOLUME_NAME": "native-artifacts",
        "VULN_DATA_VOLUME_NAME": "native-vuln",
        "TRACKER_DEPENDENCY_TRACK_ENABLED": "false",
        **updates,
    }
    path = tmp_path / "native.env"
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return path


def test_native_preflight_needs_no_dependency_track_secrets(tmp_path: Path) -> None:
    env_path = _native_env(tmp_path)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$DOCKER_TEST_LOG"\n')
    docker.chmod(0o755)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("TRACKER_", "DTRACK_", "COMPOSE_"))}
    environment.update(PATH=f"{fake_bin}:{os.environ['PATH']}", DOCKER_TEST_LOG=str(log))
    result = subprocess.run(["bash", ROOT / "scripts/preflight-airgap.sh", env_path], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--profile dependency-track" not in log.read_text()

    _native_env(tmp_path, TRACKER_DEPENDENCY_TRACK_ENABLED="true")
    result = subprocess.run(["bash", ROOT / "scripts/preflight-airgap.sh", env_path], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    _native_env(tmp_path, TRACKER_DEPENDENCY_TRACK_ENABLED="true", DTRACK_DB_PASSWORD="strong-optional-secret", TRACKER_DEPENDENCY_TRACK_API_KEY="private-team-key", DTRACK_API_BASE_URL="https://tracker.example/dependency-track")
    result = subprocess.run(["bash", ROOT / "scripts/preflight-airgap.sh", env_path], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_native_compose_has_no_retired_service_profile() -> None:
    if not shutil.which("docker"):
        pytest.skip("Docker Compose CLI unavailable")
    command = ["docker", "compose", "--env-file", str(ROOT / ".env.example"), "-f", str(ROOT / "compose.yaml"), "-f", str(ROOT / "compose.airgap.yaml")]
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("COMPOSE_", "TRACKER_", "DTRACK_"))}
    default = subprocess.run([*command, "config", "--services"], env=environment, capture_output=True, text=True)
    if "not a docker command" in default.stderr:
        pytest.skip("Docker Compose plugin unavailable")
    assert default.returncode == 0, default.stderr
    assert {"portal-api", "portal-worker", "portal-data-updater", "portal-metadata-collector", "gateway", "postgres", "portal-web"} == set(default.stdout.split())
    rendered = subprocess.run([*command, "config", "--format", "json"], env=environment, capture_output=True, text=True)
    assert rendered.returncode == 0, rendered.stderr
    services = json.loads(rendered.stdout)["services"]
    assert services["portal-api"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    for name in ("portal-worker", "portal-data-updater"):
        assert services[name]["depends_on"]["portal-api"]["condition"] == "service_healthy"
    for name in ("portal-api", "portal-worker"):
        settings = services[name]["environment"]
        assert settings["TRACKER_NOTIFICATION_WEBHOOK_ENABLED"] == "false"
        assert "TRACKER_NOTIFICATION_WEBHOOK_URL" in settings
        assert "TRACKER_NOTIFICATION_WEBHOOK_SECRET" in settings
        assert "TRACKER_NOTIFICATION_ALLOWED_HOSTS" in settings
        assert settings["TRACKER_MAX_QUEUED_JOBS"] == "100"
    assert "TRACKER_NOTIFICATION_WEBHOOK_SECRET" not in services["gateway"]["environment"]
    collector = services["portal-metadata-collector"]
    assert collector["read_only"] is True
    assert any(mount.startswith("/tmp:") for mount in collector["tmpfs"])
    assert set(collector["networks"]) == {"app"}
    assert "metadata-egress" not in services["portal-worker"]["networks"]
    optional = subprocess.run([*command, "--profile", "dependency-track", "config", "--services"], env=environment, capture_output=True, text=True)
    assert optional.returncode == 0, optional.stderr
    assert not {"dtrack-apiserver", "dtrack-frontend"} & set(optional.stdout.split())


def test_native_only_backup_verifies_without_optional_artifacts_and_requires_opt_in(tmp_path: Path) -> None:
    env_path = _native_env(tmp_path)
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "metadata.env").write_text(
        "BACKUP_CREATED_AT=20261017T010203Z\nCOMPOSE_PROJECT_NAME=native-test\n"
        "TRACKER_DB_NAME=sbom_tracker\nTRACKER_ARTIFACTS_VOLUME_NAME=native-artifacts\n"
        "VULN_DATA_VOLUME_NAME=native-vuln\nBACKUP_DEPENDENCY_TRACK_DB=0\nBACKUP_DEPENDENCY_TRACK_DATA=0\n"
    )
    (backup / "postgres-globals.sql").write_text("-- globals\n")
    (backup / "sbom_tracker.dump").write_bytes(b"database dump")
    for filename in ("tracker-artifacts.tar.gz", "vuln-data.tar.gz"):
        with tarfile.open(backup / filename, "w:gz") as archive:
            member = tarfile.TarInfo("item")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))

    def manifest() -> None:
        (backup / "manifest.sha256").write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(backup.iterdir()) if path.name != "manifest.sha256"))

    manifest()
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("TRACKER_", "DTRACK_", "COMPOSE_", "KODA_BACKUP_", "KODA_ALLOW_UNSIGNED"))}
    environment["ENV_FILE"] = str(env_path)
    command = ["bash", ROOT / "scripts/verify-backup.sh", backup]
    rejected = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "KODA_ALLOW_UNSIGNED_ARTIFACTS=1" in rejected.stderr
    environment["KODA_ALLOW_UNSIGNED_ARTIFACTS"] = "1"
    accepted = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr

    # A metadata flag may not hide unexpected optional content from validation.
    (backup / "dtrack.dump").write_bytes(b"unexpected")
    manifest()
    unexpected = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert unexpected.returncode != 0
    assert "unexpected non-native backup content" in unexpected.stderr


def test_native_postgres_initialization_does_not_create_optional_db(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    psql = fake_bin / "psql"
    log = tmp_path / "init.sql"
    psql.write_text('#!/bin/sh\ncat >> "$INIT_SQL_LOG"\n')
    psql.chmod(0o755)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("TRACKER_", "DTRACK_", "POSTGRES_"))}
    environment.update(PATH=f"{fake_bin}:{os.environ['PATH']}", INIT_SQL_LOG=str(log), POSTGRES_USER="postgres", TRACKER_DB_USER="tracker", TRACKER_DB_NAME="tracker", TRACKER_DB_PASSWORD="private-secret")
    command = ["sh", ROOT / "deploy/postgres/init/10-init-multi-db.sh"]
    native = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert native.returncode == 0, native.stderr
    assert "CREATE DATABASE tracker" in log.read_text()
    assert "dtrack" not in log.read_text()
    log.write_text("")
    environment.update(TRACKER_DEPENDENCY_TRACK_ENABLED="true", DTRACK_DB_USER="dtrack", DTRACK_DB_NAME="dtrack", DTRACK_DB_PASSWORD="optional-secret")
    enabled = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert enabled.returncode == 0, enabled.stderr
    assert "CREATE DATABASE dtrack" not in log.read_text()


CORE_SERVICES = ["portal-web", "portal-api", "gateway", "portal-data-updater", "portal-worker", "postgres"]


def _mock_docker(tmp_path: Path) -> tuple[dict[str, str], Path]:
    """Old-profile containers appear in unfiltered ps, never scoped queries."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "docker.log"
    docker = fake_bin / "docker"
    docker.write_text(r"""#!/usr/bin/env python3
import os
import sys
args = sys.argv[1:]
with open(os.environ['DOCKER_TEST_LOG'], 'a') as output:
    output.write(' '.join(args) + '\n')
if args and args[0] == 'compose':
    if 'stop' in args and os.environ.get('MOCK_FAIL_STOP'):
        sys.exit(23)
    if 'config' in args and '--services' in args:
        print('portal-web\nportal-api\ngateway\nportal-data-updater\nportal-worker\npostgres')
        if '--profile' in args:
            print('dtrack-apiserver\ndtrack-frontend')
    elif 'ps' in args and '-q' in args:
        service = args[-1]
        if service == '-q':
            print('core-container\nlegacy-dtrack-unhealthy')
        elif service != os.environ.get('MOCK_MISSING_SERVICE'):
            print(service + '-container')
    elif 'exec' in args and ('psql' in args or 'pg_restore' in args):
        sys.stdin.read()
elif args and args[0] == 'inspect':
    container_id = args[-1]
    print('running unhealthy' if 'dtrack' in container_id else 'running healthy')
""")
    docker.chmod(0o755)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("TRACKER_", "DTRACK_", "COMPOSE_", "KODA_BACKUP_", "KODA_ALLOW_UNSIGNED"))}
    environment.update(PATH=f"{fake_bin}:{os.environ['PATH']}", DOCKER_TEST_LOG=str(log))
    return environment, log


def test_native_airgap_readiness_ignores_old_optional_containers_but_requires_every_core_service(tmp_path: Path) -> None:
    env_path = _native_env(tmp_path, AIRGAP_HEALTH_TIMEOUT="1", TRACKER_PUBLIC_ORIGIN="http://127.0.0.1:8088")
    environment, log = _mock_docker(tmp_path)
    # Avoid five seconds per negative case while still expiring its deadline.
    sleeper = tmp_path / "bin/sleep"
    sleeper.write_text('#!/bin/sh\n/bin/sleep 1\n')
    sleeper.chmod(0o755)
    command = ["bash", ROOT / "scripts/start-airgap.sh", env_path]
    started = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=10)
    assert started.returncode == 0, started.stderr
    calls = log.read_text().splitlines()
    for service in CORE_SERVICES:
        assert any(f"ps -a -q {service}" in call for call in calls)
    assert not any("dtrack" in call for call in calls)
    assert not any(call.endswith("ps -q") for call in calls)

    log.write_text("")
    missing = subprocess.run(command, env={**environment, "MOCK_MISSING_SERVICE": "portal-worker"}, capture_output=True, text=True, timeout=10)
    assert missing.returncode != 0
    assert "Timed out waiting" in missing.stderr


def test_windows_readiness_checks_expected_services_individually(tmp_path: Path) -> None:
    if not shutil.which("pwsh"):
        pytest.skip("PowerShell runtime unavailable")
    environment, log = _mock_docker(tmp_path)
    environment["WINDOWS_LAUNCHER_PATH"] = str(ROOT / "scripts/start-windows.ps1")
    # Load just the real readiness function from its AST, avoiding a live start.
    command = r'''$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:WINDOWS_LAUNCHER_PATH, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0] }
$definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq "Test-ExpectedComposeServices" }, $true)
. ([scriptblock]::Create($definition.Extent.Text))
if (-not (Test-ExpectedComposeServices -Services @("portal-api", "portal-worker") -ComposeArguments @("compose"))) { exit 7 }
'''
    ready = subprocess.run(["pwsh", "-NoProfile", "-Command", command], env=environment, capture_output=True, text=True, timeout=10)
    assert ready.returncode == 0, ready.stderr
    assert "compose ps -a -q portal-api" in log.read_text()
    assert "compose ps -a -q portal-worker" in log.read_text()
    assert "dtrack" not in log.read_text()
    missing = subprocess.run(["pwsh", "-NoProfile", "-Command", command], env={**environment, "MOCK_MISSING_SERVICE": "portal-worker"}, capture_output=True, text=True, timeout=10)
    assert missing.returncode == 7, missing.stderr
    launcher = (ROOT / "scripts/start-windows.ps1").read_text()
    assert '"compose", "--env-file", $EnvFile' in launcher
    assert '$ComposeFiles[2] = $ComposeEnvFile' in launcher
