"""A missing optional data key cannot block startup or allow unsigned imports."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from koda_tracker.config import Settings
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, verification_status
from koda_tracker.models import AnalysisRevision, SbomRun, User
from sqlalchemy import func, select
from test_ssvc import setup  # noqa: F401
from test_unified_data_lifecycle import unified, apply  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]


def _env(tmp_path: Path, *, key: str = "") -> Path:
    env = tmp_path / "runtime.env"
    env.write_text("\n".join([
        "POSTGRES_PASSWORD=preserved-postgres-secret",
        "TRACKER_DB_USER=sbom_tracker", "TRACKER_DB_NAME=sbom_tracker",
        "TRACKER_DB_PASSWORD=preserved-database-secret",
        "TRACKER_DATABASE_URL=postgresql+psycopg://sbom_tracker:preserved-database-secret@postgres:5432/sbom_tracker",
        "TRACKER_BOOTSTRAP_ADMIN_PASSWORD=preserved-bootstrap-secret",
        "TRACKER_LDAP_ENCRYPTION_KEY=preserved-ldap-key",
        "KODA_TRACKER_PROVISIONING_TOKEN=preserved-token",
        "PUBLIC_HTTP_BIND=127.0.0.1", "TRACKER_ENVIRONMENT=development",
        f"TRACKER_DATA_UPDATE_VERIFY_KEY_FILE='{key}'", "",
    ]))
    return env


def _fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    directory = tmp_path / "bin"; directory.mkdir()
    log = tmp_path / "docker-args.jsonl"
    docker = directory / "docker"
    docker.write_text("#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['DOCKER_ARGUMENT_LOG'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n")
    docker.chmod(0o755)
    return directory, log


def test_base_compose_omits_key_bind_and_optional_override_is_fail_closed():
    base = yaml.safe_load((ROOT / "compose.yaml").read_text())
    override = yaml.safe_load((ROOT / "compose.data-key.yaml").read_text())
    for name in ("portal-api", "portal-worker", "portal-data-updater"):
        service = base["services"][name]
        assert "TRACKER_DATA_UPDATE_VERIFY_KEY" not in service.get("environment", {})
        assert "data-update-verify.pub" not in str(service.get("volumes", []))
        optional = override["services"][name]
        assert optional["environment"]["TRACKER_DATA_UPDATE_VERIFY_KEY"] == "/run/secrets/tracker-data-update-verify.pub"
        bind = optional["volumes"][0]
        assert bind["type"] == "bind" and bind["read_only"] is True
        assert bind["bind"]["create_host_path"] is False
        assert "TRACKER_DATA_UPDATE_VERIFY_KEY_FILE:?" in bind["source"]
    assert "tracker-artifacts:" in str(base["services"]["portal-api"]["volumes"])
    assert "postgres-data:/var/lib/postgresql/data" in base["services"]["postgres"]["volumes"]


@pytest.mark.parametrize("configured", [False, True])
def test_preflight_selects_optional_key_compose_without_changing_runtime_secrets(tmp_path, configured):
    key = tmp_path / "trust/key.pub"
    if configured:
        key.parent.mkdir()
        private = tmp_path / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", private], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", private, "-pubout", "-out", key], check=True, capture_output=True)
    env = _env(tmp_path, key="trust/key.pub" if configured else "")
    before = env.read_bytes()
    binaries, log = _fake_docker(tmp_path)
    process_env = {**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}", "DOCKER_ARGUMENT_LOG": str(log)}
    result = subprocess.run([ROOT / "scripts/preflight-airgap.sh", env], env=process_env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert env.read_bytes() == before
    arguments = json.loads(log.read_text().splitlines()[-1])
    assert (str(ROOT / "compose.data-key.yaml") in arguments) is configured
    if not configured:
        assert "unconfigured" in result.stdout
        assert not (ROOT / "config/data-update-verify.pub").is_dir()


@pytest.mark.parametrize("kind", ["missing", "private", "invalid"])
def test_explicit_bad_key_is_rejected_before_any_docker_operation(tmp_path, kind):
    key = tmp_path / "bad-key.pub"
    if kind == "private": key.write_text("-----BEGIN PRIVATE KEY-----\nnot-public\n")
    if kind == "invalid": key.write_text("not a public key\n")
    env = _env(tmp_path, key=str(key))
    binaries, log = _fake_docker(tmp_path)
    result = subprocess.run([ROOT / "scripts/preflight-airgap.sh", env], env={**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}", "DOCKER_ARGUMENT_LOG": str(log)}, capture_output=True, text=True)
    assert result.returncode != 0
    assert not log.exists()


@pytest.mark.parametrize("key", [None, "", "   "])
def test_key_absence_is_valid_settings_and_rejects_import_before_creating_state(tmp_path, monkeypatch, key):
    monkeypatch.delenv("KODA_RELEASE_VERIFY_KEY", raising=False)
    monkeypatch.setenv("KODA_ALLOW_UNSIGNED_ARTIFACTS", "1")
    runtime = tmp_path / "data"
    settings = Settings(_env_file=None, data_update_verify_key=key, grype_db_dir=runtime / "current/grype-db")
    assert settings.data_update_verify_key is None
    assert verification_status(settings)["state"] == "unconfigured"
    with pytest.raises(DataUpdateError, match="unconfigured"):
        DataUpdateEngine(settings, read_only=True).stage(tmp_path / "not-read.tar.gz", "unified")
    assert not runtime.exists()


def test_unconfigured_status_preserves_existing_user_and_analysis_records(unified, monkeypatch):
    db, client, run, revision, settings, archive = unified
    apply(client, archive())
    before_bom = json.dumps(db.get(SbomRun, run.id).normalized_bom, sort_keys=True)
    before_findings = json.dumps(db.get(AnalysisRevision, revision.id).findings, sort_keys=True)
    before_users = db.scalar(select(func.count()).select_from(User))
    settings.data_update_verify_key = None
    monkeypatch.delenv("KODA_RELEASE_VERIFY_KEY", raising=False)
    status = client.get("/api/v1/vulnerability-data-bundles/unified/status")
    assert status.status_code == 200
    document = status.json()
    assert document["verification"]["state"] == "unconfigured"
    assert document["signatureRequired"] is True and document["available"] is False
    assert db.scalar(select(func.count()).select_from(User)) == before_users
    assert json.dumps(db.get(SbomRun, run.id).normalized_bom, sort_keys=True) == before_bom
    assert json.dumps(db.get(AnalysisRevision, revision.id).findings, sort_keys=True) == before_findings


def test_real_application_starts_and_authenticates_without_data_key(tmp_path):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("TRACKER_") and key != "KODA_RELEASE_VERIFY_KEY"}
    environment.update({"PYTHONPATH": str(ROOT / "apps/api"), "TRACKER_ENVIRONMENT": "test",
        "TRACKER_DATABASE_URL": f"sqlite:///{tmp_path / 'fresh.db'}",
        "TRACKER_ARTIFACT_DIR": str(tmp_path / "artifacts"),
        "TRACKER_GRYPE_DB_DIR": str(tmp_path / "vuln-data/current/grype-db"),
        "TRACKER_DATA_UPDATE_SPOOL_DIR": str(tmp_path / "staging"),
        "TRACKER_BOOTSTRAP_ADMIN_USERNAME": "temporary-admin",
        "TRACKER_BOOTSTRAP_ADMIN_PASSWORD": "temporary-test-only-secret-123!",
        "TRACKER_DATA_UPDATE_VERIFY_KEY": "", "TRACKER_OFFLINE_MODE": "true"})
    code = '''
from fastapi.testclient import TestClient
from koda_tracker.config import get_settings
from koda_tracker.main import app
assert get_settings().data_update_verify_key is None
with TestClient(app) as client:
    assert client.get('/health').status_code == 200
    result = client.post('/api/v1/auth/login', json={'username':'temporary-admin','password':'temporary-test-only-secret-123!'})
    assert result.status_code == 200, result.text
    status = client.get('/api/v1/vulnerability-data-bundles/unified/status')
    assert status.status_code == 200, status.text
    assert status.json()['verification']['state'] == 'unconfigured'
print('application-startup-login-without-key-ok')
'''
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "application-startup-login-without-key-ok" in result.stdout
    assert not (tmp_path / "vuln-data").exists()
