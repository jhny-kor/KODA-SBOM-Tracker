from __future__ import annotations

import asyncio
import hashlib
import subprocess
import tarfile
from pathlib import Path

from fastapi.testclient import TestClient

from koda_tracker.config import get_settings
from koda_tracker.data_updates import DataUpdateEngine
from koda_tracker.main import app
from koda_tracker.worker import process_data_update_one, process_one


def _archive(tmp_path: Path, version: str) -> bytes:
    root = tmp_path / version
    root.mkdir()
    (root / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (root / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (root / "metadata.env").write_text(
        f"BUNDLE_VERSION={version}\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\nDATASET_TYPE=vuln-data\n",
        encoding="utf-8",
    )
    entries = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*")) if path.is_file()
    ]
    (root / "manifest.sha256").write_text("\n".join(entries) + "\n", encoding="utf-8")
    archive = tmp_path / f"{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for path in root.rglob("*"):
            if path.is_file():
                handle.add(path, arcname=path.relative_to(root))
    return archive.read_bytes()


def test_upload_validate_apply_rollback_lifecycle(tmp_path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("TRACKER_GRYPE_DB_DIR", str(runtime / "current" / "grype-db"))
    monkeypatch.setenv("TRACKER_DATA_UPDATE_SPOOL_DIR", str(runtime / "staging"))
    get_settings.cache_clear()
    settings = get_settings()
    def runner(command, **kwargs):
        if any(str(item).startswith("sbom:") for item in command):
            output = '{"matches": []}'
        else:
            cache = kwargs["env"]["GRYPE_DB_CACHE_DIR"]
            output = '{"valid": true, "schemaVersion": "v5.1.9", "path": "' + cache + '/5/vulnerability.db"}'
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": output})()
    engine = DataUpdateEngine(settings, runner=runner)
    base = runtime / "releases" / "base"
    (base / "grype-db" / "5").mkdir(parents=True)
    (base / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (base / "grype-db" / "5" / "import.json").write_text("{}")
    (base / "nvd.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (base / "kev.json").write_text('{"vulnerabilities": []}', encoding="utf-8")
    (base / "metadata.env").write_text("BUNDLE_VERSION=base\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\nVULN_DATA_VERSION=one\n", encoding="utf-8")
    engine._swap_pointer("current", base)
    real_run = subprocess.run
    def fake_grype(command, **kwargs):
        # Mock only Grype, retaining the real bounded archive subprocess.
        if str(command[0]) != settings.grype_binary:
            return real_run(command, **kwargs)
        if any(str(item).startswith("sbom:") for item in command):
            return type("R", (), {"returncode": 0, "stderr": "", "stdout": '{"matches": []}'})()
        cache = kwargs["env"]["GRYPE_DB_CACHE_DIR"]
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": '{"valid": true, "schemaVersion": "v5.1.9", "path": "' + cache + '/5/vulnerability.db"}'})()
    monkeypatch.setattr("koda_tracker.data_updates.subprocess.run", fake_grype)
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        assert login.status_code == 200
        csrf = login.json()["csrfToken"]
        headers = {"X-CSRF-Token": csrf}
        upload = client.post("/api/v1/vulnerability-data-bundles/upload?kind=vuln-data", content=_archive(tmp_path, "two"), headers=headers)
        assert upload.status_code == 202
        job_id = upload.json()["id"]
        while client.get(f"/api/v1/vulnerability-data-bundles/jobs/{job_id}").json()["state"] not in {"completed", "failed"}:
            assert asyncio.run(process_data_update_one()) is True
        status = client.get(f"/api/v1/vulnerability-data-bundles/jobs/{job_id}").json()
        assert status["state"] == "completed" and status["action"] == "validate"
        assert engine.current().version == "base"
        applied = client.post(f"/api/v1/vulnerability-data-bundles/jobs/{job_id}/apply", headers=headers)
        assert applied.status_code == 202
        apply_id = applied.json()["id"]
        while client.get(f"/api/v1/vulnerability-data-bundles/jobs/{apply_id}").json()["state"] not in {"completed", "failed"}:
            assert asyncio.run(process_data_update_one()) is True
        apply_status = client.get(f"/api/v1/vulnerability-data-bundles/jobs/{apply_id}").json()
        assert apply_status["state"] == "completed", apply_status.get("error")
        assert engine.current().path.joinpath("metadata.env").read_text().find("VULN_DATA_VERSION=two") >= 0
        rollback = client.post("/api/v1/vulnerability-data-bundles/vuln-data/rollback", headers=headers)
        assert rollback.status_code == 202
        rollback_id = rollback.json()["id"]
        while client.get(f"/api/v1/vulnerability-data-bundles/jobs/{rollback_id}").json()["state"] not in {"completed", "failed"}:
            assert asyncio.run(process_data_update_one()) is True
        rollback_status = client.get(f"/api/v1/vulnerability-data-bundles/jobs/{rollback_id}").json()
        assert rollback_status["state"] == "completed", rollback_status.get("error")
        assert "VULN_DATA_VERSION=one" in engine.current().path.joinpath("metadata.env").read_text()
        pending = client.post("/api/v1/vulnerability-data-bundles/upload?kind=vuln-data", content=_archive(tmp_path, "three"), headers=headers).json()
        monkeypatch.setattr("koda_tracker.worker.analyze_offline", lambda *args: None)
        async def no_external_sync(*args): pass
        asyncio.run(process_one())  # Other tests may have left ordinary jobs queued.
        assert client.get(f"/api/v1/vulnerability-data-bundles/jobs/{pending['id']}").json()["state"] == "queued"
        assert asyncio.run(process_data_update_one()) is True
        assert client.get(f"/api/v1/vulnerability-data-bundles/jobs/{apply_id}").json()["state"] == "completed"
