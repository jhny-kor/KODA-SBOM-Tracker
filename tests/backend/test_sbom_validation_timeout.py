from __future__ import annotations

import json
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from koda_tracker import main, sbom
from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal
from koda_tracker.models import Job, SbomRun


CDX = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "dataLicense": "CC0-1.0",
    "name": "timeout-regression",
    "documentNamespace": "https://example.invalid/spdx/timeout-regression",
    "creationInfo": {"created": "2026-10-30T00:00:00Z", "creators": ["Tool: test"]},
    "packages": [],
}


@pytest.mark.parametrize("kind", ["file", "raw", "spdx"])
def test_cli_validation_all_input_paths_allow_five_minutes(tmp_path, monkeypatch, kind) -> None:
    calls = []

    def validate(command, **kwargs):
        calls.append((command, kwargs))
        candidate = Path(command[command.index("--input-file") + 1])
        assert json.loads(candidate.read_text())["bomFormat"] == "CycloneDX"
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(sbom.subprocess, "run", validate)
    source = tmp_path / "extensionless-upload"
    source.write_text(json.dumps(SPDX if kind == "spdx" else CDX))
    if kind == "raw":
        sbom.validate_with_cyclonedx_cli(source.read_bytes(), "/test/cyclonedx")
    else:
        sbom.validate_file_with_cyclonedx_cli(source, "/test/cyclonedx", input_format="json")
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[-2:] == ["--input-format", "json"]
    assert kwargs["timeout"] == 300
    assert kwargs["check"] is False


@pytest.mark.parametrize("kind", ["file", "raw"])
def test_cli_timeout_is_controlled_and_does_not_expose_process_details(tmp_path, monkeypatch, kind) -> None:
    source = tmp_path / "private-upload-name"
    source.write_text(json.dumps(CDX))

    def time_out(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="secret-output", stderr="secret-stderr")

    monkeypatch.setattr(sbom.subprocess, "run", time_out)
    with pytest.raises(sbom.SbomValidationError) as caught:
        if kind == "raw":
            sbom.validate_with_cyclonedx_cli(source.read_bytes(), "/private/validator")
        else:
            sbom.validate_file_with_cyclonedx_cli(source, "/private/validator", input_format="json")
    message = str(caught.value)
    assert "300초" in message and "시간" in message
    for private in (str(tmp_path), source.name, "/private/validator", "secret-output", "secret-stderr"):
        assert private not in message


def test_cli_missing_binary_is_distinct_from_timeout(tmp_path) -> None:
    with pytest.raises(sbom.SbomValidationError, match="찾을 수 없습니다") as caught:
        sbom.validate_with_cyclonedx_cli(json.dumps(CDX).encode(), str(tmp_path / "missing-validator"))
    assert "300초" not in str(caught.value)


def test_cli_schema_rejection_still_fails_closed(tmp_path, monkeypatch) -> None:
    source = tmp_path / "upload"
    source.write_text(json.dumps(CDX))
    monkeypatch.setattr(
        sbom.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr="invalid-schema"),
    )
    with pytest.raises(sbom.SbomValidationError, match="스키마 검증에 실패했습니다: invalid-schema"):
        sbom.validate_file_with_cyclonedx_cli(source, "/test/cyclonedx", input_format="json")


def test_cli_memory_exhaustion_is_identified_before_truncating_diagnostics(tmp_path, monkeypatch) -> None:
    source = tmp_path / "private-upload-name"
    source.write_text(json.dumps(CDX))
    diagnostics = ("System.OutOfMemoryException: allocation failed\n"
                   " at /private/validator/source.cs:123\n" + "irrelevant-stack-trace\n" * 200)
    monkeypatch.setattr(
        sbom.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr=diagnostics),
    )
    with pytest.raises(sbom.SbomValidationError) as caught:
        sbom.validate_file_with_cyclonedx_cli(source, "/private/validator", input_format="json")
    message = str(caught.value)
    assert "메모리" in message
    for private in (str(tmp_path), source.name, "/private/validator", "irrelevant-stack-trace", "System.OutOfMemoryException"):
        assert private not in message


@pytest.mark.parametrize("returncode", [-9, 137])
def test_cli_forced_termination_does_not_guess_oom_or_reject_schema(tmp_path, monkeypatch, returncode) -> None:
    source = tmp_path / "upload"
    source.write_text(json.dumps(CDX))
    monkeypatch.setattr(
        sbom.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, returncode, stdout="", stderr=""),
    )
    with pytest.raises(sbom.SbomValidationError) as caught:
        sbom.validate_file_with_cyclonedx_cli(source, "/test/cyclonedx", input_format="json")
    message = str(caught.value)
    assert "종료" in message
    assert "메모리" not in message
    assert "스키마 검증에 실패했습니다" not in message


def _upload_context(client):
    login = client.post("/api/v1/auth/login", json={
        "username": "test-admin", "password": "correct-horse-battery-staple",
    })
    assert login.status_code == 200, login.text
    headers = {"X-CSRF-Token": login.json()["csrfToken"]}
    slug = f"validation-{uuid.uuid4().hex[:12]}"
    service = client.post("/api/v1/services", json={"slug": slug, "name": slug}, headers=headers)
    assert service.status_code == 201, service.text
    data = {
        "serviceId": service.json()["id"],
        "environmentId": client.get("/api/v1/environments").json()[0]["id"],
        "releaseVersion": "timeout-regression",
    }
    return data, headers


def _upload(client, data, headers):
    return client.post("/api/v1/sbom-runs", data=data, headers=headers,
                       files={"sbom": ("sbom.cdx.json", json.dumps(CDX).encode(), "application/json")})


def test_upload_validation_timeout_creates_no_run_job_or_artifact_and_removes_stage(monkeypatch) -> None:
    staged = []

    def time_out(path, binary, **kwargs):
        assert path.is_file()
        staged.append(path)
        raise sbom.SbomValidationError("CycloneDX 검증 시간이 300초 제한을 초과했습니다")

    monkeypatch.setattr(main, "validate_file_with_cyclonedx_cli", time_out)
    with TestClient(main.app) as client:
        data, headers = _upload_context(client)
        with SessionLocal() as db:
            before = tuple(db.scalar(select(func.count()).select_from(model)) for model in (SbomRun, Job))
        artifacts = get_settings().artifact_dir
        existing = set(artifacts.rglob("*"))
        response = _upload(client, data, headers)
        assert response.status_code == 422, response.text
        assert "300초" in response.json()["detail"]
        with SessionLocal() as db:
            assert tuple(db.scalar(select(func.count()).select_from(model)) for model in (SbomRun, Job)) == before
        assert set(artifacts.rglob("*")) == existing
    assert len(staged) == 1 and not staged[0].exists()


def test_slow_upload_validation_does_not_block_health_requests(monkeypatch) -> None:
    entered, release = Event(), Event()

    def wait_for_release(path, binary, **kwargs):
        entered.set()
        assert release.wait(10), "test did not release the validator"
        raise sbom.SbomValidationError("test validation stopped")

    monkeypatch.setattr(main, "validate_file_with_cyclonedx_cli", wait_for_release)
    with TestClient(main.app) as client:
        data, headers = _upload_context(client)
        with ThreadPoolExecutor(max_workers=2) as executor:
            upload = executor.submit(_upload, client, data, headers)
            try:
                assert entered.wait(5), "upload did not reach validation"
                health = executor.submit(client.get, "/health")
                assert health.result(timeout=2).status_code == 200
                assert not upload.done()
            finally:
                release.set()
            assert upload.result(timeout=5).status_code == 422
