"""Archive uploads preserve original evidence and analyze one bounded document."""
import asyncio
import base64
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
from types import SimpleNamespace
import zipfile

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.requests import Request
from starlette.datastructures import UploadFile

from koda_tracker import main, sbom as sbom_module, services, worker
from koda_tracker.config import get_settings
from koda_tracker.db import Base, get_db
from koda_tracker.models import ApiToken, Environment, Job, JobState, Release, Role, SbomRun, Service, User
from koda_tracker.quality import evaluate_quality
from koda_tracker.sbom import SbomValidationError, parse_sbom
from koda_tracker.security import digest, issue_session
from test_spdx_sbom import document as spdx_document


JSON = b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'
XML = b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component type="library"><name>sample</name><version>1</version></component></components></bom>'
SEVEN_Z = base64.b64decode('N3q8ryccAANyIy1/QQAAAAAAAAA+AAAAAAAAAKWXjaQBADx7ImJvbUZvcm1hdCI6IkN5Y2xvbmVEWCIsInNwZWNWZXJzaW9uIjoiMS42IiwiY29tcG9uZW50cyI6W119AAEEBgABCUEABwsBAAEhIQEQDD0ACAoBksnAkgAABQEREwBiAG8AbQAuAGoAcwBvAG4AAAAVBgEAIICAgQAA')
MEDIA = {"zip": "application/zip", "tar": "application/x-tar", "tar.gz": "application/gzip", "7z": "application/x-7z-compressed"}


def archive_bytes(kind, entries):
    output = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in entries:
                archive.writestr(name, raw)
    else:
        with tarfile.open(fileobj=output, mode="w:gz" if kind == "tar.gz" else "w") as archive:
            for name, raw in entries:
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


@pytest.fixture
def context(tmp_path, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "artifact_dir", tmp_path / "artifacts")
    monkeypatch.setattr(settings, "max_queued_jobs", 10_000)
    monkeypatch.setattr(settings, "cyclonedx_cli_binary", "")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    previous = dict(main.app.dependency_overrides)
    with Session(engine, expire_on_commit=False) as db:
        user = User(id="archive-admin", username="archive-admin", password_hash="unused", role=Role.ADMIN, active=True)
        service = Service(id="archive-service", slug="archive-service", name="Archive service", active=True)
        environment = Environment(id="archive-env", slug="archive-env", name="Archive env", active=True)
        db.add_all([user, service, environment])
        db.flush()
        raw_session, csrf = issue_session(db, user)
        main.app.dependency_overrides[get_db] = lambda: db
        client = TestClient(main.app)
        client.cookies.set("koda_session", raw_session)
        try:
            yield SimpleNamespace(db=db, client=client, settings=settings, service=service, environment=environment,
                                  headers={"X-CSRF-Token": csrf}, user=user)
        finally:
            client.close()
            main.app.dependency_overrides.clear()
            main.app.dependency_overrides.update(previous)
    engine.dispose()


def upload(context, raw, *, headers=None, **data):
    return context.client.post("/api/v1/sbom-runs", data={"serviceId": context.service.id,
                               "environmentId": context.environment.id, "releaseVersion": "1", **data},
                               files={"sbom": ("untrusted-name.cdx.json", raw, "text/plain")},
                               headers=context.headers if headers is None else headers)


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
@pytest.mark.parametrize("raw", [JSON, XML, json.dumps(spdx_document()).encode()], ids=["cdx-json", "cdx-xml", "spdx-json"])
def test_archive_upload_preserves_original_bytes_metadata_and_quality(context, kind, raw):
    expected, _ = parse_sbom(raw)
    compressed = archive_bytes(kind, [("nested/extensionless-document", raw)])
    response = upload(context, compressed)
    assert response.status_code == 202, response.text
    item = context.db.get(SbomRun, response.json()["runId"])
    original_path = item.artifact_path
    assert item.normalized_bom == expected
    assert item.media_type == MEDIA[kind]
    assert item.size_bytes == len(compressed)
    assert item.sha256 == response.json()["sha256"] == hashlib.sha256(compressed).hexdigest()
    assert Path(original_path).read_bytes() == compressed
    assert item.original_filename == "untrusted-name.cdx.json"
    result = context.client.get(f"/api/v1/sbom-runs/{item.id}/artifact")
    assert result.status_code == 200 and result.content == compressed
    assert result.headers["content-type"] == MEDIA[kind]
    quality = evaluate_quality(context.db, item)
    assert quality.state == "completed" and quality.original_sha256 == item.sha256
    assert quality.summary["sourceBasis"] == "verified_original_artifact"
    updated = context.client.patch(f"/api/v1/sbom-runs/{item.id}/metadata", json={"note": "archive note"}, headers=context.headers)
    assert updated.status_code == 200, updated.text
    context.db.refresh(item)
    assert item.note == "archive note" and item.artifact_path == original_path
    assert Path(item.artifact_path).read_bytes() == compressed and item.normalized_bom == expected


def test_seven_zip_upload_is_detected_by_content_and_preserves_original(context):
    response = upload(context, SEVEN_Z)
    assert response.status_code == 202, response.text
    item = context.db.get(SbomRun, response.json()["runId"])
    assert item.media_type == MEDIA["7z"] and item.size_bytes == len(SEVEN_Z)
    assert item.normalized_bom == json.loads(JSON)
    assert Path(item.artifact_path).read_bytes() == SEVEN_Z


@pytest.mark.parametrize("entries", [[], [("first.json", JSON), ("second.json", JSON)], [("bom.json", JSON), ("README", b"companion")], [("inner.zip", archive_bytes("zip", [("bom.json", JSON)]))]])
def test_empty_multiple_companion_and_recursive_archives_are_rejected_before_persistence(context, entries):
    response = upload(context, archive_bytes("zip", entries))
    assert response.status_code == 422, response.text
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert context.db.scalar(select(func.count()).select_from(Job)) == 0
    assert not list(context.settings.artifact_dir.rglob("*"))


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
def test_unsafe_archive_path_never_reaches_artifact_store(context, kind):
    response = upload(context, archive_bytes(kind, [("../escaped.json", JSON)]))
    assert response.status_code == 422 and context.db.scalar(select(func.count()).select_from(SbomRun)) == 0


def test_encrypted_zip_and_link_entry_are_rejected(context):
    encrypted = bytearray(archive_bytes("zip", [("bom.json", JSON)]))
    for marker, offset in [(b"PK\x03\x04", 6), (b"PK\x01\x02", 8)]:
        position = encrypted.index(marker) + offset
        struct.pack_into("<H", encrypted, position, struct.unpack_from("<H", encrypted, position)[0] | 1)
    assert upload(context, bytes(encrypted)).status_code == 422
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        member = zipfile.ZipInfo("bom.json")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "elsewhere")
    assert upload(context, output.getvalue()).status_code == 422
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0


@pytest.mark.parametrize("raw", [b"PK\x03\x04truncated", b"Rar!\x1a\x07\x00unsupported", archive_bytes("zip", [("not-sbom.json", b'{"message":"not an SBOM"}')])])
def test_malformed_unsupported_and_non_sbom_archive_input_is_rejected(context, raw):
    assert upload(context, raw).status_code == 422


def test_raw_upload_and_expansion_limits_are_independent(context, monkeypatch):
    raw = JSON + b" " * 8192
    compressed = archive_bytes("zip", [("bom.json", raw)])
    assert len(compressed) < 512 < len(raw)
    monkeypatch.setattr(context.settings, "max_upload_bytes", 512)
    response = upload(context, compressed)
    assert response.status_code == 422, response.text
    monkeypatch.setattr(context.settings, "max_upload_bytes", len(compressed) - 1)
    assert upload(context, compressed).status_code == 413
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0


def test_archive_document_budget_rejects_without_storing_run_or_artifact(context, monkeypatch):
    raw = JSON[:-1] + b',"notes":"' + b"x" * 512 + b'"}'
    compressed = archive_bytes("zip", [("bom.json", raw)])
    assert len(compressed) < 256 < len(raw)
    monkeypatch.setattr(sbom_module, "MAX_UPLOAD_DOCUMENT_BYTES", 256)

    response = upload(context, compressed)

    assert response.status_code == 422, response.text
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0
    assert context.db.scalar(select(func.count()).select_from(Job)) == 0
    assert not list(context.settings.artifact_dir.iterdir())


@pytest.mark.parametrize("compressed", [False, True])
def test_padded_json_is_compacted_for_validation_and_keeps_original(context, monkeypatch, compressed):
    payload = json.loads(JSON)
    payload["components"] = [{"type": "library", "name": 'Sample library "A"', "version": "1  2"}]
    document = json.dumps(payload, indent=2).encode() + b" " * 8192
    compact_limit = len(json.dumps(payload, separators=(",", ":")).encode())
    raw = archive_bytes("zip", [("bom.json", document)]) if compressed else document
    monkeypatch.setattr(sbom_module, "MAX_UPLOAD_DOCUMENT_BYTES", compact_limit)

    response = upload(context, raw)

    assert response.status_code == 202, response.text
    run = context.db.get(SbomRun, response.json()["runId"])
    assert Path(run.artifact_path).read_bytes() == raw
    assert run.normalized_bom == payload
    assert run.sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 128])
def test_json_compaction_preserves_strings_and_invalid_scalar_boundaries(chunk_size):
    class ChunkedReader(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, chunk_size))

    payload = {"key with spaces": ['two  spaces \\ "quote"', {"integer": 123, "boolean": True}], "empty": []}
    document = json.dumps(payload, indent=2).encode()
    compact = io.BytesIO()
    sbom_module._compact_large_json(ChunkedReader(document), compact)
    assert compact.getvalue() == json.dumps(payload, separators=(",", ":")).encode()

    compact = io.BytesIO()
    sbom_module._compact_large_json(ChunkedReader(b'{ "x" : [ 1 \r\n 2 ] }'), compact)
    assert compact.getvalue() == b'{"x":[1 2]}'
    with pytest.raises(json.JSONDecodeError):
        json.loads(compact.getvalue())


def test_archive_keeps_queue_component_and_idempotency_admission(context, monkeypatch):
    compressed = archive_bytes("zip", [("bom.json", JSON)])
    monkeypatch.setattr(context.settings, "max_queued_jobs", 0)
    assert upload(context, compressed).status_code == 429
    monkeypatch.setattr(context.settings, "max_queued_jobs", 10_000)
    headers = {**context.headers, "Idempotency-Key": "same-original-archive"}
    first = upload(context, compressed, headers=headers)
    second = upload(context, compressed, headers=headers)
    assert first.status_code == second.status_code == 202
    assert second.json()["idempotentReplay"] is True and second.json()["runId"] == first.json()["runId"]
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 1
    monkeypatch.setattr(context.settings, "max_sbom_components", 0)
    assert upload(context, archive_bytes("zip", [("bom.xml", XML)]), releaseVersion="2").status_code == 422


def test_archive_upload_keeps_csrf_service_scope_and_inactive_environment(context):
    compressed = archive_bytes("zip", [("bom.json", JSON)])
    assert upload(context, compressed, headers={}).status_code == 403
    context.client.cookies.clear()
    assert upload(context, compressed, headers={}).status_code == 401
    token = ApiToken(name="other-service", token_hash=digest("other-service-token"), service_id="other")
    context.db.add_all([Service(id="other", slug="other", name="Other"), token])
    context.db.commit()
    headers = {"Authorization": "Bearer other-service-token"}
    assert upload(context, compressed, headers=headers).status_code == 403
    token.service_id = context.service.id
    context.environment.active = False
    context.db.commit()
    assert upload(context, compressed, headers=headers).status_code == 409
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0


def test_temporary_document_is_removed_when_schema_validation_fails(context, monkeypatch):
    paths = []

    def reject(document, *_args, **_kwargs):
        paths.append(document)
        assert document.read_bytes() == JSON
        assert context.settings.artifact_dir in document.parents
        raise SbomValidationError("fixture schema rejection")

    monkeypatch.setattr(main, "validate_file_with_cyclonedx_cli", reject)
    assert upload(context, archive_bytes("zip", [("bom.json", JSON)])).status_code == 422
    assert paths and all(not path.exists() for path in paths)
    assert context.db.scalar(select(func.count()).select_from(SbomRun)) == 0


def test_raw_stage_uses_artifact_storage_and_removes_failed_upload(context):
    path, actual_hash, size = asyncio.run(main._stage_upload(UploadFile(file=io.BytesIO(JSON)), len(JSON)))
    try:
        assert path.parent == context.settings.artifact_dir
        assert path.read_bytes() == JSON and stat.S_IMODE(path.stat().st_mode) == 0o600
        assert actual_hash == hashlib.sha256(JSON).hexdigest() and size == len(JSON)
    finally:
        path.unlink()
    with pytest.raises(HTTPException) as raised:
        asyncio.run(main._stage_upload(UploadFile(file=io.BytesIO(JSON)), len(JSON) - 1))
    assert raised.value.status_code == 413
    assert not list(context.settings.artifact_dir.iterdir())


def test_spdx_validator_conversion_stays_beside_selected_artifact(context, monkeypatch):
    directory = context.settings.artifact_dir
    directory.mkdir()
    source = directory / "original.spdx.json"
    source.write_text(json.dumps(spdx_document()))
    seen = []

    def validate(command, **_kwargs):
        converted = Path(command[command.index("--input-file") + 1])
        assert converted != source and converted.parent == source.parent
        assert json.loads(converted.read_bytes())["bomFormat"] == "CycloneDX"
        seen.append(converted)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sbom_module, "_run_cyclonedx", validate)
    sbom_module.validate_file_with_cyclonedx_cli(source, "fixture-validator", input_format="json")
    assert seen and not seen[0].exists() and source.exists()


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz", "7z"])
def test_archive_grype_uses_temporary_document_and_preserves_analysis_history(context, monkeypatch, kind):
    compressed = SEVEN_Z if kind == "7z" else archive_bytes(kind, [("bom.json", XML)])
    expected = JSON if kind == "7z" else XML
    response = upload(context, compressed)
    assert response.status_code == 202, response.text
    item = context.db.get(SbomRun, response.json()["runId"])
    original_path = item.artifact_path
    seen = []
    original_run = services.subprocess.run

    def grype(command, **kwargs):
        if command[0] != context.settings.grype_binary:
            return original_run(command, **kwargs)
        selected = Path(command[1].removeprefix("sbom:"))
        seen.append(selected)
        assert selected != Path(original_path) and selected.read_bytes() == expected
        assert context.settings.artifact_dir in selected.parents
        assert kwargs["env"]["GRYPE_DB_AUTO_UPDATE"] == "false"
        return SimpleNamespace(returncode=0, stdout='{"matches":[],"descriptor":{"version":"fixture"}}', stderr="")

    monkeypatch.setattr(services.subprocess, "run", grype)
    first = services.analyze_offline(context.db, item)
    second = services.analyze_offline(context.db, item)
    assert first.state == second.state == JobState.COMPLETED
    assert first.id != second.id and second.sequence == first.sequence + 1
    assert first.data_sources["sbomQuality"]["originalSha256"] == item.sha256
    assert len(seen) == 2 and all(not path.exists() for path in seen)
    assert item.artifact_path == original_path and Path(original_path).read_bytes() == compressed


@pytest.mark.parametrize("archive", [False, True], ids=["plain", "zip"])
@pytest.mark.parametrize("xml", [False, True], ids=["json", "xml"])
def test_cyclonedx17_uses_grype_compatible_view_without_changing_original(context, monkeypatch, archive, xml):
    component = {"type": "library", "name": "sample", "version": "1", "bom-ref": "pkg", "purl": "pkg:npm/sample@1"}
    source = (
        b'<bom xmlns="http://cyclonedx.org/schema/bom/1.7" version="1"><components>'
        b'<component type="library" bom-ref="pkg"><name>sample</name><version>1</version>'
        b'<purl>pkg:npm/sample@1</purl></component></components></bom>'
        if xml else json.dumps({
            "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [component],
        }).encode()
    )
    original = archive_bytes("zip", [("inventory", source)]) if archive else source
    response = upload(context, original)
    assert response.status_code == 202, response.text
    run = context.db.get(SbomRun, response.json()["runId"])
    observed = []
    original_run = services.subprocess.run

    def grype(command, **kwargs):
        if command[0] != context.settings.grype_binary:
            return original_run(command, **kwargs)
        scan_input = Path(command[1].removeprefix("sbom:"))
        document = json.loads(scan_input.read_bytes())
        assert document["specVersion"] == "1.6" and "$schema" not in document
        assert document["components"] == [component]
        observed.append(scan_input)
        return SimpleNamespace(returncode=0, stdout='{"matches":[],"descriptor":{"version":"fixture"}}', stderr="")

    monkeypatch.setattr(services.subprocess, "run", grype)
    revision = services.analyze_offline(context.db, run)
    assert revision.state == JobState.COMPLETED
    assert run.spec_version == run.normalized_bom["specVersion"] == "1.7"
    assert Path(run.artifact_path).read_bytes() == original
    assert revision.data_sources["sbomQuality"]["originalSha256"] == hashlib.sha256(original).hexdigest()
    assert len(observed) == 1 and not observed[0].exists()


def test_data_upload_staging_uses_opaque_suffix_and_cleanup_is_exact(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    monkeypatch.setattr(get_settings(), "data_update_spool_dir", spool)
    raw = archive_bytes("zip", [("metadata.env", b"fixture")])

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []}, receive)
    path, actual_hash, length = asyncio.run(main._stage_data_update_request(request, kind="unified"))
    assert path.name.endswith(".archive") and path.read_bytes() == raw
    assert actual_hash == hashlib.sha256(raw).hexdigest() and length == len(raw)
    legacy = spool / ("upload-" + "a" * 32 + ".tar.gz")
    legacy.write_bytes(b"legacy")
    unrelated = [spool / "upload-user.tar.gz", spool / ("upload-" + "b" * 32 + ".archive.bak"), spool / "original.tar.gz"]
    for file in unrelated:
        file.write_bytes(b"preserve")
    directory = spool / ("upload-" + "c" * 32 + ".archive")
    directory.mkdir()
    linked = spool / ("upload-" + "d" * 32 + ".archive")
    linked.symlink_to(unrelated[0])
    worker._purge_spooled_uploads(spool)
    assert not path.exists() and not legacy.exists() and not linked.is_symlink()
    assert directory.is_dir() and all(file.read_bytes() == b"preserve" for file in unrelated)
