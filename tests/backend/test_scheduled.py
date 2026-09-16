from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select

from koda_tracker.main import app, _prune_scheduled_runs, _scheduled_environment, _validated_source_metadata
from koda_tracker.models import ApiToken, Environment, ProcessingState, Release, SbomRun, Service, User
from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal


@pytest.fixture(scope="module", autouse=True)
def initialized_tracker():
    with TestClient(app):
        yield


def _metadata(mode: str = "full") -> dict:
    return {
        "targetId": "server-a-root",
        "scheduleRunId": "run-20260907",
        "server": "server-a",
        "directory": "/srv/app",
        "mode": mode,
        "changedFiles": [],
        "rulePolicyVersion": 1,
        "kodaRunId": "koda-run-1",
    }


def test_scheduled_metadata_requires_koda_token() -> None:
    with SessionLocal() as db:
        admin = db.scalar(select(User))
        assert admin is not None
        with pytest.raises(HTTPException, match="KODA 연동 토큰"):
            _validated_source_metadata(admin, "scheduled", _metadata())


def test_scheduled_metadata_accepts_twenty_thousand_changed_files() -> None:
    token = ApiToken(name="koda-gitlab:test", token_hash="a" * 64)
    metadata = _metadata("changed") | {"changedFiles": [f"src/file-{index}.py" for index in range(20_000)]}
    assert len(_validated_source_metadata(token, "scheduled", metadata)[1]["changedFiles"]) == 20_000
    with pytest.raises(HTTPException, match="변경 파일 목록"):
        _validated_source_metadata(token, "scheduled", metadata | {"changedFiles": metadata["changedFiles"] + ["extra.py"]})


def test_scheduled_full_and_changed_use_distinct_environments() -> None:
    with SessionLocal() as db:
        requested = db.scalar(select(Environment).where(Environment.slug == "prod"))
        assert requested is not None
        service = Service(slug="environment-scope-service", name="Environment scope")
        db.add(service)
        db.flush()
        full = _scheduled_environment(db, service=service, requested=requested, metadata=_metadata("full"))
        changed = _scheduled_environment(db, service=service, requested=requested, metadata=_metadata("changed"))
        assert _scheduled_environment(db, service=service, requested=requested, metadata=_metadata("full")).id == full.id
        assert full.id != changed.id
        assert full.slug.endswith("-full")
        assert changed.slug.endswith("-changed")
        db.rollback()


def test_long_target_id_keeps_environment_identifiers_bounded() -> None:
    with SessionLocal() as db:
        requested = db.scalar(select(Environment).where(Environment.slug == "prod"))
        assert requested is not None
        service = Service(slug="long-target-service", name="Long target")
        db.add(service)
        db.flush()
        metadata = _metadata()
        metadata["targetId"] = "t" * 128
        environment = _scheduled_environment(db, service=service, requested=requested, metadata=metadata)
        assert len(environment.slug) <= 128
        assert len(environment.name) <= 255
        db.rollback()


def test_scheduled_retention_removes_old_run_and_leaves_recent() -> None:
    with SessionLocal() as db:
        service = Service(slug="retention-service", name="Retention")
        environment = Environment(slug="retention-env", name="Retention")
        db.add_all([service, environment])
        db.flush()
        release = Release(service_id=service.id, environment_id=environment.id, version="scheduled-retention")
        db.add(release)
        db.flush()
        artifact = get_settings().artifact_dir / "scheduled-retention.cdx.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("{}", encoding="utf-8")
        old = SbomRun(
            release_id=release.id, round_number=1, state=ProcessingState.COMPLETED,
            original_filename=artifact.name, media_type="application/json", spec_version="1.6",
            sha256="a" * 64, size_bytes=2, artifact_path=str(artifact), normalized_bom={},
            source="scheduled", source_metadata=_metadata(),
            created_at=datetime.now(UTC) - timedelta(days=91),
        )
        db.add(old)
        db.commit()
        old_id = old.id
    _prune_scheduled_runs()
    with SessionLocal() as db:
        assert db.get(SbomRun, old_id) is None
