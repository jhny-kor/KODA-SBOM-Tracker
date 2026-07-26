from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from koda_tracker.config import get_settings
from koda_tracker.dtrack import DependencyTrackClient


@pytest.mark.skipif(os.getenv("KODA_DTRACK_LIVE") != "1", reason="set KODA_DTRACK_LIVE=1 for an authenticated Dependency-Track smoke test")
def test_live_dependency_track_upload_token_and_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the real v5 API without running in the normal offline unit suite."""
    base_url = os.getenv("KODA_DTRACK_LIVE_URL")
    api_key = os.getenv("KODA_DTRACK_LIVE_API_KEY")
    if not base_url or not api_key:
        pytest.fail("KODA_DTRACK_LIVE_URL and KODA_DTRACK_LIVE_API_KEY are required")
    monkeypatch.setenv("TRACKER_DEPENDENCY_TRACK_URL", base_url)
    monkeypatch.setenv("TRACKER_DEPENDENCY_TRACK_API_KEY", api_key)
    get_settings.cache_clear()
    artifact = tmp_path / "koda-live-smoke.json"
    artifact.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")

    async def scenario() -> None:
        client = DependencyTrackClient()
        status = await client.status()
        assert status["authenticated"] is True, status
        assert status["missingPermissions"] == [], status
        collection = await client.ensure_collection("KODA::live-smoke")
        upload = await client.upload(
            project_name="KODA::live-smoke::qa",
            project_version="live-smoke::r1",
            artifact=artifact,
            parent_uuid=collection,
            tags=["koda", "env:qa", "run:live-smoke"],
        )
        assert upload.get("token")
        await client.wait_for_token(str(upload["token"]), timeout_seconds=180)
        project = await client.lookup_project("KODA::live-smoke::qa", "live-smoke::r1")
        metrics, policies = await client.project_snapshot(str(project["uuid"]))
        assert isinstance(metrics, dict)
        assert isinstance(policies, list)

    try:
        asyncio.run(scenario())
    finally:
        get_settings.cache_clear()
