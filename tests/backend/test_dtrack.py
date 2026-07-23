from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from koda_tracker.dtrack import DependencyTrackClient


def test_dependency_track_v5_contract(tmp_path: Path) -> None:
    artifact = tmp_path / "bom.json"
    artifact.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}')
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path == "/api/v1/project/lookup" and request.url.params.get("version") == "":
            return httpx.Response(404)
        if path == "/api/v1/project" and request.method == "PUT":
            return httpx.Response(200, json={"uuid": "collection-uuid"})
        if path == "/api/v1/bom":
            return httpx.Response(200, json={"token": "event-token"})
        if path == "/api/v1/event/token/event-token":
            return httpx.Response(200, json={"processing": False})
        if path == "/api/v1/project/lookup":
            return httpx.Response(200, json={"uuid": "run-project-uuid"})
        if path == "/api/v1/project/run-project-uuid" and request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "uuid": "run-project-uuid",
                    "name": "KODA::payment::prod",
                    "version": "1.4.2::r3",
                    "classifier": "APPLICATION",
                    "active": True,
                    "isLatest": False,
                },
            )
        if path == "/api/v1/project" and request.method == "POST":
            payload = json.loads(request.content)
            assert payload["isLatest"] is True
            return httpx.Response(200, json=payload)
        if path == "/api/v1/metrics/project/run-project-uuid/current":
            return httpx.Response(200, json={"components": 1, "critical": 0})
        if path == "/api/v1/violation/project/run-project-uuid":
            return httpx.Response(200, json=[{"uuid": "violation-1", "type": "LICENSE"}])
        return httpx.Response(500, json={"unexpected": str(request.url)})

    async def scenario() -> None:
        client = DependencyTrackClient(transport=httpx.MockTransport(handler))
        collection_uuid = await client.ensure_collection("KODA::payment")
        assert collection_uuid == "collection-uuid"
        upload = await client.upload(
            project_name="KODA::payment::prod",
            project_version="1.4.2::r3",
            artifact=artifact,
            parent_uuid=collection_uuid,
            tags=["koda", "env:prod", "run:run-uuid"],
        )
        await client.wait_for_token(upload["token"], timeout_seconds=2)
        project = await client.lookup_project("KODA::payment::prod", "1.4.2::r3")
        await client.promote_latest(project["uuid"])
        metrics, policies = await client.project_snapshot(project["uuid"])
        assert metrics["components"] == 1
        assert policies[0]["uuid"] == "violation-1"

    asyncio.run(scenario())
    bom_request = next(request for request in requests if request.url.path == "/api/v1/bom")
    body = bom_request.content.decode(errors="ignore")
    assert 'name="autoCreate"' in body and "true" in body
    assert 'name="projectName"' in body and "KODA::payment::prod" in body
    assert 'name="projectVersion"' in body and "1.4.2::r3" in body
    assert 'name="isLatest"' in body and "false" in body
    assert 'name="parentUUID"' in body and "collection-uuid" in body
    assert bom_request.headers["x-api-key"] == "test-api-key"


def test_dependency_track_status_reports_version_team_and_permissions() -> None:
    required = {
        "BOM_UPLOAD",
        "PROJECT_CREATION_UPLOAD",
        "VIEW_PORTFOLIO",
        "VIEW_VULNERABILITY",
        "VIEW_POLICY_VIOLATION",
        "PORTFOLIO_MANAGEMENT_UPDATE",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "5.0.3"})
        if request.url.path == "/api/v1/team/self":
            return httpx.Response(200, json={"name": "koda-automation"})
        if request.url.path == "/api/v1/user/self/permissions":
            return httpx.Response(200, json=[{"name": name} for name in required])
        return httpx.Response(500, json={"unexpected": str(request.url)})

    async def scenario() -> None:
        client = DependencyTrackClient(transport=httpx.MockTransport(handler))
        status = await client.status()
        assert status["configured"] is True
        assert status["reachable"] is True
        assert status["authenticated"] is True
        assert status["version"] == "5.0.3"
        assert status["team"] == "koda-automation"
        assert status["missingPermissions"] == []
        assert set(status["permissions"]) == required

    asyncio.run(scenario())
