from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from .config import get_settings


class DependencyTrackClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        settings = get_settings()
        self.base_url = settings.dependency_track_url.rstrip("/")
        self.api_key = settings.dependency_track_api_key
        self.transport = transport

    def _client(self, timeout: int = 30) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, transport=self.transport)

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def status(self) -> dict:
        """Return a secret-free connection and permission health snapshot."""
        required = {
            "BOM_UPLOAD",
            "PROJECT_CREATION_UPLOAD",
            "VIEW_PORTFOLIO",
            "VIEW_VULNERABILITY",
            "VIEW_POLICY_VIOLATION",
            "PORTFOLIO_MANAGEMENT_UPDATE",
        }
        result = {
            "configured": self.configured,
            "reachable": False,
            "authenticated": False,
            "version": None,
            "team": None,
            "permissions": [],
            "missingPermissions": sorted(required),
        }
        if not self.configured:
            result["error"] = "Dependency-Track 연결이 구성되지 않았습니다"
            return result
        try:
            headers = {"X-Api-Key": self.api_key}
            async with self._client() as client:
                version_response = await client.get(f"{self.base_url}/api/version")
                result["reachable"] = True
                version_response.raise_for_status()
                version_payload = version_response.json()
                result["version"] = version_payload.get("version") if isinstance(version_payload, dict) else version_payload
                team_response = await client.get(f"{self.base_url}/api/v1/team/self", headers=headers)
                team_response.raise_for_status()
                team_payload = team_response.json()
                result["authenticated"] = True
                result["team"] = team_payload.get("name") if isinstance(team_payload, dict) else None
                permissions_response = await client.get(f"{self.base_url}/api/v1/user/self/permissions", headers=headers)
                permissions_response.raise_for_status()
                permissions_payload = permissions_response.json()
                entries = permissions_payload if isinstance(permissions_payload, list) else permissions_payload.get("permissions", [])
                permissions = sorted(
                    item.get("name") if isinstance(item, dict) else str(item)
                    for item in entries
                )
                result["permissions"] = permissions
                result["missingPermissions"] = sorted(required - set(permissions))
                if result["missingPermissions"]:
                    result["error"] = "Dependency-Track 키 권한이 부족합니다"
        except httpx.HTTPStatusError as exc:
            result["error"] = f"Dependency-Track HTTP {exc.response.status_code}"
        except (httpx.HTTPError, ValueError) as exc:
            result["error"] = f"Dependency-Track 연결 오류: {str(exc)[:240]}"
        return result

    async def ensure_collection(self, name: str) -> str:
        """Return a collection project UUID, creating it when absent."""
        headers = {"X-Api-Key": self.api_key}
        async with self._client() as client:
            lookup = await client.get(
                f"{self.base_url}/api/v1/project/lookup",
                headers=headers,
                params={"name": name, "version": ""},
            )
            if lookup.status_code == 200:
                return str(lookup.json()["uuid"])
            if lookup.status_code != 404:
                lookup.raise_for_status()
            response = await client.put(
                f"{self.base_url}/api/v1/project",
                headers={**headers, "Content-Type": "application/json"},
                json={
                    "name": name,
                    "version": "",
                    "classifier": "APPLICATION",
                    "active": True,
                    "collectionLogic": "AGGREGATE_LATEST_VERSION_CHILDREN",
                },
            )
            response.raise_for_status()
            return str(response.json()["uuid"])

    async def upload(
        self,
        *,
        project_name: str,
        project_version: str,
        artifact: Path,
        parent_uuid: str | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        if not self.configured:
            raise RuntimeError("Dependency-Track 연결이 구성되지 않았습니다")
        fields: dict[str, str] = {
            "autoCreate": "true",
            "projectName": project_name,
            "projectVersion": project_version,
            "isLatest": "false",
        }
        if parent_uuid:
            fields["parentUUID"] = parent_uuid
        if tags:
            fields["projectTags"] = ",".join(tags)
        async with self._client(60) as client:
            with artifact.open("rb") as handle:
                response = await client.post(
                    f"{self.base_url}/api/v1/bom",
                    headers={"X-Api-Key": self.api_key},
                    data=fields,
                    files={"bom": (artifact.name, handle, "application/octet-stream")},
                )
            response.raise_for_status()
            return response.json()

    async def wait_for_token(self, token: str, timeout_seconds: int = 180) -> None:
        async with self._client() as client:
            for _ in range(timeout_seconds // 2):
                response = await client.get(
                    f"{self.base_url}/api/v1/event/token/{token}",
                    headers={"X-Api-Key": self.api_key},
                )
                if response.status_code == 404:
                    response = await client.get(
                        f"{self.base_url}/api/v1/bom/token/{token}",
                        headers={"X-Api-Key": self.api_key},
                    )
                response.raise_for_status()
                payload = response.json()
                processing = payload.get("processing", payload.get("isBeingProcessed", False))
                if not processing:
                    return
                await asyncio.sleep(2)
        raise TimeoutError("Dependency-Track 처리가 제한 시간을 초과했습니다")

    async def lookup_project(self, name: str, version: str) -> dict:
        async with self._client() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/project/lookup",
                headers={"X-Api-Key": self.api_key},
                params={"name": name, "version": version},
            )
            response.raise_for_status()
            return response.json()

    async def promote_latest(self, project_uuid: str) -> None:
        """Promote only a fully processed project; Dependency-Track demotes the prior latest."""
        headers = {"X-Api-Key": self.api_key}
        async with self._client() as client:
            response = await client.get(
                f"{self.base_url}/api/v1/project/{project_uuid}",
                headers=headers,
            )
            response.raise_for_status()
            project = response.json()
            project["isLatest"] = True
            updated = await client.post(
                f"{self.base_url}/api/v1/project",
                headers={**headers, "Content-Type": "application/json"},
                json=project,
            )
            updated.raise_for_status()

    async def project_snapshot(self, project_uuid: str) -> tuple[dict, list]:
        headers = {"X-Api-Key": self.api_key}
        async with self._client() as client:
            metrics_response, policies_response = await asyncio.gather(
                client.get(f"{self.base_url}/api/v1/metrics/project/{project_uuid}/current", headers=headers),
                client.get(
                    f"{self.base_url}/api/v1/violation/project/{project_uuid}",
                    headers=headers,
                    params={"pageNumber": 1, "pageSize": 1000},
                ),
            )
            metrics_response.raise_for_status()
            policies_response.raise_for_status()
            policies_payload = policies_response.json()
            policies = policies_payload if isinstance(policies_payload, list) else policies_payload.get("items", [])
            return metrics_response.json(), policies
