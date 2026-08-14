#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

if [[ -z "${DTRACK_ADMIN_API_KEY:-}" ]]; then
  echo "Set DTRACK_ADMIN_API_KEY in the shell environment; it is never read from or written to .env" >&2
  exit 2
fi

target_env="${DTRACK_TARGET_ENV_FILE:-$ENV_FILE}"
team_name="${DTRACK_AUTOMATION_TEAM_NAME:-KODA Portal Automation}"
base="${DTRACK_ADMIN_API_BASE_URL:-${DTRACK_API_BASE_URL:-}}"
if [[ -z "$base" || "$base" == *dtrack-apiserver* ]]; then
  base="http://127.0.0.1:${PUBLIC_HTTP_PORT:-8088}${DTRACK_BASE_PATH:-/dependency-track}/api"
fi
if [[ "$base" != */api ]]; then
  base="${base%/}/api"
fi

DTRACK_ADMIN_API_KEY="$DTRACK_ADMIN_API_KEY" \
  DTRACK_ADMIN_BASE="${base%/}" \
  DTRACK_TEAM_NAME="$team_name" \
  DTRACK_TARGET_ENV="$target_env" \
  python3 - <<'PY'
import json
import os
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path


base = os.environ["DTRACK_ADMIN_BASE"].rstrip("/")
admin_key = os.environ["DTRACK_ADMIN_API_KEY"]
team_name = os.environ["DTRACK_TEAM_NAME"]
target_env = Path(os.environ["DTRACK_TARGET_ENV"])
headers = {"Accept": "application/json", "X-Api-Key": admin_key}
required = [
    "BOM_UPLOAD",
    "PROJECT_CREATION_UPLOAD",
    "VIEW_PORTFOLIO",
    "VIEW_VULNERABILITY",
    "VIEW_POLICY_VIOLATION",
    "PORTFOLIO_MANAGEMENT_UPDATE",
]


def request(method: str, path: str, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {**headers, "Content-Type": "application/json"} if body is not None else headers
    request = urllib.request.Request(
        f"{base}/{path.lstrip('/')}", data=body, headers=request_headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()
            return response.status, json.loads(data.decode("utf-8")) if data else {}
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and method == "PUT" and path == "v1/permission/team":
            return exc.code, {}
        print(f"Dependency-Track provisioning failed: {method} {path} (HTTP {exc.code})", file=sys.stderr)
        if exc.code == 401:
            print("The administrator key is invalid or expired", file=sys.stderr)
        raise SystemExit(1)


_, teams_payload = request("GET", "v1/team?pageNumber=1&pageSize=100")
teams = teams_payload if isinstance(teams_payload, list) else teams_payload.get("items", [])
team = next((item for item in teams if item.get("name") == team_name), None)
if team is None:
    _, team = request("PUT", "v1/team", {"uuid": str(uuid.uuid4()), "name": team_name})
team_uuid = team.get("uuid")
if not team_uuid:
    print("Dependency-Track did not return a team UUID", file=sys.stderr)
    raise SystemExit(1)

request("PUT", "v1/permission/team", {"team": team_uuid, "permissions": required})
api_keys = team.get("apiKeys") or []
if api_keys:
    print(
        f"Team {team_name!r} already has an API key. Regeneration is intentionally not automatic; "
        "generate one in the UI or remove the old key before rerunning.",
        file=sys.stderr,
    )
    raise SystemExit(3)
_, generated = request("PUT", f"v1/team/{team_uuid}/key")
raw_key = generated.get("key") or generated.get("apiKey") or generated.get("value")
if not raw_key:
    print("Dependency-Track did not return the newly generated key", file=sys.stderr)
    raise SystemExit(1)

if not target_env.is_file():
    print(f"Target env file does not exist: {target_env}", file=sys.stderr)
    raise SystemExit(1)
mode = stat.S_IMODE(target_env.stat().st_mode)
lines = target_env.read_text(encoding="utf-8").splitlines()
replacement = f"TRACKER_DEPENDENCY_TRACK_API_KEY={raw_key}"
updated = False
for index, line in enumerate(lines):
    if line.startswith("TRACKER_DEPENDENCY_TRACK_API_KEY="):
        lines[index] = replacement
        updated = True
        break
if not updated:
    lines.append(replacement)

with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target_env.parent, delete=False) as handle:
    handle.write("\n".join(lines) + "\n")
    temporary = Path(handle.name)
temporary.chmod(mode)
temporary.replace(target_env)
print(f"Configured Dependency-Track team {team_name!r} and updated {target_env}")
print("The generated key is stored only in the target env file; it is not printed.")
PY
