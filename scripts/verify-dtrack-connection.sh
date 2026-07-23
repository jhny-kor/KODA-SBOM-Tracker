#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

if [[ -z "${TRACKER_DEPENDENCY_TRACK_API_KEY:-}" || "${TRACKER_DEPENDENCY_TRACK_API_KEY}" == change-me-* ]]; then
  echo "Dependency-Track API key is missing or still a placeholder" >&2
  echo "Set TRACKER_DEPENDENCY_TRACK_API_KEY to a dedicated least-privilege team key" >&2
  exit 2
fi

verify_base="${DTRACK_API_BASE_URL:-}"
if [[ -z "$verify_base" || "$verify_base" == *dtrack-apiserver* ]]; then
  verify_base="http://127.0.0.1:${PUBLIC_HTTP_PORT:-8088}${DTRACK_BASE_PATH:-/dependency-track}/api"
fi
verify_base="${verify_base%/}"

TRACKER_DEPENDENCY_TRACK_API_KEY="$TRACKER_DEPENDENCY_TRACK_API_KEY" \
  DTRACK_VERIFY_BASE="$verify_base" \
  python3 - <<'PY'
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


base = os.environ["DTRACK_VERIFY_BASE"].rstrip("/")
key = os.environ["TRACKER_DEPENDENCY_TRACK_API_KEY"]
headers = {"Accept": "application/json", "X-Api-Key": key}


def get(path: str):
    request = urllib.request.Request(f"{base}/{path.lstrip('/')}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(f"Dependency-Track request failed: {path} (HTTP {exc.code})", file=sys.stderr)
        if exc.code == 401:
            print("The key is invalid, expired, or not accepted by this backend", file=sys.stderr)
        elif exc.code == 403:
            print("The key is valid but lacks the required permission", file=sys.stderr)
        raise SystemExit(1)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Dependency-Track is unreachable: {exc}", file=sys.stderr)
        raise SystemExit(1)


_, version = get("version")
_, team = get("v1/team/self")
_, permissions_payload = get("v1/user/self/permissions")

permissions = permissions_payload if isinstance(permissions_payload, list) else permissions_payload.get("permissions", [])
permission_names = {
    item.get("name") if isinstance(item, dict) else str(item)
    for item in permissions
}
required = {
    "BOM_UPLOAD",
    "PROJECT_CREATION_UPLOAD",
    "VIEW_PORTFOLIO",
    "VIEW_VULNERABILITY",
    "VIEW_POLICY_VIOLATION",
    "PORTFOLIO_MANAGEMENT_UPDATE",
}
missing = sorted(required - permission_names)
if missing:
    print(f"Dependency-Track key is authenticated but missing permissions: {', '.join(missing)}", file=sys.stderr)
    raise SystemExit(1)

version_value = version.get("version") if isinstance(version, dict) else version
team_name = team.get("name", "unknown") if isinstance(team, dict) else "unknown"
print(f"Dependency-Track connection OK: version={version_value} team={team_name}")
print(f"Verified permissions: {', '.join(sorted(required))}")
PY
