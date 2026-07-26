#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${1:-$ROOT_DIR/.env}"
[[ -f "$env_file" ]] || { echo "Missing env file: $env_file" >&2; exit 2; }
set -a
# shellcheck disable=SC1090
source "$env_file"
set +a
required=(POSTGRES_PASSWORD DTRACK_DB_PASSWORD TRACKER_DB_PASSWORD TRACKER_BOOTSTRAP_ADMIN_PASSWORD TRACKER_DEPENDENCY_TRACK_API_KEY TRACKER_DATABASE_URL DTRACK_API_BASE_URL)
for name in "${required[@]}"; do
  value="${!name:-}"
  [[ -n "$value" && "$value" != change-me-* ]] || { echo "$name is missing or placeholder" >&2; exit 2; }
done
python3 - "$TRACKER_DATABASE_URL" "$TRACKER_DB_USER" "$TRACKER_DB_NAME" "$TRACKER_DB_PASSWORD" "$DTRACK_API_BASE_URL" <<'PY'
import sys
from urllib.parse import unquote, urlparse
db, user, name, password, dtrack = sys.argv[1:]
parsed = urlparse(db)
if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
    raise SystemExit("TRACKER_DATABASE_URL must use postgresql+psycopg")
if unquote(parsed.username or "") != user or (parsed.path or "").lstrip("/") != name:
    raise SystemExit("TRACKER_DATABASE_URL user/database does not match TRACKER_DB_*")
if unquote(parsed.password or "") != password:
    raise SystemExit("TRACKER_DATABASE_URL password does not match TRACKER_DB_PASSWORD")
if any(host in dtrack for host in ("dtrack-apiserver", "localhost", "127.0.0.1")):
    raise SystemExit("DTRACK_API_BASE_URL must be the gateway/server URL")
if not dtrack.rstrip("/").endswith("/api"):
    raise SystemExit("DTRACK_API_BASE_URL must end with /api")
PY
docker compose --env-file "$env_file" -f "$ROOT_DIR/compose.yaml" -f "$ROOT_DIR/compose.airgap.yaml" config >/dev/null
echo "Air-gap preflight OK: $env_file"
