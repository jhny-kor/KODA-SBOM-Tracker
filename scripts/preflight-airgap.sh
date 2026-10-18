#!/bin/bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${1:-$ROOT_DIR/.env}"
[[ -f "$env_file" ]] || { echo "Missing env file: $env_file" >&2; exit 2; }
set -a
# shellcheck disable=SC1090
source "$env_file"
set +a
source "$ROOT_DIR/scripts/lib.sh"
required=(POSTGRES_PASSWORD TRACKER_DB_PASSWORD TRACKER_BOOTSTRAP_ADMIN_PASSWORD TRACKER_DATABASE_URL)
profile_args=()
if dependency_track_enabled; then
  required+=(DTRACK_DB_PASSWORD TRACKER_DEPENDENCY_TRACK_API_KEY DTRACK_API_BASE_URL)
  profile_args+=(--profile dependency-track)
fi
for name in "${required[@]}"; do
  value="${!name:-}"
  [[ -n "$value" && "$value" != change-me-* ]] || { echo "$name is missing or placeholder" >&2; exit 2; }
done
python3 - "$TRACKER_DATABASE_URL" "$TRACKER_DB_USER" "$TRACKER_DB_NAME" "$TRACKER_DB_PASSWORD" "${DTRACK_API_BASE_URL:-}" "${PUBLIC_HTTP_BIND:-127.0.0.1}" "${TRACKER_ENVIRONMENT:-development}" "${TRACKER_SECURE_COOKIES:-false}" "${TRACKER_PUBLIC_ORIGIN:-}" "${TRACKER_DEPENDENCY_TRACK_ENABLED:-false}" <<'PY'
import ipaddress
import sys
from urllib.parse import unquote, urlparse
db, user, name, password, dtrack, public_bind, environment, secure_cookies, public_origin, dtrack_enabled = sys.argv[1:]
parsed = urlparse(db)
if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
    raise SystemExit("TRACKER_DATABASE_URL must use postgresql+psycopg")
if unquote(parsed.username or "") != user or (parsed.path or "").lstrip("/") != name:
    raise SystemExit("TRACKER_DATABASE_URL user/database does not match TRACKER_DB_*")
if unquote(parsed.password or "") != password:
    raise SystemExit("TRACKER_DATABASE_URL password does not match TRACKER_DB_PASSWORD")
if dtrack_enabled.lower() in {"true", "1", "yes", "on"}:
    if any(host in dtrack for host in ("dtrack-apiserver", "localhost", "127.0.0.1")):
        raise SystemExit("DTRACK_API_BASE_URL must be the gateway/server URL")
    base = dtrack.rstrip("/")
    if base.endswith("/api"):
        raise SystemExit("DTRACK_API_BASE_URL must omit /api; the frontend appends it")
    if not base:
        raise SystemExit("DTRACK_API_BASE_URL must be the browser-facing Dependency-Track base without /api")
try:
    loopback = ipaddress.ip_address(public_bind.strip("[]")).is_loopback
except ValueError:
    loopback = public_bind.lower() == "localhost"
if not loopback:
    if environment.lower() != "production":
        raise SystemExit("non-loopback PUBLIC_HTTP_BIND requires TRACKER_ENVIRONMENT=production")
    if secure_cookies.lower() != "true":
        raise SystemExit("non-loopback PUBLIC_HTTP_BIND requires TRACKER_SECURE_COOKIES=true")
    if not public_origin.lower().startswith("https://"):
        raise SystemExit("non-loopback PUBLIC_HTTP_BIND requires an HTTPS TRACKER_PUBLIC_ORIGIN")
PY
docker compose --env-file "$env_file" -f "$ROOT_DIR/compose.yaml" -f "$ROOT_DIR/compose.airgap.yaml" ${profile_args[@]+"${profile_args[@]}"} config >/dev/null
echo "Air-gap preflight OK: $env_file"
