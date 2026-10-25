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
for name in "${required[@]}"; do
  value="${!name:-}"
  [[ -n "$value" && "$value" != change-me-* ]] || { echo "$name is missing or placeholder" >&2; exit 2; }
done
python3 - "$TRACKER_DATABASE_URL" "$TRACKER_DB_USER" "$TRACKER_DB_NAME" "$TRACKER_DB_PASSWORD" "${PUBLIC_HTTP_BIND:-127.0.0.1}" "${TRACKER_ENVIRONMENT:-development}" "${TRACKER_SECURE_COOKIES:-false}" "${TRACKER_PUBLIC_ORIGIN:-}" <<'PY'
import ipaddress
import sys
from urllib.parse import unquote, urlparse
db, user, name, password, public_bind, environment, secure_cookies, public_origin = sys.argv[1:]
parsed = urlparse(db)
if parsed.scheme not in {"postgresql", "postgresql+psycopg"}:
    raise SystemExit("TRACKER_DATABASE_URL must use postgresql+psycopg")
if unquote(parsed.username or "") != user or (parsed.path or "").lstrip("/") != name:
    raise SystemExit("TRACKER_DATABASE_URL user/database does not match TRACKER_DB_*")
if unquote(parsed.password or "") != password:
    raise SystemExit("TRACKER_DATABASE_URL password does not match TRACKER_DB_PASSWORD")
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
if [[ -n "${TRACKER_DATA_UPDATE_VERIFY_KEY_FILE:-}" ]]; then
  verify_key="$TRACKER_DATA_UPDATE_VERIFY_KEY_FILE"
  [[ "$verify_key" == /* ]] || verify_key="$(dirname "$env_file")/$verify_key"
  [[ -f "$verify_key" && -r "$verify_key" ]] || { echo "register a readable data-update public key: TRACKER_DATA_UPDATE_VERIFY_KEY_FILE" >&2; exit 2; }
  if LC_ALL=C grep -q 'PRIVATE KEY' "$verify_key"; then
    echo "data-update verification mount must contain only a public key" >&2; exit 2
  fi
  openssl pkey -pubin -in "$verify_key" -noout >/dev/null 2>&1 || { echo "invalid data-update public key" >&2; exit 2; }
fi
docker compose --env-file "$env_file" -f "$ROOT_DIR/compose.yaml" -f "$ROOT_DIR/compose.airgap.yaml" config >/dev/null
echo "Air-gap preflight OK: $env_file"
