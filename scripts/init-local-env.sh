#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

target="${1:-$ROOT_DIR/.env}"
if [[ -e "$target" ]]; then
  echo "Refusing to overwrite existing env file: $target" >&2
  exit 1
fi
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

umask 077
postgres_password="$(openssl rand -hex 24)"
tracker_password="$(openssl rand -hex 24)"
admin_password="$(openssl rand -base64 32 | tr -d '\n')"
ldap_key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')"
target_dir="$(cd "$(dirname "$target")" && pwd)"
tmp="$(mktemp "$target_dir/.env.XXXXXX")"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    POSTGRES_PASSWORD=*) echo "POSTGRES_PASSWORD=$postgres_password" ;;
    TRACKER_DB_PASSWORD=*) echo "TRACKER_DB_PASSWORD=$tracker_password" ;;
    TRACKER_DATABASE_URL=*) echo "TRACKER_DATABASE_URL=postgresql+psycopg://sbom_tracker:${tracker_password}@postgres:5432/sbom_tracker" ;;
    TRACKER_BOOTSTRAP_ADMIN_PASSWORD=*) echo "TRACKER_BOOTSTRAP_ADMIN_PASSWORD=$admin_password" ;;
    TRACKER_LDAP_ENCRYPTION_KEY=*) echo "TRACKER_LDAP_ENCRYPTION_KEY=$ldap_key" ;;
    *) echo "$line" ;;
  esac
done < "$EXAMPLE_ENV_FILE" > "$tmp"

chmod 600 "$tmp"
mv "$tmp" "$target"
trap - EXIT
echo "Created $target with generated local database, bootstrap, and LDAP secrets."
