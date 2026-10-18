#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

backup_dir=""
public_key="${KODA_BACKUP_VERIFY_KEY:-}"
usage() { local rc="${1:-2}"; echo "usage: $0 <backup-dir> [--public-key FILE]" >&2; exit "$rc"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key) public_key="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage 2 ;;
    *) [[ -z "$backup_dir" ]] || usage 2; backup_dir="$1"; shift ;;
  esac
done
require_arg "$backup_dir" "backup directory is required"
[[ -d "$backup_dir" ]] || { echo "backup directory not found: $backup_dir" >&2; exit 1; }
allow_unsigned="${KODA_ALLOW_UNSIGNED_ARTIFACTS:-0}"
if [[ -n "$public_key" ]]; then
  [[ -r "$public_key" ]] || { echo "backup verification key is not readable: $public_key" >&2; exit 1; }
else
  KODA_ALLOW_UNSIGNED_ARTIFACTS="$allow_unsigned" require_unsigned_artifact_opt_in "backup restore"
fi

backup_dir="$(cd "$backup_dir" && pwd)"
if [[ -n "$public_key" ]]; then
  public_key="$(cd "$(dirname "$public_key")" && pwd)/$(basename "$public_key")"
  case "$public_key" in
    "$backup_dir"/*) echo "backup verification key must be provisioned outside the backup directory" >&2; exit 1 ;;
  esac
fi

# Copy into a private staging directory and verify the copy. Every destructive
# restore operation below reads only this immutable-by-other-users snapshot.
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/koda-backup-restore.XXXXXX")"
chmod 700 "$staging_root"
cleanup() { rm -rf "$staging_root"; }
trap cleanup EXIT
staged_backup="$staging_root/backup"
mkdir "$staged_backup"
cp -a "$backup_dir/." "$staged_backup/"
chmod -R u=rwX,go= "$staged_backup"
if [[ -n "$public_key" ]]; then
  staged_public_key="$staging_root/backup-public.pem"
  cp "$public_key" "$staged_public_key"
  chmod u=rw,go= "$staged_public_key"
  "$ROOT_DIR/scripts/verify-backup.sh" "$staged_backup" --public-key "$staged_public_key"
else
  "$ROOT_DIR/scripts/verify-backup.sh" "$staged_backup"
fi

# Restored optional data may belong to an installation whose integration is
# now disabled. Stop its writers explicitly, independent of active profiles.
if [[ -f "${staged_backup}/dtrack-data.tar.gz" || -f "${staged_backup}/${DTRACK_DB_NAME:-dtrack}.dump" ]]; then
  compose --profile dependency-track stop dtrack-frontend dtrack-apiserver
  compose --profile dependency-track down
else
  compose down
fi
alpine_untar "${staged_backup}/tracker-artifacts.tar.gz" "${TRACKER_ARTIFACTS_VOLUME_NAME}"
if [[ -f "${staged_backup}/dtrack-data.tar.gz" ]]; then
  alpine_untar "${staged_backup}/dtrack-data.tar.gz" "${DTRACK_DATA_VOLUME_NAME:-koda-sbom-dtrack-data}"
fi
alpine_untar "${staged_backup}/vuln-data.tar.gz" "${VULN_DATA_VOLUME_NAME}"

compose up -d postgres
until compose exec -T postgres pg_isready -U "${POSTGRES_SUPERUSER}" -d postgres >/dev/null 2>&1; do
  sleep 2
done

compose exec -T postgres psql -U "${POSTGRES_SUPERUSER}" -d postgres < "${staged_backup}/postgres-globals.sql"
compose exec -T postgres dropdb --if-exists -U "${POSTGRES_SUPERUSER}" "${TRACKER_DB_NAME}"
compose exec -T postgres createdb -U "${POSTGRES_SUPERUSER}" -O "${TRACKER_DB_USER}" "${TRACKER_DB_NAME}"
if [[ -f "${staged_backup}/${DTRACK_DB_NAME:-dtrack}.dump" ]]; then
  compose exec -T postgres dropdb --if-exists -U "${POSTGRES_SUPERUSER}" "${DTRACK_DB_NAME:-dtrack}"
  compose exec -T postgres createdb -U "${POSTGRES_SUPERUSER}" -O "${DTRACK_DB_USER:-dtrack}" "${DTRACK_DB_NAME:-dtrack}"
  cat "${staged_backup}/${DTRACK_DB_NAME:-dtrack}.dump" | compose exec -T postgres pg_restore -U "${POSTGRES_SUPERUSER}" -d "${DTRACK_DB_NAME:-dtrack}" --clean --if-exists
fi
cat "${staged_backup}/${TRACKER_DB_NAME}.dump" | compose exec -T postgres pg_restore -U "${POSTGRES_SUPERUSER}" -d "${TRACKER_DB_NAME}" --clean --if-exists

echo "Restored backup from ${backup_dir}"
