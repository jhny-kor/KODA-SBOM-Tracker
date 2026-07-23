#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

backup_dir="${1:-}"
require_arg "$backup_dir" "usage: $0 <backup-dir>"

"$ROOT_DIR/scripts/verify-backup.sh" "$backup_dir"

compose down
alpine_untar "${backup_dir}/tracker-artifacts.tar.gz" "${TRACKER_ARTIFACTS_VOLUME_NAME}"
alpine_untar "${backup_dir}/dtrack-data.tar.gz" "${DTRACK_DATA_VOLUME_NAME}"
alpine_untar "${backup_dir}/vuln-data.tar.gz" "${VULN_DATA_VOLUME_NAME}"

compose up -d postgres
until compose exec -T postgres pg_isready -U "${POSTGRES_SUPERUSER}" -d postgres >/dev/null 2>&1; do
  sleep 2
done

compose exec -T postgres psql -U "${POSTGRES_SUPERUSER}" -d postgres < "${backup_dir}/postgres-globals.sql"
compose exec -T postgres dropdb --if-exists -U "${POSTGRES_SUPERUSER}" "${DTRACK_DB_NAME}"
compose exec -T postgres dropdb --if-exists -U "${POSTGRES_SUPERUSER}" "${TRACKER_DB_NAME}"
compose exec -T postgres createdb -U "${POSTGRES_SUPERUSER}" -O "${DTRACK_DB_USER}" "${DTRACK_DB_NAME}"
compose exec -T postgres createdb -U "${POSTGRES_SUPERUSER}" -O "${TRACKER_DB_USER}" "${TRACKER_DB_NAME}"
cat "${backup_dir}/${DTRACK_DB_NAME}.dump" | compose exec -T postgres pg_restore -U "${POSTGRES_SUPERUSER}" -d "${DTRACK_DB_NAME}" --clean --if-exists
cat "${backup_dir}/${TRACKER_DB_NAME}.dump" | compose exec -T postgres pg_restore -U "${POSTGRES_SUPERUSER}" -d "${TRACKER_DB_NAME}" --clean --if-exists

echo "Restored backup from ${backup_dir}"
