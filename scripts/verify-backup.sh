#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

backup_dir="${1:-}"
require_arg "$backup_dir" "usage: $0 <backup-dir>"

test -d "$backup_dir"
test -f "${backup_dir}/manifest.sha256"
test -f "${backup_dir}/postgres-globals.sql"
test -f "${backup_dir}/${DTRACK_DB_NAME}.dump"
test -f "${backup_dir}/${TRACKER_DB_NAME}.dump"
test -f "${backup_dir}/tracker-artifacts.tar.gz"
test -f "${backup_dir}/dtrack-data.tar.gz"
test -f "${backup_dir}/vuln-data.tar.gz"

verify_manifest "${backup_dir}/manifest.sha256"
tar -tzf "${backup_dir}/tracker-artifacts.tar.gz" >/dev/null
tar -tzf "${backup_dir}/dtrack-data.tar.gz" >/dev/null
tar -tzf "${backup_dir}/vuln-data.tar.gz" >/dev/null

echo "Backup verified: ${backup_dir}"
