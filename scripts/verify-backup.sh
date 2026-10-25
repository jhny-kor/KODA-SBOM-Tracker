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

test -d "$backup_dir"
backup_dir="$(cd "$backup_dir" && pwd)"
[[ -z "$(find "$backup_dir" -type l -print -quit)" ]] || { echo "backup must not contain symbolic links" >&2; exit 1; }
test -f "${backup_dir}/manifest.sha256"
test -f "${backup_dir}/metadata.env"
test -f "${backup_dir}/${TRACKER_DB_NAME}.dump"
test -f "${backup_dir}/tracker-artifacts.tar.gz"
test -f "${backup_dir}/vuln-data.tar.gz"

# When a verification key is supplied, authenticate the manifest before
# trusting any path or backup content. Unsigned mode is an explicit opt-in.
if [[ -n "$public_key" ]]; then
  [[ -r "$public_key" ]] || { echo "backup verification key is not readable: $public_key" >&2; exit 1; }
  public_key="$(cd "$(dirname "$public_key")" && pwd)/$(basename "$public_key")"
  case "$public_key" in
    "$backup_dir"/*) echo "backup verification key must be provisioned outside the backup directory" >&2; exit 1 ;;
  esac
  verify_file_signature "$public_key" "${backup_dir}/manifest.sha256" "${backup_dir}/manifest.sha256.sig"
else
  require_unsigned_artifact_opt_in "backup"
fi
validate_manifest_paths "${backup_dir}/manifest.sha256"
validate_manifest_inventory "${backup_dir}/manifest.sha256" "$backup_dir"
verify_manifest "${backup_dir}/manifest.sha256"

metadata_value() {
  local key="$1"
  local count
  count="$(grep -c "^${key}=" "${backup_dir}/metadata.env" || true)"
  [[ "$count" == 1 ]] || { echo "backup metadata must contain exactly one ${key}" >&2; return 1; }
  sed -n "s/^${key}=//p" "${backup_dir}/metadata.env"
}

require_metadata_value() {
  local key="$1"
  local expected="$2"
  local actual
  actual="$(metadata_value "$key")"
  [[ "$actual" == "$expected" ]] || {
    echo "backup metadata mismatch for ${key}: expected ${expected}, found ${actual}" >&2
    return 1
  }
}

validate_backup_metadata() {
  local created_at
  created_at="$(metadata_value BACKUP_CREATED_AT)"
  [[ "$created_at" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || { echo "invalid BACKUP_CREATED_AT: $created_at" >&2; return 1; }
  require_metadata_value COMPOSE_PROJECT_NAME "${COMPOSE_PROJECT_NAME}"
  require_metadata_value TRACKER_DB_NAME "${TRACKER_DB_NAME}"
  require_metadata_value TRACKER_ARTIFACTS_VOLUME_NAME "${TRACKER_ARTIFACTS_VOLUME_NAME}"
  require_metadata_value VULN_DATA_VOLUME_NAME "${VULN_DATA_VOLUME_NAME}"
}

validate_backup_metadata
validate_tar_archive "${backup_dir}/tracker-artifacts.tar.gz"
validate_tar_archive "${backup_dir}/vuln-data.tar.gz"

# Accept only native restore inputs; old global-role SQL is inert compatibility
# material and is never executed by restore-system.sh.
python3 - "$backup_dir" "$TRACKER_DB_NAME" <<'PY_CHECK'
import pathlib
import sys
root, database = pathlib.Path(sys.argv[1]), sys.argv[2]
allowed = {'manifest.sha256', 'manifest.sha256.sig', 'metadata.env', database + '.dump',
           'tracker-artifacts.tar.gz', 'vuln-data.tar.gz', 'compose.yaml', '.env.example', '.env', 'postgres-globals.sql'}
for path in root.iterdir():
    if path.name == 'deploy' and path.is_dir(): continue
    if path.name not in allowed: raise SystemExit('unexpected non-native backup content')
PY_CHECK

echo "Backup verified: ${backup_dir}"
