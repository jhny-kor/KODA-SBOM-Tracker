#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env
umask 077

signing_key="${KODA_BACKUP_SIGNING_KEY:-}"
if [[ -n "$signing_key" ]]; then
  [[ -r "$signing_key" ]] || { echo "backup signing key is not readable: $signing_key" >&2; exit 1; }
else
  require_unsigned_artifact_opt_in "backup"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_root="${BACKUP_ROOT:-$ROOT_DIR/backups}"
backup_dir="${backup_root}/${timestamp}"
ensure_dir "$backup_root"
mkdir "$backup_dir"

compose up -d postgres
compose exec -T postgres pg_dump -Fc -U "${POSTGRES_SUPERUSER}" "${TRACKER_DB_NAME}" > "${backup_dir}/${TRACKER_DB_NAME}.dump"

alpine_tar "${TRACKER_ARTIFACTS_VOLUME_NAME}" "${backup_dir}/tracker-artifacts.tar.gz" --exclude-nvd-cache
alpine_tar "${VULN_DATA_VOLUME_NAME}" "${backup_dir}/vuln-data.tar.gz"

cp "$ROOT_DIR/compose.yaml" "${backup_dir}/compose.yaml"
cp "$EXAMPLE_ENV_FILE" "${backup_dir}/.env.example"
cp -R "$ROOT_DIR/deploy" "${backup_dir}/deploy"

if [[ "${INCLUDE_ENV_IN_BACKUP:-0}" == "1" && -f "$ENV_FILE" ]]; then
  cp "$ENV_FILE" "${backup_dir}/.env"
fi

cat > "${backup_dir}/metadata.env" <<EOF
BACKUP_CREATED_AT=${timestamp}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME}
TRACKER_DB_NAME=${TRACKER_DB_NAME}
TRACKER_ARTIFACTS_VOLUME_NAME=${TRACKER_ARTIFACTS_VOLUME_NAME}
VULN_DATA_VOLUME_NAME=${VULN_DATA_VOLUME_NAME}
EOF

(
  cd "$backup_dir"
  while IFS= read -r -d '' file; do
    sha256_file "$file"
  done < <(find . -type f ! -name manifest.sha256 -print0 | sort -z)
) > "${backup_dir}/manifest.sha256"
if [[ -n "$signing_key" ]]; then
  sign_file "$signing_key" "${backup_dir}/manifest.sha256" "${backup_dir}/manifest.sha256.sig"
fi
echo "Created backup: ${backup_dir}"
[[ -z "$signing_key" ]] || echo "Detached signature: ${backup_dir}/manifest.sha256.sig"
[[ -n "$signing_key" ]] || echo "Unsigned backup created by explicit opt-in" >&2
