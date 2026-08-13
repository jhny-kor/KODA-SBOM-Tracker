#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
EXAMPLE_ENV_FILE="${ROOT_DIR}/.env.example"

load_env() {
  local candidate="${1:-$ENV_FILE}"
  if [[ -f "$candidate" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$candidate"
    set +a
  elif [[ -f "$EXAMPLE_ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$EXAMPLE_ENV_FILE"
    set +a
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

verify_manifest() {
  local manifest_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$manifest_path")" && sha256sum --check "$(basename "$manifest_path")")
  else
    (cd "$(dirname "$manifest_path")" && shasum -a 256 -c "$(basename "$manifest_path")")
  fi
}

compose() {
  if [[ -f "$ENV_FILE" ]]; then
    docker compose --project-directory "$ROOT_DIR" --env-file "$ENV_FILE" \
      -f "$ROOT_DIR/compose.yaml" "$@"
  else
    docker compose --project-directory "$ROOT_DIR" --env-file "$EXAMPLE_ENV_FILE" \
      -f "$ROOT_DIR/compose.yaml" "$@"
  fi
}

require_arg() {
  local value="${1:-}"
  local message="${2:-argument required}"
  if [[ -z "$value" ]]; then
    echo "$message" >&2
    exit 1
  fi
}

ensure_dir() {
  mkdir -p "$1"
}

alpine_tar() {
  local volume_name="$1"
  local target_path="$2"
  local target_dir
  target_dir="$(cd "$(dirname "$target_path")" && pwd)"
  docker run --rm \
    -v "${volume_name}:/from:ro" \
    -v "${target_dir}:/backup" \
    "${ALPINE_BASE_IMAGE}" \
    sh -c "cd /from && tar -czf /backup/$(basename "$target_path") ."
}

alpine_untar() {
  local archive_path="$1"
  local volume_name="$2"
  local archive_dir
  archive_dir="$(cd "$(dirname "$archive_path")" && pwd)"
  docker run --rm \
    -v "${volume_name}:/to" \
    -v "${archive_dir}:/backup:ro" \
    "${ALPINE_BASE_IMAGE}" \
    sh -c "rm -rf /to/* /to/.[!.]* /to/..?* 2>/dev/null || true; mkdir -p /to; tar -xzf /backup/$(basename "$archive_path") -C /to"
}
