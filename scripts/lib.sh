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
    candidate="$EXAMPLE_ENV_FILE"
  fi
  # Compose resolves bind mounts against its project directory. Preserve the
  # operator's .env-relative trust-key path even for an external ENV_FILE.
  if [[ -n "${TRACKER_DATA_UPDATE_VERIFY_KEY_FILE:-}" && "$TRACKER_DATA_UPDATE_VERIFY_KEY_FILE" != /* ]]; then
    TRACKER_DATA_UPDATE_VERIFY_KEY_FILE="$(cd "$(dirname "$candidate")" && pwd)/$TRACKER_DATA_UPDATE_VERIFY_KEY_FILE"
    export TRACKER_DATA_UPDATE_VERIFY_KEY_FILE
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

sign_file() {
  local private_key="$1"
  local input_path="$2"
  local signature_path="$3"
  [[ -r "$private_key" ]] || { echo "signing key is not readable: $private_key" >&2; return 1; }
  [[ -f "$input_path" ]] || { echo "file to sign is missing: $input_path" >&2; return 1; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required for signing" >&2; return 1; }
  openssl dgst -sha256 -sign "$private_key" -out "$signature_path" "$input_path"
}

verify_file_signature() {
  local public_key="$1"
  local input_path="$2"
  local signature_path="$3"
  [[ -r "$public_key" ]] || { echo "verification key is not readable: $public_key" >&2; return 1; }
  [[ -f "$input_path" ]] || { echo "signed file is missing: $input_path" >&2; return 1; }
  [[ -f "$signature_path" ]] || { echo "detached signature is missing: $signature_path" >&2; return 1; }
  command -v openssl >/dev/null 2>&1 || { echo "openssl is required for signature verification" >&2; return 1; }
  openssl dgst -sha256 -verify "$public_key" -signature "$signature_path" "$input_path" >/dev/null 2>&1 || {
    echo "signature verification failed: $input_path" >&2
    return 1
  }
}

require_unsigned_artifact_opt_in() {
  local artifact_label="${1:-artifact}"
  if [[ "${KODA_ALLOW_UNSIGNED_ARTIFACTS:-0}" != 1 ]]; then
    echo "${artifact_label} signature is required; set KODA_ALLOW_UNSIGNED_ARTIFACTS=1 only for an explicitly trusted unsigned transfer" >&2
    return 1
  fi
  echo "WARNING: accepting unsigned ${artifact_label}; authenticity is not verified" >&2
}

validate_manifest_paths() {
  local manifest_path="$1"
  python3 - "$manifest_path" <<'PY'
import pathlib
import re
import sys

manifest = pathlib.Path(sys.argv[1])
if not manifest.is_file():
    raise SystemExit(f"manifest is missing: {manifest}")
seen = set()
for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
    match = re.fullmatch(r"[0-9a-fA-F]{64} [ *](.+)", line)
    if not match:
        raise SystemExit(f"unsafe manifest entry at line {line_number}")
    raw_name = match.group(1)
    if "\\" in raw_name or raw_name.startswith("/"):
        raise SystemExit(f"unsafe manifest path: {raw_name}")
    parts = pathlib.PurePosixPath(raw_name).parts
    if not parts or ".." in parts:
        raise SystemExit(f"unsafe manifest path: {raw_name}")
    normalized = pathlib.PurePosixPath(*[part for part in parts if part != "."]).as_posix()
    if not normalized or normalized in seen:
        raise SystemExit(f"duplicate or empty manifest path: {raw_name}")
    seen.add(normalized)
PY
}

validate_manifest_inventory() {
  local manifest_path="$1"
  local root_path="$2"
  python3 - "$manifest_path" "$root_path" <<'PY'
import pathlib
import re
import sys

manifest = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
if not manifest.is_file() or not root.is_dir():
    raise SystemExit("manifest inventory inputs are missing")
if any(path.is_symlink() for path in root.rglob("*")):
    raise SystemExit("manifest inventory mismatch: symbolic links are not allowed")

expected = set()
for line in manifest.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"[0-9a-fA-F]{64} [ *](.+)", line)
    if not match:
        raise SystemExit("manifest inventory mismatch: invalid manifest entry")
    parts = [part for part in pathlib.PurePosixPath(match.group(1)).parts if part != "."]
    expected.add(pathlib.PurePosixPath(*parts).as_posix())

excluded = {"manifest.sha256", "manifest.sha256.sig"}
actual = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*")
    if path.is_file() and path.relative_to(root).as_posix() not in excluded
}
missing = sorted(expected - actual)
extra = sorted(actual - expected)
if missing or extra:
    raise SystemExit(f"manifest inventory mismatch: missing={missing[:3]} extra={extra[:3]}")
PY
}

validate_tar_archive() {
  local archive_path="$1"
  python3 - "$archive_path" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
if not archive_path.is_file():
    raise SystemExit(f"archive is missing: {archive_path}")

def safe_path(raw_name: str, label: str) -> str:
    if not raw_name or "\\" in raw_name or raw_name.startswith("/"):
        raise SystemExit(f"unsafe archive {label}: {raw_name}")
    parts = pathlib.PurePosixPath(raw_name).parts
    if ".." in parts:
        raise SystemExit(f"unsafe archive {label}: {raw_name}")
    return pathlib.PurePosixPath(*[part for part in parts if part != "."]).as_posix()

seen = set()
try:
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            normalized = safe_path(member.name, "path")
            if normalized:
                if normalized in seen:
                    raise SystemExit(f"unsafe archive duplicate path: {member.name}")
                seen.add(normalized)
            if member.ischr() or member.isblk() or member.isfifo():
                raise SystemExit(f"unsafe archive special file: {member.name}")
            if member.issym() or member.islnk():
                safe_path(member.linkname, "link target")
except (tarfile.TarError, OSError) as error:
    raise SystemExit(f"unsafe archive: {error}") from error
PY
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

# Inspect the configured services individually. An old container belonging to
# an inactive profile must neither block readiness nor hide a missing worker.
compose_services_ready() {
  local services service ids id state checked=0
  services="$(docker compose "$@" config --services 2>/dev/null)" || return 1
  [[ -n "$services" ]] || return 1
  while IFS= read -r service; do
    [[ -n "$service" ]] || continue
    checked=$((checked + 1))
    ids="$(docker compose "$@" ps -a -q "$service" 2>/dev/null)" || return 1
    [[ -n "$ids" ]] || return 1
    for id in $ids; do
      state="$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id" 2>/dev/null)" || return 1
      [[ "$state" == running* ]] || return 1
      [[ "$state" != *starting* && "$state" != *unhealthy* ]] || return 1
    done
  done <<< "$services"
  [[ "$checked" -gt 0 ]]
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
