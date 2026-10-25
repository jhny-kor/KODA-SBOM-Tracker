#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "$script_dir/lib.sh"
archive="${1:-}"
install_dir="${AIRGAP_INSTALL_DIR:-/opt/koda-sbom}"
env_file=""
import_vuln=0
public_key="${KODA_RELEASE_VERIFY_KEY:-}"
signature=""
[[ -n "$archive" ]] || { echo "usage: $0 <release.tar.gz> [install-dir] [--public-key FILE] [--signature FILE] [--env-file FILE]" >&2; exit 2; }
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --public-key) public_key="${2:-}"; shift 2 ;;
    --signature) signature="${2:-}"; shift 2 ;;
    --import-vuln-bundle) import_vuln=1; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) install_dir="$1"; shift ;;
  esac
done
[[ -f "$archive" ]] || { echo "release archive not found: $archive" >&2; exit 1; }
allow_unsigned="${KODA_ALLOW_UNSIGNED_ARTIFACTS:-0}"
if [[ -n "$public_key" ]]; then
  [[ -r "$public_key" ]] || { echo "release verification key is not readable: $public_key" >&2; exit 1; }
  [[ -n "$signature" ]] || signature="${archive}.sig"
  [[ -f "$signature" ]] || { echo "detached release signature not found: $signature" >&2; exit 1; }
else
  KODA_ALLOW_UNSIGNED_ARTIFACTS="$allow_unsigned" require_unsigned_artifact_opt_in "air-gap release installation"
fi
mkdir -p "$install_dir"
install_dir="$(cd "$install_dir" && pwd)"
[[ -n "$env_file" ]] || env_file="${install_dir}/.env"
if [[ "$env_file" != /* ]]; then
  env_file="$(cd "$(dirname "$env_file")" && pwd)/$(basename "$env_file")"
fi
[[ -f "$env_file" ]] || { echo "provide a production .env with --env-file (the example is intentionally rejected)" >&2; exit 1; }

tmp="$(mktemp -d)"
chmod 700 "$tmp"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
staged_archive="$tmp/release.tar.gz"
extracted_release="$tmp/extracted"
mkdir "$extracted_release"
cp "$archive" "$staged_archive"
if [[ -n "$public_key" ]]; then
  staged_signature="$tmp/release.tar.gz.sig"
  staged_public_key="$tmp/release-public.pem"
  cp "$signature" "$staged_signature"
  cp "$public_key" "$staged_public_key"
  "$script_dir/verify-airgap-release.sh" "$staged_archive" --public-key "$staged_public_key" --signature "$staged_signature"
else
  "$script_dir/verify-airgap-release.sh" "$staged_archive"
fi
tar -xzf "$staged_archive" -C "$extracted_release"
[[ -f "$extracted_release/scripts/remove-retired-analysis.py" ]] || { echo "release lacks required upgrade cleanup" >&2; exit 1; }
[[ -f "$extracted_release/scripts/release-images.sh" ]] || { echo "release lacks required image identity helper" >&2; exit 1; }
legacy_env="$tmp/previous.env"
if [[ -f "$install_dir/.env" ]]; then
  cp "$install_dir/.env" "$legacy_env"
else
  cp "$env_file" "$legacy_env"
fi
# Keep the registered host public-key path valid after relocating the runtime .env.
original_env_file="$env_file"
cp "$env_file" "$tmp/runtime.env"
chmod 600 "$tmp/runtime.env"
python3 - "$original_env_file" "$tmp/runtime.env" <<'PY_VERIFY_KEY'
from pathlib import Path
import re
import sys
source, destination = map(Path, sys.argv[1:])
lines = destination.read_text().splitlines()
for index, line in enumerate(lines):
    match = re.fullmatch(r"\s*(?:export\s+)?TRACKER_DATA_UPDATE_VERIFY_KEY_FILE\s*=(.*)", line)
    if not match: continue
    value = match.group(1).strip().strip("\"'")
    if not value: continue
    key = Path(value)
    if not key.is_absolute(): key = source.parent / key
    key = key.resolve(strict=True)
    if any(character in str(key) for character in "\n\r'"):
        raise SystemExit('unsafe registered public-key path')
    lines[index] = "TRACKER_DATA_UPDATE_VERIFY_KEY_FILE='" + str(key) + "'"
destination.write_text("\n".join(lines) + "\n")
PY_VERIFY_KEY
env_file="$tmp/runtime.env"
"$extracted_release/scripts/preflight-airgap.sh" "$env_file"
python3 "$extracted_release/scripts/remove-retired-analysis.py" --env-file "$legacy_env" --phase resources
cp -a "$extracted_release/." "$install_dir/"
[[ "$env_file" == "$install_dir/.env" ]] || cp "$env_file" "$install_dir/.env"
python3 "$install_dir/scripts/remove-retired-analysis.py" --env-file "$legacy_env" --install-dir "$install_dir" --phase files
source "$install_dir/scripts/release-images.sh"
apply_release_images "$install_dir/config/release-images.env" "$install_dir/.env"
"$install_dir/scripts/preflight-airgap.sh" "$install_dir/.env"
declare -A loaded_ids=()
while IFS= read -r -d '' image; do
  output="$(docker load -i "$image")"
  printf '%s\n' "$output"
  loaded_id="$(awk '/Loaded image ID:/ { print $4; exit }' <<<"$output")"
  [[ -z "$loaded_id" ]] || loaded_ids["$(basename "$image")"]="$loaded_id"
done < <(find "$install_dir/images" -type f -name '*.tar' -print0)

# Registry manifest digests do not survive the Docker save/load archive format.
# The release manifest authenticates each tar, so pin the verified loaded image
# to its configured tag and use only that local tag with --pull never.
while IFS='=' read -r variable image_ref; do
  [[ -n "$variable" && -n "$image_ref" ]] || continue
  safe_name="$(printf '%s' "$image_ref" | tr '/:@' '___').tar"
  [[ -f "$install_dir/images/$safe_name" ]] || continue
  runtime_ref="${image_ref%@*}"
  image_id="${loaded_ids[$safe_name]:-}"
  [[ -n "$image_id" ]] || image_id="$(docker image inspect "$runtime_ref" --format '{{.Id}}' 2>/dev/null || true)"
  [[ -n "$image_id" ]] || { echo "could not identify loaded image: $safe_name" >&2; exit 1; }
  docker tag "$image_id" "$runtime_ref"
  [[ "$(docker image inspect "$runtime_ref" --format '{{.Architecture}}')" == amd64 ]] \
    || { echo "loaded image is not linux/amd64: $runtime_ref" >&2; exit 1; }
  python3 - "$install_dir/.env" "$variable" "$runtime_ref" <<'PY'
import pathlib
import sys

path, key, value = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lines = path.read_text(encoding="utf-8").splitlines()
path.write_text("\n".join(f"{key}={value}" if line.startswith(f"{key}=") else line for line in lines) + "\n", encoding="utf-8")
PY
done < "$install_dir/config/images.lock"

cd "$install_dir"
load_env "$install_dir/.env"
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml up -d --no-build --pull never --wait --wait-timeout "${AIRGAP_HEALTH_TIMEOUT:-420}" postgres
python3 "$install_dir/scripts/remove-retired-analysis.py" --env-file "$legacy_env" --phase database
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml up -d --no-build --pull never --remove-orphans
deadline=$((SECONDS + ${AIRGAP_HEALTH_TIMEOUT:-420}))
while (( SECONDS < deadline )); do
  if compose_services_ready --env-file .env -f compose.yaml -f compose.airgap.yaml; then
    if (( import_vuln )); then
      [[ -d vulnerability-data ]] || { echo "--import-vuln-bundle requested but release has no bundle" >&2; exit 1; }
      ENV_FILE="$install_dir/.env" "$install_dir/scripts/import-vuln-bundle.sh" "$install_dir/vulnerability-data"
    fi
    echo "Air-gap services are healthy"
    echo "Installed application image tag: ${PORTAL_IMAGE_TAG:-dev}"
    exit 0
  fi
  sleep 5
done
echo "Timed out waiting for air-gap service health" >&2
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml ps >&2 || true
exit 1
