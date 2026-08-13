#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
archive="${1:-}"
install_dir="${AIRGAP_INSTALL_DIR:-/opt/koda-sbom}"
env_file=""
import_vuln=0
[[ -n "$archive" ]] || { echo "usage: $0 <release.tar.gz> [install-dir] [--env-file FILE]" >&2; exit 2; }
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --import-vuln-bundle) import_vuln=1; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) install_dir="$1"; shift ;;
  esac
done
[[ -f "$archive" ]] || { echo "release archive not found: $archive" >&2; exit 1; }
mkdir -p "$install_dir"
install_dir="$(cd "$install_dir" && pwd)"
[[ -n "$env_file" ]] || env_file="${install_dir}/.env"
if [[ "$env_file" != /* ]]; then
  env_file="$(cd "$(dirname "$env_file")" && pwd)/$(basename "$env_file")"
fi
[[ -f "$env_file" ]] || { echo "provide a production .env with --env-file (the example is intentionally rejected)" >&2; exit 1; }
grep -Eiq '(^|=)(change-me|your-|example|todo|<[^>]+>)' "$env_file" && { echo "placeholder values are not allowed in .env" >&2; exit 1; }

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT
"$script_dir/verify-airgap-release.sh" "$archive"
tar -xzf "$archive" -C "$tmp"
cp -a "$tmp/." "$install_dir/"
[[ "$env_file" == "$install_dir/.env" ]] || cp "$env_file" "$install_dir/.env"
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
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml up -d --no-build --pull never
deadline=$((SECONDS + ${AIRGAP_HEALTH_TIMEOUT:-420}))
while (( SECONDS < deadline )); do
  ids="$(docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml ps -q 2>/dev/null || true)"
  ready=1
  for id in $ids; do
    state="$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id")"
    [[ "$state" == running* ]] || ready=0
    [[ "$state" != *starting* && "$state" != *unhealthy* ]] || ready=0
  done
  if [[ -n "$ids" && "$ready" == 1 ]]; then
    if (( import_vuln )); then
      [[ -d vulnerability-data ]] || { echo "--import-vuln-bundle requested but release has no bundle" >&2; exit 1; }
      ENV_FILE="$install_dir/.env" "$install_dir/scripts/import-vuln-bundle.sh" "$install_dir/vulnerability-data"
    fi
    echo "Air-gap services are healthy"
    exit 0
  fi
  sleep 5
done
echo "Timed out waiting for air-gap service health" >&2
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml ps >&2 || true
exit 1
