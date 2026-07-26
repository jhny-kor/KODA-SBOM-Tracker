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
cp "$env_file" "$install_dir/.env"
"$install_dir/scripts/preflight-airgap.sh" "$install_dir/.env"
find "$install_dir/images" -type f -name '*.tar' -print0 | while IFS= read -r -d '' image; do docker load -i "$image"; done

cd "$install_dir"
docker compose --env-file .env -f compose.yaml -f compose.airgap.yaml up -d --no-build --pull never
deadline=$((SECONDS + ${AIRGAP_HEALTH_TIMEOUT:-240}))
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
