#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"
env_file="${1:-$root_dir/.env}"
[[ -f "$env_file" ]] || { echo "env file not found: $env_file" >&2; exit 1; }

"$script_dir/preflight-airgap.sh" "$env_file"
source "$script_dir/lib.sh"
load_env "$env_file"
data_update_key_compose_args "$root_dir"
compose_args=(--env-file "$env_file" -f "$root_dir/compose.yaml" -f "$root_dir/compose.airgap.yaml" ${DATA_UPDATE_KEY_COMPOSE_ARGS[@]+"${DATA_UPDATE_KEY_COMPOSE_ARGS[@]}"})
docker compose "${compose_args[@]}" up -d --no-build --pull never

deadline=$((SECONDS + ${AIRGAP_HEALTH_TIMEOUT:-420}))
while (( SECONDS < deadline )); do
  if compose_services_ready "${compose_args[@]}"; then
    echo "Air-gap services are running behind the configured HTTPS origin."
    echo "Portal: ${TRACKER_PUBLIC_ORIGIN%/}/"
    exit 0
  fi
  sleep 5
done

echo "Timed out waiting for air-gap service health" >&2
docker compose "${compose_args[@]}" ps >&2 || true
exit 1
