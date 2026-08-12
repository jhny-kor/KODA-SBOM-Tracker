#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"
env_file="${1:-$root_dir/.env}"
[[ -f "$env_file" ]] || { echo "env file not found: $env_file" >&2; exit 1; }

"$script_dir/preflight-airgap.sh" "$env_file"
compose_args=(--env-file "$env_file" -f "$root_dir/compose.yaml" -f "$root_dir/compose.airgap.yaml")
docker compose "${compose_args[@]}" up -d --no-build --pull never

deadline=$((SECONDS + ${AIRGAP_HEALTH_TIMEOUT:-420}))
while (( SECONDS < deadline )); do
  ids="$(docker compose "${compose_args[@]}" ps -q 2>/dev/null || true)"
  ready=1
  for id in $ids; do
    state="$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id")"
    [[ "$state" == running* ]] || ready=0
    [[ "$state" != *starting* && "$state" != *unhealthy* ]] || ready=0
  done
  if [[ -n "$ids" && "$ready" == 1 ]]; then
    echo "Air-gap services are running; open the configured PUBLIC_HTTP_PORT on this server."
    echo "Portal: http://<server>:<PUBLIC_HTTP_PORT>/"
    echo "Dependency-Track: http://<server>:<PUBLIC_HTTP_PORT>/dependency-track/"
    exit 0
  fi
  sleep 5
done

echo "Timed out waiting for air-gap service health" >&2
docker compose "${compose_args[@]}" ps >&2 || true
exit 1
