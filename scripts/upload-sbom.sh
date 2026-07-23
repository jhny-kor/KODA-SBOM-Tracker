#!/bin/bash
set -euo pipefail

base_url="${KODA_TRACKER_URL:-}"
api_token="${KODA_TRACKER_TOKEN:-}"
service_id="${1:-}"
environment_id="${2:-}"
release_version="${3:-}"
sbom_path="${4:-}"
idempotency_key="${5:-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ -z "$base_url" || -z "$api_token" || -z "$service_id" || -z "$environment_id" || -z "$release_version" || -z "$sbom_path" ]]; then
  echo "usage: KODA_TRACKER_URL=... KODA_TRACKER_TOKEN=... $0 <service-id> <environment-id> <release> <sbom-path> [idempotency-key]" >&2
  exit 1
fi
if [[ ! -f "$sbom_path" ]]; then
  echo "SBOM file not found: $sbom_path" >&2
  exit 1
fi

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${api_token}" \
  -H "Idempotency-Key: ${idempotency_key}" \
  -F "serviceId=${service_id}" \
  -F "environmentId=${environment_id}" \
  -F "releaseVersion=${release_version}" \
  -F "sbom=@${sbom_path}" \
  "${base_url%/}/api/v1/sbom-runs"
