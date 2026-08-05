#!/bin/bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
input="${1:-}"
require_arg "$input" "usage: $0 <release.tar.gz|release-dir>"
tmp=""
cleanup() { [[ -n "$tmp" ]] && rm -rf "$tmp"; }
trap cleanup EXIT
if [[ -f "$input" ]]; then
  [[ "$input" == *.tar.gz ]] || { echo "release must be a tar.gz archive" >&2; exit 1; }
  if [[ -f "${input}.sha256" ]]; then
    (cd "$(dirname "$input")" && { command -v sha256sum >/dev/null && sha256sum --check "$(basename "$input").sha256" || shasum -a 256 -c "$(basename "$input").sha256"; })
  fi
  while IFS= read -r name; do
    [[ "$name" != /* && "$name" != ../* && "$name" != */../* && "$name" != .. && "$name" != */.. ]] || { echo "unsafe archive path: $name" >&2; exit 1; }
  done < <(tar -tzf "$input")
  tmp="$(mktemp -d)"
  tar -xzf "$input" -C "$tmp"
  input="$tmp"
fi
[[ -d "$input" && -f "$input/manifest.sha256" && -f "$input/metadata.env" ]] || { echo "invalid release directory" >&2; exit 1; }
verify_manifest "$input/manifest.sha256"
for required_file in \
  LICENSE \
  NOTICE \
  THIRD_PARTY_NOTICES.md \
  compose.yaml \
  compose.airgap.yaml \
  deploy/nginx/gateway.conf.template \
  deploy/postgres/init/10-init-multi-db.sh \
  config/.env.example \
  config/images.lock \
  scripts/install-airgap.sh \
  scripts/start-airgap.sh \
  scripts/preflight-airgap.sh \
  scripts/verify-airgap-release.sh; do
  [[ -f "$input/$required_file" ]] || { echo "release file missing: $required_file" >&2; exit 1; }
done
grep -q '^DISTRIBUTION_SCOPE=internal-only$' "$input/metadata.env" || { echo "release is not marked internal-only" >&2; exit 1; }
[[ -d "$input/source/apps" ]] || { echo "application source missing" >&2; exit 1; }
[[ ! -e "$input/config/.env" ]] || { echo "release must not contain a real .env" >&2; exit 1; }
count="$(find "$input/images" -type f -name '*.tar' | wc -l | tr -d ' ')"
[[ "$count" -ge 10 ]] || { echo "expected at least 10 image archives, found $count" >&2; exit 1; }
for archive in "$input"/images/*.tar; do
  config_file="$(tar -xOf "$archive" manifest.json | sed -n 's/.*"Config":"\([^"]*\)".*/\1/p' | head -1)"
  [[ -n "$config_file" ]] || { echo "image manifest is missing: $archive" >&2; exit 1; }
  tar -xOf "$archive" "$config_file" | grep -q '"architecture":"amd64"' || {
    echo "image is not linux/amd64: $archive" >&2
    exit 1
  }
done
if [[ -d "$input/vulnerability-data" ]]; then
  [[ -f "$input/scripts/verify-vuln-bundle.sh" ]] || { echo "vulnerability verifier missing" >&2; exit 1; }
  "$input/scripts/verify-vuln-bundle.sh" "$input/vulnerability-data"
fi
echo "Air-gap release verified: $count image tar files"
