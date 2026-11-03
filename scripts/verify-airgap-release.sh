#!/bin/bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
input=""
public_key="${KODA_RELEASE_VERIFY_KEY:-}"
signature=""
usage() { local rc="${1:-2}"; echo "usage: $0 <release.tar.gz> [--public-key FILE] [--signature FILE]" >&2; exit "$rc"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key) public_key="${2:-}"; shift 2 ;;
    --signature) signature="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage 2 ;;
    *) [[ -z "$input" ]] || usage 2; input="$1"; shift ;;
  esac
done
require_arg "$input" "release archive is required"
[[ -f "$input" && "$input" == *.tar.gz ]] || { echo "release must be a tar.gz archive" >&2; exit 1; }
tmp=""
cleanup() { [[ -n "$tmp" ]] && rm -rf "$tmp"; }
trap cleanup EXIT
if [[ -n "$public_key" ]]; then
  [[ -r "$public_key" ]] || { echo "release verification key is not readable: $public_key" >&2; exit 1; }
  [[ -n "$signature" ]] || signature="${input}.sig"
  verify_file_signature "$public_key" "$input" "$signature"
else
  require_unsigned_artifact_opt_in "air-gap release"
fi
if [[ -f "${input}.sha256" ]]; then
  (cd "$(dirname "$input")" && { command -v sha256sum >/dev/null && sha256sum --check "$(basename "$input").sha256" || shasum -a 256 -c "$(basename "$input").sha256"; })
fi
validate_tar_archive "$input"
tmp="$(mktemp -d)"
chmod 700 "$tmp"
tar -xzf "$input" -C "$tmp"
input="$tmp"
[[ -d "$input" && -f "$input/manifest.sha256" && -f "$input/metadata.env" ]] || { echo "invalid release directory" >&2; exit 1; }
validate_manifest_paths "$input/manifest.sha256"
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
if grep -Fq './deploy/nginx/http-error.html:' "$input/compose.yaml"; then
  [[ -s "$input/deploy/nginx/http-error.html" ]] || { echo "release file missing: deploy/nginx/http-error.html" >&2; exit 1; }
fi
grep -q '^DISTRIBUTION_SCOPE=internal-only$' "$input/metadata.env" || { echo "release is not marked internal-only" >&2; exit 1; }
grep -Eq '^TRACKER_GIT_REVISION=[0-9a-f]{40}$' "$input/metadata.env" || { echo "release git revision is missing or invalid" >&2; exit 1; }
grep -q '^TRACKER_WORKTREE_DIRTY=false$' "$input/metadata.env" || { echo "release was not built from a clean worktree" >&2; exit 1; }
[[ -d "$input/source/apps" ]] || { echo "application source missing" >&2; exit 1; }
[[ ! -e "$input/config/.env" ]] || { echo "release must not contain a real .env" >&2; exit 1; }
count="$(find "$input/images" -type f -name '*.tar' | wc -l | tr -d ' ')"
[[ "$count" -ge 8 ]] || { echo "expected at least 8 image archives, found $count" >&2; exit 1; }
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
