#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

bundle_dir=""
public_key="${KODA_RELEASE_VERIFY_KEY:-}"
usage() { local rc="${1:-2}"; echo "usage: $0 <bundle-dir> [--public-key FILE]" >&2; exit "$rc"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key) public_key="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage 2 ;;
    *) [[ -z "$bundle_dir" ]] || usage 2; bundle_dir="$1"; shift ;;
  esac
done
require_arg "$bundle_dir" "offline bundle directory is required"

test -d "$bundle_dir"
bundle_dir="$(cd "$bundle_dir" && pwd)"
test -f "${bundle_dir}/metadata.env"
test -f "${bundle_dir}/manifest.sha256"
test -d "${bundle_dir}/images"
test -f "${bundle_dir}/LICENSE"
test -f "${bundle_dir}/NOTICE"
test -f "${bundle_dir}/THIRD_PARTY_NOTICES.md"
grep -q '^TARGET_PLATFORM=linux/amd64$' "${bundle_dir}/metadata.env"
grep -q '^DISTRIBUTION_SCOPE=internal-only$' "${bundle_dir}/metadata.env"

if [[ -n "$public_key" ]]; then
  [[ -r "$public_key" ]] || { echo "release verification key is not readable: $public_key" >&2; exit 1; }
  public_key="$(cd "$(dirname "$public_key")" && pwd)/$(basename "$public_key")"
  case "$public_key" in
    "$bundle_dir"/*) echo "release verification key must be provisioned outside the bundle" >&2; exit 1 ;;
  esac
  verify_file_signature "$public_key" "${bundle_dir}/manifest.sha256" "${bundle_dir}/manifest.sha256.sig"
else
  require_unsigned_artifact_opt_in "offline bundle"
fi
validate_manifest_paths "${bundle_dir}/manifest.sha256"
validate_manifest_inventory "${bundle_dir}/manifest.sha256" "$bundle_dir"
verify_manifest "${bundle_dir}/manifest.sha256"

image_count="$(find "${bundle_dir}/images" -type f -name '*.tar' | wc -l | tr -d ' ')"
test "$image_count" -ge 8

for archive in "${bundle_dir}"/images/*.tar; do
  validate_tar_archive "$archive"
  config_file="$(tar -xOf "$archive" manifest.json | sed -n 's/.*"Config":"\([^"]*\)".*/\1/p' | head -1)"
  test -n "$config_file"
  tar -xOf "$archive" "$config_file" | grep -q '"architecture":"amd64"'
done

echo "Bundle verified: ${bundle_dir} (${image_count} image tar files)"
