#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

bundle_dir="${1:-}"
require_arg "$bundle_dir" "usage: $0 <bundle-dir>"

test -d "$bundle_dir"
test -f "${bundle_dir}/metadata.env"
test -f "${bundle_dir}/manifest.sha256"
test -d "${bundle_dir}/images"
test -f "${bundle_dir}/LICENSE"
test -f "${bundle_dir}/NOTICE"
test -f "${bundle_dir}/THIRD_PARTY_NOTICES.md"
grep -q '^TARGET_PLATFORM=linux/amd64$' "${bundle_dir}/metadata.env"
grep -q '^DISTRIBUTION_SCOPE=internal-only$' "${bundle_dir}/metadata.env"

verify_manifest "${bundle_dir}/manifest.sha256"

image_count="$(find "${bundle_dir}/images" -type f -name '*.tar' | wc -l | tr -d ' ')"
test "$image_count" -ge 10

for archive in "${bundle_dir}"/images/*.tar; do
  config_file="$(tar -xOf "$archive" manifest.json | sed -n 's/.*"Config":"\([^"]*\)".*/\1/p' | head -1)"
  test -n "$config_file"
  tar -xOf "$archive" "$config_file" | grep -q '"architecture":"amd64"'
done

echo "Bundle verified: ${bundle_dir} (${image_count} image tar files)"
