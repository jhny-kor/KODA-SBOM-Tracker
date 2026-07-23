#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

bundle_dir="${1:-}"
require_arg "$bundle_dir" "usage: $0 <bundle-dir>"

test -f "${bundle_dir}/metadata.env"
test -f "${bundle_dir}/manifest.sha256"
verify_manifest "${bundle_dir}/manifest.sha256"

grep -q '^BUNDLE_VERSION=' "${bundle_dir}/metadata.env"
grep -q '^DATASET_DATE=' "${bundle_dir}/metadata.env"
grep -q '^GRYPE_DB_SCHEMA=' "${bundle_dir}/metadata.env"

# Optional sidecar indexes are consumed by the offline analyzer. Keep their
# paths manifest-controlled and reject traversal or absolute paths before the
# bundle can be staged into the runtime volume.
for key in NVD_INDEX ALIAS_INDEX KEV_CATALOG; do
  value="$(awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "${bundle_dir}/metadata.env")"
  if [[ -n "$value" ]]; then
    case "$value" in
      /*|../*|*/../*|*"/.."|*$'\n'*)
        echo "${key} contains an unsafe path" >&2
        exit 1
        ;;
    esac
    test -f "${bundle_dir}/${value}"
  fi
done

echo "Vulnerability bundle verified: ${bundle_dir}"
