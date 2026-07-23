#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

bundle_dir="${1:-}"
require_arg "$bundle_dir" "usage: $0 <bundle-dir>"

test -d "$bundle_dir"
test -f "${bundle_dir}/metadata.env"
test -f "${bundle_dir}/manifest.sha256"
verify_manifest "${bundle_dir}/manifest.sha256"

BUNDLE_VERSION="$(
  awk -F= '
    $1 == "BUNDLE_VERSION" {
      value = substr($0, index($0, "=") + 1)
      if (value !~ /^[A-Za-z0-9._-]+$/) exit 2
      print value
      found = 1
    }
    END { if (!found) exit 3 }
  ' "${bundle_dir}/metadata.env"
)" || {
  echo "metadata.env has an invalid or missing BUNDLE_VERSION" >&2
  exit 1
}
if [[ ! "$BUNDLE_VERSION" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "BUNDLE_VERSION contains unsupported characters" >&2
  exit 1
fi

bundle_abs="$(cd "$bundle_dir" && pwd)"
docker run --rm \
  -e BUNDLE_VERSION="$BUNDLE_VERSION" \
  -v "${VULN_DATA_VOLUME_NAME}:/runtime" \
  -v "${bundle_abs}:/bundle:ro" \
  "${ALPINE_BASE_IMAGE}" \
  sh -euc '
    mkdir -p /runtime/releases /runtime/staging
    rm -rf "/runtime/staging/${BUNDLE_VERSION}"
    mkdir -p "/runtime/staging/${BUNDLE_VERSION}"
    cp -a /bundle/. "/runtime/staging/${BUNDLE_VERSION}/"
    # Grype creates cache directories as 0700. The portal API/worker run as a
    # non-root user and mount this volume read-only, so normalize directory
    # traversal and read permissions before the release becomes current.
    chmod -R a+rX "/runtime/staging/${BUNDLE_VERSION}"
    rm -rf "/runtime/releases/${BUNDLE_VERSION}"
    mv "/runtime/staging/${BUNDLE_VERSION}" "/runtime/releases/${BUNDLE_VERSION}"
    if [ -L /runtime/current ]; then
      ln -sfn "$(readlink /runtime/current)" /runtime/previous
    fi
    ln -sfn "releases/${BUNDLE_VERSION}" /runtime/current
  '

echo "Imported vulnerability data bundle ${BUNDLE_VERSION}"
