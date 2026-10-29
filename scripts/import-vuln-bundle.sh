#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

bundle_dir="${1:-}"
require_arg "$bundle_dir" "usage: $0 <bundle-dir>"

test -d "$bundle_dir"
bundle_abs="$(cd "$bundle_dir" && pwd)"
compose -f "$ROOT_DIR/compose.airgap.yaml" run --rm -T --no-deps \
  -v "$ROOT_DIR/scripts/bootstrap-vuln-data.py:/bootstrap-vuln-data.py:ro" \
  -v "$bundle_abs:/bundle:ro" \
  portal-data-updater python /bootstrap-vuln-data.py /bundle/unified-update.tar.gz
