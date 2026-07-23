#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

previous_target="$(
  docker run --rm \
    -v "${VULN_DATA_VOLUME_NAME}:/runtime" \
    "${ALPINE_BASE_IMAGE}" \
    sh -euc '
      test -L /runtime/previous
      previous_target="$(readlink /runtime/previous)"
      current_target=""
      if [ -L /runtime/current ]; then current_target="$(readlink /runtime/current)"; fi
      ln -sfn "$previous_target" /runtime/current
      if [ -n "$current_target" ]; then ln -sfn "$current_target" /runtime/previous; fi
      printf "%s" "$previous_target"
    '
)"

echo "Rolled back vulnerability data to ${previous_target}"
