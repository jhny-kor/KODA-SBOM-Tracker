#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

input_path="${1:-}"
require_arg "$input_path" "usage: $0 <bundle-dir>"

"$ROOT_DIR/scripts/verify-offline-bundle.sh" "$input_path"

find "${input_path}/images" -type f -name '*.tar' | sort | while read -r tar_file; do
  docker load -i "$tar_file"
done

echo "Imported images from ${input_path}"
