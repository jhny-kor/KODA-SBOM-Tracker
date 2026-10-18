#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

input_path=""
public_key="${KODA_RELEASE_VERIFY_KEY:-}"
usage() { local rc="${1:-2}"; echo "usage: $0 <bundle-dir> [--public-key FILE]" >&2; exit "$rc"; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key) public_key="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage 2 ;;
    *) [[ -z "$input_path" ]] || usage 2; input_path="$1"; shift ;;
  esac
done
require_arg "$input_path" "offline bundle directory is required"
[[ -d "$input_path" ]] || { echo "offline bundle directory not found: $input_path" >&2; exit 1; }
allow_unsigned="${KODA_ALLOW_UNSIGNED_ARTIFACTS:-0}"
if [[ -n "$public_key" ]]; then
  [[ -r "$public_key" ]] || { echo "release verification key is not readable: $public_key" >&2; exit 1; }
else
  KODA_ALLOW_UNSIGNED_ARTIFACTS="$allow_unsigned" require_unsigned_artifact_opt_in "offline bundle import"
fi

staging_root="$(mktemp -d "${TMPDIR:-/tmp}/koda-offline-import.XXXXXX")"
chmod 700 "$staging_root"
cleanup() { rm -rf "$staging_root"; }
trap cleanup EXIT
staged_bundle="$staging_root/bundle"
mkdir "$staged_bundle"
cp -a "$input_path/." "$staged_bundle/"
chmod -R u=rwX,go= "$staged_bundle"
if [[ -n "$public_key" ]]; then
  staged_public_key="$staging_root/release-public.pem"
  cp "$public_key" "$staged_public_key"
  chmod u=rw,go= "$staged_public_key"
  "$ROOT_DIR/scripts/verify-offline-bundle.sh" "$staged_bundle" --public-key "$staged_public_key"
else
  "$ROOT_DIR/scripts/verify-offline-bundle.sh" "$staged_bundle"
fi

find "${staged_bundle}/images" -type f -name '*.tar' | sort | while read -r tar_file; do
  docker load -i "$tar_file"
done

echo "Imported images from ${input_path}"
