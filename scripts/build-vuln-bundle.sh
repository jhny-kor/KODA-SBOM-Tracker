#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

usage() {
  cat >&2 <<'EOF'
usage: build-vuln-bundle.sh <output-dir> --grype-db <grype-db-dir> --data-date YYYY-MM-DD
  [--version VERSION] [--nvd-index FILE | --nvd-feed FILE ...]
  [--nvd-date YYYY-MM-DD] [--alias-index FILE] [--kev FILE] [--kev-date YYYY-MM-DD]

The command is offline-first: it never downloads vulnerability data. Fetch
and verify source feeds on an approved build host, then pass their paths here.
EOF
  exit 2
}

output_dir=""
grype_source=""
bundle_version=""
data_date=""
nvd_index=""
nvd_date="unknown"
alias_index=""
kev_catalog=""
kev_date="unknown"
nvd_feeds=()

[[ $# -ge 1 ]] || usage
output_dir="$1"
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --grype-db) grype_source="${2:-}"; shift 2 ;;
    --version) bundle_version="${2:-}"; shift 2 ;;
    --data-date) data_date="${2:-}"; shift 2 ;;
    --nvd-index) nvd_index="${2:-}"; shift 2 ;;
    --nvd-feed) nvd_feeds+=("${2:-}"); shift 2 ;;
    --nvd-date) nvd_date="${2:-}"; shift 2 ;;
    --alias-index) alias_index="${2:-}"; shift 2 ;;
    --kev) kev_catalog="${2:-}"; shift 2 ;;
    --kev-date) kev_date="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$grype_source" && -n "$data_date" ]] || usage
[[ -z "$nvd_index" || ${#nvd_feeds[@]} -eq 0 ]] || {
  echo "use either --nvd-index or --nvd-feed, not both" >&2
  exit 2
}
[[ "$output_dir" =~ ^[A-Za-z0-9._/-]+$ ]] || {
  echo "output path contains unsupported characters" >&2
  exit 2
}
[[ "$data_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || {
  echo "--data-date must be YYYY-MM-DD" >&2
  exit 2
}
[[ -d "$grype_source" ]] || { echo "Grype DB directory not found: $grype_source" >&2; exit 1; }
[[ -z "$nvd_index" || -f "$nvd_index" ]] || { echo "NVD index not found: $nvd_index" >&2; exit 1; }
[[ -z "$alias_index" || -f "$alias_index" ]] || { echo "alias index not found: $alias_index" >&2; exit 1; }
[[ -z "$kev_catalog" || -f "$kev_catalog" ]] || { echo "KEV catalog not found: $kev_catalog" >&2; exit 1; }
if [[ ${#nvd_feeds[@]} -gt 0 ]]; then
  for feed in "${nvd_feeds[@]}"; do
    [[ -f "$feed" ]] || { echo "NVD feed not found: $feed" >&2; exit 1; }
  done
fi

bundle_version="${bundle_version:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$bundle_version" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid bundle version" >&2; exit 2; }
output_abs="$(mkdir -p "$(dirname "$output_dir")" && cd "$(dirname "$output_dir")" && pwd)/$(basename "$output_dir")"
[[ ! -e "$output_abs" ]] || { echo "output already exists: $output_abs" >&2; exit 1; }

grype_root="$grype_source"
if [[ "$(basename "$grype_source")" =~ ^[0-9]+$ ]]; then
  grype_root="$(dirname "$grype_source")"
fi
schema_dir="$(find "$grype_root" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' | sort | head -1)"
[[ -n "$schema_dir" && -f "$schema_dir/vulnerability.db" ]] || {
  echo "Grype DB must contain <schema>/vulnerability.db: $grype_source" >&2
  exit 1
}
grype_schema="$(basename "$schema_dir")"

parent_dir="$(dirname "$output_abs")"
stage_dir="$(mktemp -d "$parent_dir/.vuln-bundle.XXXXXX")"
cleanup() {
  if [[ -n "${stage_dir:-}" && -d "$stage_dir" ]]; then
    rm -rf "$stage_dir"
  fi
}
trap cleanup EXIT
mkdir -p "$stage_dir/grype-db"
cp -a "$grype_root/." "$stage_dir/grype-db/"

metadata_extra=()
if [[ -n "$nvd_index" ]]; then
  cp "$nvd_index" "$stage_dir/nvd.json"
  metadata_extra+=("NVD_INDEX=nvd.json" "NVD_SHA256=$(sha256_file "$stage_dir/nvd.json" | awk '{print $1}')")
elif [[ ${#nvd_feeds[@]} -gt 0 ]]; then
  python3 "$ROOT_DIR/scripts/nvd-alias-index.py" --output "$stage_dir/nvd.json" "${nvd_feeds[@]}"
  metadata_extra+=("NVD_INDEX=nvd.json" "NVD_SHA256=$(sha256_file "$stage_dir/nvd.json" | awk '{print $1}')")
fi
if [[ -n "$alias_index" ]]; then
  cp "$alias_index" "$stage_dir/alias-index.json"
  metadata_extra+=("ALIAS_INDEX=alias-index.json" "ALIAS_SHA256=$(sha256_file "$stage_dir/alias-index.json" | awk '{print $1}')")
fi
if [[ -n "$kev_catalog" ]]; then
  cp "$kev_catalog" "$stage_dir/kev.json"
  python3 - "$stage_dir/kev.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)
if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
    raise SystemExit("KEV catalog must contain a vulnerabilities array")
PY
  metadata_extra+=("KEV_CATALOG=kev.json" "KEV_SHA256=$(sha256_file "$stage_dir/kev.json" | awk '{print $1}')")
fi

{
  echo "BUNDLE_VERSION=$bundle_version"
  echo "DATASET_DATE=$data_date"
  echo "GRYPE_DB_SCHEMA=$grype_schema"
  echo "NVD_DATASET_DATE=$nvd_date"
  echo "KEV_DATASET_DATE=$kev_date"
  if [[ ${#metadata_extra[@]} -gt 0 ]]; then
    printf '%s\n' "${metadata_extra[@]}"
  fi
} > "$stage_dir/metadata.env"

(
  cd "$stage_dir"
  while IFS= read -r -d '' file; do
    sha256_file "$file"
  done < <(find . -type f ! -name manifest.sha256 -print0 | sort -z)
) > "$stage_dir/manifest.sha256"

"$ROOT_DIR/scripts/verify-vuln-bundle.sh" "$stage_dir"
mv "$stage_dir" "$output_abs"
stage_dir=""
echo "Created vulnerability data bundle: $output_abs"
