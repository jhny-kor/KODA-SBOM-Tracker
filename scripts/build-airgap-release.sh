#!/bin/bash
set -euo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
# A release must use the digest-pinned example values, never an operator's
# local runtime .env.  The latter is intentionally supplied only on the
# closed-network server.
ENV_FILE="$EXAMPLE_ENV_FILE"
load_env "$EXAMPLE_ENV_FILE"
usage() { local rc="${1:-2}"; echo "usage: $0 [output.tar.gz] [--vuln-bundle DIR]" >&2; exit "$rc"; }
distribution_scope="${KODA_DISTRIBUTION_SCOPE:-internal}"
[[ "$distribution_scope" == internal ]] || {
  echo "external image redistribution is unsupported until corresponding-source delivery and legal review are approved" >&2
  exit 1
}
for legal_file in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
  [[ -f "$ROOT_DIR/$legal_file" ]] || { echo "legal file missing: $legal_file" >&2; exit 1; }
done
output="${ROOT_DIR}/dist/airgap-release/$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
vuln_bundle=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vuln-bundle) vuln_bundle="${2:-}"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) usage 2 ;;
    *) output="$1"; shift ;;
  esac
done
[[ -z "$vuln_bundle" || -d "$vuln_bundle" ]] || { echo "vulnerability bundle not found: $vuln_bundle" >&2; exit 1; }
mkdir -p "$(dirname "$output")"
output="$(cd "$(dirname "$output")" && pwd)/$(basename "$output")"
stage_dir="$(mktemp -d "$(dirname "$output")/.airgap-release.XXXXXX")"
cleanup() { rm -rf "$stage_dir"; }
trap cleanup EXIT
image_dir="$stage_dir/images"
mkdir -p "$image_dir" "$stage_dir/config" "$stage_dir/deploy" "$stage_dir/scripts" "$stage_dir/docs" "$stage_dir/source"
DOCKER_DEFAULT_PLATFORM=linux/amd64 compose build portal-web portal-api portal-worker
remote_images=("$DTRACK_APISERVER_IMAGE" "$DTRACK_FRONTEND_IMAGE" "$POSTGRES_IMAGE" "$NGINX_IMAGE" "$GRYPE_IMAGE" "$CYCLONEDX_CLI_IMAGE" "$ALPINE_BASE_IMAGE")
for image in "${remote_images[@]}"; do docker pull --platform linux/amd64 "$image"; done
local_images=("${PORTAL_WEB_IMAGE}:${PORTAL_IMAGE_TAG:-dev}" "${PORTAL_API_IMAGE}:${PORTAL_IMAGE_TAG:-dev}" "${PORTAL_WORKER_IMAGE}:${PORTAL_IMAGE_TAG:-dev}")
for image in "${local_images[@]}"; do
  architecture="$(docker image inspect "$image" --format '{{.Architecture}}')"
  [[ "$architecture" == amd64 ]] || { echo "image is not linux/amd64: $image ($architecture)" >&2; exit 1; }
done
for image in "${remote_images[@]}" "${local_images[@]}"; do
  safe_name="$(echo "$image" | tr '/:@' '___')"
  docker save --platform linux/amd64 -o "$image_dir/${safe_name}.tar" "$image"
done
cp "$ROOT_DIR/compose.yaml" "$stage_dir/compose.yaml"
cp "$ROOT_DIR/compose.airgap.yaml" "$stage_dir/compose.airgap.yaml"
cp "$ROOT_DIR/LICENSE" "$ROOT_DIR/NOTICE" "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$stage_dir/"
cp "$EXAMPLE_ENV_FILE" "$stage_dir/config/.env.example"
cp "$ROOT_DIR/deploy/manifests/images.lock" "$stage_dir/config/images.lock"
cp -a "$ROOT_DIR/deploy/." "$stage_dir/deploy/"
cp -a "$ROOT_DIR/scripts/." "$stage_dir/scripts/"
cp -a "$ROOT_DIR/docs/." "$stage_dir/docs/"

# Keep the checked-in application and test source in the same archive as the
# runtime files.  Reading the working tree (rather than `git archive HEAD`)
# ensures modified tracked files are packaged even before they are committed.
while IFS= read -r -d '' relative_path; do
  case "$relative_path" in
    .env|*.env) continue ;;
  esac
  destination="$stage_dir/source/$relative_path"
  mkdir -p "$(dirname "$destination")"
  cp -p "$ROOT_DIR/$relative_path" "$destination"
done < <(git -C "$ROOT_DIR" ls-files -z)

if [[ -n "$vuln_bundle" ]]; then
  "$ROOT_DIR/scripts/verify-vuln-bundle.sh" "$vuln_bundle"
  cp -a "$vuln_bundle" "$stage_dir/vulnerability-data"
fi

# Do not ship local interpreter caches or desktop metadata in an operational
# release.  The stage directory is temporary and is removed on exit.
find "$stage_dir" -type d \( -name __pycache__ -o -name .pytest_cache -o -name node_modules \) \
  -prune -exec rm -rf {} +
find "$stage_dir" -type f \( -name '*.pyc' -o -name '.DS_Store' \) -delete

cat > "$stage_dir/metadata.env" <<EOF
RELEASE_CREATED_AT=$(date -u +%Y%m%dT%H%M%SZ)
TARGET_PLATFORM=linux/amd64
DISTRIBUTION_SCOPE=internal-only
COMPOSE_FILE=compose.yaml:compose.airgap.yaml
VULNERABILITY_BUNDLE=$([[ -n "$vuln_bundle" ]] && echo included || echo absent)
EOF
(
  cd "$stage_dir"
  while IFS= read -r -d '' file; do sha256_file "$file"; done < <(find . -type f ! -name manifest.sha256 -print0 | sort -z)
) > "$stage_dir/manifest.sha256"
tar -czf "$output" -C "$stage_dir" .
(cd "$(dirname "$output")" && sha256_file "$(basename "$output")") > "${output}.sha256"
echo "Created air-gap release: $output"
echo "SHA-256: ${output}.sha256"
