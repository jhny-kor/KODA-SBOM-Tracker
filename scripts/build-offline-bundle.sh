#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

distribution_scope="${KODA_DISTRIBUTION_SCOPE:-internal}"
[[ "$distribution_scope" == internal ]] || {
  echo "external image redistribution is unsupported until corresponding-source delivery and legal review are approved" >&2
  exit 1
}
for legal_file in LICENSE NOTICE THIRD_PARTY_NOTICES.md; do
  [[ -f "$ROOT_DIR/$legal_file" ]] || { echo "legal file missing: $legal_file" >&2; exit 1; }
done
signing_key="${KODA_RELEASE_SIGNING_KEY:-}"
if [[ -n "$signing_key" ]]; then
  [[ -r "$signing_key" ]] || { echo "release signing key is not readable: $signing_key" >&2; exit 1; }
else
  require_unsigned_artifact_opt_in "offline bundle"
fi
umask 077

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
bundle_root="${OFFLINE_BUNDLE_ROOT:-$ROOT_DIR/dist/offline-bundle}"
bundle_dir="${bundle_root}/${timestamp}"
image_dir="${bundle_dir}/images"
config_dir="${bundle_dir}/config"

ensure_dir "$image_dir"
ensure_dir "$config_dir"

source "$ROOT_DIR/scripts/release-images.sh"
prepare_release_images
DOCKER_DEFAULT_PLATFORM=linux/amd64 compose build portal-web portal-api portal-worker --build-arg KODA_IMAGE_CREATED="$KODA_IMAGE_CREATED" --build-arg KODA_IMAGE_REVISION="$KODA_IMAGE_REVISION" --build-arg KODA_IMAGE_VERSION="$PORTAL_IMAGE_TAG"

remote_images=()
while IFS= read -r image; do
  [[ -n "$image" ]] && remote_images+=("$image")
done <<EOF
${POSTGRES_IMAGE}
${NGINX_IMAGE}
${GRYPE_IMAGE}
${CYCLONEDX_CLI_IMAGE}
${ALPINE_BASE_IMAGE}
EOF

for image in "${remote_images[@]}"; do
  docker pull --platform linux/amd64 "$image"
done

local_images=()
while IFS= read -r image; do
  [[ -n "$image" ]] && local_images+=("$image")
done <<EOF
${PORTAL_WEB_IMAGE}:${PORTAL_IMAGE_TAG:-dev}
${PORTAL_API_IMAGE}:${PORTAL_IMAGE_TAG:-dev}
${PORTAL_WORKER_IMAGE}:${PORTAL_IMAGE_TAG:-dev}
EOF

all_images=("${remote_images[@]}" "${local_images[@]}")

for image in "${local_images[@]}"; do
  architecture="$(docker image inspect "$image" --format '{{.Architecture}}')"
  if [[ "$architecture" != "amd64" ]]; then
    echo "Local image has unexpected architecture: ${image} (${architecture})" >&2
    exit 1
  fi
done

for image in "${all_images[@]}"; do
  safe_name="$(echo "$image" | tr '/:@' '___')"
  docker save --platform linux/amd64 -o "${image_dir}/${safe_name}.tar" "$image"
done

cp "$ROOT_DIR/compose.yaml" "$config_dir/"
cp "$ROOT_DIR/LICENSE" "$ROOT_DIR/NOTICE" "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$bundle_dir/"
cp "$EXAMPLE_ENV_FILE" "$config_dir/.env.example"
cp "$ROOT_DIR/deploy/manifests/images.lock" "$config_dir/"
write_release_images "$config_dir/release-images.env"
apply_release_images "$config_dir/release-images.env" "$config_dir/.env.example"
cp -R "$ROOT_DIR/deploy" "$config_dir/"
cp -R "$ROOT_DIR/docs" "$config_dir/"
cp -R "$ROOT_DIR/scripts" "$config_dir/"

cat > "${bundle_dir}/metadata.env" <<EOF
BUNDLE_CREATED_AT=${timestamp}
TARGET_PLATFORM=linux/amd64
IMAGE_TAG=$PORTAL_IMAGE_TAG
IMAGE_BUILT_AT=$KODA_IMAGE_CREATED
IMAGE_REVISION=$KODA_IMAGE_REVISION
DISTRIBUTION_SCOPE=internal-only
ANALYSIS_BACKEND=koda-native
POSTGRES_IMAGE=${POSTGRES_IMAGE}
GRYPE_IMAGE=${GRYPE_IMAGE}
CYCLONEDX_CLI_IMAGE=${CYCLONEDX_CLI_IMAGE}
ALPINE_BASE_IMAGE=${ALPINE_BASE_IMAGE}
EOF

(
  cd "$bundle_dir"
  while IFS= read -r -d '' file; do
    sha256_file "$file"
  done < <(find . -type f ! -name manifest.sha256 -print0 | sort -z)
) > "${bundle_dir}/manifest.sha256"
if [[ -n "$signing_key" ]]; then
  sign_file "$signing_key" "${bundle_dir}/manifest.sha256" "${bundle_dir}/manifest.sha256.sig"
fi
echo "Created offline bundle: ${bundle_dir}"
[[ -z "$signing_key" ]] || echo "Detached signature: ${bundle_dir}/manifest.sha256.sig"
[[ -n "$signing_key" ]] || echo "Unsigned offline bundle created by explicit opt-in" >&2
