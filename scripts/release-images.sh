#!/bin/bash
# Sourced by release builders and verified installers; no runtime .env changes at build time.
prepare_release_images() {
  local stamp revision suffix
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  revision="$(git -C "$ROOT_DIR" rev-parse --short=12 HEAD)"
  suffix=""
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then suffix="-dirty"; fi
  export PORTAL_IMAGE_TAG="${TRACKER_RELEASE_IMAGE_TAG:-${stamp}-${revision}${suffix}}"
  [[ "$PORTAL_IMAGE_TAG" =~ ^[0-9]{8}T[0-9]{6}Z[-.][A-Za-z0-9_.-]+$ && ${#PORTAL_IMAGE_TAG} -le 128 ]] || {
    echo "TRACKER_RELEASE_IMAGE_TAG must start with UTC YYYYMMDDTHHMMSSZ- and contain a Docker-safe suffix" >&2; return 1;
  }
  export KODA_IMAGE_CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  export KODA_IMAGE_REVISION="$revision$suffix"
}

write_release_images() {
  local destination="$1"
  printf 'PORTAL_IMAGE_TAG=%s\nPORTAL_API_IMAGE=%s\nPORTAL_WEB_IMAGE=%s\nPORTAL_WORKER_IMAGE=%s\n' \
    "$PORTAL_IMAGE_TAG" "$PORTAL_API_IMAGE" "$PORTAL_WEB_IMAGE" "$PORTAL_WORKER_IMAGE" > "$destination"
}

apply_release_images() {
  local release_file="$1" runtime_file="$2"
  [[ -f "$release_file" ]] || return 0  # Older authenticated releases remain installable.
  python3 - "$release_file" "$runtime_file" <<'PY'
import os
from pathlib import Path
import re
import sys
import tempfile
source, target = map(Path, sys.argv[1:])
keys = {'PORTAL_IMAGE_TAG', 'PORTAL_API_IMAGE', 'PORTAL_WEB_IMAGE', 'PORTAL_WORKER_IMAGE'}
values = {}
for line in source.read_text().splitlines():
    key, sep, value = line.partition('=')
    if not sep or key not in keys or key in values:
        raise SystemExit('invalid release image settings')
    pattern = r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}' if key == 'PORTAL_IMAGE_TAG' else r'[a-z0-9][a-z0-9./:_-]{0,254}'
    if not re.fullmatch(pattern, value): raise SystemExit('invalid release image reference')
    values[key] = value
if set(values) != keys: raise SystemExit('incomplete release image settings')
lines = target.read_text().splitlines()
kept = [line for line in lines if not re.match(r'\s*(?:export\s+)?(?:' + '|'.join(keys) + r')\s*=', line)]
mode = target.stat().st_mode & 0o777
fd, temporary = tempfile.mkstemp(dir=target.parent)
try:
    with os.fdopen(fd, 'w') as stream:
        stream.write('\n'.join(kept + [f'{key}={value}' for key, value in values.items()]) + '\n')
    os.chmod(temporary, mode)
    os.replace(temporary, target)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
PY
}
