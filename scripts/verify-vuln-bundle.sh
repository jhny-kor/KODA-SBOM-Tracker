#!/bin/bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
load_env

bundle_dir="${1:-}"
require_arg "$bundle_dir" "usage: $0 <bundle-dir>"

test -f "${bundle_dir}/metadata.env"
test -f "${bundle_dir}/manifest.sha256"
validate_manifest_paths "${bundle_dir}/manifest.sha256"
validate_manifest_inventory "${bundle_dir}/manifest.sha256" "$bundle_dir"
verify_manifest "${bundle_dir}/manifest.sha256"
if grep -q '^UNIFIED_BOOTSTRAP_FILE=' "${bundle_dir}/metadata.env"; then
  python3 - "$bundle_dir" <<'PY_COMPACT'
from pathlib import Path, PurePosixPath
import hashlib
import re
import sys
import tarfile

root = Path(sys.argv[1])
literal = {'metadata.env', 'manifest.sha256', 'unified-update.tar.gz'}
if {path.name for path in root.iterdir()} != literal or any(path.is_symlink() or not path.is_file() for path in root.iterdir()):
    raise SystemExit('compact unified seed must contain only metadata.env, manifest.sha256 and unified-update.tar.gz')
def metadata(raw):
    values = {}
    for line in raw.decode().splitlines():
        if '=' not in line or line.startswith('#'):
            continue
        key, value = line.split('=', 1)
        if key in values:
            raise SystemExit('duplicate compact seed metadata field')
        values[key] = value
    return values
if (root / 'metadata.env').stat().st_size > 65536:
    raise SystemExit('compact seed metadata exceeds limit')
outer = metadata((root / 'metadata.env').read_bytes())
if outer.get('UNIFIED_BOOTSTRAP_FILE') != 'unified-update.tar.gz':
    raise SystemExit('UNIFIED_BOOTSTRAP_FILE must be literal unified-update.tar.gz')
if not {'BUNDLE_VERSION', 'DATASET_DATE', 'GRYPE_DB_SCHEMA'} <= set(outer):
    raise SystemExit('compact seed must retain original dataset metadata')
checksums, proof, seen, expanded = {}, {}, set(), 0
with tarfile.open(root / 'unified-update.tar.gz', 'r|gz') as archive:
    for count, member in enumerate(archive, 1):
        name = member.name.removeprefix('./').rstrip('/')
        expanded += member.size
        if count > 100_000 or member.size > 4 * 1024 ** 3 or expanded > 12 * 1024 ** 3:
            raise SystemExit('compact bootstrap exceeds data-update limits')
        if name in seen or not name or PurePosixPath(name).as_posix() != name or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe or duplicate compact bootstrap member')
        seen.add(name)
        if not member.isfile():
            continue
        limit = 16 * 1024 * 1024 if name == 'manifest.sha256' else 65536
        capture = name in {'metadata.env', 'manifest.sha256', 'manifest.sha256.sig'}
        if capture and not 0 < member.size <= limit:
            raise SystemExit('invalid compact bootstrap proof size')
        checksum, data = hashlib.sha256(), bytearray()
        with archive.extractfile(member) as incoming:
            for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                checksum.update(chunk)
                if capture:
                    data.extend(chunk)
        checksums[name] = checksum.hexdigest()
        if capture:
            proof[name] = bytes(data)
if set(proof) != {'metadata.env', 'manifest.sha256', 'manifest.sha256.sig'}:
    raise SystemExit('compact bootstrap requires original metadata, manifest and signature proof')
inner = metadata(proof['metadata.env'])
if inner.get('DATASET_TYPE') != 'unified' or not inner.get('EPSS_SNAPSHOT') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', inner.get('BUNDLE_VERSION', '')):
    raise SystemExit('compact bootstrap must be a unified dataset with official EPSS metadata')
for key, value in outer.items():
    if key != 'UNIFIED_BOOTSTRAP_FILE' and key in inner and inner[key] != value:
        raise SystemExit('compact seed source metadata differs from signed bootstrap: ' + key)
declared = {}
for line in proof['manifest.sha256'].decode().splitlines():
    fields = line.split()
    if len(fields) != 2 or not re.fullmatch(r'[0-9a-fA-F]{64}', fields[0]):
        raise SystemExit('invalid signed bootstrap manifest')
    name = fields[1].removeprefix('./')
    if name in declared or checksums.get(name) != fields[0].lower():
        raise SystemExit('signed bootstrap manifest mismatch')
    declared[name] = fields[0]
if set(declared) != set(checksums) - {'manifest.sha256', 'manifest.sha256.sig'}:
    raise SystemExit('signed bootstrap manifest inventory mismatch')
schema = inner.get('GRYPE_DB_SCHEMA', '')
required = {'metadata.env', f'grype-db/{schema}/vulnerability.db', f'grype-db/{schema}/import.json', inner.get('NVD_INDEX', ''), inner.get('KEV_CATALOG', ''), inner['EPSS_SNAPSHOT']}
if not schema.isdigit() or not required <= set(declared):
    raise SystemExit('compact bootstrap is missing required unified datasets')
print('Compact unified seed integrity verified; registered-key approval is checked during installation')
PY_COMPACT
  exit 0
fi
python3 "$ROOT_DIR/scripts/stage-intelligence.py" --verify "$bundle_dir"

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
