#!/usr/bin/env python3
"""Prepare one independently uploadable offline dataset, without rebuilding images."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import importlib.util

import sys
_script_dir = Path(__file__).resolve().parent
_archive_module = next((candidate for candidate in (
    _script_dir.parent / 'apps/api/koda_tracker/archive_formats.py',
    _script_dir / 'archive_formats.py',
    _script_dir.parent / 'source/apps/api/koda_tracker/archive_formats.py',
) if candidate.is_file()), None)
if _archive_module is None:
    raise RuntimeError('archive format helpers are missing from this distribution')
sys.path.insert(0, str(_archive_module.parent))
from archive_formats import FORMATS, create_archive, output_format


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def build(kind: str, source: Path, output: Path, version: str, data_date: str, *, archive_format: str | None = None) -> Path:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', version):
        raise ValueError('invalid version')
    dt.date.fromisoformat(data_date)
    selected_format = output_format(output, archive_format)
    if output.exists():
        raise ValueError(f'output already exists: {output}')
    if any(p.is_symlink() for p in source.rglob('*')):
        raise ValueError('source symlinks are not allowed')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.data-package-', dir=output.parent) as temporary:
        root = Path(temporary)
        metadata = {'BUNDLE_VERSION': version, 'DATASET_TYPE': kind, 'DATASET_DATE': data_date,
                    'CREATED_AT': dt.datetime.now(dt.timezone.utc).isoformat()}
        if kind == 'grype-db':
            schemas = [p for p in source.iterdir() if p.is_dir() and p.name.isdigit() and (p / 'vulnerability.db').is_file()]
            if len(schemas) != 1 or not (schemas[0] / 'import.json').is_file():
                raise ValueError('source must contain one imported <schema>/vulnerability.db and import.json; use grype db import/update')
            schema = schemas[0]
            shutil.copytree(schema, root / 'grype-db' / schema.name)
            metadata.update(GRYPE_DB_SCHEMA=schema.name, GRYPE_DATASET_DATE=data_date,
                            SOURCE_URL='https://grype.anchore.io/databases/v6/latest.json')
        else:
            nvd = source / 'nvd.json'
            if nvd.is_file():
                shutil.copy2(nvd, root / 'nvd.json')
            else:
                feeds = sorted((source / 'nvd').glob('nvdcve-2.0-*.json.gz'))
                if not feeds:
                    raise ValueError('source requires nvd.json or nvd/nvdcve-2.0-*.json.gz')
                # Year feeds first, then mutable feeds to retain the freshest record.
                feeds.sort(key=lambda p: ('recent' in p.name or 'modified' in p.name, p.name))
                subprocess.run(['python3', str(Path(__file__).with_name('nvd-alias-index.py')), '--output', str(root / 'nvd.json'), *map(str, feeds)], check=True)
            kev = source / 'kev.json'
            if not kev.is_file():
                kev = source / 'known_exploited_vulnerabilities.json'
            payload = json.loads(kev.read_text())
            if not isinstance(payload, dict) or not isinstance(payload.get('vulnerabilities'), list):
                raise ValueError('invalid KEV catalog')
            shutil.copy2(kev, root / 'kev.json')
            metadata.update(NVD_INDEX='nvd.json', NVD_DATASET_DATE=data_date, NVD_SHA256=sha256(root / 'nvd.json'),
                            KEV_CATALOG='kev.json', KEV_DATASET_DATE=str(payload.get('dateReleased') or data_date),
                            KEV_SHA256=sha256(root / 'kev.json'),
                            SOURCE_URL='https://nvd.nist.gov/feeds/json/cve/2.0/;https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
            sidecar_spec = importlib.util.spec_from_file_location('stage_intelligence', Path(__file__).with_name('stage-intelligence.py'))
            sidecars = importlib.util.module_from_spec(sidecar_spec)
            sidecar_spec.loader.exec_module(sidecars)
            epss = next((source / name for name in ('epss.csv.gz', 'epss.csv') if (source / name).is_file()), None)
            intelligence_index = source / 'intelligence.json'
            metadata.update(sidecars.stage(root, epss=epss, intelligence_index=intelligence_index if intelligence_index.is_file() else None))
        for path in root.rglob('*'):
            if path.is_symlink():
                raise ValueError('source symlinks are not allowed')
        (root / 'metadata.env').write_text(''.join(f'{k}={v}\n' for k, v in metadata.items()))
        files = sorted(p for p in root.rglob('*') if p.is_file())
        (root / 'manifest.sha256').write_text(''.join(f'{sha256(p)}  {p.relative_to(root).as_posix()}\n' for p in files))
        create_archive(root, output, archive_format=selected_format)
    output.with_suffix(output.suffix + '.sha256').write_text(f'{sha256(output)}  {output.name}\n')
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['grype-db', 'vuln-data'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--format', choices=FORMATS, dest='archive_format', help='archive format; inferred from --output extension when omitted')
    parser.add_argument('--source', type=Path, help='verified imported Grype cache or NVD/KEV source directory')
    parser.add_argument('--download', action='store_true', help='refresh from official sources on this internet-connected host')
    parser.add_argument('--cache', type=Path, default=Path('.data-update-cache'))
    parser.add_argument('--koda-repo', type=Path, help='KODA checkout containing platforms/linux/package-offline.sh')
    parser.add_argument('--grype-binary', default='grype')
    parser.add_argument('--version', default=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    parser.add_argument('--data-date', help='effective source date (required when packaging existing sources)')
    args = parser.parse_args()
    if args.download:
        args.cache = args.cache.resolve()
        args.cache.mkdir(parents=True, exist_ok=True)
        if args.kind == 'grype-db':
            args.source = args.cache / 'grype-db'
            env = {**os.environ, 'GRYPE_DB_CACHE_DIR': str(args.source), 'GRYPE_DB_AUTO_UPDATE': 'true'}
            subprocess.run([args.grype_binary, 'db', 'update'], env=env, check=True)
            status = json.loads(subprocess.check_output([args.grype_binary, 'db', 'status', '-o', 'json'], env=env, text=True))
            args.data_date = args.data_date or str(status.get('built') or status.get('builtAt') or '')[:10]
        else:
            if not args.koda_repo:
                parser.error('--download vuln-data requires --koda-repo')
            subprocess.run(['bash', str(args.koda_repo.resolve() / 'platforms/linux/package-offline.sh'), '--refresh', '--data-cache-only'],
                           env={**os.environ, 'KODA_OFFLINE_CACHE_DIR': str(args.cache)}, check=True)
            args.source = args.cache / 'assets/vuln-data'
            args.data_date = args.data_date or dt.datetime.now(dt.timezone.utc).date().isoformat()
    if not args.source or not args.data_date:
        parser.error('supply --source and --data-date, or --download')
    print(build(args.kind, args.source, args.output, args.version, args.data_date, archive_format=args.archive_format))


if __name__ == '__main__':
    main()
