#!/usr/bin/env python3
"""One connected-host entry point producing one signed offline archive. Never run by runtime."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
OPTIONAL = {'vulnrichment', 'csaf', 'vex', 'ubuntu-oval', 'lifecycle', 'cpe-dictionary', 'cpe-match', 'cwe', 'spdx', 'package-metadata'}


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''): value.update(data)
    return value.hexdigest()


def build(source, output, signing_key, *, version, data_date, grype_date=None, required_kinds=()):
    source, output, signing_key = map(Path, (source, output, signing_key))
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', version) or version in {'.', '..'}:
        raise ValueError('invalid version')
    dt.date.fromisoformat(data_date)
    dt.date.fromisoformat(grype_date or data_date)
    if output.exists(): raise ValueError('output already exists')
    if not signing_key.is_file(): raise ValueError('a signing private key is required')
    if source.resolve() == signing_key.resolve() or source.resolve() in signing_key.resolve().parents:
        raise ValueError('signing private key must be outside all collected source directories')
    if source.is_symlink() or any(path.is_symlink() for path in source.rglob('*')): raise ValueError('source symlinks are not allowed')
    if source.resolve() in output.resolve().parents: raise ValueError('output must be outside the source directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    builder = module('component_builder', 'build-data-update.py')
    stages = module('unified_sidecars', 'stage-intelligence.py')
    with tempfile.TemporaryDirectory(prefix='.unified-build-', dir=output.parent) as temporary:
        temporary = Path(temporary)
        root = temporary / 'unified'; root.mkdir()
        # Existing validated builders define the same component formats as the runtime.
        for kind, directory, stamp in (('grype-db', source / 'grype-db', grype_date or data_date), ('vuln-data', source / 'vuln-data', data_date)):
            archive = builder.build(kind, directory, temporary / (kind + '.tar.gz'), version, stamp)
            part = temporary / kind; part.mkdir()
            with tarfile.open(archive) as handle: handle.extractall(part, filter='data')
            values = dict(line.split('=', 1) for line in (part / 'metadata.env').read_text().splitlines())
            if kind == 'grype-db':
                metadata = values
                for candidate in (part / 'grype-db').rglob('*'):
                    if candidate.is_file() and candidate.name not in {'vulnerability.db', 'import.json'}:
                        raise ValueError('unexpected file in Grype DB cache; refuse collecting keys or local files')
            else: metadata.update(values)
            for path in part.iterdir():
                if path.name not in {'metadata.env', 'manifest.sha256'}:
                    if path.is_dir(): shutil.copytree(path, root / path.name)
                    else: shutil.copy2(path, root / path.name)
            # Keep a multi-gigabyte database once after its verified component
            # has been copied into the final signed payload.
            shutil.rmtree(part)
            archive.unlink()
        if 'EPSS_SNAPSHOT' not in metadata: raise ValueError('unified packages require an approved EPSS snapshot')
        kinds = set()
        reference_dates = {}
        if (root / 'intelligence.json').is_file():
            document = stages.parser.load_intelligence(root)
            kinds = set(document['datasets'])
            reference_dates = {kind: [{'sourceId': item['id'], 'dataDate': item.get('dataDate'), 'sha256': item.get('sha256')} for item in dataset['sources']] for kind, dataset in document['datasets'].items()}
        required = set(required_kinds)
        if required - kinds: raise ValueError('missing required reference kinds: ' + ', '.join(sorted(required - kinds)))
        created = dt.datetime.now(dt.timezone.utc).isoformat()
        metadata.update(DATASET_TYPE='unified', BUNDLE_VERSION=version, CREATED_AT=created,
                        GRYPE_DB_VERSION=version, VULN_DATA_VERSION=version)
        (root / 'collection.json').write_text(json.dumps({
            'format': 'koda-unified-collection-v1', 'createdAt': created, 'version': version,
            'requiredKinds': ['grype-db', 'nvd', 'kev', 'epss', *sorted(required)],
            'includedKinds': ['grype-db', 'nvd', 'kev', 'epss', *sorted(kinds - {'epss'})],
            'missingOptionalKinds': sorted(OPTIONAL - kinds),
            'dataDates': {key: value for key, value in metadata.items() if key.endswith('_DATE')},
            'referenceDates': reference_dates,
        }, ensure_ascii=False, indent=2) + '\n')
        (root / 'metadata.env').write_text(''.join(f'{key}={value}\n' for key, value in sorted(metadata.items())))
        files = sorted(path for path in root.rglob('*') if path.is_file())
        manifest = root / 'manifest.sha256'
        manifest.write_text(''.join(f'{digest(path)}  {path.relative_to(root).as_posix()}\n' for path in files))
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(signing_key), '-out', str(root / 'manifest.sha256.sig'), str(manifest)], check=True, capture_output=True)
        packed = temporary / 'complete.tar.gz'
        with tarfile.open(packed, 'w:gz') as handle:
            for path in sorted(root.rglob('*')):
                if path.is_file(): handle.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
        # Publish a completed file atomically on the same filesystem; never leave
        # a partial named release after an interrupted copy or replace another build.
        with packed.open('rb') as stream: os.fsync(stream.fileno())
        os.link(packed, output)
    return output


def acquire(args, destination):
    grype = destination / 'grype-db'
    env = {**os.environ, 'GRYPE_DB_CACHE_DIR': str(grype), 'GRYPE_DB_AUTO_UPDATE': 'true', 'GRYPE_CHECK_FOR_APP_UPDATE': 'false'}
    subprocess.run([args.grype_binary, 'db', 'update'], env=env, check=True)
    status = json.loads(subprocess.check_output([args.grype_binary, 'db', 'status', '-o', 'json'], env=env, text=True))
    if status.get('valid') is not True: raise ValueError('downloaded Grype DB is invalid')
    args.grype_date = str(status.get('built') or status.get('builtAt') or '')[:10]
    dt.date.fromisoformat(args.grype_date)
    if not args.koda_repo: raise ValueError('--koda-repo is required for connected NVD/KEV collection')
    cache = args.cache.resolve(); cache.mkdir(parents=True, exist_ok=True)
    subprocess.run(['bash', str(args.koda_repo.resolve() / 'platforms/linux/package-offline.sh'), '--refresh', '--data-cache-only'],
                   env={**os.environ, 'KODA_OFFLINE_CACHE_DIR': str(cache), 'KODA_EPSS_SNAPSHOT': '', 'KODA_INTELLIGENCE_SNAPSHOT': ''}, check=True)
    shutil.copytree(cache / 'assets/vuln-data', destination / 'vuln-data')
    for name in ('epss.csv', 'epss.csv.gz'):
        (destination / 'vuln-data' / name).unlink(missing_ok=True)
    collector = module('unified_collector', 'collect-offline-intelligence.py')
    if args.epss:
        shutil.copyfile(args.epss, destination / 'vuln-data/epss.csv.gz' if args.epss.suffix == '.gz' else destination / 'vuln-data/epss.csv')
    else:
        raw = collector.fetch_url('https://epss.empiricalsecurity.com/epss_scores-current.csv.gz', collector.HOSTS)
        (destination / 'vuln-data/epss.csv.gz').write_bytes(raw)
    if args.intelligence_spec:
        target = destination / 'references'
        collector.collect(json.loads(args.intelligence_spec.read_text()), target, fetch=True, base=args.intelligence_spec.parent, allow_hosts=getattr(args, 'allow_host', ()))
        shutil.copy2(target / 'intelligence.json', destination / 'vuln-data/intelligence.json')
        shutil.copytree(target / 'intelligence-sources', destination / 'vuln-data/intelligence-sources', dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--signing-key', type=Path, required=True, help='private RSA key, never included in the archive')
    parser.add_argument('--source', type=Path, help='approved local directory containing grype-db/ and vuln-data/; without this, collect online')
    parser.add_argument('--data-date', help='required when packaging approved local sources')
    parser.add_argument('--grype-date', help='original Grype DB build date for local sources')
    parser.add_argument('--version', default=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    parser.add_argument('--koda-repo', type=Path)
    parser.add_argument('--grype-binary', default='grype')
    parser.add_argument('--cache', type=Path, default=Path('.unified-collection-cache'))
    parser.add_argument('--epss', type=Path, help='approved FIRST snapshot instead of connected download')
    parser.add_argument('--intelligence-spec', type=Path, help='existing collector source specification for scoped reference datasets')
    parser.add_argument('--allow-host', action='append', default=[], help='explicit approved vendor HTTPS hostname for reference collection')
    parser.add_argument('--profile', choices=['core', 'full'], default='core', help='full requires every supported reference kind; core reports optional omissions')
    parser.add_argument('--require-kind', action='append', default=[], help='fail if a requested reference kind was not collected')
    args = parser.parse_args()
    if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', host) for host in args.allow_host):
        parser.error('--allow-host requires a hostname, not a URL or credentials')
    if args.profile == "full": args.require_kind = sorted(OPTIONAL | set(args.require_kind))
    try:
        if args.source:
            if not args.data_date or not args.grype_date: parser.error('--source requires --data-date and --grype-date')
            if args.epss or args.intelligence_spec: parser.error('with --source place approved EPSS/references inside vuln-data/')
            output = build(args.source, args.output, args.signing_key, version=args.version, data_date=args.data_date, grype_date=args.grype_date, required_kinds=args.require_kind)
        else:
            with tempfile.TemporaryDirectory(prefix='koda-connected-collect-') as temp:
                source = Path(temp)
                acquire(args, source)
                output = build(source, args.output, args.signing_key, version=args.version,
                               data_date=dt.datetime.now(dt.timezone.utc).date().isoformat(), grype_date=args.grype_date, required_kinds=args.require_kind)
        print('Created signed unified archive: ' + str(output))
        print('SHA-256: ' + digest(output))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, str(exc) + '\n')

if __name__ == '__main__': main()
