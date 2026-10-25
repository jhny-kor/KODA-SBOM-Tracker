import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile

import pytest

from test_offline_intelligence_formats import fixtures, document

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('unified_builder', ROOT / 'scripts/collect-unified-data.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


def approved(tmp_path, *, all_kinds=False):
    source = tmp_path / 'source'; directory = source / 'grype-db/6'; directory.mkdir(parents=True)
    (directory / 'vulnerability.db').write_bytes(b'unit fixture, not production DB')
    (directory / 'import.json').write_text('{}')
    vuln = source / 'vuln-data'; vuln.mkdir()
    (vuln / 'nvd.json').write_text('{"vulnerabilities":{}}')
    (vuln / 'kev.json').write_text('{"vulnerabilities":[],"dateReleased":"2026-10-19"}')
    (vuln / 'epss.csv').write_bytes(fixtures()['epss'])
    if all_kinds: (vuln / 'intelligence.json').write_text(json.dumps(document(vuln)))
    key = tmp_path / 'key.pem'; public = tmp_path / 'public.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key)], check=True, capture_output=True)
    subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)], check=True, capture_output=True)
    return source, key, public


def test_single_archive_signed_manifest_inventory_and_complete_profile(tmp_path):
    source, key, public = approved(tmp_path, all_kinds=True)
    output = builder.build(source, tmp_path / 'one.tar.gz', key, version='20261020-test', data_date='2026-10-19', grype_date='2026-10-10', required_kinds=builder.OPTIONAL)
    extracted = tmp_path / 'extracted'; extracted.mkdir()
    with tarfile.open(output) as archive: archive.extractall(extracted, filter='data')
    assert (extracted / 'grype-db/6/vulnerability.db').is_file()
    assert (extracted / 'epss.csv').is_file()
    assert json.loads((extracted / 'collection.json').read_text())['missingOptionalKinds'] == []
    text = (extracted / 'metadata.env').read_text()
    assert 'DATASET_TYPE=unified' in text and 'GRYPE_DATASET_DATE=2026-10-10' in text
    assert not list(extracted.rglob('*.pem'))
    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public), '-signature', str(extracted / 'manifest.sha256.sig'), str(extracted / 'manifest.sha256')], check=True, capture_output=True)
    rows = [line.split('  ', 1) for line in (extracted / 'manifest.sha256').read_text().splitlines()]
    assert all(builder.digest(extracted / name) == digest for digest, name in rows)
    assert {name for _, name in rows} == {str(p.relative_to(extracted)) for p in extracted.rglob('*') if p.is_file()} - {'manifest.sha256', 'manifest.sha256.sig'}
    with pytest.raises(ValueError, match='already exists'):
        builder.build(source, output, key, version='new', data_date='2026-10-19')


def test_missing_required_sources_never_publish_completed_archive(tmp_path):
    source, key, _ = approved(tmp_path)
    output = tmp_path / 'one.tar.gz'
    with pytest.raises(ValueError, match='missing required reference'):
        builder.build(source, output, key, version='one', data_date='2026-10-19', required_kinds=['cwe'])
    assert not output.exists()
    (source / 'vuln-data/epss.csv').unlink()
    with pytest.raises(ValueError, match='EPSS'):
        builder.build(source, output, key, version='one', data_date='2026-10-19')
    assert not output.exists()


def test_local_source_symlink_rejected_and_core_omissions_explicit(tmp_path):
    source, key, _ = approved(tmp_path)
    output = tmp_path / 'one.tar.gz'
    builder.build(source, output, key, version='one', data_date='2026-10-19')
    with tarfile.open(output) as archive:
        collection = json.load(archive.extractfile('collection.json'))
        assert set(collection['missingOptionalKinds']) == builder.OPTIONAL
    (source / 'unsafe-link').symlink_to(key)
    with pytest.raises(ValueError, match='symlinks'):
        builder.build(source, tmp_path / 'two.tar.gz', key, version='two', data_date='2026-10-19')


def test_private_key_in_source_and_unrelated_cache_files_are_rejected(tmp_path):
    source, key, _ = approved(tmp_path)
    inside = source / 'grype-db/6/private.pem'
    inside.write_bytes(key.read_bytes())
    output = tmp_path / 'one.tar.gz'
    with pytest.raises(ValueError, match='outside'):
        builder.build(source, output, inside, version='one', data_date='2026-10-19')
    with pytest.raises(ValueError, match='unexpected file'):
        builder.build(source, output, key, version='one', data_date='2026-10-19')
    assert not output.exists()


def test_connected_entry_collects_core_data_without_runtime_http(monkeypatch, tmp_path):
    from types import SimpleNamespace
    destination = tmp_path / 'collected'; destination.mkdir()
    cache = tmp_path / 'cache'
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        if command[1:3] == ['db', 'update']:
            schema = Path(kwargs['env']['GRYPE_DB_CACHE_DIR']) / '6'; schema.mkdir(parents=True)
            (schema / 'vulnerability.db').write_bytes(b'fixture')
            (schema / 'import.json').write_text('{}')
        else:
            assert kwargs['env']['KODA_EPSS_SNAPSHOT'] == ''
            assert kwargs['env']['KODA_INTELLIGENCE_SNAPSHOT'] == ''
            vuln = cache / 'assets/vuln-data'; vuln.mkdir(parents=True)
            (vuln / 'nvd.json').write_text('{"vulnerabilities":{}}')
            (vuln / 'kev.json').write_text('{"vulnerabilities":[],"dateReleased":"2026-10-19"}')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(builder.subprocess, 'run', run)
    monkeypatch.setattr(builder.subprocess, 'check_output', lambda *args, **kwargs: '{"valid":true,"built":"2026-10-10T00:00:00Z"}')
    monkeypatch.setattr(builder, 'module', lambda *args: SimpleNamespace(HOSTS={'epss.empiricalsecurity.com'}, fetch_url=lambda url, hosts: fixtures()['epss']))
    args = SimpleNamespace(grype_binary='grype', grype_date=None, koda_repo=tmp_path, cache=cache, epss=None, intelligence_spec=None)
    builder.acquire(args, destination)
    assert args.grype_date == '2026-10-10'
    assert (destination / 'grype-db/6/vulnerability.db').is_file()
    assert (destination / 'vuln-data/epss.csv.gz').read_bytes() == fixtures()['epss']
    assert len(commands) == 2 and commands[1][-1] == '--data-cache-only'


def test_linux_compose_consumers_get_registered_key_and_updater_original_store():
    import re
    text = (ROOT / 'compose.yaml').read_text()
    def service(name):
        match = re.search(rf'(?ms)^  {name}:\n.*?(?=^  [a-z][a-z0-9-]*:\n|^volumes:|\Z)', text)
        assert match is not None
        return match.group()
    target = '/run/secrets/tracker-data-update-verify.pub'
    for name in ('portal-api', 'portal-worker', 'portal-data-updater'):
        block = service(name)
        assert 'TRACKER_DATA_UPDATE_VERIFY_KEY: ' + target in block
        assert target + ':ro' in block
    assert 'TRACKER_DATA_UPDATE_VERIFY_KEY' not in service('gateway')
    assert 'TRACKER_ARTIFACT_DIR' in service('portal-data-updater')
    assert 'tracker-artifacts:' in service('portal-data-updater')


def test_publish_failure_leaves_no_partially_named_archive(tmp_path, monkeypatch):
    source, key, _ = approved(tmp_path)
    output = tmp_path / 'one.tar.gz'
    def denied(*args): raise OSError('simulated publish failure')
    monkeypatch.setattr(builder.os, 'link', denied)
    with pytest.raises(OSError, match='publish failure'):
        builder.build(source, output, key, version='one', data_date='2026-10-19')
    assert not output.exists()


def test_registered_public_key_relative_path_is_relocated_without_source_edit(tmp_path):
    import sys
    source = tmp_path / 'source'; source.mkdir()
    (source / 'verify.pub').write_text('registered public key fixture')
    original = source / '.env'; original.write_text('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE=verify.pub\nTRACKER_DB_PASSWORD=preserve-test-only\n')
    destination = tmp_path / 'installed.env'; destination.write_bytes(original.read_bytes()); destination.chmod(0o600)
    script = (ROOT / 'scripts/install-airgap.sh').read_text().split("<<'PY_VERIFY_KEY'\n", 1)[1].split('\nPY_VERIFY_KEY', 1)[0]
    subprocess.run([sys.executable, '-c', script, str(original), str(destination)], check=True)
    assert str((source / 'verify.pub').resolve()) in destination.read_text()
    assert original.read_text().startswith('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE=verify.pub\n')
    assert 'TRACKER_DB_PASSWORD=preserve-test-only' in destination.read_text()
    assert destination.stat().st_mode & 0o777 == 0o600


def test_runtime_env_loading_keeps_key_relative_to_original_env(tmp_path):
    config = tmp_path / 'operator config'; config.mkdir()
    env = config / '.env'; env.write_text('TRACKER_DATA_UPDATE_VERIFY_KEY_FILE=verify.pub\n')
    result = subprocess.run(['bash', '-c', 'source "$1"; load_env "$2"; printf "%s" "$TRACKER_DATA_UPDATE_VERIFY_KEY_FILE"', '_', str(ROOT / 'scripts/lib.sh'), str(env)], capture_output=True, text=True, check=True)
    assert result.stdout == str(config / 'verify.pub')
