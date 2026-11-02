"""A chosen container format never bypasses signed data lifecycle checks."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

from koda_tracker.archive_formats import create_archive, extract_archive
from test_ssvc import setup
from test_unified_data_lifecycle import unified, process, HEADERS
from test_unified_collector import approved, builder


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz", "7z"])
def test_signed_data_upload_validate_separate_apply_preserves_old_run(unified, tmp_path, kind):
    db, client, run, revision, settings, fixture = unified
    original = fixture()
    tree = tmp_path / "repack"; tree.mkdir()
    extract_archive(original, tree)
    compressed = create_archive(tree, tmp_path / ("chosen." + kind))
    upload = client.post('/api/v1/vulnerability-data-bundles/upload?kind=unified', content=compressed.read_bytes(), headers=HEADERS)
    assert upload.status_code == 202, upload.text
    process()
    job = client.get('/api/v1/vulnerability-data-bundles/jobs/' + upload.json()['id']).json()
    assert job['state'] == 'completed', job
    status = client.get('/api/v1/vulnerability-data-bundles/unified/status').json()
    assert not status['available'], 'validation must never activate data automatically'
    activation = client.post('/api/v1/vulnerability-data-bundles/jobs/' + job['id'] + '/apply', headers=HEADERS)
    assert activation.status_code == 202, activation.text
    process()
    assert client.get('/api/v1/vulnerability-data-bundles/jobs/' + activation.json()['id']).json()['state'] == 'completed'
    assert client.get('/api/v1/vulnerability-data-bundles/unified/status').json()['available']
    assert (settings.grype_db_dir.parent.parent / 'current/approved-manifest.sha256.sig').is_file()
    from koda_tracker.models import SbomRun, AnalysisRevision
    assert db.get(SbomRun, run.id) is not None
    assert db.get(AnalysisRevision, revision.id) is not None


@pytest.mark.parametrize("kind", ["zip", "tar", "7z"])
@pytest.mark.parametrize("signed,tamper", [(False, False), (True, True)])
def test_wrong_unsigned_or_tampered_archive_never_becomes_active(unified, tmp_path, kind, signed, tamper):
    _, client, _, _, settings, fixture = unified
    original = fixture(sign=signed, tamper=tamper)
    tree = tmp_path / "repack"; tree.mkdir(); extract_archive(original, tree)
    compressed = create_archive(tree, tmp_path / ("chosen." + kind))
    result = client.post('/api/v1/vulnerability-data-bundles/upload?kind=unified', content=compressed.read_bytes(), headers=HEADERS)
    assert result.status_code == 202
    process()
    job = client.get('/api/v1/vulnerability-data-bundles/jobs/' + result.json()['id']).json()
    assert job['state'] == 'failed'
    assert not client.get('/api/v1/vulnerability-data-bundles/unified/status').json()['available']
    assert not (settings.grype_db_dir.parent.parent / 'current').exists()


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz", "7z"])
def test_connected_builder_selects_real_format_and_retains_manifest_signature(tmp_path, kind):
    source, key, public = approved(tmp_path)
    output = builder.build(source, tmp_path / ("unified." + kind), key,
                           version='formats-test', data_date='2026-10-19', grype_date='2026-10-10', archive_format=kind)
    root = tmp_path / "read"; root.mkdir(); extract_archive(output, root)
    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public), '-signature', str(root / 'manifest.sha256.sig'), str(root / 'manifest.sha256')], check=True, capture_output=True)
    for row in (root / 'manifest.sha256').read_text().splitlines():
        digest, name = row.split('  ', 1)
        assert builder.digest(root / name) == digest


@pytest.mark.parametrize("script", ['build-data-update.py', 'collect-unified-data.py'])
def test_format_selector_works_from_installed_source_layout(tmp_path, script):
    import shutil
    repo = Path(__file__).parents[2]
    scripts = tmp_path / 'installed/scripts'; scripts.mkdir(parents=True)
    modules = tmp_path / 'installed/source/apps/api/koda_tracker'; modules.mkdir(parents=True)
    shutil.copy2(repo / 'scripts' / script, scripts / script)
    for filename in ['archive_formats.py', 'archive_native.py']:
        shutil.copy2(repo / 'apps/api/koda_tracker' / filename, modules / filename)
    result = subprocess.run([sys.executable, str(scripts / script), '--help'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert '--format {tar.gz,zip,tar,7z}' in result.stdout
    assert 'rar' not in result.stdout.lower()
