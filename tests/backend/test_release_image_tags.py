"""Dated build identity survives packaging and installation without changing secrets."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/release-images.sh'


def shell(code, **environment):
    return subprocess.run(['bash', '-c', 'set -euo pipefail; source "$HELPER"; ' + code],
                          env={**os.environ, 'HELPER': str(HELPER), 'ROOT_DIR': str(ROOT), **environment},
                          capture_output=True, text=True)


def test_default_tag_is_utc_revision_and_is_exported():
    result = shell('prepare_release_images; python3 -c \'import os; print(os.environ["PORTAL_IMAGE_TAG"]); print(os.environ["KODA_IMAGE_CREATED"])\'')
    assert result.returncode == 0, result.stderr
    import re
    tag, created = result.stdout.splitlines()
    assert re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{12}(?:-dirty)?', tag)
    assert re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', created)


def test_explicit_release_tag_and_invalid_tags():
    tag = '20261019T120000Z-release1'
    assert shell('prepare_release_images; echo "$PORTAL_IMAGE_TAG"', TRACKER_RELEASE_IMAGE_TAG=tag).stdout.strip() == tag
    for invalid in ('dev', 'latest', '20261019;echo bad', '20261019T120000Z-' + 'a' * 128):
        assert shell('prepare_release_images', TRACKER_RELEASE_IMAGE_TAG=invalid).returncode != 0


def test_release_identity_roundtrip_preserves_native_settings(tmp_path):
    runtime = tmp_path / '.env'
    release = tmp_path / 'release-images.env'
    runtime.write_text('PORTAL_IMAGE_TAG=dev\nPOSTGRES_IMAGE=postgres:keep\nTRACKER_DB_PASSWORD=keep-secret\n')
    runtime.chmod(0o600)
    result = shell('prepare_release_images; write_release_images "$RELEASE"; apply_release_images "$RELEASE" "$RUNTIME"',
                   TRACKER_RELEASE_IMAGE_TAG='20261019T120000Z-test', PORTAL_API_IMAGE='local/api',
                   PORTAL_WEB_IMAGE='local/web', PORTAL_WORKER_IMAGE='local/worker',
                   RELEASE=str(release), RUNTIME=str(runtime))
    assert result.returncode == 0, result.stderr
    value = runtime.read_text()
    assert 'PORTAL_IMAGE_TAG=20261019T120000Z-test' in value
    assert 'PORTAL_API_IMAGE=local/api' in value
    assert 'TRACKER_DB_PASSWORD=keep-secret' in value
    assert 'POSTGRES_IMAGE=postgres:keep' in value
    assert runtime.stat().st_mode & 0o777 == 0o600
    release.write_text('PORTAL_IMAGE_TAG=$(touch /tmp/should-not-run)\n')
    before = runtime.read_bytes()
    assert shell('apply_release_images "$RELEASE" "$RUNTIME"', RELEASE=str(release), RUNTIME=str(runtime)).returncode != 0
    assert runtime.read_bytes() == before


def test_builders_labels_and_install_use_the_same_identity():
    for name in ('build-airgap-release.sh', 'build-offline-bundle.sh'):
        script = (ROOT / 'scripts' / name).read_text()
        assert script.index('prepare_release_images') < script.index('compose build')
        assert 'write_release_images' in script and 'IMAGE_TAG=$PORTAL_IMAGE_TAG' in script
        assert '--build-arg KODA_IMAGE_CREATED=' in script
    installer = (ROOT / 'scripts/install-airgap.sh').read_text()
    assert installer.index('apply_release_images') < installer.index('docker load')
    for name in ('apps/api/Dockerfile', 'apps/web/Dockerfile'):
        data = (ROOT / name).read_text()
        for key in ('created', 'revision', 'version'):
            assert f'org.opencontainers.image.{key}=' in data
