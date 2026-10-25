"""Owned legacy resources are removed; native and foreign resources survive."""
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('retired_cleanup', ROOT / 'scripts/remove-retired-analysis.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def container(service, identifier=None, project='koda-sbom', image=None):
    return {'Id': identifier or service, 'Image': image or service + '-image', 'Config': {'Labels': {'com.docker.compose.project': project, 'com.docker.compose.service': service}}}


class Docker:
    def __init__(self):
        self.containers = {row['Id']: row for row in [container('dtrack-apiserver', 'retired-api', image='old-image'), container('dtrack-frontend', 'retired-web', image='web-image'), container('portal-api'), container('portal-worker'), container('postgres')]}
        self.volumes = {'koda-sbom-dtrack-data': {'Labels': {'com.docker.compose.project': 'koda-sbom', 'com.docker.compose.volume': 'dtrack-data'}}, 'koda-sbom-postgres-data': {'Labels': {'com.docker.compose.project': 'koda-sbom', 'com.docker.compose.volume': 'postgres-data'}}}
        self.images = {'old-image': {'RepoTags': ['dependencytrack/apiserver:5.0.3', 'unrelated:keep']}, 'web-image': {'RepoTags': ['dependencytrack/frontend:5.0.3']}}
        self.calls = []
        self.mutations = []
        self.db = {'exists': True, 'owned': True, 'other': False}
        self.shared = False

    def __call__(self, command, **kwargs):
        args = command[1:]
        self.calls.append((args, kwargs.get('input')))
        result = ''
        if args[1:2] == ['inspect']:
            kind, _, name = args
            if kind == 'container':
                value = self.containers.get(name) or next((value for value in self.containers.values() if name == value['Config']['Labels']['com.docker.compose.project'] + '-' + value['Config']['Labels']['com.docker.compose.service']), None)
            else: value = (self.volumes if kind == 'volume' else self.images).get(name)
            if value is None: return subprocess.CompletedProcess(command, 1, '', 'Error: No such object')
            result = json.dumps([value])
        elif args[0] == 'ps':
            selector = args[-1]
            if selector.startswith('label='):
                result = '\n'.join(identifier for identifier, value in self.containers.items() if value['Config']['Labels']['com.docker.compose.project'] == selector.split('=', 2)[2])
            elif selector.startswith('volume='):
                result = '\n'.join(identifier for identifier in ('retired-api', 'retired-web') if identifier in self.containers)
                if self.shared: result += '\nforeign-container'
            elif selector.startswith('ancestor='):
                result = '\n'.join(identifier for identifier, value in self.containers.items() if value['Image'] == selector.split('=', 1)[1])
        elif args[:2] == ['volume', 'ls']: result = '\n'.join(self.volumes)
        elif args[0] == 'stop': self.mutations.append(args)
        elif args[0] == 'rm':
            self.mutations.append(args); self.containers.pop(args[-1])
        elif args[:2] == ['volume', 'rm']:
            self.mutations.append(args); self.volumes.pop(args[-1])
        elif args[:2] == ['image', 'rm']:
            self.mutations.append(args)
            for value in self.images.values():
                if args[-1] in value['RepoTags']: value['RepoTags'].remove(args[-1])
        elif args[0] == 'exec':
            if kwargs['input'].startswith('SELECT json_build_object'): result = json.dumps(self.db)
            else: self.mutations.append(args); self.db['exists'] = False
        else: raise AssertionError(args)
        return subprocess.CompletedProcess(command, 0, result, '')


def test_removes_only_owned_retired_containers_volume_and_tags():
    docker = Docker()
    result = module.Cleaner({}, runner=docker).resources()
    assert result == {'containers': 2, 'volumes': 1, 'images': 2}
    assert set(docker.containers) == {'portal-api', 'portal-worker', 'postgres'}
    assert set(docker.volumes) == {'koda-sbom-postgres-data'}
    assert docker.images['old-image']['RepoTags'] == ['unrelated:keep']
    assert module.Cleaner({}, runner=docker).resources()['containers'] == 0


def test_shared_or_foreign_volume_aborts_before_any_mutation():
    for mode in ('shared', 'foreign', 'protected'):
        docker = Docker()
        values = {}
        if mode == 'shared': docker.shared = True
        if mode == 'foreign': docker.volumes['koda-sbom-dtrack-data']['Labels']['com.docker.compose.project'] = 'another-project'
        if mode == 'protected': values['DTRACK_DATA_VOLUME_NAME'] = 'koda-sbom-postgres-data'
        with pytest.raises(ValueError): module.Cleaner(values, runner=docker).resources()
        assert not docker.mutations


def test_foreign_container_and_failed_inventory_are_not_treated_as_absent():
    docker = Docker()
    docker.containers['spoof'] = container('dtrack-apiserver', 'spoof', project='foreign')
    # A foreign expected name is discovered by explicit inspect and refused.
    original = docker.__call__
    def run(command, **kwargs):
        if command[-1] == 'koda-sbom-dtrack-apiserver':
            return subprocess.CompletedProcess(command, 0, json.dumps([docker.containers['spoof']]), '')
        return original(command, **kwargs)
    with pytest.raises(ValueError): module.Cleaner({}, runner=run).resources()
    assert not docker.mutations
    def denied(command, **kwargs): return subprocess.CompletedProcess(command, 1, '', 'permission denied')
    with pytest.raises(ValueError): module.Cleaner({}, runner=denied).inspect('volume', 'anything')


def test_database_identity_ownership_and_sql_boundaries():
    docker = Docker()
    assert module.Cleaner({}, runner=docker).database()['databaseRemoved']
    statements = [text for args, text in docker.calls if text]
    assert 'DROP DATABASE %I' in statements[-1]
    assert 'DROP ROLE %I' in statements[-1]
    assert ':\'retired_db\'' in statements[-1]
    for values in ({'DTRACK_DB_NAME': 'sbom_tracker'}, {'DTRACK_DB_USER': 'postgres'}, {'DTRACK_DB_NAME': 'bad;DROP DATABASE sbom_tracker'}):
        with pytest.raises(ValueError): module.Cleaner(values, runner=Docker()).database()
    for state in ({'exists': True, 'owned': False, 'other': False}, {'exists': True, 'owned': True, 'other': True}):
        candidate = Docker(); candidate.db = state
        with pytest.raises(ValueError): module.Cleaner({}, runner=candidate).database()
        assert not candidate.mutations


def test_retired_files_and_settings_removed_native_files_retained(tmp_path):
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'scripts/configure-dtrack-key.sh').write_text('obsolete')
    (tmp_path / '.env').write_text('DTRACK_DB_NAME=old\nTRACKER_DEPENDENCY_TRACK_ENABLED=true\nTRACKER_DB_PASSWORD=keep-native-secret\n')
    (tmp_path / '.env').chmod(0o600)
    (tmp_path / 'images').mkdir()
    (tmp_path / 'images/dependencytrack_apiserver_5.0.3.tar').write_bytes(b'old')
    (tmp_path / 'images/postgres_16.tar').write_bytes(b'native')
    (tmp_path / 'sbom-original.json').write_text('keep-original')
    module.files(tmp_path, {})
    assert not (tmp_path / 'scripts/configure-dtrack-key.sh').exists()
    assert (tmp_path / '.env').read_text() == 'TRACKER_DB_PASSWORD=keep-native-secret\n'
    assert (tmp_path / '.env').stat().st_mode & 0o777 == 0o600
    assert list(path.name for path in (tmp_path / 'images').iterdir()) == ['postgres_16.tar']
    assert (tmp_path / 'sbom-original.json').read_text() == 'keep-original'


def test_install_verifies_release_then_cleans_before_loading_and_starting():
    script = (ROOT / 'scripts/install-airgap.sh').read_text()
    assert script.index('"$script_dir/verify-airgap-release.sh"') < script.index('--phase resources') < script.index('cp -a "$extracted_release/."')
    assert script.index('--phase files') < script.index('docker load')
    assert script.index('--phase database') < script.index('up -d --no-build --pull never --remove-orphans')


def test_leftover_configured_image_removed_but_shared_image_preserved():
    docker = Docker()
    docker.containers.pop('retired-api')
    docker.containers.pop('retired-web')
    docker.images['old-image']['Id'] = 'old-image'
    docker.images['legacy.example/apiserver:old'] = docker.images['old-image']
    docker.images['old-image']['RepoTags'].append('legacy.example/apiserver:old')
    result = module.Cleaner({'DTRACK_APISERVER_IMAGE': 'legacy.example/apiserver:old'}, runner=docker).resources()
    assert result['images'] == 1
    assert docker.images['old-image']['RepoTags'] == ['unrelated:keep']
    shared = Docker()
    shared.containers['foreign-user'] = container('other', 'foreign-user', project='another', image='old-image')
    module.Cleaner({}, runner=shared).resources()
    assert 'dependencytrack/apiserver:5.0.3' in shared.images['old-image']['RepoTags']
