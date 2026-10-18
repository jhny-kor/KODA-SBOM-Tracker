from __future__ import annotations

from datetime import UTC, datetime
import httpx
import pytest
from koda_tracker import package_metadata as metadata

SERVICE_INDEX = 'https://api.nuget.org/v3/index.json'
BASE = 'https://api.nuget.org/v3/registration5-gz-semver2/'
AT = datetime(2026, 10, 18, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    monkeypatch.setattr(metadata, 'setting', lambda name, default: 0 if name == 'min_interval_seconds' else default)


def entry(version, *, listed=True, published='2025-01-01T00:00:00Z', package='example'):
    return {'catalogEntry': {'id': package, 'version': version, 'listed': listed, 'published': published}}


def service_index(base=BASE):
    return {'resources': [
        {'@id': 'https://api.nuget.org/v3/registration5-semver1/', '@type': 'RegistrationsBaseUrl/3.4.0'},
        {'@id': base, '@type': 'RegistrationsBaseUrl/3.6.0'},
    ]}


def fetch(handler, version='1.0.0'):
    with metadata.RegistryClient(httpx.MockTransport(handler)) as client:
        return metadata.fetch_metadata(metadata.parse_purl('pkg:nuget/Example@' + version), client, at=AT)


def test_service_index_selects_semver2_and_keeps_build_release():
    requested = []
    def registry(request):
        requested.append(str(request.url))
        if str(request.url) == SERVICE_INDEX:
            return httpx.Response(200, json=service_index())
        assert str(request.url) == BASE + 'example/index.json'
        return httpx.Response(200, json={'count': 1, 'items': [{'count': 2, 'items': [entry('1.0.0'), entry('2.0.0+build.1')]}]})
    result = fetch(registry, '01.0.0+local.hash')
    assert requested[0] == SERVICE_INDEX
    assert all('semver1' not in url for url in requested)
    assert result['latestVersion'] == '2.0.0+build.1'
    assert result['currentVersionPublishedAt'] == '2025-01-01T00:00:00+00:00'
    assert result['versionDistance'] == 1
    assert result['currentVersionMissing'] is False


def test_nine_external_registration_pages_are_fully_collected():
    requested = []
    def registry(request):
        url = str(request.url); requested.append(url)
        if url == SERVICE_INDEX:
            return httpx.Response(200, json=service_index())
        if url.endswith('/index.json'):
            return httpx.Response(200, json={'count': 9, 'items': [{'@id': BASE + f'example/page/{i}.json', 'count': 64} for i in range(9)]})
        page = int(request.url.path.rsplit('/', 1)[-1].split('.')[0])
        return httpx.Response(200, json={'count': 64, 'items': [entry(f'1.0.{page * 64 + i}') for i in range(64)]})
    result = fetch(registry)
    assert result['latestVersion'] == '1.0.575'
    assert result['versionDistance'] == 575
    assert len(requested) == 11
    assert len(result['sourceUrls']) == 11


def test_current_semver2_prerelease_is_matched_case_insensitively_but_latest_stays_stable():
    records = [entry('1.0.0'), entry('2.0.0-beta.10', published='2024-01-01T00:00:00Z'),
               entry('2.0.0'), entry('3.0.0+build.1'), entry('4.0.0-rc.1'), entry('9.0.0', listed=False)]
    def registry(request):
        return httpx.Response(200, json=service_index() if str(request.url) == SERVICE_INDEX else {'items': [{'items': records}]})
    result = fetch(registry, '2.0.0-BETA.10+local')
    assert result['latestVersion'] == '3.0.0+build.1'
    assert result['latestIsPrerelease'] is False
    assert result['currentVersionPublishedAt'].startswith('2024-01-01')
    assert result['versionDistance'] == 2
    assert result['currentVersionMissing'] is False


def test_current_missing_registration_is_explicit():
    def registry(request):
        return httpx.Response(200, json=service_index() if str(request.url) == SERVICE_INDEX else {'items': [{'items': [entry('2.0.0')]}]})
    result = fetch(registry)
    assert result['currentVersionMissing'] is True
    assert result['currentVersionPublishedAt'] is None


@pytest.mark.parametrize('resource', [
    {'resources': []},
    service_index('https://evil.invalid/registration/'),
    service_index('https://registry.npmjs.org/registration/'),
])
def test_missing_or_untrusted_semver2_discovery_fails_without_fallback(resource):
    requested = []
    def registry(request):
        requested.append(str(request.url))
        return httpx.Response(200, json=resource)
    with pytest.raises(metadata.RegistryError):
        fetch(registry)
    assert requested == [SERVICE_INDEX]


@pytest.mark.parametrize('page', [
    {'@id': 'https://evil.invalid/page'},
    {'@id': BASE + 'another-package/page/1.json'},
    {'count': 2, 'items': [entry('1.0.0')]},
    {'items': [entry('1.0.0', package='other')]},
])
def test_partial_wrong_package_or_unsafe_registration_cannot_report_success(page):
    def registry(request):
        return httpx.Response(200, json=service_index() if str(request.url) == SERVICE_INDEX else {'count': 1, 'items': [page]})
    with pytest.raises(metadata.RegistryError):
        fetch(registry)


def test_missing_external_page_is_a_failure_not_a_partial_latest():
    def registry(request):
        if str(request.url) == SERVICE_INDEX:
            return httpx.Response(200, json=service_index())
        if str(request.url).endswith('/index.json'):
            return httpx.Response(200, json={'items': [{'items': [entry('1.0.0')]}, {'@id': BASE + 'example/page/missing.json'}]})
        return httpx.Response(503)
    with pytest.raises(metadata.RegistryError):
        fetch(registry)


def test_cache_upgrade_requeues_legacy_failures_and_successes_preserving_offline_evidence():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from koda_tracker.db import Base
    from koda_tracker.package_metadata_models import PackageMetadataCache
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        rows = []
        for name, state, document in [
            ('legacy-success', 'completed', {'latestVersion':'1.0.0', 'sourceKind':'public_registry'}),
            ('legacy-failure', 'failed', {}),
            ('current-success', 'completed', {'nugetRegistrationApi':'RegistrationsBaseUrl/3.6.0'}),
            ('offline', 'completed', {'latestVersion':'2.0.0', 'sourceKind':'offline_import'}),
            ('pending', 'queued', {}),
        ]:
            row = PackageMetadataCache(id=name, package_key='nuget/'+name, current_version='1.0.0', purl='pkg:nuget/'+name+'@1.0.0', ecosystem='nuget', state=state, document=document, attempts=3, next_attempt_at=None, error='NuGet registry 페이지 한도 초과' if state=='failed' else None, fetched_at=AT if state=='completed' else None)
            db.add(row); rows.append(row)
        db.flush()
        assert metadata.requeue_legacy_nuget_metadata(db, at=AT) == 2
        assert metadata.requeue_legacy_nuget_metadata(db, at=AT) == 0
        assert rows[0].document['latestVersion'] == '1.0.0'
        assert metadata.metadata_payload(rows[0], at=AT)['status'] == 'stale'
        assert rows[1].state == 'queued' and rows[1].attempts == 0 and rows[1].next_attempt_at == AT
        assert rows[1].document['nugetCollectorUpgrade']['previousError'] == 'NuGet registry 페이지 한도 초과'
        assert rows[2].state == 'completed' and rows[3].document == {'latestVersion':'2.0.0','sourceKind':'offline_import'}
    engine.dispose()


def test_registration_safety_bounds_fail_instead_of_publishing_partial_results(monkeypatch):
    monkeypatch.setattr(metadata, 'MAX_NUGET_PAGES', 1)
    def registry(request):
        return httpx.Response(200, json=service_index() if str(request.url)==SERVICE_INDEX else {'items':[{'items':[entry('1.0.0')]},{'items':[entry('2.0.0')]}]})
    with pytest.raises(metadata.RegistryError, match='안전 한도'):
        fetch(registry)
