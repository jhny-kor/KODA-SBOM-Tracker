from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from koda_tracker import package_metadata as metadata
from koda_tracker.db import Base
from koda_tracker.models import RunComponent
from koda_tracker.package_metadata_models import PackageMetadataCache

AT = datetime(2026, 10, 18, tzinfo=UTC)


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(metadata, "setting", lambda name, default: {"enabled": True, "ttl_seconds": 3600, "min_interval_seconds": 0, "max_attempts": 3, "retry_seconds": 10}.get(name, default))
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        yield db
    engine.dispose()


def client(handler):
    return metadata.RegistryClient(httpx.MockTransport(handler))


def npm_payload():
    return {"dist-tags": {"latest": "2.0.0"}, "versions": {version: {} for version in ("1.0.0", "1.1.0", "2.0.0", "3.0.0-beta.1")},
            "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-01-01T00:00:00Z", "modified": "2099-01-01T00:00:00Z"}}


def test_npm_scoped_package_registry_dist_tag_and_release_specific_dates(db):
    target = metadata.parse_purl("pkg:npm/%40scope/library@1.0.0")
    requests = []
    def registry(request):
        requests.append(request)
        return httpx.Response(200, json=npm_payload())
    with client(registry) as http:
        result = metadata.fetch_metadata(target, http, at=AT)
    assert target.namespace == "@scope"
    assert str(requests[0].url).endswith("%40scope%2Flibrary")
    assert result["latestVersion"] == "2.0.0"
    assert result["versionDistance"] == 2
    assert result["latestPublishedAt"].startswith("2026-01-01")
    assert result["currentVersionPublishedAt"].startswith("2020-01-01")
    assert result["sourceKind"] == "public_registry"
    assert result["expiresAt"] == (AT + timedelta(hours=1)).isoformat()


def test_npm_prerelease_latest_tag_is_preserved_not_silently_called_stable(db):
    payload = npm_payload()
    payload["dist-tags"]["latest"] = "3.0.0-beta.1"
    with client(lambda _: httpx.Response(200, json=payload)) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:npm/library@1.0.0"), http, at=AT)
    assert result["latestVersion"] == "2.0.0"
    assert result["registryLatestVersion"] == "3.0.0-beta.1"
    assert result["registryLatestIsPrerelease"] is True
    assert result["latestIsPrerelease"] is False
    assert result["versionDistance"] == 2


def test_pypi_normalization_yanked_prerelease_and_earliest_distribution(db):
    def files(*dates, yanked=False):
        return [{"upload_time_iso_8601": date, "yanked": yanked} for date in dates]
    payload = {"info": {"version": "9.0rc1"}, "releases": {
        "1.0": files("2020-01-02T00:00:00Z", "2020-01-01T00:00:00Z"),
        "1.0.post1": files("2021-01-01T00:00:00Z"), "2.0": files("2025-01-01T00:00:00Z"),
        "3.0": files("2026-01-01T00:00:00Z", yanked=True), "9.0rc1": files("2026-02-01T00:00:00Z"), "99.0.dev1": files("2026-03-01T00:00:00Z")}}
    target = metadata.parse_purl("pkg:pypi/My_Package@1.0")
    with client(lambda _: httpx.Response(200, json=payload)) as http:
        result = metadata.fetch_metadata(target, http, at=AT)
    assert target.name == "my-package"
    assert result["latestVersion"] == "2.0"
    assert result["currentVersionPublishedAt"].startswith("2020-01-01")
    assert result["versionDistance"] == 2
    assert result["versionDistanceBasis"] == "pep440_final_post_release_count"


def test_maven_parent_last_updated_never_used_as_version_release_date(db):
    def registry(request):
        if request.url.host == "repo.maven.apache.org":
            return httpx.Response(200, content=b"<metadata><versioning><release>2.0</release><lastUpdated>20990101000000</lastUpdated></versioning></metadata>")
        query = request.url.params["q"]
        version = "1.0" if 'v:"1.0"' in query else "2.0"
        return httpx.Response(200, json={"response": {"docs": [{"g": "org.example", "a": "library", "v": version, "timestamp": 1577836800000 if version == "1.0" else 1735689600000}]}})
    with client(registry) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:maven/org.example/library@1.0"), http, at=AT)
    assert result["latestVersion"] == "2.0"
    assert result["currentVersionPublishedAt"].startswith("2020-01-01")
    assert result["latestPublishedAt"].startswith("2025-01-01")
    assert result["versionDistance"] is None
    assert len(result["sourceUrls"]) == 3


def test_maven_search_lag_is_explicit_missing_date_with_latest_retained(db):
    def registry(request):
        if request.url.host == "repo.maven.apache.org":
            return httpx.Response(200, content=b"<metadata><versioning><release>2.0</release></versioning></metadata>")
        return httpx.Response(200, json={"response": {"docs": []}})
    with client(registry) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:maven/org.example/library@1.0"), http, at=AT)
    assert result["latestVersion"] == "2.0"
    assert result["currentVersionPublishedAt"] is None
    assert result["fieldStatus"]["currentVersionPublishedAt"] == "unavailable"


def test_maven_missing_index_uses_labelled_version_artifact_timestamp_not_first_release(db):
    requests = []
    def registry(request):
        requests.append(request)
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Last-Modified": "Wed, 01 Jan 2020 00:00:00 GMT"})
        if request.url.host == "repo.maven.apache.org":
            return httpx.Response(200, content=b"<metadata><versioning><release>2.0</release><lastUpdated>20990101000000</lastUpdated></versioning></metadata>")
        return httpx.Response(200, json={"response": {"docs": []}})
    with client(registry) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:maven/org.example/library@1.0"), http, at=AT)
    assert result["currentVersionPublishedAt"].startswith("2020-01-01")
    assert result["currentVersionPublishedAtBasis"] == "artifact_last_modified"
    assert result["fieldStatus"]["currentVersionPublishedAt"] == "repository_timestamp"
    assert any("최초 공개일과 다를" in warning for warning in result["warnings"])
    assert [str(request.url) for request in requests if request.method == "HEAD"] == [
        "https://repo.maven.apache.org/maven2/org/example/library/1.0/library-1.0.pom",
        "https://repo.maven.apache.org/maven2/org/example/library/2.0/library-2.0.pom"]


def test_maven_release_metadata_prerelease_retains_tag_but_selects_numeric_stable(db):
    def registry(request):
        if request.url.host == "repo.maven.apache.org":
            return httpx.Response(200, content=b"<metadata><versioning><release>3.0-beta1</release><versions><version>2.9</version><version>2.10</version><version>3.0-beta1</version></versions></versioning></metadata>")
        return httpx.Response(200, json={"response": {"docs": []}})
    with client(registry) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:maven/org.example/library@1.0"), http, at=AT)
    assert result["latestVersion"] == "2.10"
    assert result["registryLatestVersion"] == "3.0-beta1"
    assert result["registryLatestIsPrerelease"] is True
    assert result["latestSelection"] == "maven_numeric_stable_subset"


def test_cargo_yanked_versions_excluded_from_latest_and_distance(db):
    payload = {"crate": {"max_stable_version": "9.0.0"}, "versions": [
        {"num": "1.0.0", "yanked": False, "created_at": "2020-01-01T00:00:00Z"},
        {"num": "2.0.0", "yanked": False, "created_at": "2025-01-01T00:00:00Z"},
        {"num": "9.0.0", "yanked": True, "created_at": "2026-01-01T00:00:00Z"}]}
    with client(lambda _: httpx.Response(200, json=payload)) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:cargo/example@1.0.0"), http, at=AT)
    assert result["latestVersion"] == "2.0.0"
    assert result["versionDistance"] == 1


def test_go_uppercase_escaping_and_no_retraction_unaware_distance(db):
    requests = []
    def registry(request):
        requests.append(str(request.url))
        return httpx.Response(200, json={"Version": "v2.0.0", "Time": "2025-01-01T00:00:00Z"} if request.url.path.endswith("@latest") else {"Version": "v1.0.0", "Time": "2020-01-01T00:00:00Z"})
    with client(registry) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:golang/github.com/Azure/example@v1.0.0"), http, at=AT)
    assert "github.com/!azure/example/@latest" in requests[0]
    assert result["latestVersion"] == "v2.0.0"
    assert result["versionDistance"] is None


def test_nuget_unlisted_and_prerelease_ignored(db):
    def entry(version, listed=True):
        return {"catalogEntry": {"version": version, "listed": listed, "published": "2025-01-01T00:00:00Z"}}
    with client(lambda _: httpx.Response(200, json={"items": [{"items": [entry("1.0.0"), entry("2.0.0"), entry("3.0.0", False), entry("4.0.0-beta")]}]})) as http:
        result = metadata.fetch_metadata(metadata.parse_purl("pkg:nuget/Newtonsoft.Json@1.0.0"), http, at=AT)
    assert result["latestVersion"] == "2.0.0"
    assert result["versionDistance"] == 1


@pytest.mark.parametrize("purl", ["https://internal.local/a", "pkg:npm/../library@1.0.0", "pkg:npm/lib@1.0.0?repository_url=https://internal", "pkg:maven/group/artifact", "pkg:npm/%40bad/scope/name@1.0.0"])
def test_invalid_or_custom_registry_purls_rejected_without_io(purl):
    with pytest.raises(ValueError):
        metadata.parse_purl(purl)


def test_fixed_registry_hosts_no_redirects_and_bounded_response(db, monkeypatch):
    requests = []
    def registry(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "http://127.0.0.1/secret"})
    with client(registry) as http:
        with pytest.raises(metadata.RegistryError):
            http.get("http://registry.npmjs.org/library")
        with pytest.raises(metadata.RegistryError):
            http.get("https://127.0.0.1/library")
        assert not requests
        with pytest.raises(metadata.RegistryError, match="302"):
            http.get("https://registry.npmjs.org/library")
        assert len(requests) == 1
    monkeypatch.setattr(metadata, "MAX_RESPONSE_BYTES", 10)
    with client(lambda _: httpx.Response(200, content=b"x" * 11)) as http:
        with pytest.raises(metadata.RegistryError, match="크기"):
            http.get("https://registry.npmjs.org/library")


def test_upload_queue_cache_ttl_and_offline_enrichment_are_separate(db, monkeypatch):
    components = [{"name": "library", "version": "1.0.0", "purl": "pkg:npm/library@1.0.0"}, {"name": "unsupported", "purl": "pkg:deb/debian/lib@1.0"}, {"name": "no-purl"}]
    original = copy.deepcopy(components)
    counts = metadata.enqueue_components(db, components, at=AT)
    assert counts["queued"] == counts["unsupported"] == counts["invalid"] == 1
    with client(lambda _: httpx.Response(200, json=npm_payload())) as http:
        assert metadata.collect_one(db, http, at=AT)
    monkeypatch.setattr(metadata, "RegistryClient", lambda: pytest.fail("enrichment must not use network"))
    fresh = metadata.enrich_components(db, components, at=AT + timedelta(minutes=1))
    assert components == original
    assert [item["metadataStatus"] for item in fresh] == ["fresh", "unsupported", "invalid"]
    properties = {item["name"]: item["value"] for item in fresh[0]["properties"]}
    assert properties["koda:latestVersion"] == "2.0.0"
    assert properties["koda:versionDistance"] == "2"
    stale = metadata.enrich_components(db, components, at=AT + timedelta(hours=2))
    assert stale[0]["metadataStatus"] == "stale"
    assert "properties" not in stale[0]
    assert stale[0]["packageMetadata"]["latestVersion"] == "2.0.0"
    assert metadata.metadata_summary(fresh)["fresh"] == 1
    assert metadata.enqueue_components(db, components, at=AT + timedelta(hours=2))["queued"] == 1


def test_rate_limit_retry_is_bounded_and_keeps_explicit_error(db):
    metadata.enqueue_components(db, [{"purl": "pkg:npm/library@1.0.0"}], at=AT)
    target = metadata.parse_purl("pkg:npm/library@1.0.0")
    with client(lambda _: httpx.Response(429, headers={"Retry-After": "20"})) as http:
        assert metadata.collect_one(db, http, at=AT)
        row = db.get(PackageMetadataCache, target.id)
        assert row.state == "failed" and row.attempts == 1
        assert metadata.utc(row.next_attempt_at) == AT + timedelta(seconds=20)
        assert not metadata.collect_one(db, http, at=AT + timedelta(seconds=19))
        assert metadata.collect_one(db, http, at=AT + timedelta(seconds=20))
        assert metadata.collect_one(db, http, at=AT + timedelta(seconds=40))
        assert row.attempts == 3 and row.next_attempt_at is None
        assert metadata.metadata_payload(row, at=AT)["status"] == "error"
        assert "429" in row.error


def test_malformed_registry_response_is_terminal_not_an_infinite_worker_loop(db):
    metadata.enqueue_components(db, [{"purl": "pkg:npm/library@1.0.0"}], at=AT)
    with client(lambda _: httpx.Response(200, json=["not-a-package-object"])) as http:
        assert metadata.collect_one(db, http, at=AT)
        row = db.get(PackageMetadataCache, metadata.parse_purl("pkg:npm/library@1.0.0").id)
        assert row.state == "failed"
        assert row.attempts == 3
        assert "형식" in row.error
        assert not metadata.collect_one(db, http, at=AT)


def test_offline_import_is_labelled_and_never_replaces_newer_observation(db, monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from koda_tracker import package_metadata_api as api

    monkeypatch.setattr(api, "setting", metadata.setting)
    observed = datetime.now(UTC) - timedelta(minutes=10)
    metadata.enqueue_components(db, [{"purl": "pkg:npm/library@1.0.0"}], at=observed)
    with client(lambda _: httpx.Response(200, json=npm_payload())) as http:
        metadata.collect_one(db, http, at=observed)
    row = db.get(PackageMetadataCache, metadata.parse_purl("pkg:npm/library@1.0.0").id)
    item = metadata.metadata_payload(row, at=observed)
    body = api.ImportRequest(format="koda-package-metadata-v1", exportedAt=observed.isoformat(), items=[item])
    assert api.import_metadata(body, db, SimpleNamespace(username="admin"))["imported"] == 1
    assert row.document["sourceKind"] == "offline_import"
    older = {**item, "fetchedAt": (observed - timedelta(minutes=1)).isoformat()}
    assert api.import_metadata(api.ImportRequest(format=body.format, exportedAt=body.exportedAt, items=[older]), db, SimpleNamespace(username="admin"))["skipped"] == 1
    unsafe = {**item, "sourceUrls": ["https://registry.npmjs.org:9443/library"]}
    with pytest.raises(HTTPException) as error:
        api.import_metadata(api.ImportRequest(format=body.format, exportedAt=body.exportedAt, items=[unsafe]), db, SimpleNamespace(username="admin"))
    assert error.value.status_code == 422


def test_backfill_existing_components_is_bounded_and_idempotent(db):
    for index in range(3):
        db.add(RunComponent(run_id="test", identity_key=f"key-{index}", name=f"library-{index}", version="1.0.0", purl=f"pkg:npm/library-{index}@1.0.0"))
    db.flush()
    assert metadata.backfill_components(db, batch=2) == 2
    assert metadata.backfill_components(db, batch=2) == 1
    assert metadata.backfill_components(db, batch=2) == 0
    assert metadata.backfill_components(db, batch=2) == 2
    assert len(list(db.scalars(select(PackageMetadataCache)))) == 3
