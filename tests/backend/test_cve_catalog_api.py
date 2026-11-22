from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from koda_tracker import cve_catalog_api as catalog
from koda_tracker.data_updates import DataUpdateError
from koda_tracker.db import Base, get_db
from koda_tracker.models import AnalysisRevision, ApiToken, Environment, JobState, ProcessingState, Release, Role, RolePolicy, SbomRun, Service, User
from koda_tracker.environment_admin_models import EnvironmentAdministrator
from koda_tracker.security import current_principal
from koda_tracker.vulnerability import _nvd_details

CVE = "CVE-2026-10001"
CPE = "cpe:2.3:a:vendor:sample-json:*:*:*:*:*:*:*:*"


def record(**overrides):
    value = {"id": CVE, "description": "Local catalog example", "published": "2026-10-25", "lastModified": "2026-10-29", "cvss": {"cvssV3": {"baseScore": 8.1}}, "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"criteria": CPE, "vulnerable": True, "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.4.2"}]}]}], "references": ["https://example.test/advisory", "javascript:alert(1)", "https://user:password@example.test/private"]}
    value.update(overrides)
    return value


@pytest.fixture
def context(tmp_path, monkeypatch):
    catalog._search_index.cache_clear()
    root = tmp_path / "vuln-data"
    release = root / "releases" / "one"
    release.mkdir(parents=True)
    (release / "metadata.env").write_text("BUNDLE_VERSION=one\nDATASET_DATE=2026-10-29\nNVD_INDEX=nvd.json\n")
    (release / "manifest.sha256").write_text("fixture manifest\n")
    (root / "current").symlink_to(release, target_is_directory=True)
    data = release / "nvd.json"
    data.write_text(json.dumps({"vulnerabilities": {CVE: record()}}))
    monkeypatch.setattr(catalog, "get_settings", lambda: SimpleNamespace(grype_db_dir=root / "current" / "grype-db", offline_mode=False, data_update_spool_dir=tmp_path / "index-spool"))
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        user = User(id="reader", username="reader", password_hash="unused", role=Role.VIEWER, active=True)
        policy = RolePolicy(role=Role.VIEWER, permissions=["metadata.view", "runs.view"])
        db.add_all([user, policy]); db.commit()
        auth = {"principal": user}
        app = FastAPI(); app.include_router(catalog.router)
        app.dependency_overrides[current_principal] = lambda: auth["principal"]
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            yield SimpleNamespace(client=client, root=root, release=release, data=data, auth=auth, db=db, policy=policy)
    engine.dispose(); catalog._search_index.cache_clear()


def test_product_version_range_is_numeric_and_exclusive(context):
    base = "/api/v1/cve-catalog?product=sample-json&version="
    result = context.client.get(base + "1.4.1")
    assert result.status_code == 200
    assert result.json()["items"][0]["versionMatch"] == "match"
    assert context.client.get(base + "1.4.2").json()["total"] == 0
    assert context.client.get(base + "1.10.0").json()["total"] == 0
    # Vendor-specific nonnumeric ordering is not guessed or discarded as safe.
    unknown = context.client.get(base + "1.4.1-vendor")
    assert unknown.json()["items"][0]["versionMatch"] == "unknown"


def test_and_environment_condition_stays_unknown_and_raw_conditions_preserved(context):
    value = record()
    value["configurations"] = [{"operator": "AND", "nodes": [value["configurations"][0]["nodes"][0], {"operator": "OR", "cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:o:vendor:os:10:*:*:*:*:*:*:*"}]}]}]
    context.data.write_text(json.dumps({"vulnerabilities": {CVE: value}}))
    result = context.client.get("/api/v1/cve-catalog?product=sample-json&version=1.4.0").json()
    assert result["items"][0]["versionMatch"] == "unknown"
    detail = context.client.get(f"/api/v1/cve-catalog/{CVE}").json()
    assert detail["configurations"] == value["configurations"]
    assert detail["products"][1]["condition"] == "환경 선행조건"
    assert detail["references"] == ["https://example.test/advisory"]


def test_issuing_cna_status_version_scheme_and_runtime_preservation(context):
    affected = [{"vendor": "Issuer", "product": "issued-product", "defaultStatus": "unaffected", "versions": [{"version": "1.0.0", "lessThan": "2.0.0", "status": "affected", "versionType": "semver"}, {"version": "2.0.0", "status": "unaffected"}]}]
    value = record(affected=affected)
    context.data.write_text(json.dumps({"vulnerabilities": [{"cve": value}]}))
    assert _nvd_details({"vulnerabilities": [{"cve": value}]})[CVE]["affected"] == affected
    result = context.client.get("/api/v1/cve-catalog?product=issued-product&version=1.9.0").json()
    assert result["total"] == 1 and result["items"][0]["versionMatch"] == "match"
    assert context.client.get("/api/v1/cve-catalog?product=issued-product&version=2.0.0").json()["total"] == 0
    assert context.client.get(f"/api/v1/cve-catalog/{CVE}").json()["affected"] == affected
    affected[0]["versions"][0]["versionType"] = "custom"
    assert catalog._cna_version(affected[0], "1.9.0") == "unknown"


def test_missing_or_invalid_active_data_is_unavailable_not_empty(context, monkeypatch):
    (context.root / "current").unlink()
    response = context.client.get("/api/v1/cve-catalog")
    assert response.status_code == 503 and "활성" in response.json()["detail"]
    assert catalog._search_index.cache_info().currsize == 0
    (context.root / "current").symlink_to(context.release, target_is_directory=True)
    monkeypatch.setattr(catalog, "assert_approved_release", lambda *_: (_ for _ in ()).throw(DataUpdateError("서명 검증 실패")))
    response = context.client.get("/api/v1/cve-catalog")
    assert response.status_code == 503 and "서명" in response.json()["detail"]


def test_cache_rechecks_file_identity_and_never_serves_purged_state(context):
    first = context.client.get("/api/v1/cve-catalog").json()
    assert first["total"] == 1
    context.client.get("/api/v1/cve-catalog")
    assert catalog._search_index.cache_info().hits >= 1
    context.data.write_text(json.dumps({"vulnerabilities": {}}))
    assert context.client.get("/api/v1/cve-catalog").json()["total"] == 0
    (context.root / ".managed.json").write_text('{"state":"purged"}')
    assert context.client.get("/api/v1/cve-catalog").status_code == 503
    assert catalog._search_index.cache_info().currsize == 0


def test_catalog_permission_and_service_token_do_not_leak_observations(context):
    context.policy.permissions = ["metadata.view"]; context.db.commit()
    detail = context.client.get(f"/api/v1/cve-catalog/{CVE}")
    assert detail.status_code == 200
    assert detail.json()["observations"]["available"] is False
    context.policy.permissions = ["dashboard.view"]; context.db.commit()
    assert context.client.get("/api/v1/cve-catalog").status_code == 403
    context.auth["principal"] = ApiToken(id="token", service_id="private-service", name="token", token_hash="x", active=True)
    assert context.client.get("/api/v1/cve-catalog").status_code == 403
    assert context.client.get(f"/api/v1/cve-catalog/{CVE}").status_code == 403


def test_details_not_found_validation_and_empty_page(context):
    assert context.client.get("/api/v1/cve-catalog/invalid").status_code == 422
    assert context.client.get("/api/v1/cve-catalog/CVE-2026-99999").status_code == 404
    response = context.client.get("/api/v1/cve-catalog?page=2&size=1").json()
    assert response["total"] == 1 and response["items"] == []


def test_internal_evidence_uses_latest_saved_analysis_per_release(context):
    service = Service(id="service", slug="service", name="결제 API")
    environment = Environment(id="environment", slug="prod", name="운영")
    release = Release(id="release", service_id=service.id, environment_id=environment.id, version="2026.10.1")
    context.db.add_all([service, environment, release]); context.db.flush()
    context.db.add(EnvironmentAdministrator(environment_id=environment.id, user_id="reader", assigned_by="admin"))
    for number, version in ((1, "1.0.0"), (2, "1.4.0")):
        run = SbomRun(id=f"run-{number}", release_id=release.id, round_number=number, state=ProcessingState.COMPLETED, analysis_state=JobState.COMPLETED, original_filename="input.json", media_type="application/json", spec_version="1.6", sha256="a" * 64, size_bytes=2, artifact_path="/test/input.json", normalized_bom={})
        context.db.add(run); context.db.flush()
        context.db.add(AnalysisRevision(id=f"analysis-{number}", run_id=run.id, sequence=1, state=JobState.COMPLETED, findings=[{"id": CVE, "component": "sample-json", "version": version}], data_as_of="2026-10-29"))
        if number == 2:
            context.db.add(AnalysisRevision(id="old-analysis", run_id=run.id, sequence=0, state=JobState.COMPLETED, findings=[{"id": CVE, "component": "sample-json", "version": "OLD"}], data_as_of="2025-01-01"))
    context.db.commit()
    statements = []
    def capture(_connection, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())
    event.listen(context.db.get_bind(), "before_cursor_execute", capture)
    try:
        result = context.client.get(f"/api/v1/cve-catalog/{CVE}").json()
    finally:
        event.remove(context.db.get_bind(), "before_cursor_execute", capture)
    evidence = result["observations"]["items"]
    assert len(evidence) == 1
    assert evidence[0]["runId"] == "run-2" and evidence[0]["version"] == "1.4.0"
    assert evidence[0]["release"] == "2026.10.1" and evidence[0]["environment"] == "운영"
    assert not any("normalized_bom" in statement for statement in statements)
    assert not any("analysis_revisions.policies" in statement for statement in statements)


def test_search_returns_product_paired_with_its_own_range(context):
    affected = [{"source": "issuer@example.test", "affectedData": [
        {"vendor": "Vendor", "product": "alpha", "defaultStatus": "unaffected", "versions": [{"version": "1.0.0", "lessThan": "2.0.0", "status": "affected", "versionType": "semver"}]},
        {"vendor": "Vendor", "product": "beta", "defaultStatus": "unaffected", "versions": [{"version": "3.0.0", "lessThan": "4.0.0", "status": "affected", "versionType": "semver"}]},
    ]}]
    context.data.write_text(json.dumps({"vulnerabilities": {CVE: record(affected=affected)}}))
    result = context.client.get("/api/v1/cve-catalog?product=beta&version=3.5.0").json()
    assert result["total"] == 1
    assert [product["product"] for product in result["items"][0]["matchedProducts"]] == ["beta"]
    assert result["items"][0]["matchedProducts"][0]["ranges"][0]["label"] == "3.0.0 이상 · 4.0.0 미만"


def test_malformed_optional_containers_do_not_crash_catalog(context):
    context.data.write_text(json.dumps({"vulnerabilities": {CVE: record(containers=["bad"])}}))
    response = context.client.get("/api/v1/cve-catalog")
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_compact_builder_keeps_affected_original_without_alias_side_effects(tmp_path):
    path = Path(__file__).parents[2] / "scripts" / "nvd-alias-index.py"
    spec = importlib.util.spec_from_file_location("catalog_nvd_builder", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    affected = [{"vendor": "Vendor", "product": "Product", "versions": [{"version": "1", "lessThan": "2", "status": "affected", "versionType": "semver"}]}]
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"vulnerabilities": [{"cve": record(affected=affected)}]}))
    aliases, details, count = module.build_metadata([feed])
    assert details[CVE]["affected"] == affected and count == 1 and aliases[CVE] == CVE


def test_official_nvd_affected_data_envelopes_keep_contributor_attribution(context, tmp_path):
    # NVD cve_api_json_2.0.schema definitions.affected requires source and
    # affectedData; its product records follow cve_affected_1.0.json.
    affected = [
        {"source": "issuer@example.test", "affectedData": [{"vendor": "Issuer", "product": "official-product", "defaultStatus": "unaffected", "versions": [{"version": "1.0.0", "lessThan": "1.4.2", "versionType": "semver", "status": "affected"}]}]},
        {"source": "additional-provider@example.test", "affectedData": [{"vendor": "Issuer", "product": "official-product", "defaultStatus": "unknown", "versions": [{"version": "1.4.2", "status": "unaffected"}]}]},
    ]
    path = Path(__file__).parents[2] / "scripts" / "nvd-alias-index.py"
    spec = importlib.util.spec_from_file_location("official_nvd_builder", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    feed = tmp_path / "official-feed.json"
    feed.write_text(json.dumps({"vulnerabilities": [{"cve": record(affected=affected, sourceIdentifier="original-assigner@example.test")}]}))
    _, details, _ = module.build_metadata([feed])
    assert details[CVE]["affected"] == affected
    assert details[CVE]["sourceIdentifier"] == "original-assigner@example.test"
    context.data.write_text(json.dumps({"vulnerabilities": details}))
    response = context.client.get("/api/v1/cve-catalog?product=official-product&version=1.4.0").json()
    assert response["total"] == 1 and response["items"][0]["versionMatch"] == "match"
    products = [product for product in response["items"][0]["products"] if product["source"] == "cna"]
    assert len(products) == 2
    assert [product["sourceIdentifier"] for product in products] == ["issuer@example.test", "additional-provider@example.test"]
    assert products[0]["ranges"][0]["label"] == "1.0.0 이상 · 1.4.2 미만"
    assert products[1]["ranges"][0]["status"] == "unaffected"
    detail = context.client.get(f"/api/v1/cve-catalog/{CVE}").json()
    assert detail["affected"] == affected


def test_large_page_window_keeps_sorted_deduplicated_ids_and_exact_total(context):
    values = [record(id=f"CVE-2020-{10000+n}") for n in reversed(range(70))]
    values += [record(id="CVE-2020-10004", description="last duplicate")]
    context.data.write_text(json.dumps({"vulnerabilities": values}))
    result = context.client.get("/api/v1/cve-catalog?page=3&size=7").json()
    assert result["total"] == 70
    assert [r["id"] for r in result["items"]] == [f"CVE-2020-{10000+n}" for n in range(14, 21)]
    assert context.client.get("/api/v1/cve-catalog?page=1000000000&size=100").json()["items"] == []
    detail = context.client.get("/api/v1/cve-catalog/CVE-2020-10004").json()
    assert detail["description"] == "last duplicate"


def test_tampered_disposable_index_fails_closed_then_rebuilds_signed_source(context):
    assert context.client.get("/api/v1/cve-catalog").status_code == 200
    stat = context.data.stat()
    identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    from koda_tracker.vulnerability import active_bundle
    bundle = active_bundle(catalog.get_settings())
    index = catalog._search_index(str(context.data), identity, bundle.manifest_sha256)
    index.path.chmod(0o600)
    import sqlite3
    with sqlite3.connect(index.path) as db:
        db.execute("DELETE FROM records")
    index.path.chmod(0o400)
    assert context.client.get("/api/v1/cve-catalog").status_code == 503
    rebuilt = context.client.get("/api/v1/cve-catalog")
    assert rebuilt.status_code == 200 and rebuilt.json()["total"] == 1


def test_source_change_while_index_is_built_never_returns_unapproved_rows(context, monkeypatch):
    original = catalog._search_index

    def mutate(*args):
        context.data.write_text(json.dumps({"vulnerabilities": {CVE: record(description="unapproved replacement")}}))
        return original(*args)

    monkeypatch.setattr(catalog, "_search_index", mutate)
    mutate.cache_clear = original.cache_clear
    response = context.client.get("/api/v1/cve-catalog")
    assert response.status_code == 503
    assert "변경" in response.json()["detail"]


def test_approval_is_checked_again_before_returning_cached_results(context, monkeypatch):
    calls = []

    def approval(*args):
        calls.append(1)
        if len(calls) == 2:
            raise DataUpdateError("approval changed during lookup")

    monkeypatch.setattr(catalog, "assert_approved_release", approval)
    response = context.client.get("/api/v1/cve-catalog")
    assert response.status_code == 503
    assert "approval changed" in response.json()["detail"]


def test_catalog_only_expands_the_page_and_exact_identifier(context, monkeypatch):
    values = [record(id=f"CVE-2020-{10000 + n}", description="shared keyword") for n in range(120)]
    values[-1]["description"] += " references CVE-2020-10000"
    context.data.write_text(json.dumps({"vulnerabilities": values}))
    original = catalog.products_for
    expanded = []

    def count(record):
        expanded.append(record["id"])
        return original(record)

    monkeypatch.setattr(catalog, "products_for", count)
    result = context.client.get("/api/v1/cve-catalog?q=shared%20keyword&page=4&size=3").json()
    assert result["total"] == 120
    assert expanded == ["CVE-2020-10009", "CVE-2020-10010", "CVE-2020-10011"]
    expanded.clear()
    exact = context.client.get("/api/v1/cve-catalog?q=cve-2020-10000").json()
    assert exact["total"] == 1 and expanded == ["CVE-2020-10000"]
