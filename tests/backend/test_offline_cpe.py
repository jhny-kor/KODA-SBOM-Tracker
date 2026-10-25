from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from koda_tracker.cpe_analysis import enrich_cpe_findings
from koda_tracker.offline_cpe import evaluate, product_key
from koda_tracker.vulnerability import VulnerabilityContext, _nvd_details

APP = "cpe:2.3:a:acme:widget:1.2.0:*:*:*:*:*:*:*"
OS = "cpe:2.3:o:acme:server:8:*:*:*:*:*:*:*"


def tree():
    return [{"operator": "AND", "nodes": [
        {"cpeMatch": [{"criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "vulnerable": True, "versionEndExcluding": "2.0"}]},
        {"cpeMatch": [{"criteria": OS, "vulnerable": False}]},
    ]}]


def context(record):
    return VulnerabilityContext(None, {}, {"CVE-2026-12345": record}, {"CVE-2026-12345": {"dueDate": "2026-12-01"}}, {"nvd": {"dataAsOf": "2026-10-19"}})


def test_index_and_loader_preserve_complete_applicability(tmp_path):
    path = Path(__file__).parents[2] / "scripts/nvd-alias-index.py"
    spec = importlib.util.spec_from_file_location("nvd_index_cpe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    record = {"id": "CVE-2026-12345", "configurations": tree(), "weaknesses": [{"description": [{"value": "CWE-79"}]}]}
    source = tmp_path / "nvd.json"
    source.write_text(json.dumps({"vulnerabilities": [{"cve": record}]}))
    _, details, _ = module.build_metadata([source])
    reduced = _nvd_details({"vulnerabilities": details})
    assert reduced[record["id"]]["configurations"] == tree()
    assert reduced[record["id"]]["weaknesses"] == record["weaknesses"]
    assert evaluate(reduced[record["id"]]["configurations"], [APP]).status == "unknown"
    assert evaluate(reduced[record["id"]]["configurations"], [APP, OS]).status == "affected"
    assert details[record["id"]]["applicabilityFormat"] == "nvd-2.0-configurations-v1"


def test_cpe_matches_add_findings_and_retain_environment_and_kev_evidence():
    components = [{"name": "widget", "purl": "pkg:generic/widget@1.2.0", "version": "1.2.0", "cpe": APP}, {"name": "OS", "cpe": OS}]
    record = {"id": "CVE-2026-12345", "configurations": tree(), "cvss": {"cvssV3": {"baseScore": 9.8}}}
    findings, summary = enrich_cpe_findings(components, context(record), [])
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["kev"] is True
    assert findings[0]["sourceKind"] == "nvd_cpe"
    assert findings[0]["cpeEvidence"][0]["matchedCpes"] == [APP]
    assert summary["addedFindings"] == 1
    assert summary["inventoryComplete"] is False
    assert enrich_cpe_findings(components[:1], context(record), [])[1]["unknownCves"] == 1


def test_grype_matches_are_enriched_without_duplicate_or_severity_rewrite():
    components = [{"name": "widget", "version": "1.2.0", "cpe": APP}]
    record = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": APP, "vulnerable": True}]}]}]}
    original = [{"id": "GHSA-test", "canonicalId": "CVE-2026-12345", "component": "widget", "version": "1.2.0", "severity": "Medium", "fixedIn": ["2"]}]
    findings, summary = enrich_cpe_findings(components, context(record), original)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["fixedIn"] == ["2"]
    assert "cpeEvidence" not in original[0]
    assert summary["matchedExisting"] == 1


def test_legacy_metadata_invalid_identity_and_rejected_records_cannot_match():
    components = [{"name": "widget", "cpe": APP}]
    assert enrich_cpe_findings(components, context({"cpe": [APP]}), [])[0] == []
    rejected = {"vulnStatus": "Rejected", "configurations": [{"cpeMatch": [{"criteria": APP, "vulnerable": True}]}]}
    assert enrich_cpe_findings(components, context(rejected), [])[0] == []
    rows, summary = enrich_cpe_findings([{"cpe": "cpe:/a:acme:widget:1.2"}], context({}), [])
    assert rows == []
    assert summary["invalidCpes"] == 1
    assert summary["status"] == "not_evaluated"


def test_escaping_boundaries_unknowns_and_no_positive_evidence():
    escaped = r"cpe:2.3:a:acme:widget\:pro:1.2:*:*:*:*:*:*:*"
    assert product_key(escaped) == ("a", "acme", "widget:pro")
    assert evaluate(tree(), [APP.replace("1.2.0", "1.2rc1"), OS]).status == "unknown"
    assert evaluate(tree(), [APP.replace("1.2.0", "2.0"), OS]).status == "not_affected"
    assert evaluate(None, [APP]).status == "unknown"
    environment_only = [{"nodes": [{"cpeMatch": [{"criteria": OS, "vulnerable": False}]}]}]
    assert evaluate(environment_only, [OS]).status == "unknown"


def test_negated_missing_environment_is_unknown_unless_inventory_asserted_complete():
    conditions = tree()
    conditions[0]["nodes"][1]["negate"] = True
    assert evaluate(conditions, [APP]).status == "unknown"
    assert evaluate(conditions, [APP, OS]).status == "not_affected"
    assert evaluate(conditions, [APP], complete_inventory=True).status == "affected"


def test_truncated_and_malformed_index_records_prevent_false_complete_coverage():
    normal = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": APP, "vulnerable": True, "versionEndExcluding": "1"}]}]}]}
    deep = {"cpeMatch": [{"criteria": APP, "vulnerable": True}]}
    for _ in range(30):
        deep = {"nodes": [deep]}
    for conditions in ([deep], [{"operator": [], "cpeMatch": [{"criteria": APP, "vulnerable": True}]}],
                       [{"operator": "OR", "cpeMatch": [{"criteria": APP, "vulnerable": True}] * 4097}],
                       [{"nodes": "invalid"}]):
        value = context(normal)
        value.nvd["CVE-2026-54321"] = {"configurations": conditions}
        findings, summary = enrich_cpe_findings([{"name": "widget", "cpe": APP}], value, [])
        assert findings == []
        assert summary["unmatchedProducts"] == 0
        assert summary["status"] == "incomplete"
        assert summary["indexIncompleteCves"] == 1
        assert summary["unknownCves"] == 1
        assert summary["unresolved"][0]["id"] == "CVE-2026-54321"




def test_standard_tracker_analysis_runs_local_cpe_and_persists_evidence(tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from koda_tracker import services
    from koda_tracker.config import Settings
    from koda_tracker.db import Base
    from koda_tracker.models import Environment, JobState, Release, SbomRun, Service

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as db:
        service, environment = Service(slug="cpe", name="CPE"), Environment(slug="cpe", name="CPE")
        db.add_all([service, environment])
        db.flush()
        release = Release(service_id=service.id, environment_id=environment.id, version="1")
        db.add(release)
        db.flush()
        components = [{"name": "widget", "version": "1.2.0", "cpe": APP}, {"name": "server", "version": "8", "cpe": OS}]
        artifact = tmp_path / "bom.json"
        artifact.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components}))
        run = SbomRun(release_id=release.id, round_number=1, original_filename="bom.json", media_type="application/json", spec_version="1.6", sha256="a" * 64, size_bytes=artifact.stat().st_size, artifact_path=str(artifact), normalized_bom={"components": components})
        db.add(run)
        db.flush()
        settings = Settings(grype_db_dir=tmp_path / "data" / "grype-db", offline_mode=True)
        monkeypatch.setattr(services, "get_settings", lambda: settings)
        monkeypatch.setattr(services, "load_context", lambda _: context({"configurations": tree(), "cvss": {"cvssV3": {"baseScore": 9.8}}}))
        monkeypatch.setattr(services.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps({"matches": [], "descriptor": {"version": "test"}}), stderr=""))
        revision = services.analyze_offline(db, run)
        assert revision.state == JobState.COMPLETED
        assert len(revision.findings) == 1
        assert revision.findings[0]["canonicalId"] == "CVE-2026-12345"
        assert revision.findings[0]["cpeEvidence"][0]["cpe"] == APP
        assert revision.data_sources["cpeApplicability"]["addedFindings"] == 1
        db.commit()
        db.refresh(revision)
        assert revision.data_sources["cpeApplicability"]["version"] == "koda-offline-cpe-v1"
        assert revision.findings[0]["cpeEvidence"][0]["dataAsOf"] == "2026-10-19"
    engine.dispose()
