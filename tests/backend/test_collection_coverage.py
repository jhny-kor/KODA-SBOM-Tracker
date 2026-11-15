import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

from koda_tracker.collection_coverage import KEY, SPDX_ROOT_KEY, coverage_for_bom
from koda_tracker.db import SessionLocal
from koda_tracker.main import app
from koda_tracker.models import Job, SbomRun
from koda_tracker.sbom import parse_sbom
from koda_tracker.services import analyze_offline
from koda_tracker.vulnerability import VulnerabilityContext


def claim(**changes):
    return {
        "status": "partial", "sourceType": "filesystem", "componentCount": 2,
        "excludedDirectoryCount": 1, "excludedPatternCount": 2,
        "issueCounts": [{"code": "static_js_identity_unconfirmed", "count": 1}],
        **changes,
    }


def cdx(raw):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"properties": [{"name": KEY, "value": raw}]},
            "components": [{"type": "application", "name": "app", "components": [
                {"type": "library", "name": "library"},
            ]}]}


def test_nested_cyclonedx_count_and_missing_legacy_metadata():
    evidence, source = coverage_for_bom(cdx(json.dumps(claim())))
    assert evidence == {"collectionCoverage": claim()} and source is None
    assert coverage_for_bom({"components": [{"name": "old"}]}) == ({}, None)


@pytest.mark.parametrize("raw", [
    "{",
    "[" * 3000 + "]" * 3000,
    " " * 16385,
    json.dumps(claim(componentCount=3)),
    json.dumps(claim(componentCount=True)),
    json.dumps(claim(sourceType=[])),
    json.dumps(claim(excludedDirectories=["/private/location"])),
    json.dumps(claim(issueCounts=[{"code": "a", "count": 1}, {"code": "a", "count": 2}])),
    json.dumps(claim(issueCounts=[{"code": "C:/sensitive", "count": 1}])),
    json.dumps(claim()).replace('"status":', '"status":"completed","status":'),
])
def test_untrusted_claims_are_not_used_for_counts(raw):
    assert coverage_for_bom(cdx(raw)) == ({"collectionCoverageState": "invalid"}, None)


def test_duplicate_coverage_property_is_ambiguous():
    bom = cdx(json.dumps(claim()))
    bom["metadata"]["properties"] *= 2
    assert coverage_for_bom(bom) == ({"collectionCoverageState": "invalid"}, None)


def with_koda_distro(coverage=None, *, distro_id="ol", version="8.2"):
    reference = f"os:{distro_id}@{version}" if version else f"os:{distro_id}"
    distro = {
        "bom-ref": reference, "type": "operating-system", "name": distro_id,
        "cpe": "cpe:2.3:o:oracle:linux:8:2:server:*:*:*:*:*",
        "swid": {"tagId": distro_id, "name": distro_id},
        "properties": [{"name": "syft:distro:id", "value": distro_id}],
    }
    if version:
        distro["version"] = version
        distro["swid"]["version"] = version
        distro["properties"].append({"name": "syft:distro:versionID", "value": version})
    bom = cdx(json.dumps(coverage or claim()))
    bom["metadata"]["tools"] = {"components": [
        {"type": "application", "author": "anchore", "name": "koda-sbom", "version": "0.1.4"},
    ]}
    bom["components"].append(distro)
    return bom


@pytest.mark.parametrize("coverage", [claim(), claim(componentCount=3)])
@pytest.mark.parametrize(("distro_id", "version"), [("ol", "8.2"), ("debian", "12"), ("alpine", "")])
def test_koda_distro_metadata_preserves_coverage_and_the_os_row(coverage, distro_id, version):
    bom = with_koda_distro(coverage, distro_id=distro_id, version=version)
    normalized, _ = parse_sbom(json.dumps(bom).encode())
    assert coverage_for_bom(normalized) == ({"collectionCoverage": coverage}, None)
    assert normalized == bom
    assert normalized["components"][-1]["cpe"] == bom["components"][-1]["cpe"]


@pytest.mark.parametrize("row_changes", [
    {"type": "platform"},
    {"bom-ref": "other"},
    {"version": "8.3"},
    {"purl": "pkg:generic/ol@8.2"},
    {"properties": [{"name": "syft:distro:id", "value": "ol"}]},
    {"swid": {"tagId": "ol", "name": "ol", "version": "8.3"}},
])
def test_koda_tool_marker_does_not_make_an_arbitrary_os_row_synthetic(row_changes):
    bom = with_koda_distro()
    bom["components"][-1].update(row_changes)
    assert coverage_for_bom(bom) == ({"collectionCoverageState": "invalid"}, None)


def test_distro_deduction_requires_koda_origin_and_unambiguous_top_level_identity():
    bom = with_koda_distro()
    bom["metadata"]["tools"]["components"][0]["name"] = "syft"
    assert coverage_for_bom(bom) == ({"collectionCoverageState": "invalid"}, None)

    bom = with_koda_distro()
    bom["components"][0]["components"].append(bom["components"].pop())
    assert coverage_for_bom(bom) == ({"collectionCoverageState": "invalid"}, None)

    bom = with_koda_distro(claim(componentCount=3))
    distro_ref = bom["components"][-1]["bom-ref"]
    bom["components"][0]["components"].append({"type": "library", "name": "duplicate", "bom-ref": distro_ref})
    assert coverage_for_bom(bom) == ({"collectionCoverageState": "invalid"}, None)

    bom = with_koda_distro(claim(componentCount=3))
    bom["components"].append(with_koda_distro(distro_id="debian", version="12")["components"][-1])
    assert coverage_for_bom(bom) == ({"collectionCoverageState": "invalid"}, None)


def test_spdx_normalization_retains_claim_and_identifies_source_root_without_removing_inventory():
    root = "SPDXRef-DocumentRoot-Directory-local-filesystem"
    document = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
        "name": "fixture", "documentNamespace": "https://example.invalid/test",
        "creationInfo": {"created": "2026-11-14T00:00:00Z", "creators": ["Tool: koda-sbom"]},
        "comment": KEY + " " + json.dumps(claim(componentCount=1)),
        "packages": [
            {"SPDXID": root, "name": "local-filesystem", "downloadLocation": "NOASSERTION", "primaryPackagePurpose": "FILE"},
            {"SPDXID": "SPDXRef-lib", "name": "library", "downloadLocation": "NOASSERTION", "versionInfo": "1"},
        ],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}],
    }
    normalized, _ = parse_sbom(json.dumps(document).encode())
    assert [row["bom-ref"] for row in normalized["components"]] == [root, "SPDXRef-lib"]
    assert coverage_for_bom(normalized) == ({"collectionCoverage": claim(componentCount=1)}, root)
    normalized["components"][0]["version"] = "1.0"
    assert coverage_for_bom(normalized) == ({"collectionCoverageState": "invalid"}, None)
    forged_cdx = cdx(json.dumps(claim(componentCount=1)))
    forged_cdx["metadata"]["properties"].append({"name": SPDX_ROOT_KEY, "value": root})
    assert coverage_for_bom(forged_cdx) == ({"collectionCoverageState": "invalid"}, None)


@pytest.mark.parametrize("grype_success", [True, False])
def test_run_detail_and_analysis_preserve_collection_coverage(monkeypatch, grype_success):
    cpe = "cpe:2.3:a:oracle:rdbms_listener:19.25.0.0.0:*:*:*:*:*:*:*"
    record = {"id": "CVE-2025-30733", "configurations": [{"nodes": [{
        "operator": "OR", "cpeMatch": [{
            "criteria": "cpe:2.3:a:oracle:rdbms_listener:*:*:*:*:*:*:*:*",
            "vulnerable": True, "versionStartIncluding": "19.3", "versionEndIncluding": "19.26",
        }],
    }]}]}
    context = VulnerabilityContext(None, {}, {record["id"]: record}, {}, {})
    expected = claim()
    bom = cdx(json.dumps(expected))
    bom["components"] = [
        {"type": "application", "name": "Oracle RDBMS Listener", "version": "19.25.0.0.0", "cpe": cpe},
        {"type": "library", "name": "jquery", "version": "3.1.1", "purl": "pkg:npm/jquery@3.1.1"},
    ]
    suffix = "success" if grype_success else "failed"
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        assert login.status_code == 200, login.text
        headers = {"X-CSRF-Token": login.json()["csrfToken"]}
        service = client.post("/api/v1/services", json={"slug": "coverage-" + suffix, "name": "Coverage test " + suffix}, headers=headers)
        assert service.status_code == 201, service.text
        environment = client.get("/api/v1/environments").json()[0]["id"]
        upload = client.post("/api/v1/sbom-runs", headers=headers,
                             data={"serviceId": service.json()["id"], "environmentId": environment, "releaseVersion": "1"},
                             files={"sbom": ("coverage.json", json.dumps(bom), "application/json")})
        assert upload.status_code == 202, upload.text
        run_id = upload.json()["runId"]
        url = f"/api/v1/sbom-runs/{run_id}"
        try:
            pending = client.get(url).json()
            assert pending["collectionCoverage"] == expected
            assert pending["analyses"] == []
            monkeypatch.setattr("koda_tracker.services.load_context", lambda *args, **kwargs: context)
            monkeypatch.setattr("koda_tracker.services.subprocess.run", lambda *args, **kwargs: SimpleNamespace(
                returncode=0 if grype_success else 1,
                stdout=json.dumps({"matches": [], "descriptor": {"version": "test"}}),
                stderr="" if grype_success else "fixture failure",
            ))
            with SessionLocal() as db:
                analyze_offline(db, db.get(SbomRun, run_id))
                db.commit()
            result = client.get(url).json()
            revision, = result["analyses"]
            assert revision["dataSources"]["collectionCoverage"] == expected
            if grype_success:
                assert revision["state"] == "completed"
                assert revision["dataSources"]["cpeApplicability"]["componentCoverage"] == {
                    "evaluated": 1, "inconclusive": 0, "notEvaluated": 1,
                    "reasons": [{"code": "missing_cpe", "count": 1}],
                }
                assert revision["findingCount"] == 1
            else:
                assert revision["state"] == "failed" and "cpeApplicability" not in revision["dataSources"]
        finally:
            with SessionLocal() as db:
                db.execute(delete(Job).where(Job.run_id == run_id))
                db.delete(db.get(SbomRun, run_id))
                db.commit()
