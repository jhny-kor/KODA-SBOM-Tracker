from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from koda_tracker.cpe_analysis import enrich_cpe_findings
from koda_tracker.models import JobState
from koda_tracker.oracle_evidence import LISTENER, read_oracle_home
from koda_tracker.policies import build_cel_contexts
from koda_tracker.sbom import normalized_identity
from koda_tracker.vulnerability import VulnerabilityContext, project_cve_findings
from koda_tracker.workflows import bom_targets, resolve_target, targets

CVE = "CVE-2025-30733"
VERSION = "19.25.0.0.0"
LISTENER_CPE = f"cpe:2.3:a:oracle:rdbms_listener:{VERSION}:*:*:*:*:*:*:*"
DATABASE_CPE = f"cpe:2.3:a:oracle:database_server:{VERSION}:*:*:*:*:*:*:*"


def home_row(number, *, name=LISTENER, patch="36912597", spdx=False, version=VERSION):
    home = "oracle-home/" + str(number) * 64
    ref = "SPDXRef-KODA-Oracle-" + hashlib.sha256(f"{home}\x00{name}\x00{version}".encode()).hexdigest()
    paths = [f"homes/{number}/opatch.txt"]
    if name == LISTENER:
        paths.append(f"homes/{number}/listener.txt")
    evidence = {
        "homeId": home,
        "observation": "installed inventory" if version else "listener executable observed; version unconfirmed",
        "inventoryStatus": "completed",
        "opatchEvidenceSha256": "b" * 64,
        "opatchInventoryPatchIds": [patch],
        "opatchInventoryPatchIdsTruncated": True,
    }
    if name == LISTENER:
        evidence.update(listenerExecutableObserved=True, listenerEvidenceSha256="c" * 64)
        if version:
            evidence.update(release="19.25.0.0.241015", versionSource="opatch_inventory_ru",
                            listenerReleaseBasis="database_ru" if number == 1 else "grid_ru",
                            listenerReleasePatchIds=[patch])
    row = {"bom-ref": ref, "name": name, "version": version}
    if version:
        row["cpe"] = LISTENER_CPE if name == LISTENER else DATABASE_CPE
    if spdx:
        row["properties"] = [{"name": "koda:spdx:package", "value": json.dumps({
            "SPDXID": ref, "name": name, "versionInfo": version,
            "comment": json.dumps({**evidence, "evidencePaths": paths}),
        })}]
    else:
        row["properties"] = [{"name": "syft:package:foundBy", "value": "koda-aix-oracle-inventory"}]
        for key, value in evidence.items():
            values = {f"{key}:{index}": patch for index, patch in enumerate(value)} if isinstance(value, list) else {key: value}
            row["properties"].extend({"name": "syft:metadata:" + field,
                                      "value": str(item).lower() if isinstance(item, bool) else item}
                                     for field, item in values.items())
        row["evidence"] = {"occurrences": [{"location": path} for path in paths]}
    return row


def nvd_context(*, requires_database=False):
    leaf = {"cpeMatch": [{"criteria": LISTENER_CPE, "vulnerable": True}]}
    if requires_database:
        leaf = {"operator": "AND", "nodes": [
            leaf, {"cpeMatch": [{"criteria": DATABASE_CPE, "vulnerable": False}]},
        ]}
    return VulnerabilityContext(None, {}, {CVE: {"configurations": [leaf]}}, {}, {})


@pytest.mark.parametrize("spdx", [False, True])
def test_same_cve_and_listener_version_preserve_both_homes(spdx):
    first = home_row(1, spdx=spdx)
    second = home_row(2, patch="36916690", spdx=spdx)
    found, summary = enrich_cpe_findings([first, second], nvd_context(), [])
    assert summary["affectedCves"] == 1 and summary["addedFindings"] == 2
    assert len(project_cve_findings(found)) == 2
    assert {item["bomRef"] for item in found} == {first["bom-ref"], second["bom-ref"]}
    assert {tuple(item["oracleHomeEvidence"]["listenerReleasePatchIds"]) for item in found} == {("36912597",), ("36916690",)}
    for item in found:
        assert item["oracleHomeEvidence"]["opatchInventoryPatchIdsTruncated"] is True
        assert item["oracleHomeEvidence"]["patchApplicability"] == "unverified"
        assert item["fixedIn"] == []
        assert item["cpeEvidence"][0]["oracleHomeId"] == item["oracleHomeEvidence"]["homeId"]
    assert normalized_identity(first)[0] != normalized_identity(second)[0]
    run = SimpleNamespace(normalized_bom={"components": [first, second]},
                          analyses=[SimpleNamespace(findings=found, state=JobState.COMPLETED, sequence=1)])
    assert len(targets(run)) == 2
    for item in found:
        scoped, _, _ = bom_targets(run)[item["bomRef"]]
        assert resolve_target(run, scoped, CVE)[0] == scoped
    with pytest.raises(HTTPException):
        resolve_target(run, f"{LISTENER}@{VERSION}", CVE)
    first["properties"].append({"name": "fixture:home", "value": "first-home"})
    second["properties"].append({"name": "fixture:home", "value": "second-home"})
    policy = build_cel_contexts([first, second], found)["vulnerability"]
    assert [value["component"]["properties"]["fixture:home"] for value in policy] == ["first-home", "second-home"]


def test_oracle_environment_is_not_borrowed_across_homes():
    first, second = home_row(1), home_row(2)
    database = home_row(2, name="Oracle Database Server")
    found, summary = enrich_cpe_findings([first, database, second], nvd_context(requires_database=True), [])
    assert [item["bomRef"] for item in found] == [second["bom-ref"]]
    assert summary["unknownCves"] == 1
    assert summary["componentCoverage"]["inconclusive"] == 1
    assert any(row.get("oracleHomeId") == "oracle-home/" + "1" * 64 for row in summary["unresolved"])


def test_only_exact_scanner_reference_can_bind_to_home():
    first, second = home_row(1), home_row(2)
    by_ref = {"id": CVE, "component": LISTENER, "version": VERSION,
              "bomRef": first["bom-ref"], "severity": "Medium", "fixedIn": ["vendor-specific"]}
    unscoped = {"id": CVE, "component": LISTENER, "version": VERSION, "severity": "Low"}
    found, summary = enrich_cpe_findings([first, second], nvd_context(), [by_ref, unscoped])
    assert summary["matchedExisting"] == 1 and summary["addedFindings"] == 1
    assert found[1] == unscoped
    assert found[0]["severity"] == "Medium" and found[0]["fixedIn"] == ["vendor-specific"]
    assert found[0]["oracleHomeEvidence"]["homeId"] == "oracle-home/" + "1" * 64
    assert "oracleHomeEvidence" not in by_ref


def test_missing_listener_version_is_distinct_from_missing_cpe_and_conflicting_scope_rejected():
    row = home_row(1, version="")
    assert read_oracle_home(row)["observation"] == "listener executable observed; version unconfirmed"
    assert enrich_cpe_findings([row], nvd_context(), [])[1]["componentCoverage"] == {
        "evaluated": 0, "inconclusive": 0, "notEvaluated": 1,
        "reasons": [{"code": "oracle_listener_version_unconfirmed", "count": 1}],
    }
    row["properties"].append({"name": "syft:metadata:homeId", "value": "oracle-home/" + "2" * 64})
    assert read_oracle_home(row) is None


def test_duplicate_component_ref_stays_unscoped():
    first = home_row(1)
    duplicate = home_row(1, patch="36916690")
    original = {"id": CVE, "component": LISTENER, "version": VERSION, "bomRef": first["bom-ref"]}
    findings, _ = enrich_cpe_findings([first, duplicate], nvd_context(), [original])
    assert len(findings) == 1
    assert findings[0]["component"] == LISTENER
    assert "oracleHomeEvidence" not in findings[0]
