import hashlib
import json

import pytest

from koda_tracker.asset_evidence import apply_spdx_asset, validate_asset_properties
from koda_tracker.spdx import to_cyclonedx


def spdx_id(value):
    return "SPDXRef-KodaAsset-" + hashlib.sha256(value.encode()).hexdigest()[:32]


def package(identity, kind, parent=""):
    asset = {"id": identity, "kind": kind, "name": identity, "version": "1.0", "parentId": parent,
             "source": "test", "properties": {"applicationState": "Staged", "storedVersion": "2.0"}}
    purpose = {"device-driver": "OTHER", "operating-system": "OPERATING_SYSTEM"}.get(kind, kind.upper())
    return {"SPDXID": spdx_id(identity), "name": identity, "versionInfo": "1.0", "primaryPackagePurpose": purpose,
            "downloadLocation": "NOASSERTION", "comment": "koda:asset:" + json.dumps(asset)}


def test_spdx_driver_and_os_evidence_retained():
    doc = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0", "name": "test",
           "documentNamespace": "https://example.invalid/test", "creationInfo": {"created": "2026-11-18T00:00:00Z", "creators": ["Tool: test"]},
           "packages": [package("board", "device"), package("driver", "device-driver", "board"), package("os", "operating-system")]}
    out = to_cyclonedx(doc)
    assert [row["type"] for row in out["components"]] == ["device", "device-driver", "operating-system"]
    props = {p["name"]: p["value"] for p in out["components"][1]["properties"]}
    assert props["koda:asset:parent-id"] == spdx_id("board")
    assert props["koda:asset:original-parent-id"] == "board"
    assert props["koda:asset:evidence:applicationState"] == "Staged"
    assert props["koda:asset:evidence:storedVersion"] == "2.0"
    assert "vulnerabilities" not in out


def test_conflicting_asset_comment_rejected():
    pkg = package("driver", "device-driver")
    component = {"bom-ref": pkg["SPDXID"], "name": "driver", "version": "2.0", "properties": []}
    with pytest.raises(ValueError, match="conflicts"):
        apply_spdx_asset(pkg, component)


@pytest.mark.parametrize("props", [
    [{"name": "koda:asset:parent-id", "value": "missing"}],
    [{"name": "koda:asset:parent-id", "value": "a"}],
    [{"name": "koda:asset:source", "value": "a"}, {"name": "koda:asset:source", "value": "b"}],
    [{"name": "koda:asset:model", "value": []}],
])
def test_invalid_properties_rejected(props):
    with pytest.raises(ValueError):
        validate_asset_properties({"components": [{"bom-ref": "a", "type": "firmware", "properties": props}]})


def test_cyclonedx_keeps_reported_states():
    doc = {"components": [{"bom-ref": "a", "type": "firmware", "properties": [{"name": "koda:asset:evidence:applicationState", "value": "unknown"}]}]}
    before = json.dumps(doc)
    validate_asset_properties(doc)
    assert json.dumps(doc) == before


def test_cyclic_parents_rejected():
    doc = {"components": [
        {"bom-ref": "a", "type": "device", "properties": [{"name": "koda:asset:parent-id", "value": "b"}]},
        {"bom-ref": "b", "type": "device", "properties": [{"name": "koda:asset:parent-id", "value": "a"}]},
    ]}
    with pytest.raises(ValueError, match="Cyclic"):
        validate_asset_properties(doc)


def test_parser_rejects_bad_parent():
    from koda_tracker.sbom import SbomValidationError, parse_sbom
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "components": [{"bom-ref": "a", "name": "firmware", "type": "firmware", "properties": [{"name": "koda:asset:parent-id", "value": "missing"}]}]}
    with pytest.raises(SbomValidationError, match="parent"):
        parse_sbom(json.dumps(doc).encode())
