from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace
import uuid

from fastapi.testclient import TestClient
import pytest

from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal
from koda_tracker.main import app
from koda_tracker.models import SbomRun
from koda_tracker.sbom import SbomValidationError, parse_sbom, parse_sbom_file, validate_file_with_cyclonedx_cli
from koda_tracker.spdx import to_cyclonedx


def document():
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "product",
            "documentNamespace": "https://example.invalid/spdx/product-1", "creationInfo": {"created": "2026-10-19T10:11:12Z", "creators": ["Tool: KODA-0.1.0"]},
            "packages": [
                {"SPDXID": "SPDXRef-Root", "name": "product", "versionInfo": "1", "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                 "licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION"},
                {"SPDXID": "SPDXRef-Lib", "name": "demo", "versionInfo": "1.2", "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                 "licenseDeclared": "MIT OR Apache-2.0", "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
                 "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}], "supplier": "Organization: Acme",
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:maven/org.example/demo@1.2"},
                                  {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:acme:demo:1.2:*:*:*:*:*:*:*"}]}],
            "documentDescribes": ["SPDXRef-Root"],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"},
                              {"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Lib"},
                              {"spdxElementId": "SPDXRef-Root", "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-Lib"}]}


def test_spdx_bytes_and_file_normalization_preserve_identity_graph_and_evidence(tmp_path):
    original = document()
    raw = json.dumps(original).encode()
    source = tmp_path / "demo.spdx.json"
    source.write_bytes(raw)
    parsed, media = parse_sbom(raw)
    file_parsed, file_media = parse_sbom_file(source)
    assert parsed == file_parsed and media == file_media == "application/spdx+json"
    package = parsed["components"][1]
    assert package["bom-ref"] == "SPDXRef-Lib"
    assert package["purl"] == "pkg:maven/org.example/demo@1.2"
    assert package["cpe"].startswith("cpe:2.3:a:acme:demo")
    assert package["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]
    assert package["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
    assert "licenses" not in parsed["components"][0]
    assert parsed["dependencies"][0] == {"ref": "SPDXRef-Root", "dependsOn": ["SPDXRef-Lib"]}
    metadata = {value["name"]: value["value"] for value in parsed["metadata"]["properties"]}
    assert json.loads(metadata["koda:spdx:relationships"]) == original["relationships"]
    assert json.loads(package["properties"][0]["value"]) == original["packages"][1]
    assert source.read_bytes() == raw


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(spdxVersion="SPDX-3.0"),
    lambda value: value["packages"].append(copy.deepcopy(value["packages"][0])),
    lambda value: value["relationships"][0].update(relatedSpdxElement="SPDXRef-Missing"),
    lambda value: value["packages"][1]["checksums"][0].update(checksumValue="not-a-hash"),
    lambda value: value["packages"][1]["externalRefs"].append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/different@2"}),
    lambda value: value["creationInfo"].update(created="2026-10-19T00:00:00"),
])
def test_invalid_or_ambiguous_spdx_is_rejected(mutate):
    value = document()
    mutate(value)
    with pytest.raises(SbomValidationError):
        parse_sbom(json.dumps(value).encode())


def test_optional_cyclonedx_validator_receives_normalized_view(tmp_path, monkeypatch):
    from koda_tracker import sbom
    original = json.dumps(document()).encode()
    path = tmp_path / "upload"
    path.write_bytes(original)
    seen = []
    def validate(command, **kwargs):
        candidate = json.loads(open(command[command.index("--input-file") + 1]).read())
        seen.append(candidate)
        assert candidate["bomFormat"] == "CycloneDX"
        assert "--input-format" in command and command[-1] == "json"
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(sbom, "_run_cyclonedx", validate)
    validate_file_with_cyclonedx_cli(path, "validator", input_format="json")
    assert len(seen) == 1 and path.read_bytes() == original


def test_authenticated_spdx_upload_and_original_artifact_roundtrip(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_queued_jobs", 10000)
    raw = json.dumps(document()).encode()
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        assert login.status_code == 200
        headers = {"X-CSRF-Token": login.json()["csrfToken"]}
        service = client.post("/api/v1/services", json={"slug": "spdx-" + uuid.uuid4().hex[:10], "name": "SPDX product"}, headers=headers)
        assert service.status_code == 201
        environment = client.get("/api/v1/environments").json()[0]["id"]
        response = client.post("/api/v1/sbom-runs", data={"serviceId": service.json()["id"], "environmentId": environment, "releaseVersion": "1"},
                               files={"sbom": ("product.spdx.json", raw, "application/spdx+json")}, headers=headers)
        assert response.status_code == 202, response.text
        run_id = response.json()["runId"]
        assert response.json()["sha256"] == hashlib.sha256(raw).hexdigest()
        artifact = client.get(f"/api/v1/sbom-runs/{run_id}/artifact")
        assert artifact.status_code == 200 and artifact.content == raw
        components = client.get(f"/api/v1/sbom-runs/{run_id}/components").json()
        assert components["total"] == 2
        with SessionLocal() as db:
            row = db.get(SbomRun, run_id)
            assert row.media_type == "application/spdx+json"
            assert row.normalized_bom["components"][1]["purl"] == "pkg:maven/org.example/demo@1.2"
            assert row.normalized_bom["dependencies"][0]["dependsOn"] == ["SPDXRef-Lib"]
