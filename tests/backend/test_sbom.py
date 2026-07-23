from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from koda_tracker.sbom import (
    SbomValidationError,
    normalized_identity,
    parse_sbom,
    store_artifact,
    validate_with_cyclonedx_cli,
)


def test_parse_koda_cyclonedx_json() -> None:
    payload, media = parse_sbom(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": "urn:uuid:test",
                "components": [{"type": "library", "name": "demo", "version": "1.0", "purl": "pkg:pypi/demo@1.0"}],
            }
        ).encode()
    )
    assert media.endswith("+json")
    assert payload["components"][0]["name"] == "demo"


def test_rejects_xml_doctype() -> None:
    with pytest.raises(SbomValidationError, match="DTD"):
        parse_sbom(b'<!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><bom>&xxe;</bom>')


def test_parses_cyclonedx_xml() -> None:
    raw = b"""<?xml version="1.0"?>
    <bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="urn:uuid:test">
      <components><component type="library" bom-ref="demo"><name>demo</name><version>1.0</version>
      <purl>pkg:maven/org.example/demo@1.0</purl></component></components>
    </bom>"""
    payload, media = parse_sbom(raw)
    assert payload["specVersion"] == "1.5"
    assert media.endswith("+xml")


def test_normalized_purl_ignores_version() -> None:
    first, _ = normalized_identity({"purl": "pkg:maven/org.example/demo@1.0"})
    second, _ = normalized_identity({"purl": "pkg:maven/org.example/demo@2.0"})
    assert first == second


def test_cli_validation_failure_is_reported(tmp_path) -> None:
    validator = tmp_path / "validator"
    validator.write_text("#!/bin/sh\necho invalid schema >&2\nexit 1\n")
    validator.chmod(0o755)
    with pytest.raises(SbomValidationError, match="invalid schema"):
        validate_with_cyclonedx_cli(b'{"bomFormat":"CycloneDX"}', str(validator))


def test_content_addressed_store_is_safe_for_concurrent_duplicates(tmp_path) -> None:
    raw = b"same immutable sbom"
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store_artifact(tmp_path, raw), range(32)))
    assert len({digest for digest, _ in results}) == 1
    assert len({path for _, path in results}) == 1
    assert results[0][1].read_bytes() == raw
