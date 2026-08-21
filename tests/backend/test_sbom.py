from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from koda_tracker.sbom import (
    SbomValidationError,
    normalized_identity,
    parse_sbom,
    parse_sbom_file,
    store_artifact,
    store_artifact_file,
    validate_file_with_cyclonedx_cli,
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


def test_rejects_xml_doctype_after_long_prolog() -> None:
    with pytest.raises(SbomValidationError, match="DTD"):
        parse_sbom(b"<bom>" + (b" " * 5000) + b"<!DOCTYPE bom><components/></bom>")


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


def test_cli_validation_specifies_format_for_extensionless_upload(tmp_path) -> None:
    validator = tmp_path / "validator"
    validator.write_text(
        '#!/bin/sh\ncase "$*" in *"--input-format json"*) exit 0;; *) exit 1;; esac\n'
    )
    validator.chmod(0o755)
    source = tmp_path / "koda-sbom-upload"
    source.write_text('{"bomFormat":"CycloneDX"}')

    validate_file_with_cyclonedx_cli(source, str(validator), input_format="json")


def test_content_addressed_store_is_safe_for_concurrent_duplicates(tmp_path) -> None:
    raw = b"same immutable sbom"
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store_artifact(tmp_path, raw), range(32)))
    assert len({digest for digest, _ in results}) == 1
    assert len({path for _, path in results}) == 1
    assert results[0][1].read_bytes() == raw


def test_file_parser_and_store_keep_upload_on_disk(tmp_path) -> None:
    raw = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    source = tmp_path / "upload.json"
    source.write_bytes(raw)

    payload, media = parse_sbom_file(source)
    digest, stored = store_artifact_file(tmp_path / "artifacts", source, digest=hashlib.sha256(raw).hexdigest())

    assert payload["components"] == []
    assert media.endswith("+json")
    assert source.read_bytes() == raw
    assert stored.read_bytes() == raw
    assert digest == hashlib.sha256(raw).hexdigest()
