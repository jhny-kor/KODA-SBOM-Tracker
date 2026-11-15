from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from koda_tracker import sbom as sbom_module
from koda_tracker.sbom import (
    SbomValidationError,
    normalized_identity,
    parse_sbom,
    parse_sbom_file,
    store_artifact,
    store_artifact_file,
    validate_component_count,
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


def test_component_count_is_bounded_before_rows_are_created() -> None:
    payload = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{}, {}]}
    with pytest.raises(SbomValidationError, match="구성요소"):
        validate_component_count(payload, 1)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-32-le"])
def test_upload_json_keeps_escaped_text_across_preflight_chunks(tmp_path, monkeypatch, encoding):
    prefix = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"metadata":{"note":'
    note = "x" * (64 * 1024 - 2 - len(prefix)) + '"{[},:' * 20 + "예제"
    source = tmp_path / "sbom.json"
    source.write_bytes((prefix + json.dumps(note, ensure_ascii=False) + "}}").encode(encoding))
    monkeypatch.setattr(sbom_module, "MAX_UPLOAD_JSON_MARKS", 16)

    payload, _ = sbom_module.parse_sbom_upload_document(source)

    assert payload["metadata"]["note"] == note


@pytest.mark.parametrize(
    ("setting", "limit", "message"),
    [("MAX_UPLOAD_DOCUMENT_BYTES", 10, "파싱 크기"),
     ("MAX_UPLOAD_DOCUMENT_DEPTH", 1, "중첩 깊이"),
     ("MAX_UPLOAD_JSON_MARKS", 5, "구조 복잡도")],
)
def test_upload_json_checks_document_budget_before_decoding(tmp_path, monkeypatch, setting, limit, message):
    source = tmp_path / "sbom.json"
    source.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
    monkeypatch.setattr(sbom_module, setting, limit)

    def should_not_decode(_source):
        pytest.fail("Out-of-budget JSON reached the whole-document decoder")

    monkeypatch.setattr(sbom_module.json, "load", should_not_decode)
    with pytest.raises(SbomValidationError, match=message):
        sbom_module.parse_sbom_upload_document(source)


@pytest.mark.parametrize(
    ("setting", "limit", "message"),
    [("MAX_UPLOAD_DOCUMENT_DEPTH", 2, "중첩 깊이"),
     ("MAX_UPLOAD_XML_NODES", 4, "구조 복잡도"),
     ("MAX_UPLOAD_XML_CHARS", 16, "구조 복잡도")],
)
def test_upload_xml_checks_tree_budget_before_normalization(tmp_path, monkeypatch, setting, limit, message):
    source = tmp_path / "sbom.xml"
    source.write_text('<bom version="1.6"><components><component type="library"/></components></bom>', encoding="utf-8")
    monkeypatch.setattr(sbom_module, setting, limit)

    def should_not_normalize(_source):
        pytest.fail("Out-of-budget XML reached normalization")

    monkeypatch.setattr(sbom_module, "_xml_payload", should_not_normalize)
    with pytest.raises(SbomValidationError, match=message):
        sbom_module.parse_sbom_upload_document(source)


def test_upload_json_accounts_for_widened_source_before_decoding(tmp_path, monkeypatch):
    source = tmp_path / "sbom.json"
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "metadata": {"description": "Example"}}
    control = json.dumps(document, ensure_ascii=False)
    monkeypatch.setattr(sbom_module, "MAX_UPLOAD_JSON_DECODED_BYTES", len(control) + 10)
    source.write_text(control, encoding="utf-8")
    assert sbom_module.parse_sbom_upload_document(source)[0] == document

    source.write_text(control.replace("Example", "Sample 🎻"), encoding="utf-8")
    with pytest.raises(SbomValidationError, match="디코딩 크기"):
        sbom_module.parse_sbom_upload_document(source)


@pytest.mark.parametrize("binary", ["", "configured-validator"])
def test_upload_spdx_conversion_keeps_its_budget_without_reparsing(tmp_path, monkeypatch, binary):
    source = tmp_path / "spdx.json"
    source.write_text("{}", encoding="utf-8")
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    monkeypatch.setattr(sbom_module, "MAX_UPLOAD_DOCUMENT_BYTES", 10)

    def unexpected_cli(*_args, **_kwargs):
        pytest.fail("Out-of-budget SPDX conversion reached the CLI")

    monkeypatch.setattr(sbom_module, "_run_cyclonedx", unexpected_cli)
    with pytest.raises(SbomValidationError, match="파싱 크기"):
        validate_file_with_cyclonedx_cli(source, binary, parsed_document=(document, "application/spdx+json"))
    assert list(tmp_path.iterdir()) == [source]
