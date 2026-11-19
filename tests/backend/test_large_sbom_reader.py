import json

import pytest

from koda_tracker import large_sbom_reader as reader
from koda_tracker.asset_evidence import AssetPropertyValidator
from koda_tracker.sbom import SbomValidationError


def test_streams_records_and_retains_other_root_sections(tmp_path, monkeypatch):
    monkeypatch.setattr(reader, "_CHUNK_SIZE", 7)
    monkeypatch.setattr(reader, "MAX_LARGE_SBOM_RECORD_BYTES", 256)
    component = {
        "type": "library", "name": '청크 경계 \\ "test" 🎻', "bom-ref": "alpha",
        "properties": [{"name": "syft:location:0:path", "value": "/path   /package.py"}],
        "components": [{"type": "library", "name": "nested", "bom-ref": "beta"}],
    }
    relationships = [{"ref": "alpha", "dependsOn": ["beta"], "provides": ["capability"]}]
    metadata = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 100001,
                "metadata": {"properties": [{"name": "optional-value"}]}, "compositions": [{"aggregate": "incomplete"}]}
    path = tmp_path / "large.cdx.json"
    raw = json.dumps({"components": [component] * 4, "dependencies": relationships, **metadata}, ensure_ascii=False)
    path.write_text(raw, encoding="utf-8")
    components, dependencies = [], []

    assert reader.read_large_cyclonedx(path, components.append, dependencies.append) == metadata
    assert components == [component] * 4
    assert dependencies == relationships
    assert path.read_text(encoding="utf-8") == raw


@pytest.mark.parametrize("suffix", [
    b',"components":{}}',
    b',"components":[{"name":"no-type"}]}',
    b',"dependencies":[{"ref":"a","dependsOn":"b"}]}',
    b',"components":[{"type":"library","name":"a","name":"b"}]}',
    b',"components":[],"components":[]}',
    b',"components":[{"type":"library","name":"a"},]}',
    b',"components":[{"type":"library","name":"\xff"}]}',
    b',"metadata":{"number":Infinity}}',
    b',"metadata":{"number":1e999999}}',
    b'} trailing',
])
def test_rejects_invalid_records_or_document(tmp_path, suffix):
    path = tmp_path / "invalid.json"
    path.write_bytes(b'{"bomFormat":"CycloneDX","specVersion":"1.6"' + suffix)
    with pytest.raises(SbomValidationError):
        reader.read_large_cyclonedx(path, lambda _: None, lambda _: None)


def test_checks_per_record_and_aggregate_metadata_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(reader, "MAX_LARGE_SBOM_RECORD_BYTES", 100)
    path = tmp_path / "limited.json"
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "components": [{"type": "library", "name": "한" * 32}]}
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(SbomValidationError, match="100바이트"):
        reader.read_large_cyclonedx(path, pytest.fail, pytest.fail)

    monkeypatch.setattr(reader, "MAX_LARGE_SBOM_METADATA_BYTES", 70)
    document.update(components=[], metadata={"description": "x" * 120})
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SbomValidationError, match="크기"):
        reader.read_large_cyclonedx(path, pytest.fail, pytest.fail)


def test_checks_asset_parent_links_incrementally():
    validator = AssetPropertyValidator(track_references=False)
    validator.observe({"type": "device", "bom-ref": "child", "properties": [
        {"name": "koda:asset:parent-id", "value": "parent"},
    ]})
    validator.finish({"parent"}.__contains__)

    validator.observe({"type": "device", "bom-ref": "parent", "properties": [
        {"name": "koda:asset:parent-id", "value": "child"},
    ]})
    with pytest.raises(ValueError, match="Cyclic"):
        validator.finish({"child", "parent"}.__contains__)
