from __future__ import annotations

import gzip
import json
import shutil
import tracemalloc
from pathlib import Path

import pytest

from koda_tracker import streaming_nvd
from koda_tracker.config import Settings
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, _validate_tree, _write_manifest
from koda_tracker.streaming_nvd import NvdShapeError, read_json_sections, read_nvd


def _source(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "nvd.json"
    path.write_text(text, encoding="utf-8")
    return path


def _rebuild(path: Path, *, allow_root_list: bool = False):
    state = None
    events = []

    def section(kind):
        nonlocal state
        events.append(kind)
        state = {} if kind == "dict" else [] if kind == "list" else None

    def entry(key, value):
        if isinstance(state, dict):
            state[key] = value
        else:
            assert key == len(state)
            state.append(value)

    result = read_nvd(path, on_section=section, on_entry=entry, allow_root_list=allow_root_list)
    return state, events, result


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 64 * 1024])
@pytest.mark.parametrize("text", [
    '{"vulnerabilities":[]}',
    '{"vulnerabilities":{}}',
    '{"vulnerabilities":{"b":{"id":"CVE-2026-2000"},"a":1,"b":{"id":"CVE-2026-3000"}}}',
    '{"aliases":[1],"unknown":{"x":[null,true,false,1.2e-4]},"vulnerabilities":[{"nested":{"x":1,"x":2}}]}',
    '{"vulnerabilities":false,"vulnerabilities":{},"vulnerabilities":[null,NaN,Infinity,-Infinity,-0.0,1e9999]}',
    ' \r\n {"vulnerabilities":["한글🙂","\\uD83D\\uDE00","\\ud800","\\\"\\\\\\/\\b\\f\\n\\r\\t"]} \t',
    '{"vulnerabilitie\\u0073":{"\\ud800":[],"한글🙂":[[{}]]},"aliases":null}',
])
def test_callbacks_match_standard_json_and_duplicate_order(tmp_path, monkeypatch, chunk_size, text):
    monkeypatch.setattr(streaming_nvd, "_CHUNK_SIZE", chunk_size)
    rebuilt, _, result = _rebuild(_source(tmp_path, text))
    expected = json.loads(text)["vulnerabilities"]
    assert json.dumps(rebuilt, ensure_ascii=True) == json.dumps(expected, ensure_ascii=True)
    assert result.sections["vulnerabilities"].kind == ("dict" if isinstance(expected, dict) else "list")
    read_nvd(tmp_path / "nvd.json")


def test_duplicate_root_sections_reset_and_final_shape_decides(tmp_path):
    path = _source(tmp_path, '{"vulnerabilities":{"old":1},"vulnerabilities":"bad","vulnerabilities":[{"id":"new"}]}')
    rebuilt, events, _ = _rebuild(path)
    assert events == ["dict", None, "list"]
    assert rebuilt == [{"id": "new"}]
    _source(tmp_path, '{"vulnerabilities":[],"vulnerabilities":false}')
    with pytest.raises(NvdShapeError):
        read_nvd(path)


@pytest.mark.parametrize("text", [
    "{}", "[]", "null", "123", '"value"',
    '{"vulnerabilities":null}', '{"vulnerabilities":true}',
    '{"vulnerabilities":0}', '{"vulnerabilities":"[]"}',
])
def test_nvd_requires_final_object_root_and_container(tmp_path, text):
    with pytest.raises(NvdShapeError):
        read_nvd(_source(tmp_path, text))


@pytest.mark.parametrize("text", [
    "", " ", "{", "[", '{"vulnerabilities":[]',
    '{"vulnerabilities":[1,]}', '{"vulnerabilities":{"x":1,}}',
    '{"vulnerabilities":[],}', '{"vulnerabilities" []}',
    '{vulnerabilities:[]}', '{"vulnerabilities":[]}:',
    '{"vulnerabilities":[]} null', '{"vulnerabilities":[],"aliases":[1,]}',
    '{"vulnerabilities":[],"unknown":{"nested":[{"bad":} ]}}',
    '{"vulnerabilities":[01]}', '{"vulnerabilities":[1.]}',
    '{"vulnerabilities":[1e]}', '{"vulnerabilities":[+1]}',
    '{"vulnerabilities":[truefalse]}', '{"vulnerabilities":[-NaN]}',
    '{"vulnerabilities":[nan]}', '{"vulnerabilities":["\\x20"]}',
    '{"vulnerabilities":["\\u123Z"]}', '{"vulnerabilities":["\\u12"]}',
    '{"vulnerabilities":["\x1f"]}', '{"vulnerabilities":["unterminated]}',
    '{"vulnerabilities":[]\v}',
])
@pytest.mark.parametrize("chunk_size", [2, 64 * 1024])
def test_invalid_json_anywhere_is_rejected(tmp_path, monkeypatch, text, chunk_size):
    monkeypatch.setattr(streaming_nvd, "_CHUNK_SIZE", chunk_size)
    path = _source(tmp_path, text)
    with pytest.raises(json.JSONDecodeError):
        read_nvd(path)
    with pytest.raises(json.JSONDecodeError):
        _rebuild(path)


def test_root_list_is_explicit_and_generic_empty_object_is_valid(tmp_path):
    path = _source(tmp_path, '[{"cve":{"id":"CVE-2026-1234"}},null]')
    rebuilt, events, result = _rebuild(path, allow_root_list=True)
    assert rebuilt == json.loads(path.read_text())
    assert events == ["list"] and result.sections[None].count == 2
    result = read_json_sections(_source(tmp_path, "{}"), section_names={"CVE_Items"})
    assert result.root_kind == "dict" and result.sections == {}


def test_generic_sections_alias_scalars_metadata_and_final_truthiness(tmp_path):
    text = '{"aliases":{"A":["B"],"A":["C"]},"items":[],"items":"blocks fallback","group":["D","E"],"CVE_Items":[{"cve":{"id":"CVE-2026-1234"}}],"timestamp":"old","timestamp":"new","unknown":{"large":[1,2,3]}}'
    entries = []
    fields = []
    sections = []
    result = read_json_sections(
        _source(tmp_path, text),
        section_names=lambda name, kind: name in {"aliases", "items", "CVE_Items"} or kind == "list",
        on_section=lambda name, kind: sections.append((name, kind)),
        on_entry=lambda name, key, value: entries.append((name, key, value)),
        on_field=lambda name, value: fields.append((name, value)),
    )
    assert entries[:2] == [("aliases", "A", ["B"]), ("aliases", "A", ["C"])]
    assert ("group", 0, "D") in entries
    assert ("CVE_Items", 0, {"cve": {"id": "CVE-2026-1234"}}) in entries
    assert ("items", "blocks fallback") in fields
    assert fields[-2:] == [("timestamp", "old"), ("timestamp", "new")]
    assert result.sections["items"].kind is None and result.sections["items"].truthy
    assert result.sections["aliases"].count == 2
    assert ("unknown", "dict") in sections
    assert not any(name == "unknown" for name, *_ in entries + fields)


def test_gzip_explicit_and_scalar_field_filter(tmp_path):
    path = tmp_path / "nvd.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as out:
        out.write('{"CVE_Items":[{"id":"CVE-2026-1234"}],"timestamp":"2026-10-29","ignored":"long"}')
    fields = []
    result = read_json_sections(path, section_names={"CVE_Items"}, on_field=lambda *args: fields.append(args), field_names={"timestamp"}, allow_gzip=True)
    assert fields == [("timestamp", "2026-10-29")]
    assert result.sections["CVE_Items"].count == 1
    with pytest.raises(UnicodeDecodeError):
        read_json_sections(path, section_names={"CVE_Items"})


def test_number_split_across_chunk_is_not_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(streaming_nvd, "_CHUNK_SIZE", 8)
    values = [12345678901234567890, 123.456789e20, -1.234567890123e-20, True, None, float("inf")]
    rebuilt, _, _ = _rebuild(_source(tmp_path, json.dumps({"vulnerabilities": values})))
    assert rebuilt == values


def test_large_unicode_input_and_long_unknown_keys_use_bounded_validation_memory(tmp_path):
    path = tmp_path / "nvd.json"
    row = json.dumps({"id": "CVE-2026-1234", "description": "한글🙂" * 256}, ensure_ascii=False)
    with path.open("w", encoding="utf-8") as out:
        out.write('{"' + "unknown" * 150_000 + '":"')
        # Exceeds the old prototype's scalar/record limits; no such input limit
        # is part of the existing package contract.
        for _ in range(300):
            out.write("설명🙂" * 8192)
        out.write('","vulnerabilities":[')
        for index in range(10_000):
            out.write(("," if index else "") + row)
        out.write('],"aliases":{"CVE-2026-1234":["GHSA-aaaa-bbbb-cccc"]}}')
    assert path.stat().st_size > 45 * 1024 * 1024
    tracemalloc.start()
    try:
        result = read_nvd(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.sections["vulnerabilities"].count == 10_000
    assert peak < 4 * 1024 * 1024


def _tree(tmp_path: Path, nvd_text: str) -> Path:
    root = tmp_path / "source"
    root.mkdir()
    (root / "metadata.env").write_text("BUNDLE_VERSION=test\nDATASET_TYPE=vuln-data\nGRYPE_DB_SCHEMA=5\nKEV_CATALOG=kev.json\n")
    (root / "nvd.json").write_text(nvd_text, encoding="utf-8")
    (root / "kev.json").write_text('{"vulnerabilities":[]}')
    (root / "grype-db" / "5").mkdir(parents=True)
    (root / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (root / "grype-db" / "5" / "import.json").write_text("{}")
    _write_manifest(root)
    return root


def test_both_engine_validation_paths_do_not_read_entire_nvd(tmp_path, monkeypatch):
    root = _tree(tmp_path, '{"vulnerabilities":false,"vulnerabilities":[{"x":NaN,"x":Infinity}],"aliases":"optional"}')
    original = Path.read_text

    def guarded_read(path, *args, **kwargs):
        assert path.name != "nvd.json", "NVD must not be materialized with read_text"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)
    # The package branch need not include a Grype DB for a vuln-data package.
    shutil.rmtree(root / "grype-db")
    _write_manifest(root)
    _validate_tree(root, "vuln-data")
    (root / "grype-db" / "5").mkdir(parents=True)
    (root / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (root / "grype-db" / "5" / "import.json").write_text("{}")
    _write_manifest(root)
    engine = DataUpdateEngine(Settings(grype_db_dir=tmp_path / "runtime/current/grype-db"))
    monkeypatch.setattr(engine, "_validate_grype", lambda path: None)
    engine._validate_composite(root)


@pytest.mark.parametrize("nvd_text, expected", [
    ('{"vulnerabilities":[],"unknown":[1,]}', "JSON"),
    ('{"vulnerabilities":[],"vulnerabilities":null}', "NVD"),
    ('[]', "NVD"),
])
def test_engine_validation_error_contracts(tmp_path, monkeypatch, nvd_text, expected):
    root = _tree(tmp_path, nvd_text)
    shutil.rmtree(root / "grype-db")
    _write_manifest(root)
    with pytest.raises(DataUpdateError, match=expected if expected == "JSON" else "NVD data must contain vulnerabilities"):
        _validate_tree(root, "vuln-data")
    (root / "grype-db" / "5").mkdir(parents=True)
    (root / "grype-db" / "5" / "vulnerability.db").write_bytes(b"db")
    (root / "grype-db" / "5" / "import.json").write_text("{}")
    _write_manifest(root)
    engine = DataUpdateEngine(Settings(grype_db_dir=tmp_path / "runtime/current/grype-db"))
    monkeypatch.setattr(engine, "_validate_grype", lambda path: None)
    with pytest.raises(DataUpdateError, match=f"composite vulnerability {expected}" if expected == "JSON" else "composite NVD data is invalid"):
        engine._validate_composite(root)
