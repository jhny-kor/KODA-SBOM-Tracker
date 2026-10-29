from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tracemalloc

import pytest

from koda_tracker.nvd_record_index import NvdRecordIndex
from koda_tracker.vulnerability import _nvd_details


def build(tmp_path, raw):
    source = tmp_path / "nvd.json"
    source.write_text(raw, encoding="utf-8")
    return NvdRecordIndex(source, tmp_path / "spool", _nvd_details)


@pytest.mark.parametrize("raw", [
    '{"vulnerabilities":[{"id":"CVE-2020-99999","description":"old"},{"cve":{"id":"CVE-2020-11111"}},{"id":"CVE-2020-99999","description":"last"}]}',
    '{"vulnerabilities":{"x":{"id":"CVE-2020-99999"},"y":{"id":"CVE-2020-99999","description":"y"},"x":{"id":"CVE-2020-11111","description":"last x"}}}',
    '{"vulnerabilities":{"x":{"id":"CVE-2020-99999"},"y":{"id":"CVE-2020-99999","description":"y"},"x":false}}',
    '{"vulnerabilities":{"x":{"id":"CVE-2020-99999"}},"vulnerabilities":[{"id":"CVE-2020-11111"}]}',
    '{"vulnerabilities":false,"vulnerabilities":[{"id":"CVE-2020-11111","description":"한글 🌏"}]}',
    '[{"id":"CVE-2020-99999","cvss":{"score":NaN}},{"id":"CVE-2020-11111"}]',
])
def test_disk_index_matches_json_normalization_sort_and_duplicate_precedence(tmp_path, raw):
    expected = _nvd_details(json.loads(raw))
    index = build(tmp_path, raw)
    # NaN requires serialization comparison rather than Python float equality.
    assert json.dumps(dict(index.items()), sort_keys=True) == json.dumps(expected, sort_keys=True)
    assert list(index) == sorted(expected)
    assert len(index) == len(expected)
    for key in expected:
        assert json.dumps(index[key], sort_keys=True) == json.dumps(expected[key], sort_keys=True)
    assert index.get("CVE-1900-00000") is None


@pytest.mark.parametrize("raw", [
    '{"vulnerabilities":[]} trailing',
    '{"vulnerabilities":[{"id":"CVE-2020-11111"}]} false',
    '{"vulnerabilities":{},"vulnerabilities":false}',
])
def test_invalid_source_never_leaves_partial_cache(tmp_path, raw):
    with pytest.raises(ValueError):
        build(tmp_path, raw)
    assert list((tmp_path / "spool").iterdir()) == []


def test_cache_mutation_is_detected_and_connections_are_read_only(tmp_path):
    index = build(tmp_path, '{"vulnerabilities":[{"id":"CVE-2020-11111"}]}')
    assert index.path.stat().st_mode & 0o777 == 0o400
    with index._connection() as db, pytest.raises(sqlite3.OperationalError):
        db.execute("DELETE FROM records")
    index.path.chmod(0o600)
    with sqlite3.connect(index.path) as db:
        db.execute("DELETE FROM records")
    index.path.chmod(0o400)
    with pytest.raises(ValueError, match="changed"):
        index.get("CVE-2020-11111")


def test_mutation_during_iteration_is_rejected_at_context_exit(tmp_path):
    index = build(tmp_path, '{"vulnerabilities":[{"id":"CVE-2020-11111"}]}')
    with pytest.raises(ValueError, match="changed"):
        with index.checked():
            index.path.chmod(0o600)
            index.path.write_bytes(b"tampered")


def test_large_unicode_source_uses_bounded_python_memory(tmp_path):
    source = tmp_path / "large.json"
    with source.open("w", encoding="utf-8") as stream:
        stream.write('{"aliases":{')
        for n in range(15000):
            if n:
                stream.write(',')
            stream.write(json.dumps(str(n)) + ':"CVE-2020-11111"')
        stream.write('},"vulnerabilities":[')
        for n in range(15000):
            if n:
                stream.write(',')
            json.dump({"id": f"CVE-2020-{10000+n}", "description": "한글🌏" * 250}, stream, ensure_ascii=False)
        stream.write(']}')
    tracemalloc.start()
    try:
        index = NvdRecordIndex(source, tmp_path / "spool", _nvd_details)
        assert len(index) == 15000
        assert next(iter(index.items()))[0] == "CVE-2020-10000"
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert source.stat().st_size > 30 * 1024 * 1024
    assert peak < 16 * 1024 * 1024


def test_concurrent_cold_requests_share_one_disk_index(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from koda_tracker import nvd_record_index as module
    source = tmp_path / "nvd.json"
    source.write_text('{"vulnerabilities":[{"id":"CVE-2020-11111"}]}')
    original = module.NvdRecordIndex
    constructions = []
    gate = threading.Barrier(4)

    def construct(*args):
        constructions.append(1)
        return original(*args)

    monkeypatch.setattr(module, "NvdRecordIndex", construct)
    module.cached_nvd_records.cache_clear()

    def request(_):
        gate.wait()
        index = module.cached_nvd_records(str(source), (1,), "manifest", str(tmp_path / "spool"), _nvd_details)
        return index.path, index.get("CVE-2020-11111")

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(request, range(4)))
        assert len(constructions) == 1
        assert len({str(path) for path, _record in results}) == 1
        assert all(record["id"] == "CVE-2020-11111" for _path, record in results)
    finally:
        module.cached_nvd_records.cache_clear()


@pytest.mark.parametrize("descriptions", [1, True, {}, "legacy value", None])
def test_optional_description_shape_never_breaks_existing_analysis_records(tmp_path, descriptions):
    payload = {"vulnerabilities": [{"id": "CVE-2020-11111", "descriptions": descriptions}]}
    expected = _nvd_details(payload)
    index = build(tmp_path, json.dumps(payload))
    assert dict(index.items()) == expected
    assert [identifier for identifier, _record in index.items("CVE-2020-11111")] == ["CVE-2020-11111"]
