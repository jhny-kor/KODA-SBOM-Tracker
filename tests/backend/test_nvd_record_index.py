from __future__ import annotations

import json
import gc
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import sys
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


_CHILD_CACHE = """
import os, sys
from pathlib import Path
from koda_tracker.nvd_record_index import NvdRecordIndex
from koda_tracker.vulnerability import _nvd_details
index = NvdRecordIndex(Path(sys.argv[1]), Path(sys.argv[2]), _nvd_details)
print(index.path.parent, flush=True)
if sys.argv[3] == 'live':
    sys.stdin.buffer.read(1)
os._exit(0)
"""


def test_abrupt_process_exit_is_reclaimed_and_normal_gc_closes_lease(tmp_path):
    source = tmp_path / "nvd.json"
    source.write_text('{"vulnerabilities":[{"id":"CVE-2020-11111"}]}')
    spool = tmp_path / "spool"
    child = subprocess.run([sys.executable, "-c", _CHILD_CACHE, str(source), str(spool), "exit"], capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    orphan = Path(child.stdout.strip())
    assert orphan.parent == spool and (orphan / "records.sqlite3").is_file()
    # An interrupted build can leave writable DB/journal files, before the
    # completed cache's chmod. They are still recognizable, private cache data.
    (orphan / "records.sqlite3").chmod(0o644)
    with (orphan / "records.sqlite3").open("r+b") as stream:
        stream.truncate(2_500_000_000)  # Sparse: no multi-GB test payload or read.
    (orphan / "records.sqlite3-journal").write_bytes(b"partial SQLite journal")
    index = NvdRecordIndex(source, spool, _nvd_details)
    assert not orphan.exists()
    assert index.path.parent.stat().st_mode & 0o777 == 0o700
    assert (index.path.parent / ".lease").stat().st_mode & 0o777 == 0o400
    directory, descriptor = index.path.parent, index._lease_fd
    del index
    gc.collect()
    assert not directory.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_other_live_instances_and_processes_keep_their_cache(tmp_path):
    source = tmp_path / "nvd.json"
    source.write_text('{"vulnerabilities":[{"id":"CVE-2020-11111"}]}')
    spool = tmp_path / "spool"
    existing = NvdRecordIndex(source, spool, _nvd_details)
    child = subprocess.Popen([sys.executable, "-c", _CHILD_CACHE, str(source), str(spool), "live"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([child.stdout], [], [], 10)[0], "child did not create a cache"
        line = child.stdout.readline()
        assert line, child.stderr.read()
        live = Path(line.strip())
        assert live.parent == spool
        other = NvdRecordIndex(source, spool, _nvd_details)
        assert existing.path.is_file() and (live / "records.sqlite3").is_file()
        assert existing["CVE-2020-11111"]["id"] == "CVE-2020-11111"
        child.communicate("x", timeout=10)
        assert child.returncode == 0
        after_exit = NvdRecordIndex(source, spool, _nvd_details)
        assert not live.exists()
        assert existing.path.is_file() and other.path.is_file() and after_exit.path.is_file()
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)


def test_unknown_foreign_and_symlink_entries_are_preserved(tmp_path, monkeypatch):
    from koda_tracker import nvd_record_index as module
    spool = tmp_path / "spool"
    spool.mkdir()

    def marked(name, magic=module._LEASE_MAGIC):
        directory = spool / name
        directory.mkdir(mode=0o700)
        (directory / ".lease").write_bytes(magic)
        (directory / ".lease").chmod(0o400)
        (directory / "records.sqlite3").write_bytes(b"cache")
        return directory

    unrelated = marked("releases")
    unknown_magic = marked("cve-records-unknown", b"unrecognized lease\n")
    unknown_child = marked("cve-records-extra")
    (unknown_child / "original-sbom.json").write_text("preserve original")
    nonprivate = marked("cve-records-public")
    nonprivate.chmod(0o755)
    missing_lease = spool / "cve-records-no-lease"
    missing_lease.mkdir(mode=0o700)
    symlink_dir = spool / "cve-records-symlink"
    symlink_dir.symlink_to(unrelated, target_is_directory=True)
    symlink_lease = marked("cve-records-linked-lease")
    (symlink_lease / ".lease").unlink()
    (symlink_lease / ".lease").symlink_to(unrelated / ".lease")
    foreign = marked("cve-records-foreign")
    # Exercise the owner boundary without requiring chown/root on the test host.
    uid = os.geteuid()
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "geteuid", lambda: uid + 1)
        module._reclaim_orphaned_caches(spool)
    assert (foreign / "records.sqlite3").read_bytes() == b"cache"
    # Recheck the same entry as its actual owner: it is then an eligible orphan.
    module._reclaim_orphaned_caches(spool)
    assert not foreign.exists()
    for directory in (unrelated, unknown_magic, unknown_child, nonprivate, missing_lease, symlink_dir, symlink_lease):
        assert directory.is_dir()
    assert symlink_dir.is_symlink() and (symlink_lease / ".lease").is_symlink()
    assert (unknown_child / "original-sbom.json").read_text() == "preserve original"
    assert (unrelated / "records.sqlite3").read_bytes() == b"cache"
