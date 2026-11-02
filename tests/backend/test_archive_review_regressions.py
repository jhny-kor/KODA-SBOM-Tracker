"""Compatibility checks from the independent archive implementation review."""
import gzip
import io
import os
import struct
import tarfile
import zipfile

import pytest

from koda_tracker.archive_formats import ArchiveError, _zip_bounds, archive_unpacked_size, create_archive, extract_archive


def test_zip_actual_member_count_is_checked_before_object_allocation(tmp_path, monkeypatch):
    archive = tmp_path / "records.zip"
    with zipfile.ZipFile(archive, "w") as target:
        for index in range(8): target.writestr(str(index), b"x")
    raw = bytearray(archive.read_bytes()); end = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, end + 8, 0, 0)
    archive.write_bytes(raw)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: pytest.fail("ZipFile allocated records before validation"))
    with pytest.raises(ArchiveError, match="too many members"):
        _zip_bounds(archive, 2)


def test_truncated_gzip_remains_a_validation_error_and_cleans_up(tmp_path):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        member = tarfile.TarInfo("document.json"); member.size = 8192
        archive.addfile(member, io.BytesIO(os.urandom(member.size)))
    archive = tmp_path / "truncated.tar.gz"
    archive.write_bytes(gzip.compress(raw.getvalue())[:2000])
    target = tmp_path / "out"; target.mkdir()
    with pytest.raises(ArchiveError): archive_unpacked_size(archive)
    with pytest.raises(ArchiveError): extract_archive(archive, target)
    assert not list(target.iterdir())


@pytest.mark.parametrize("kind", ["tar", "tar.gz"])
def test_source_hardlinks_are_serialized_as_independent_regular_files(tmp_path, kind):
    root = tmp_path / "source"; root.mkdir()
    (root / "first.json").write_bytes(b"{}")
    os.link(root / "first.json", root / "second.json")
    output = create_archive(root, tmp_path / ("output." + kind))
    target = tmp_path / "out"; target.mkdir()
    assert sorted(p.read_bytes() for p in extract_archive(output, target)) == [b"{}", b"{}"]


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_standard_zip_compression_methods_keep_the_same_document(tmp_path, method):
    archive = tmp_path / "document.zip"
    with zipfile.ZipFile(archive, "w", compression=method) as target:
        target.writestr("bom.json", b'{"bomFormat":"CycloneDX"}')
    target = tmp_path / "out"; target.mkdir()
    assert extract_archive(archive, target)[0].read_bytes() == b'{"bomFormat":"CycloneDX"}'
