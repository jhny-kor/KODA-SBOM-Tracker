"""Public archive contracts shared by SBOM uploads and signed data packages."""
import io
from pathlib import Path
import stat
import struct
import tarfile
import zipfile

import pytest

from koda_tracker.archive_formats import ArchiveError, archive_kind, archive_unpacked_size, create_archive, extract_archive, output_format


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
def test_real_roundtrip_uses_magic_with_opaque_upload_name(tmp_path, kind):
    root = tmp_path / "source"; root.mkdir()
    (root / "unicode 이름").mkdir()
    expected = {"document.json": b'{"components":[]}', "unicode 이름/data.xml": b"<bom/>"}
    for name, value in expected.items(): (root / name).write_bytes(value)
    output = create_archive(root, tmp_path / ("input." + kind))
    opaque = output.rename(tmp_path / "upload.archive")
    assert archive_kind(opaque) == kind
    destination = tmp_path / "expanded"; destination.mkdir()
    result = extract_archive(opaque, destination)
    assert {p.relative_to(destination).as_posix(): p.read_bytes() for p in result} == expected
    assert archive_unpacked_size(opaque) == sum(map(len, expected.values()))
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in result)


def zip_archive(path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries: archive.writestr(name, data)
    return path


@pytest.mark.parametrize("name", ["../outside", "/outside", "dir/../../outside", "C:/outside", "dir\\outside", "dir/./file", "dir//file", "bad\nfile"])
@pytest.mark.parametrize("kind", ["zip", "tar.gz"])
def test_unsafe_entries_rejected_before_any_files_are_written(tmp_path, name, kind):
    path = tmp_path / ("bad." + kind)
    if kind == "zip": zip_archive(path, [("good.json", b"{}"), (name, b"bad")])
    else:
        with tarfile.open(path, "w:gz") as archive:
            for entry in ["good.json", name]:
                member = tarfile.TarInfo(entry); member.size = 2
                archive.addfile(member, io.BytesIO(b"{}"))
    destination = tmp_path / "expanded"; destination.mkdir()
    with pytest.raises(ArchiveError, match="path"):
        extract_archive(path, destination)
    assert not list(destination.iterdir())


@pytest.mark.parametrize("entries", [[("same", b"a"), ("same", b"b")], [("a", b"file"), ("a/b", b"child")], [("a/", b""), ("a", b"file")]])
def test_duplicate_and_file_directory_collision_are_rejected(tmp_path, entries):
    path = zip_archive(tmp_path / "bad.zip", entries)
    destination = tmp_path / "expanded"; destination.mkdir()
    with pytest.raises(ArchiveError, match="duplicate|collision"):
        extract_archive(path, destination)
    assert not list(destination.iterdir())


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK])
def test_zip_links_and_special_files_are_not_materialized(tmp_path, mode):
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w") as archive:
        member = zipfile.ZipInfo("link"); member.create_system = 3; member.external_attr = (mode | 0o777) << 16
        archive.writestr(member, b"/etc/passwd")
    destination = tmp_path / "expanded"; destination.mkdir()
    with pytest.raises(ArchiveError, match="links|special"):
        extract_archive(path, destination)


@pytest.mark.parametrize("limits", [{"max_members": 1}, {"max_member_bytes": 4}, {"max_unpacked_bytes": 8}])
def test_zip_expansion_limits_precede_writes(tmp_path, limits):
    path = zip_archive(tmp_path / "bomb.zip", [("a", bytes(100000)), ("b", b"12345")])
    destination = tmp_path / "expanded"; destination.mkdir()
    with pytest.raises(ArchiveError, match="limit|many"):
        extract_archive(path, destination, **limits)
    assert not list(destination.iterdir())


def test_corrupt_zip_content_removes_partial_extraction(tmp_path):
    path = tmp_path / "crc.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("first", b"11111"); archive.writestr("second", b"22222")
    value = bytearray(path.read_bytes()); position = value.index(b"22222"); value[position] = 0
    path.write_bytes(value)
    destination = tmp_path / "expanded"; destination.mkdir()
    with pytest.raises(ArchiveError): extract_archive(path, destination)
    assert not list(destination.iterdir())


def test_encrypted_zip_refused_without_requesting_a_password(tmp_path):
    path = zip_archive(tmp_path / "encrypted.zip", [("document.json", b"{}")])
    value = bytearray(path.read_bytes())
    for signature, offset in [(b"PK\x03\x04", 6), (b"PK\x01\x02", 8)]:
        position = value.index(signature); value[position + offset] |= 1
    path.write_bytes(value)
    destination = tmp_path / "expanded"; destination.mkdir()
    with pytest.raises(ArchiveError, match="encrypted"): extract_archive(path, destination)


def test_zip_central_directory_allocation_is_bounded_before_zipfile(tmp_path, monkeypatch):
    path = zip_archive(tmp_path / "oversized-directory.zip", [("file", b"x")])
    value = bytearray(path.read_bytes()); position = value.rfind(b"PK\x05\x06")
    struct.pack_into("<L", value, position + 12, 64 * 1024 * 1024); path.write_bytes(value)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *a, **k: pytest.fail("unbounded ZipFile constructor called"))
    with pytest.raises(ArchiveError, match="directory exceeds size limit"): archive_unpacked_size(path)


def test_explicit_format_extension_mismatch_and_rar_do_not_publish(tmp_path):
    root = tmp_path / "source"; root.mkdir(); (root / "file").write_bytes(b"x")
    with pytest.raises(ArchiveError, match="does not match"): create_archive(root, tmp_path / "bad.zip", archive_format="tar")
    with pytest.raises(ArchiveError, match="choose"): create_archive(root, tmp_path / "bad.rar")
    assert output_format(Path("chosen.tgz")) == "tar.gz"
    assert not (tmp_path / "bad.zip").exists()
    assert not (tmp_path / "bad.rar").exists()
    rar = tmp_path / "upload.archive"; rar.write_bytes(b"Rar!\x1a\x07\x01\x00")
    with pytest.raises(ArchiveError, match="RAR"): archive_kind(rar)


def test_generation_never_overwrites_and_rejects_source_links(tmp_path):
    root = tmp_path / "source"; root.mkdir(); (root / "file").write_bytes(b"original")
    target = tmp_path / "package.zip"; target.write_bytes(b"existing")
    with pytest.raises(ArchiveError, match="exists"): create_archive(root, target)
    assert target.read_bytes() == b"existing"
    (root / "link").symlink_to(target)
    with pytest.raises(ArchiveError, match="links"): create_archive(root, tmp_path / "second.zip")
    assert not (tmp_path / "second.zip").exists()


def test_valid_zip64_single_small_document(tmp_path):
    path = tmp_path / "zip64.zip"
    with zipfile.ZipFile(path, "w") as archive:
        with archive.open("bom.json", "w", force_zip64=True) as output: output.write(b"{}")
    destination = tmp_path / "expanded"; destination.mkdir()
    assert extract_archive(path, destination)[0].read_bytes() == b"{}"
