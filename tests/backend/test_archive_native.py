"""Exercise the real system libarchive, including hostile 7-Zip inventories."""
import ctypes
import ctypes.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unicodedata
import zipfile

import pytest

from koda_tracker import archive_native
from koda_tracker.archive_formats import ArchiveError, create_archive, extract_archive, archive_unpacked_size


LIMITS = dict(max_members=100, max_unpacked_bytes=1024 * 1024, max_member_bytes=1024 * 1024)


@pytest.fixture
def library():
    if not ctypes.util.find_library("archive"):
        pytest.skip("system libarchive is required for native archive tests")
    return archive_native._Library()


def _untrusted_archive(library, target, members):
    """Build intentionally unchecked names through libarchive's public C API."""
    archive = library.archive_write_new()
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        library.check(library.archive_write_set_format_7zip(archive), archive)
        library.check(library.archive_write_open_fd(archive, descriptor), archive)
        for name, data, filetype in members:
            entry = library.archive_entry_new()
            try:
                library.archive_entry_set_pathname_utf8(entry, name.encode())
                library.archive_entry_set_filetype(entry, filetype)
                library.archive_entry_set_perm(entry, 0o600)
                library.archive_entry_set_size(entry, len(data))
                if filetype == stat.S_IFLNK:
                    setter = library.library.archive_entry_set_symlink
                    setter.argtypes, setter.restype = [ctypes.c_void_p, ctypes.c_char_p], None
                    setter(entry, data)
                library.check(library.archive_write_header(archive, entry), archive)
                if data and filetype != stat.S_IFLNK:
                    assert library.archive_write_data(archive, data, len(data)) == len(data)
                library.check(library.archive_write_finish_entry(archive), archive)
            finally:
                library.archive_entry_free(entry)
        library.check(library.archive_write_close(archive), archive)
    finally:
        library.archive_write_free(archive)
        os.close(descriptor)


def test_actual_7z_child_roundtrip_preserves_unicode_binary_and_empty_files(tmp_path, library):
    source = tmp_path / "source"
    source.mkdir()
    (source / "환경").mkdir()
    values = {"환경/긴 이름.json": '{"이름":"서버"}'.encode(), "binary": bytes(range(256)) * 1024, "empty": b""}
    for name, value in values.items():
        (source / name).write_bytes(value)
    expected = {path.relative_to(source).as_posix(): path.read_bytes() for path in source.rglob("*") if path.is_file()}
    packed = tmp_path / "data.7z"
    create_archive(source, packed)
    assert packed.read_bytes().startswith(b"7z\xbc\xaf\x27\x1c")
    assert stat.S_IMODE(packed.stat().st_mode) == 0o600
    assert archive_unpacked_size(packed) == sum(map(len, values.values()))
    destination = tmp_path / "unpacked"
    destination.mkdir(mode=0o700)
    extracted = extract_archive(packed, destination)
    assert [item.relative_to(destination).as_posix() for item in extracted] == [entry.name for entry in archive_native.scan(packed, LIMITS)]
    names = {item.relative_to(destination).as_posix() for item in extracted}
    if sys.platform == "darwin":
        # Apple's libarchive performs decomposed Unicode pathname conversion.
        assert {unicodedata.normalize("NFC", name) for name in names} == set(expected)
    else:
        assert names == set(expected)
    for name, value in expected.items():
        assert (destination / name).read_bytes() == value
        assert stat.S_IMODE((destination / name).stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".7z-work-*"))


@pytest.mark.parametrize("names", [
    ["../escape"], ["/absolute"], ["C:/drive"], ["back\\slash"], ["line\nbreak"],
    ["a//b"], ["a/./b"], ["same", "same"], ["a/b", "a"],
])
def test_7z_full_preflight_rejects_hostile_inventory_without_writes(tmp_path, library, names):
    packed = tmp_path / "hostile.7z"
    _untrusted_archive(library, packed, [(name, b"data", stat.S_IFREG) for name in names])
    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(ArchiveError):
        archive_native.extract(packed, destination, LIMITS)
    assert list(destination.iterdir()) == []
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("changed", [
    {"max_members": 1}, {"max_unpacked_bytes": 7}, {"max_member_bytes": 3},
])
def test_7z_metadata_limits_are_enforced_before_extracting(tmp_path, library, changed):
    packed = tmp_path / "limited.7z"
    _untrusted_archive(library, packed, [("one", b"abcd", stat.S_IFREG), ("two", b"efgh", stat.S_IFREG)])
    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(ArchiveError):
        archive_native.extract(packed, destination, LIMITS | changed)
    assert list(destination.iterdir()) == []


def test_actual_7z_crc_failure_is_rejected_and_parent_removes_partial_output(tmp_path, library):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data").write_bytes(bytes(range(256)))
    packed = tmp_path / "corrupt.7z"
    create_archive(source, packed)
    raw = bytearray(packed.read_bytes())
    raw[40] ^= 0x40  # Payload only; the 7z header and its declared sizes remain intact.
    packed.write_bytes(raw)
    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(ArchiveError):
        extract_archive(packed, destination)
    assert list(destination.iterdir()) == []


def test_native_decoder_does_not_enable_zip_or_follow_archive_symlinks(tmp_path, library):
    packed = tmp_path / "other.zip"
    with zipfile.ZipFile(packed, "w") as archive:
        archive.writestr("data", "value")
    with pytest.raises(ArchiveError):
        archive_native.scan(packed, LIMITS)
    linked = tmp_path / "linked.7z"
    linked.symlink_to(packed)
    with pytest.raises(OSError):
        archive_native.scan(linked, LIMITS)


def test_actual_7z_symlink_is_rejected_before_any_extraction(tmp_path, library):
    packed = tmp_path / "link.7z"
    _untrusted_archive(library, packed, [("link", b"../outside", stat.S_IFLNK)])
    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(ArchiveError, match="links and special"):
        archive_native.extract(packed, destination, LIMITS)
    assert list(destination.iterdir()) == []


def test_native_create_rejects_source_symlink_and_unsafe_inventory(tmp_path, library):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"private")
    (source / "link").symlink_to(outside)
    with pytest.raises(OSError):
        archive_native.create7z(source, tmp_path / "linked.7z", ["link"])
    with pytest.raises(ArchiveError):
        archive_native.create7z(source, tmp_path / "escape.7z", ["../outside"])
    assert not (tmp_path / "escape.7z").exists()


def test_child_sets_resource_limits_before_native_decoder(tmp_path):
    script = """
import json,resource,sys
from koda_tracker.archive_native import _resource_limits
_resource_limits()
print(json.dumps({name:resource.getrlimit(getattr(resource,name)) for name in ['RLIMIT_CPU','RLIMIT_FSIZE','RLIMIT_CORE'] } | {'linux':sys.platform.startswith('linux'),'address':resource.getrlimit(resource.RLIMIT_AS)}))
"""
    environment = os.environ | {"PYTHONPATH": str(Path(archive_native.__file__).parents[1])}
    result = subprocess.run([sys.executable, "-c", script], env=environment, capture_output=True, text=True, check=True)
    limits = json.loads(result.stdout)
    assert limits["RLIMIT_CPU"] == [600, 600]
    assert limits["RLIMIT_FSIZE"] == [12 * 1024**3, 12 * 1024**3]
    assert limits["RLIMIT_CORE"] == [0, 0]
    if limits["linux"]:
        assert limits["address"] == [768 * 1024**2] * 2


def test_child_7z_temporary_payload_uses_private_output_directory(tmp_path, library):
    source = tmp_path / "source"
    source.mkdir()
    (source / "data").write_bytes(os.urandom(128 * 1024))
    control = tmp_path / "control.json"
    control.write_text(json.dumps({"limits": None, "files": ["data"]}))
    packed = tmp_path / "output.7z"
    environment = os.environ | {"TMPDIR": str(tmp_path / "missing-global-tmp")}
    result = subprocess.run([sys.executable, archive_native.__file__, "create7z", str(source), str(packed), str(control)], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) is None
    assert archive_native.scan(packed, LIMITS)[0].size == 128 * 1024
    assert not list(tmp_path.glob(".7z-work-*"))


@pytest.mark.parametrize("kind", ["zip", "tar", "tar.gz"])
def test_stdlib_archives_use_same_isolated_child_roundtrip(tmp_path, kind):
    source = tmp_path / "source"
    source.mkdir()
    (source / "bom.json").write_text('{"bomFormat":"CycloneDX"}')
    packed = tmp_path / ("documents." + kind)
    create_archive(source, packed)
    assert archive_unpacked_size(packed) == (source / "bom.json").stat().st_size
    destination = tmp_path / "destination"
    destination.mkdir()
    assert extract_archive(packed, destination) == [destination / "bom.json"]
    assert (destination / "bom.json").read_bytes() == (source / "bom.json").read_bytes()


def test_linux_image_includes_runtime_and_preserves_nonroot_boundary():
    root = Path(__file__).parents[2]
    dockerfile = (root / "apps/api/Dockerfile").read_text()
    assert "apt-get install --no-install-recommends -y libarchive-tools" in dockerfile
    assert "USER tracker" in dockerfile
    assert "pip install --no-cache-dir -c constraints.txt" in dockerfile
    assert "libarchive" in (root / "THIRD_PARTY_NOTICES.md").read_text()
