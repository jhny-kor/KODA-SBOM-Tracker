"""Bounded archive IO for uploaded documents and signed data (not installers)."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile


FORMATS = ("tar.gz", "zip", "tar", "7z")
SUFFIXES = {"tar.gz": (".tar.gz", ".tgz"), "zip": (".zip",), "tar": (".tar",), "7z": (".7z",)}
MEDIA_TYPES = {"tar.gz": "application/gzip", "zip": "application/zip", "tar": "application/x-tar", "7z": "application/x-7z-compressed"}


class ArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    name: str
    size: int
    directory: bool = False


def archive_kind(source: Path) -> str | None:
    """Inspect bytes, never use a client-supplied filename to select a decoder."""
    with Path(source).open("rb") as stream:
        head = stream.read(512)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        raise ArchiveError("RAR archives are not supported")
    if head.startswith(b"\x1f\x8b"):
        return "tar.gz"
    if len(head) == 512 and (head[257:262] == b"ustar" or head == bytes(512)):
        return "tar"
    # Older, valid V7 TAR headers have no ustar marker.
    try:
        tarfile.TarInfo.frombuf(head, "utf-8", "surrogateescape")
        return "tar"
    except (tarfile.HeaderError, ValueError):
        return None


def archive_media_type(kind: str) -> str:
    return MEDIA_TYPES[kind]


def output_format(output: Path, requested: str | None = None) -> str:
    inferred = next((kind for kind, suffixes in SUFFIXES.items() if str(output).lower().endswith(suffixes)), None)
    selected = requested or inferred
    if selected not in FORMATS:
        raise ArchiveError("choose --format tar.gz, zip, tar or 7z and a matching output extension")
    if inferred != selected:
        raise ArchiveError("output extension does not match the selected archive format")
    return selected


def _name(value: str, directory: bool) -> str:
    if not value or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value) or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ArchiveError("archive path traversal or invalid path")
    parts = value.rstrip("/").split("/")
    if parts and parts[0] == ".":
        parts.pop(0)
    if not parts and directory:
        return ""
    if any(part in {"", ".", ".."} for part in parts):
        raise ArchiveError("archive path traversal")
    return "/".join(parts)


def _checked(entries, *, max_members, max_unpacked_bytes, max_member_bytes):
    checked, names, total, name_bytes = [], {}, 0, 0
    for count, entry in enumerate(entries, 1):
        if count > max_members:
            raise ArchiveError("archive has too many members")
        name = _name(entry.name, entry.directory)
        if not name:
            continue
        if len(name.encode("utf-8")) > 4096 or len(PurePosixPath(name).parts) > 64:
            raise ArchiveError("archive path exceeds size limit")
        if name in names:
            raise ArchiveError("duplicate archive member")
        if entry.size < 0 or entry.size > max_member_bytes:
            raise ArchiveError("archive member exceeds size limit")
        total += 0 if entry.directory else entry.size
        if total > max_unpacked_bytes:
            raise ArchiveError("archive exceeds size limit")
        name_bytes += len(name.encode("utf-8"))
        if name_bytes > 16 * 1024 * 1024:
            raise ArchiveError("archive names exceed size limit")
        names[name] = entry.directory
        checked.append(Entry(name, entry.size, entry.directory))
    for name in names:
        for parent in PurePosixPath(name).parents:
            if str(parent) != "." and names.get(str(parent)) is False:
                raise ArchiveError("archive file/directory path collision")
    return checked


def _native(operation, source, destination=None, *, limits=None, files=None):
    command = [sys.executable, str(Path(__file__).with_name("archive_native.py")), operation, str(source)]
    if destination is not None:
        command.append(str(destination))
    # A private control file avoids argument-size limits for large inventories.
    with tempfile.TemporaryDirectory(prefix="koda-archive-control-") as directory:
        control = Path(directory) / "control.json"
        control.write_text(json.dumps({"limits": limits, "files": files}))
        command.append(str(control))
        try:
            result = subprocess.run(command, capture_output=True, timeout=900, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ArchiveError("archive decoder unavailable or resource/time limit exceeded") from exc
    if result.returncode or len(result.stdout) > 32 * 1024 * 1024:
        message = result.stderr.decode("utf-8", "replace").strip()[:1000]
        raise ArchiveError(message or "archive decoder failed or exceeded its resource limit")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise ArchiveError("invalid archive decoder result") from exc


def _zip_bounds(source, max_members):
    # ZipFile loads its central directory eagerly. Bound it BEFORE constructing
    # ZipFile, including ZIP64, so a small-file inventory cannot exhaust the API.
    with Path(source).open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
        position = tail.rfind(b"PK\x05\x06")
        if position < 0 or len(tail) - position < 22:
            raise ArchiveError("invalid ZIP directory")
        record = struct.unpack("<4s4H2LH", tail[position:position + 22])
        if position + 22 + record[7] != len(tail) or record[1] or record[2] or record[3] != record[4]:
            raise ArchiveError("multi-volume or malformed ZIP is not supported")
        count, central_size, central_offset = record[4], record[5], record[6]
        if count == 65535 or central_size == 0xFFFFFFFF or record[6] == 0xFFFFFFFF:
            end = size - len(tail) + position
            if end < 20:
                raise ArchiveError("invalid ZIP64 directory")
            stream.seek(end - 20)
            marker, disk, offset, disks = struct.unpack("<4sLQL", stream.read(20))
            if marker != b"PK\x06\x07" or disk or disks != 1 or offset > end - 76:
                raise ArchiveError("invalid ZIP64 directory")
            stream.seek(offset)
            values = struct.unpack("<4sQ2H2L4Q", stream.read(56))
            if values[0] != b"PK\x06\x06" or values[1] != 44 or values[4] or values[5] or values[6] != values[7]:
                raise ArchiveError("multi-volume or malformed ZIP64 is not supported")
            count, central_size, central_offset = values[7], values[8], values[9]
        if count > max_members:
            raise ArchiveError("archive has too many members")
        if central_size > 32 * 1024 * 1024:
            raise ArchiveError("ZIP directory exceeds size limit")
        if central_offset + central_size > size - len(tail) + position:
            raise ArchiveError("invalid ZIP directory extent")
        # Verify physical records as well as the untrusted EOCD count, before
        # ZipFile allocates one object per central record.
        stream.seek(central_offset)
        end, actual = central_offset + central_size, 0
        while stream.tell() < end:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise ArchiveError("invalid ZIP central record")
            name_size, extra_size, comment_size = struct.unpack_from("<3H", header, 28)
            skip = name_size + extra_size + comment_size
            if stream.tell() + skip > end:
                raise ArchiveError("invalid ZIP central record extent")
            stream.seek(skip, os.SEEK_CUR)
            actual += 1
            if actual > max_members:
                raise ArchiveError("archive has too many members")
        if actual != count:
            raise ArchiveError("ZIP member count does not match directory")


def _entries(source, kind):
    if kind == "zip":
        with zipfile.ZipFile(source) as archive:
            for member in archive.infolist():
                mode = member.external_attr >> 16
                if member.flag_bits & 1:
                    raise ArchiveError("encrypted archives are not allowed")
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or stat.S_ISLNK(mode):
                    raise ArchiveError("links and special files are not allowed")
                if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
                    raise ArchiveError("unsupported ZIP compression method")
                yield Entry(member.orig_filename, member.file_size, member.is_dir())
    else:
        with tarfile.open(source, "r:gz" if kind == "tar.gz" else "r:") as archive:
            for member in archive:
                if not (member.isfile() or member.isdir()):
                    raise ArchiveError("links and special files are not allowed")
                yield Entry(member.name, member.size, member.isdir())


def _inspect(source, kind, limits, *, _local=False):
    if kind == "7z":
        return [Entry(**item) for item in _native("scan", source, limits=limits)]
    if not _local:
        return [Entry(**item) for item in _native("scanstd", source, limits=limits)]
    if kind == "zip":
        _zip_bounds(source, limits["max_members"])
    return _checked(_entries(source, kind), **limits)


def archive_unpacked_size(source, *, max_members=100_000, max_unpacked_bytes=12 * 1024**3, max_member_bytes=4 * 1024**3, _local=False):
    limits = dict(max_members=max_members, max_unpacked_bytes=max_unpacked_bytes, max_member_bytes=max_member_bytes)
    try:
        kind = archive_kind(Path(source))
        if kind is None:
            raise ArchiveError("unsupported archive; use ZIP, TAR.GZ, TAR or 7Z")
        return sum(item.size for item in _inspect(source, kind, limits, _local=_local) if not item.directory)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, UnicodeError, RuntimeError, EOFError, struct.error) as exc:
        raise ArchiveError("invalid or corrupt archive") from exc


def _identity(source):
    value = source.stat()
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _copy(stream, target, expected, remaining):
    count = 0
    with target.open("xb") as output:
        target.chmod(0o600)
        while data := stream.read(min(1024 * 1024, expected - count + 1)):
            count += len(data)
            if count > expected or count > remaining:
                raise ArchiveError("archive exceeds actual size limit")
            output.write(data)
    if count != expected:
        raise ArchiveError("truncated archive member")
    return count


def extract_archive(source, destination, *, max_members=100_000, max_unpacked_bytes=12 * 1024**3, max_member_bytes=4 * 1024**3, _local=False):
    source, destination = Path(source), Path(destination)
    limits = dict(max_members=max_members, max_unpacked_bytes=max_unpacked_bytes, max_member_bytes=max_member_bytes)
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ArchiveError("archive destination must be a private empty directory")
    identity = _identity(source)
    try:
        kind = archive_kind(source)
        if kind is None:
            raise ArchiveError("unsupported archive; use ZIP, TAR.GZ, TAR or 7Z")
        entries = _inspect(source, kind, limits, _local=_local)
        inventory = set(entries)
        if kind == "7z" or not _local:
            written = _native("extract" if kind == "7z" else "extractstd", source, destination, limits=limits)
            if written != [item.name for item in entries if not item.directory]:
                raise ArchiveError("archive inventory changed during extraction")
        else:
            total = 0
            with (zipfile.ZipFile(source) if kind == "zip" else tarfile.open(source, "r:gz" if kind == "tar.gz" else "r:")) as archive:
                for member in (archive.infolist() if kind == "zip" else archive):
                    directory = member.is_dir() if kind == "zip" else member.isdir()
                    name = _name(member.orig_filename if kind == "zip" else member.name, directory)
                    if not name:
                        continue
                    entry = Entry(name, member.file_size if kind == "zip" else member.size, directory)
                    if entry not in inventory:
                        raise ArchiveError("archive inventory changed during extraction")
                    target = destination / name
                    if directory:
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        with (archive.open(member) if kind == "zip" else archive.extractfile(member)) as stream:
                            total += _copy(stream, target, entry.size, max_unpacked_bytes - total)
        if _identity(source) != identity:
            raise ArchiveError("archive changed during extraction")
        return [destination / item.name for item in entries if not item.directory]
    except (ArchiveError, OSError, tarfile.TarError, zipfile.BadZipFile, UnicodeError, RuntimeError, EOFError, struct.error) as exc:
        for child in destination.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("invalid or corrupt archive") from exc


def create_archive(root, output, *, archive_format=None):
    if Path(root).is_symlink() or not Path(root).is_dir():
        raise ArchiveError("source must be a real directory")
    root, output = Path(root).resolve(), Path(output).absolute()
    kind = output_format(output, archive_format)
    if output.exists() or output.is_symlink():
        raise ArchiveError("output already exists")
    if root == output or root in output.parents:
        raise ArchiveError("output must be outside the source directory")
    paths = sorted(root.rglob("*"))
    if any(path.is_symlink() or not (path.is_dir() or path.is_file()) for path in paths):
        raise ArchiveError("source links and special files are not allowed")
    files = [path.relative_to(root).as_posix() for path in paths if path.is_file()]
    for name in files:
        _name(name, False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".archive-build-", dir=output.parent) as temporary:
        packed = Path(temporary) / ("package" + SUFFIXES[kind][0])
        if kind == "zip":
            with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as archive:
                for name in files:
                    archive.write(root / name, name)
        elif kind in {"tar", "tar.gz"}:
            with tarfile.open(packed, "w:gz" if kind == "tar.gz" else "w", dereference=True, **({"compresslevel": 1} if kind == "tar.gz" else {})) as archive:
                for name in files:
                    archive.add(root / name, arcname=name, recursive=False)
        elif kind == "7z":
            _native("create7z", root, packed, files=files)
        with packed.open("r+b") as stream:
            os.fsync(stream.fileno())
        os.link(packed, output)  # atomic, exclusive publication on this filesystem
    return output
