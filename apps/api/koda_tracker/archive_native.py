"""Isolated libarchive 7-Zip IO; invoked by archive_formats, never extractall."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import ctypes.util
from dataclasses import asdict
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile

try:
    from . import archive_formats as _formats
    from .archive_formats import ArchiveError, Entry, _checked, _name
except ImportError:  # Executed by absolute filename, including installed wheels.
    import archive_formats as _formats
    from archive_formats import ArchiveError, Entry, _checked, _name


_BUFFER_SIZE = 64 * 1024
_DEFAULT_LIMITS = dict(max_members=100_000, max_unpacked_bytes=12 * 1024**3, max_member_bytes=4 * 1024**3)


class _Library:
    def __init__(self):
        name = ctypes.util.find_library("archive")
        if not name:
            raise ArchiveError("7Z support requires the installed libarchive runtime")
        try:
            self.library = ctypes.CDLL(name)
            pointer, integer = ctypes.c_void_p, ctypes.c_int
            signatures = {
                "archive_read_new": (pointer, []),
                "archive_read_support_filter_none": (integer, [pointer]),
                "archive_read_support_format_7zip": (integer, [pointer]),
                "archive_read_open_fd": (integer, [pointer, integer, ctypes.c_size_t]),
                "archive_read_next_header": (integer, [pointer, ctypes.POINTER(pointer)]),
                "archive_read_data": (ctypes.c_ssize_t, [pointer, pointer, ctypes.c_size_t]),
                "archive_read_data_skip": (integer, [pointer]),
                "archive_read_free": (integer, [pointer]),
                "archive_entry_pathname_utf8": (ctypes.c_char_p, [pointer]),
                "archive_entry_hardlink": (ctypes.c_char_p, [pointer]),
                "archive_entry_symlink": (ctypes.c_char_p, [pointer]),
                "archive_entry_filetype": (ctypes.c_uint, [pointer]),
                "archive_entry_size": (ctypes.c_int64, [pointer]),
                "archive_entry_size_is_set": (integer, [pointer]),
                "archive_entry_is_encrypted": (integer, [pointer]),
                "archive_write_new": (pointer, []),
                "archive_write_set_format_7zip": (integer, [pointer]),
                "archive_write_add_filter_none": (integer, [pointer]),
                "archive_write_set_format_option": (integer, [pointer, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]),
                "archive_write_open_fd": (integer, [pointer, integer]),
                "archive_write_header": (integer, [pointer, pointer]),
                "archive_write_data": (ctypes.c_ssize_t, [pointer, pointer, ctypes.c_size_t]),
                "archive_write_finish_entry": (integer, [pointer]),
                "archive_write_close": (integer, [pointer]),
                "archive_write_free": (integer, [pointer]),
                "archive_entry_new": (pointer, []),
                "archive_entry_set_pathname_utf8": (None, [pointer, ctypes.c_char_p]),
                "archive_entry_set_filetype": (None, [pointer, ctypes.c_uint]),
                "archive_entry_set_perm": (None, [pointer, ctypes.c_uint]),
                "archive_entry_set_size": (None, [pointer, ctypes.c_int64]),
                "archive_entry_free": (None, [pointer]),
                "archive_error_string": (ctypes.c_char_p, [pointer]),
            }
            for symbol, (result, arguments) in signatures.items():
                function = getattr(self.library, symbol)
                function.restype, function.argtypes = result, arguments
                setattr(self, symbol, function)
        except (OSError, AttributeError) as exc:
            raise ArchiveError("installed libarchive lacks required 7Z support") from exc

    def check(self, status, archive):
        if status != 0:
            raw = self.archive_error_string(archive)
            detail = raw.decode("utf-8", "replace")[:500] if raw else "unsupported or corrupt 7Z archive"
            raise ArchiveError(detail)


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def _source(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ArchiveError("archive input must be a regular file")
        yield descriptor
        if _identity(os.fstat(descriptor)) != _identity(before) or _identity(Path(path).lstat()) != _identity(before):
            raise ArchiveError("archive input changed during processing")
    finally:
        os.close(descriptor)


@contextmanager
def _reader(library, descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    archive = library.archive_read_new()
    if not archive:
        raise ArchiveError("cannot allocate 7Z decoder")
    try:
        library.check(library.archive_read_support_filter_none(archive), archive)
        library.check(library.archive_read_support_format_7zip(archive), archive)
        library.check(library.archive_read_open_fd(archive, descriptor, _BUFFER_SIZE), archive)
        yield archive
    finally:
        library.archive_read_free(archive)


def _header(library, archive):
    entry = ctypes.c_void_p()
    status = library.archive_read_next_header(archive, ctypes.byref(entry))
    if status == 1:
        return None
    library.check(status, archive)
    if not entry:
        raise ArchiveError("missing 7Z entry metadata")
    if library.archive_entry_is_encrypted(entry):
        raise ArchiveError("encrypted archives are not allowed")
    if library.archive_entry_hardlink(entry) is not None or library.archive_entry_symlink(entry) is not None:
        raise ArchiveError("links and special files are not allowed")
    filetype = library.archive_entry_filetype(entry)
    if filetype not in (stat.S_IFREG, stat.S_IFDIR):
        raise ArchiveError("links and special files are not allowed")
    pathname = library.archive_entry_pathname_utf8(entry)
    if pathname is None:
        raise ArchiveError("archive pathname is not valid UTF-8")
    name = pathname.decode("utf-8", "strict")
    if not library.archive_entry_size_is_set(entry):
        raise ArchiveError("archive member has no declared size")
    size = library.archive_entry_size(entry)
    directory = filetype == stat.S_IFDIR
    if directory and size:
        raise ArchiveError("archive directory contains data")
    return Entry(name, size, directory)


def _scan(library, descriptor, limits):
    with _reader(library, descriptor) as archive:
        def entries():
            while (entry := _header(library, archive)) is not None:
                yield entry
                library.check(library.archive_read_data_skip(archive), archive)
        return _checked(entries(), **limits)


def scan(source, limits):
    library = _Library()
    with _source(source) as descriptor:
        return _scan(library, descriptor, limits)


def extract(source, destination, limits):
    destination = Path(destination)
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ArchiveError("archive destination must be a private empty directory")
    library = _Library()
    with _source(source) as descriptor:
        entries = _scan(library, descriptor, limits)  # Complete preflight before any filesystem writes.
        position, total, written = 0, 0, []
        buffer = ctypes.create_string_buffer(_BUFFER_SIZE)
        with _reader(library, descriptor) as archive:
            while (raw := _header(library, archive)) is not None:
                name = _name(raw.name, raw.directory)
                if not name:
                    library.check(library.archive_read_data_skip(archive), archive)
                    continue
                entry = Entry(name, raw.size, raw.directory)
                if position >= len(entries) or entry != entries[position]:
                    raise ArchiveError("archive inventory changed during extraction")
                position += 1
                target = destination / name
                if entry.directory:
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    library.check(library.archive_read_data_skip(archive), archive)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(output_fd, "wb") as output:
                    count = 0
                    while True:
                        amount = library.archive_read_data(archive, buffer, min(_BUFFER_SIZE, entry.size - count + 1))
                        if amount < 0:
                            library.check(amount, archive)
                        if not amount:
                            break
                        count += amount
                        total += amount
                        if count > entry.size or count > limits["max_member_bytes"] or total > limits["max_unpacked_bytes"]:
                            raise ArchiveError("archive exceeds actual size limit")
                        output.write(buffer.raw[:amount])
                    if count != entry.size:
                        raise ArchiveError("truncated archive member")
                written.append(name)
        if position != len(entries):
            raise ArchiveError("archive inventory changed during extraction")
        return written


def create7z(source, destination, files):
    root, destination = Path(source).resolve(), Path(destination)
    if not root.is_dir() or destination.is_symlink() or destination.exists():
        raise ArchiveError("invalid archive source or output")
    if root == destination.absolute() or root in destination.absolute().parents:
        raise ArchiveError("output must be outside the source directory")
    if not isinstance(files, list) or not all(isinstance(name, str) for name in files):
        raise ArchiveError("invalid 7Z creation inventory")
    entries = _checked((Entry(name, 0) for name in files), **_DEFAULT_LIMITS)
    if [entry.name for entry in entries] != files:
        raise ArchiveError("7Z creation paths must be normalized")
    library = _Library()
    archive = library.archive_write_new()
    if not archive:
        raise ArchiveError("cannot allocate 7Z encoder")
    try:
        library.check(library.archive_write_set_format_7zip(archive), archive)
        library.check(library.archive_write_add_filter_none(archive), archive)
        library.check(library.archive_write_set_format_option(archive, b"7zip", b"compression", b"lzma2"), archive)
        library.check(library.archive_write_set_format_option(archive, b"7zip", b"compression-level", b"1"), archive)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            library.check(library.archive_write_open_fd(archive, descriptor), archive)
            for name in files:
                path = root / name
                if any(parent.is_symlink() for parent in path.parents if parent != root and root in parent.parents):
                    raise ArchiveError("source links and special files are not allowed")
                with _source(path) as source_fd:
                    size = os.fstat(source_fd).st_size
                    entry = library.archive_entry_new()
                    if not entry:
                        raise ArchiveError("cannot allocate 7Z entry")
                    try:
                        library.archive_entry_set_pathname_utf8(entry, name.encode("utf-8"))
                        library.archive_entry_set_filetype(entry, stat.S_IFREG)
                        library.archive_entry_set_perm(entry, 0o600)
                        library.archive_entry_set_size(entry, size)
                        library.check(library.archive_write_header(archive, entry), archive)
                        count = 0
                        while data := os.read(source_fd, _BUFFER_SIZE):
                            count += len(data)
                            if count > size:
                                raise ArchiveError("source file changed during compression")
                            offset = 0
                            while offset < len(data):
                                remaining = data[offset:]
                                amount = library.archive_write_data(archive, remaining, len(remaining))
                                if amount <= 0 or amount > len(remaining):
                                    if amount < 0:
                                        library.check(amount, archive)
                                    raise ArchiveError("incomplete 7Z write")
                                offset += amount
                        if count != size:
                            raise ArchiveError("source file changed during compression")
                        library.check(library.archive_write_finish_entry(archive), archive)
                    finally:
                        library.archive_entry_free(entry)
            library.check(library.archive_write_close(archive), archive)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        library.archive_write_free(archive)


def _resource_limits():
    def cap(kind, ceiling):
        _soft, hard = resource.getrlimit(kind)
        limit = ceiling if hard == resource.RLIM_INFINITY else min(hard, ceiling)
        resource.setrlimit(kind, (limit, limit))

    if sys.platform.startswith("linux"):
        cap(resource.RLIMIT_AS, 768 * 1024**2)
    cap(resource.RLIMIT_CPU, 600)
    cap(resource.RLIMIT_FSIZE, 12 * 1024**3)
    cap(resource.RLIMIT_CORE, 0)


def main(arguments=None):
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    try:
        _resource_limits()
        if len(arguments) not in (3, 4):
            raise ArchiveError("invalid native archive command")
        operation, source = arguments[:2]
        control = Path(arguments[-1])
        if control.stat().st_size > 32 * 1024**2:
            raise ArchiveError("archive control exceeds size limit")
        options = json.loads(control.read_text(encoding="utf-8"))
        if not isinstance(options, dict):
            raise ArchiveError("invalid archive control")
        limits = options.get("limits") or _DEFAULT_LIMITS
        if set(limits) != set(_DEFAULT_LIMITS) or any(type(value) is not int or value < 0 for value in limits.values()):
            raise ArchiveError("invalid archive limits")
        if operation in {"scan", "scanstd"} and len(arguments) == 3:
            if operation == "scan":
                entries = scan(source, limits)
            else:
                if _formats.archive_kind(Path(source)) not in {"zip", "tar", "tar.gz"}:
                    raise ArchiveError("unsupported standard archive")
                with _source(source):
                    entries = _formats._inspect(Path(source), _formats.archive_kind(Path(source)), limits, _local=True)
            result = [asdict(entry) for entry in entries]
        elif operation in {"extract", "extractstd", "create7z"} and len(arguments) == 4:
            destination = Path(arguments[2])
            with tempfile.TemporaryDirectory(prefix=".7z-work-", dir=destination.parent) as temporary:
                os.environ["TMPDIR"] = temporary
                if operation == "extract":
                    result = extract(source, destination, limits)
                elif operation == "extractstd":
                    if _formats.archive_kind(Path(source)) not in {"zip", "tar", "tar.gz"}:
                        raise ArchiveError("unsupported standard archive")
                    result = [path.relative_to(destination).as_posix() for path in _formats.extract_archive(Path(source), destination, **limits, _local=True)]
                else:
                    create7z(source, destination, options.get("files"))
                    result = None
        else:
            raise ArchiveError("invalid native archive operation")
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except (ArchiveError, OSError, ValueError, TypeError, MemoryError) as exc:
        print(str(exc)[:1000] or "archive decoder exceeded its resource limit", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
