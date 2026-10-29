"""Disposable, bounded-memory NVD records; the signed release remains authoritative."""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from functools import lru_cache
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import threading
import weakref

from .streaming_nvd import read_nvd

_CACHE_PREFIX = "cve-records-"
_LEASE_NAME = ".lease"
_LEASE_MAGIC = b"KODA Tracker disposable NVD SQLite cache lease v1\n"
_CACHE_FILES = {_LEASE_NAME, "records.sqlite3", "records.sqlite3-journal"}
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _reclaim_cache(parent_fd, name, uid):
    """Remove only an unlocked, recognizable, flat cache owned by this user."""
    if not name.startswith(_CACHE_PREFIX):
        return
    directory_fd = lease_fd = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode) or before.st_uid != uid or stat.S_IMODE(before.st_mode) != 0o700:
            return
        directory_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        if _stat_identity(os.fstat(directory_fd)) != _stat_identity(before):
            return
        lease_fd = os.open(_LEASE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        lease = os.fstat(lease_fd)
        if (not stat.S_ISREG(lease.st_mode) or lease.st_uid != uid or
                stat.S_IMODE(lease.st_mode) != 0o400 or lease.st_nlink != 1 or
                lease.st_size != len(_LEASE_MAGIC)):
            return
        fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.read(lease_fd, len(_LEASE_MAGIC) + 1) != _LEASE_MAGIC:
            return
        children = {}
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if (entry.name not in _CACHE_FILES or not stat.S_ISREG(info.st_mode) or
                        info.st_uid != uid or info.st_nlink != 1):
                    return
                children[entry.name] = _stat_identity(info)
        if children.get(_LEASE_NAME) != _stat_identity(lease):
            return
        if (_stat_identity(os.fstat(directory_fd)) != _stat_identity(before) or
                _stat_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != _stat_identity(before)):
            return
        for child, expected in children.items():
            if _stat_identity(os.stat(child, dir_fd=directory_fd, follow_symlinks=False)) != expected:
                return
        # The opened directory anchors every unlink. Never recurse into other
        # directories, and retain the lease until the potentially huge DB is gone.
        for child in children:
            if child != _LEASE_NAME:
                if _stat_identity(os.stat(child, dir_fd=directory_fd, follow_symlinks=False)) != children[child]:
                    return
                os.unlink(child, dir_fd=directory_fd)
        if _stat_identity(os.stat(_LEASE_NAME, dir_fd=directory_fd, follow_symlinks=False)) != _stat_identity(lease):
            return
        os.unlink(_LEASE_NAME, dir_fd=directory_fd)
        if _stat_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) == _stat_identity(os.fstat(directory_fd)):
            os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        # A live lock, inaccessible/changed entry or another collector wins:
        # preserve it and let normal cache creation report its own I/O errors.
        return
    finally:
        if lease_fd is not None:
            os.close(lease_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _reclaim_orphaned_caches(parent):
    parent_fd = os.open(parent, _DIRECTORY_FLAGS)
    try:
        with os.scandir(parent_fd) as entries:
            for entry in entries:
                if entry.name.startswith(_CACHE_PREFIX):
                    _reclaim_cache(parent_fd, entry.name, os.geteuid())
    finally:
        os.close(parent_fd)


def _open_cache_lease(directory):
    descriptor = os.open(directory / _LEASE_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        # Publish the recognizable magic only after holding the lifetime lock.
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        if os.write(descriptor, _LEASE_MAGIC) != len(_LEASE_MAGIC):
            raise OSError("incomplete NVD cache lease")
        os.fchmod(descriptor, 0o400)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _cleanup_cache(temporary, descriptor):
    try:
        temporary.cleanup()
    finally:
        os.close(descriptor)


def _identity(path):
    stat = path.lstat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
            stat.st_ctime_ns, stat.st_mode)


def nvd_description(record):
    if isinstance(record.get("description"), str):
        return record["description"]
    values = record.get("descriptions")
    if not isinstance(values, list):
        values = []
    return next((item.get("value", "") for item in values if isinstance(item, dict) and item.get("lang") == "en"), next((item.get("value", "") for item in values if isinstance(item, dict)), ""))


class NvdRecordIndex(Mapping):
    """Retain JSON key insertion order and normalized ID last-value precedence.

    Each source key occupies one row. Replacing its value keeps its first
    position, matching json.loads. Distinct keys with the same normalized ID
    are resolved using their original positions. Connections are request-local.
    """

    def __init__(self, source, cache_parent, normalize_fn):
        cache_parent = Path(cache_parent).resolve()
        cache_parent.mkdir(parents=True, exist_ok=True)
        _reclaim_orphaned_caches(cache_parent)
        self._temporary = tempfile.TemporaryDirectory(prefix=_CACHE_PREFIX, dir=cache_parent)
        self.path = Path(self._temporary.name) / "records.sqlite3"
        try:
            self.path.parent.chmod(0o700)
            self._lease_fd = _open_cache_lease(self.path.parent)
            self._cleanup = weakref.finalize(self, _cleanup_cache, self._temporary, self._lease_fd)
            with sqlite3.connect(self.path) as db:
                db.execute("PRAGMA cache_size=-4096")
                db.execute("CREATE TABLE records (source_key TEXT PRIMARY KEY, position INTEGER NOT NULL, id TEXT, record_json TEXT NOT NULL, search_text BLOB NOT NULL) WITHOUT ROWID")
                db.execute("CREATE INDEX records_by_id ON records(id, position DESC)")
                position = 0

                def reset(_kind):
                    nonlocal position
                    db.execute("DELETE FROM records")
                    position = 0

                def entry(key, value):
                    nonlocal position
                    values = normalize_fn([value])
                    identifier, record = next(iter(values.items()), (None, {}))
                    db.execute("INSERT INTO records VALUES (?, ?, ?, ?, ?) ON CONFLICT(source_key) DO UPDATE SET id=excluded.id, record_json=excluded.record_json, search_text=excluded.search_text",
                               (json.dumps(key), position, identifier,
                                json.dumps(record, ensure_ascii=True, separators=(",", ":")),
                                f"{identifier} {nvd_description(record)}".casefold().encode("utf-8", "surrogatepass")))
                    position += 1

                read_nvd(Path(source), on_section=reset, on_entry=entry, allow_root_list=True)
            db.close()
            os.chmod(self.path, 0o400)
            self._file_identity = _identity(self.path)
        except BaseException:
            if "db" in locals():
                db.close()
            if hasattr(self, "_cleanup"):
                self._cleanup()
            else:
                try:
                    self._temporary.cleanup()
                finally:
                    if hasattr(self, "_lease_fd"):
                        os.close(self._lease_fd)
            raise

    @contextmanager
    def checked(self):
        if self.path.is_symlink() or _identity(self.path) != self._file_identity:
            raise ValueError("NVD temporary index changed; retry from the approved release")
        try:
            yield
        finally:
            if self.path.is_symlink() or _identity(self.path) != self._file_identity:
                raise ValueError("NVD temporary index changed; retry from the approved release")

    @contextmanager
    def _connection(self):
        with self.checked():
            # immutable prevents journaling and does not grant write access.
            db = sqlite3.connect(self.path.as_uri() + "?mode=ro&immutable=1", uri=True)
            db.execute("PRAGMA cache_size=-4096")
            try:
                yield db
            finally:
                db.close()

    def __getitem__(self, identifier):
        with self._connection() as db:
            row = db.execute("SELECT record_json FROM records WHERE id=? ORDER BY position DESC LIMIT 1", (identifier,)).fetchone()
            if row is None:
                raise KeyError(identifier)
            return json.loads(row[0])

    def __len__(self):
        with self._connection() as db:
            return db.execute("SELECT COUNT(DISTINCT id) FROM records").fetchone()[0]

    def __iter__(self):
        with self._connection() as db:
            for row in db.execute("SELECT DISTINCT id FROM records WHERE id IS NOT NULL ORDER BY id COLLATE BINARY"):
                yield row[0]

    def items(self, query=""):
        with self._connection() as db:
            predicate = " AND instr(r.search_text, ?) > 0" if query else ""
            parameters = (query.casefold().encode("utf-8", "surrogatepass"),) if query else ()
            cursor = db.execute("SELECT r.id, r.record_json FROM records AS r WHERE r.id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM records AS later WHERE later.id=r.id AND later.position>r.position)" + predicate + " ORDER BY r.id COLLATE BINARY", parameters)
            for identifier, record_json in cursor:
                yield identifier, json.loads(record_json)


    def values(self):
        for _identifier, record in self.items():
            yield record


@lru_cache(maxsize=2)
def _cached_nvd_records(source, source_identity, manifest_hash, cache_parent, normalize_fn):
    """Share a disposable index only for the exact immutable release identity."""
    return NvdRecordIndex(source, cache_parent, normalize_fn)


_index_build_lock = threading.RLock()


def cached_nvd_records(source, source_identity, manifest_hash, cache_parent, normalize_fn):
    # lru_cache alone permits duplicate simultaneous cold builds of a multi-GB
    # source. Serialize construction while keeping SQLite readers independent.
    with _index_build_lock:
        return _cached_nvd_records(source, source_identity, manifest_hash, cache_parent, normalize_fn)


cached_nvd_records.cache_clear = _cached_nvd_records.cache_clear
cached_nvd_records.cache_info = _cached_nvd_records.cache_info
