"""Disposable, bounded-memory NVD records; the signed release remains authoritative."""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from functools import lru_cache
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading

from .streaming_nvd import read_nvd


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
        self._temporary = tempfile.TemporaryDirectory(prefix="cve-records-", dir=cache_parent)
        self.path = Path(self._temporary.name) / "records.sqlite3"
        try:
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
            self._temporary.cleanup()
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
