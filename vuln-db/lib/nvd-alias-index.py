#!/usr/bin/env python3
"""Build a compact CVE/GHSA index with offline NVD metadata from NVD 2.0 JSON feeds.

The runtime does not need the full NVD feed. It keeps deterministic aliases and
small CVSS/description/CPE/reference records so analysis can explain findings
without network access.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sqlite3
import sys
import tempfile
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path
from typing import Any, TextIO

_SCRIPT_DIR = Path(__file__).resolve().parent
_READER_DIR = next((directory for directory in (
    _SCRIPT_DIR.parent / "apps/api/koda_tracker",
    _SCRIPT_DIR,
    _SCRIPT_DIR.parent / "source/apps/api/koda_tracker",
    _SCRIPT_DIR.parent.parent / "source/tracker/koda_tracker",
) if (directory / "streaming_nvd.py").is_file()), None)
if _READER_DIR is None:
    raise RuntimeError("NVD streaming reader is missing from this distribution")
sys.path.insert(0, str(_READER_DIR))
from streaming_nvd import Kind, NvdShapeError, read_json_sections


IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z-]+)\b", re.IGNORECASE)


def _identifiers(value: Any) -> set[str]:
    if isinstance(value, str):
        return {match.group(0).upper() for match in IDENTIFIER.finditer(value)}
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(_identifiers(item))
        return result
    if isinstance(value, dict):
        result: set[str] = set()
        for item in value.values():
            result.update(_identifiers(item))
        return result
    return set()


def _cve_record(record: dict[str, Any]) -> dict[str, Any] | None:
    cve = record.get("cve") if isinstance(record.get("cve"), dict) else record
    if not isinstance(cve, dict):
        return None
    identifier = next(iter(_identifiers(cve.get("id"))), None)
    if not identifier or not identifier.startswith("CVE-"):
        return None
    descriptions = [item.get("value") for item in cve.get("descriptions", []) if isinstance(item, dict) and item.get("value") and item.get("lang", "en").lower().startswith("en")]
    if not descriptions:
        descriptions = [item.get("value") for item in cve.get("descriptions", []) if isinstance(item, dict) and item.get("value")]
    metrics: dict[str, Any] = {}
    raw_metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for version, key in (("cvssV4", "cvssMetricV40"), ("cvssV3", "cvssMetricV31"), ("cvssV3", "cvssMetricV30"), ("cvssV2", "cvssMetricV2")):
        entries = raw_metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        data = entries[0].get("cvssData") if isinstance(entries[0], dict) else None
        if isinstance(data, dict):
            metrics[version] = {field: data.get(field) for field in ("baseScore", "baseSeverity", "vectorString") if data.get(field) is not None}
            if entries[0].get("exploitabilityScore") is not None:
                metrics[version]["exploitabilityScore"] = entries[0]["exploitabilityScore"]
            if entries[0].get("impactScore") is not None:
                metrics[version]["impactScore"] = entries[0]["impactScore"]
        if version in metrics:
            break
    cpes: list[str] = []
    configurations = cve.get("configurations", [])
    def collect(value):
        if isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            if isinstance(value.get("criteria"), str):
                cpes.append(value["criteria"])
            for key in ("nodes", "children", "cpeMatch"):
                if key in value:
                    collect(value[key])
    collect(configurations)
    references = [item.get("url") for item in cve.get("references", []) if isinstance(item, dict) and item.get("url")]
    return {
        "id": identifier,
        "description": descriptions[0] if descriptions else None,
        "cvss": metrics,
        "cpe": sorted(set(cpes))[:100],
        # Required for offline applicability. The display-only CPE list above
        # cannot recover version bounds, AND/OR, negation or environment leaves.
        "configurations": copy.deepcopy(configurations) if isinstance(configurations, list) else [],
        # Keep the issuing CNA's products/statuses and version-comparison scheme
        # separate from NVD's CPE applicability conditions.
        "affected": copy.deepcopy(cve.get("affected", [])),
        "sourceIdentifier": cve.get("sourceIdentifier"),
        "applicabilityFormat": "nvd-2.0-configurations-v1",
        "vulnStatus": cve.get("vulnStatus"),
        "weaknesses": copy.deepcopy(cve.get("weaknesses", [])),
        "references": sorted(set(references))[:100],
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
    }


def _merge_feed(database: sqlite3.Connection, path: Path) -> int:
    records_seen = 0
    database.execute("SAVEPOINT nvd_feed")

    def start_section(name: str | None, _kind: Kind | None) -> None:
        nonlocal records_seen
        # Match json.load when a duplicate vulnerabilities field replaces an
        # earlier section, including when the final field is not an array.
        if name == "vulnerabilities" and records_seen:
            database.execute("ROLLBACK TO nvd_feed")
            records_seen = 0

    def add_record(_name: str | None, _key: str | int, record: object) -> None:
        nonlocal records_seen
        if not isinstance(record, dict):
            return
        metadata = _cve_record(record)
        if metadata is None:
            return
        cve = record["cve"] if isinstance(record.get("cve"), dict) else record
        canonical = metadata["id"]
        records_seen += 1
        # A real CVE overrides an alias of the same name. Reference aliases
        # keep their first target, even when the metadata revision is older.
        database.execute(
            "INSERT INTO aliases VALUES (?, ?) ON CONFLICT(alias) DO UPDATE SET cve = excluded.cve",
            (canonical, canonical),
        )
        database.executemany(
            "INSERT INTO aliases VALUES (?, ?) ON CONFLICT(alias) DO NOTHING",
            ((alias, canonical) for alias in _identifiers(cve.get("references", []))),
        )
        modified = metadata["lastModified"]
        database.execute(
            """INSERT INTO vulnerabilities VALUES (?, ?, ?)
               ON CONFLICT(cve) DO UPDATE SET modified = excluded.modified, payload = excluded.payload
               WHERE vulnerabilities.modified IS NULL OR excluded.modified >= vulnerabilities.modified""",
            (canonical, modified if isinstance(modified, str) else None,
             json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True)),
        )

    try:
        read_json_sections(
            path,
            section_names=lambda name, kind: name == "vulnerabilities" and kind == "list",
            on_section=start_section,
            on_entry=add_record,
            allow_root_list=True,
            allow_gzip=True,
        )
    except NvdShapeError:
        # Like the previous indexer, a valid scalar root contains no records.
        pass
    except (ValueError, OSError, EOFError) as error:
        raise ValueError(f"NVD feed {path}: {error}") from error
    database.execute("RELEASE nvd_feed")
    return records_seen


def _populate(database: sqlite3.Connection, inputs: list[Path]) -> int:
    database.executescript("""
        PRAGMA cache_size = -8192;
        CREATE TABLE aliases (alias TEXT PRIMARY KEY, cve TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE vulnerabilities (
            cve TEXT PRIMARY KEY, modified TEXT, payload TEXT NOT NULL
        ) WITHOUT ROWID;
    """)
    return sum(_merge_feed(database, path) for path in inputs)


def build_metadata(inputs: list[Path]) -> tuple[dict[str, str], dict[str, dict[str, Any]], int]:
    """Materialize an index for callers that need a Python mapping."""
    with tempfile.TemporaryDirectory(prefix="nvd-index-") as temporary:
        with closing(sqlite3.connect(Path(temporary) / "index.sqlite3")) as database:
            records_seen = _populate(database, inputs)
            aliases = dict(database.execute("SELECT alias, cve FROM aliases ORDER BY alias"))
            details = {
                cve: json.loads(payload)
                for cve, payload in database.execute("SELECT cve, payload FROM vulnerabilities ORDER BY cve")
            }
    return aliases, details, records_seen


def build_index(inputs: list[Path]) -> tuple[dict[str, str], int]:
    aliases, _, records_seen = build_metadata(inputs)
    return aliases, records_seen


def _write_section(handle: TextIO, rows: Iterable[tuple[str, str]]) -> None:
    handle.write("{")
    separator = "\n"
    for key, value_json in rows:
        handle.write(separator)
        indented = value_json.replace("\n", "\n    ")
        handle.write(f"    {json.dumps(key)}: {indented}")
        separator = ",\n"
    if separator == ",\n":
        handle.write("\n  ")
    handle.write("}")


def write_index(inputs: list[Path], output: Path) -> tuple[int, int]:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".nvd-index-", dir=output.parent) as temporary:
        workspace = Path(temporary)
        with closing(sqlite3.connect(workspace / "index.sqlite3")) as database:
            records_seen = _populate(database, inputs)
            alias_count = database.execute("SELECT count(*) FROM aliases").fetchone()[0]
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=workspace, delete=False) as handle:
                staged = Path(handle.name)
                aliases = database.execute("SELECT alias, cve FROM aliases ORDER BY alias")
                handle.write('{\n  "aliases": ')
                _write_section(handle, ((alias, json.dumps(cve)) for alias, cve in aliases))
                handle.write(',\n  "vulnerabilities": ')
                _write_section(handle, database.execute("SELECT cve, payload FROM vulnerabilities ORDER BY cve"))
                handle.write("\n}\n")
        staged.replace(output)
    return records_seen, alias_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.inputs:
        if not path.is_file():
            parser.error(f"NVD input does not exist: {path}")
    try:
        records_seen, alias_count = write_index(args.inputs, args.output)
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f"NVD index build failed: {error}\n")
    print(f"Built NVD alias index: {args.output} ({records_seen} CVE records, {alias_count} identifiers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
