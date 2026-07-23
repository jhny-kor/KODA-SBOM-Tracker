#!/usr/bin/env python3
"""Build a compact CVE/GHSA alias index from NVD 2.0 JSON feeds.

The runtime does not need the full NVD feed. It only needs a deterministic
mapping for aliases that appeared in CVE references, so this helper keeps the
closed-network bundle small and avoids parsing multi-hundred-megabyte feeds on
every SBOM analysis.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import tempfile
from pathlib import Path
from typing import Any, TextIO


IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9A-Z-]+)\b", re.IGNORECASE)


def _open_json(path: Path) -> TextIO:
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


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


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        return [item for item in payload["vulnerabilities"] if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def build_index(inputs: list[Path]) -> tuple[dict[str, str], int]:
    aliases: dict[str, str] = {}
    records_seen = 0
    for path in inputs:
        with _open_json(path) as handle:
            payload = json.load(handle)
        for record in _records(payload):
            cve = record.get("cve") if isinstance(record.get("cve"), dict) else record
            canonical = next(iter(_identifiers(cve.get("id"))), None) if isinstance(cve, dict) else None
            if not canonical or not canonical.startswith("CVE-"):
                continue
            records_seen += 1
            aliases[canonical] = canonical
            references = cve.get("references", []) if isinstance(cve, dict) else []
            for alias in _identifiers(references):
                aliases.setdefault(alias, canonical)
    return dict(sorted(aliases.items())), records_seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.inputs:
        if not path.is_file():
            parser.error(f"NVD input does not exist: {path}")
    aliases, records_seen = build_index(args.inputs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=args.output.parent, delete=False) as handle:
        json.dump(aliases, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(args.output)
    print(f"Built NVD alias index: {args.output} ({records_seen} CVE records, {len(aliases)} identifiers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
