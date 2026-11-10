#!/usr/bin/env python3
"""Build a compact CVE/GHSA index with offline NVD metadata from NVD 2.0 JSON feeds.

The runtime does not need the full NVD feed. It keeps deterministic aliases and
small CVSS/description/CPE/reference records so analysis can explain findings
without network access.
"""

from __future__ import annotations

import argparse
import copy
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


def build_metadata(inputs: list[Path]) -> tuple[dict[str, str], dict[str, dict[str, Any]], int]:
    aliases: dict[str, str] = {}
    details: dict[str, dict[str, Any]] = {}
    records_seen = 0
    for path in inputs:
        with _open_json(path) as handle:
            payload = json.load(handle)
        for record in _records(payload):
            cve = record.get("cve") if isinstance(record.get("cve"), dict) else record
            metadata = _cve_record(record)
            if metadata is None or not isinstance(cve, dict):
                continue
            canonical = metadata["id"]
            records_seen += 1
            aliases[canonical] = canonical
            for alias in _identifiers(cve.get("references", [])):
                aliases.setdefault(alias, canonical)
            previous = details.get(canonical, {}).get("lastModified")
            current = metadata.get("lastModified")
            if isinstance(previous, str) and (not isinstance(current, str) or current < previous):
                continue
            details[canonical] = metadata
    return dict(sorted(aliases.items())), dict(sorted(details.items())), records_seen


def build_index(inputs: list[Path]) -> tuple[dict[str, str], int]:
    aliases, _, records_seen = build_metadata(inputs)
    return aliases, records_seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("inputs", type=Path, nargs="+")
    args = parser.parse_args()
    for path in args.inputs:
        if not path.is_file():
            parser.error(f"NVD input does not exist: {path}")
    aliases, details, records_seen = build_metadata(args.inputs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=args.output.parent, delete=False) as handle:
        json.dump({"aliases": aliases, "vulnerabilities": details}, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(args.output)
    print(f"Built NVD alias index: {args.output} ({records_seen} CVE records, {len(aliases)} identifiers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
