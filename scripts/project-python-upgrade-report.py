#!/usr/bin/env python3
"""Project a local-wheel pip installation report into Tracker Python evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

_MAX_REPORT_BYTES = 32 * 1024 * 1024
_REQUIRED_MARKERS = ("python_full_version", "implementation_name", "sys_platform", "platform_machine")
_OPTIONAL_MARKERS = ("implementation_version", "os_name", "platform_release", "platform_system",
                     "platform_version", "python_version", "platform_python_implementation")


def project_report(data: bytes, source: str) -> dict:
    if not source.strip() or len(source) > 255:
        raise ValueError("source must identify the isolated resolver run in at most 255 characters")
    report = json.loads(data)
    if report["version"] != "1" or not isinstance(report["pip_version"], str) or not report["pip_version"]:
        raise ValueError("unsupported pip installation report")
    environment = report["environment"]
    if any(not isinstance(environment.get(key), str) or not environment[key] for key in _REQUIRED_MARKERS):
        raise ValueError("pip report lacks target runtime or platform markers")
    markers = {key: environment[key] for key in _REQUIRED_MARKERS + _OPTIONAL_MARKERS if key in environment}
    if any(not isinstance(value, str) or len(value) > 255 for value in markers.values()):
        raise ValueError("invalid pip environment marker")
    if not isinstance(report["install"], list) or not 1 <= len(report["install"]) <= 2_000:
        raise ValueError("pip report must contain 1 to 2000 selected packages")

    packages = []
    for entry in report["install"]:
        download = entry["download_info"]
        url = urlsplit(download["url"])
        sha256 = download.get("archive_info", {}).get("hashes", {}).get("sha256", "")
        if (url.scheme != "file" or url.netloc not in {"", "localhost"} or url.query or url.fragment
                or not unquote(url.path).lower().endswith(".whl") or not re.fullmatch(r"[0-9a-f]{64}", sha256)):
            raise ValueError("each selected artifact must be a local wheel with a SHA-256 in the pip report")
        name, version, requested = entry["metadata"]["name"], entry["metadata"]["version"], entry["requested"]
        if not all(isinstance(value, str) and 1 <= len(value) <= 255 for value in (name, version)) or type(requested) is not bool:
            raise ValueError("invalid package identity in pip report")
        packages.append({"name": name, "version": version, "requested": requested, "wheelSha256": sha256})

    return {"kind": "python", "source": source, "outcome": "resolved", "pipVersion": report["pip_version"],
            "reportSha256": hashlib.sha256(data).hexdigest(), "environment": markers, "packages": packages}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="pip --dry-run --report JSON from an offline target-equivalent runner")
    parser.add_argument("--source", required=True, help="CI or isolated runner reference")
    args = parser.parse_args()
    try:
        with args.report.open("rb") as file:
            data = file.read(_MAX_REPORT_BYTES + 1)
        if len(data) > _MAX_REPORT_BYTES:
            raise ValueError("pip report exceeds 32 MiB")
        print(json.dumps(project_report(data, args.source), ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError, AttributeError, TypeError) as error:
        print(f"Could not project Python evidence: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
