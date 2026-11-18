#!/usr/bin/env python3
"""Copy validated local intelligence sidecars; print metadata.env additions."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
from pathlib import Path
import shutil

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE = next((candidate for candidate in (
    SCRIPT_DIR.parent / "apps/api/koda_tracker/offline_intelligence.py",
    SCRIPT_DIR / "offline_intelligence.py",
    SCRIPT_DIR.parent / "source/apps/api/koda_tracker/offline_intelligence.py",
) if candidate.is_file()), None)
if MODULE is None:
    raise RuntimeError("validated offline intelligence parser is missing from this distribution")
spec = importlib.util.spec_from_file_location("offline_intelligence", MODULE)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def stage(destination: Path, *, epss: Path | None = None, intelligence_index: Path | None = None) -> dict:
    metadata = {}
    if epss is not None:
        if epss.is_symlink() or not epss.is_file() or epss.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("invalid EPSS snapshot")
        raw = epss.read_bytes()
        normalized = parser.normalize_source("epss", raw, {"id": "epss"})
        name = "epss.csv.gz" if raw.startswith(b"\x1f\x8b") else "epss.csv"
        (destination / name).write_bytes(raw)
        metadata.update(EPSS_SNAPSHOT=name, EPSS_DATASET_DATE=normalized["sources"][0]["dataDate"], EPSS_SHA256=hashlib.sha256(raw).hexdigest())
    if intelligence_index is not None:
        document = parser.load_intelligence(intelligence_index.parent, index=intelligence_index.name)
        shutil.copyfile(intelligence_index, destination / "intelligence.json")
        for dataset in document["datasets"].values():
            for source in dataset["sources"]:
                path = source["sourceFile"]
                target = destination / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(intelligence_index.parent / path, target)
        metadata.update(INTELLIGENCE_INDEX="intelligence.json", INTELLIGENCE_SHA256=hashlib.sha256((destination / "intelligence.json").read_bytes()).hexdigest())
    return metadata


def verify(root: Path) -> None:
    metadata = dict(line.split("=", 1) for line in (root / "metadata.env").read_text().splitlines() if "=" in line and not line.startswith("#"))
    for name, key in (("epss.csv", "EPSS_SNAPSHOT"), ("epss.csv.gz", "EPSS_SNAPSHOT"), ("intelligence.json", "INTELLIGENCE_INDEX"), ("intelligence-sources", "INTELLIGENCE_INDEX")):
        if (root / name).exists() and (key not in metadata or (name.startswith("epss.") and metadata[key] != name)):
            raise ValueError(f"undeclared optional intelligence: {name}")
    for key, digest_key, names in (("EPSS_SNAPSHOT", "EPSS_SHA256", {"epss.csv", "epss.csv.gz"}), ("INTELLIGENCE_INDEX", "INTELLIGENCE_SHA256", {"intelligence.json"})):
        if key not in metadata:
            continue
        name = metadata[key]
        file = root / name
        if name not in names or file.is_symlink() or not file.is_file() or file.stat().st_size > parser.MAX_FILE_BYTES:
            raise ValueError(f"invalid {key}")
        raw = file.read_bytes()
        if hashlib.sha256(raw).hexdigest() != metadata.get(digest_key):
            raise ValueError(f"{digest_key} mismatch")
        if key == "EPSS_SNAPSHOT":
            result = parser.normalize_source("epss", raw, {"id": "epss"})
            if result["sources"][0]["dataDate"] != metadata.get("EPSS_DATASET_DATE"):
                raise ValueError("EPSS_DATASET_DATE mismatch")
        else:
            parser.load_intelligence(root)


if __name__ == "__main__":
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--destination", type=Path)
    arguments.add_argument("--epss", type=Path)
    arguments.add_argument("--intelligence-index", type=Path)
    arguments.add_argument("--verify", type=Path)
    args = arguments.parse_args()
    if args.verify:
        verify(args.verify)
    else:
        if not args.destination:
            arguments.error("--destination required")
        for key, value in stage(args.destination, epss=args.epss, intelligence_index=args.intelligence_index).items():
            print(f"{key}={value}")
