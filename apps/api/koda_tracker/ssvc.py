"""Local CERT/CC Deployer decision table. No network, inferred EPSS inputs or silent defaults."""
from __future__ import annotations

import csv
import hashlib
import io
import itertools
import json
from functools import lru_cache
from pathlib import Path

MODEL = "ssvc:DT_DP:1.0.0"
OPTIONS = {"exploitation": ("none", "public poc", "active"),
           "systemExposure": ("small", "controlled", "open"),
           "automatable": ("no", "yes"),
           "humanImpact": ("low", "medium", "high", "very high")}
OUTCOMES = {"defer", "scheduled", "out-of-cycle", "immediate"}


@lru_cache(maxsize=1)
def decision_table():
    root = Path(__file__).with_name("ssvc_data")
    raw = (root / "deployer-1.0.0.csv").read_bytes()
    provenance = json.loads((root / "provenance.json").read_text())
    if hashlib.sha256(raw).hexdigest() != provenance["sha256"]:
        raise ValueError("SSVC 결정표 해시가 일치하지 않습니다")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))[1:]
    table = {tuple(row[1:5]): row[5] for row in rows}
    expected = set(itertools.product(*OPTIONS.values()))
    if len(rows) != 72 or set(table) != expected or set(table.values()) != OUTCOMES:
        raise ValueError("SSVC 결정표의 입력 조합이 올바르지 않습니다")
    return table, provenance


def evaluate(inputs: dict) -> str | None:
    if set(inputs) != set(OPTIONS):
        raise ValueError("SSVC 입력 항목이 올바르지 않습니다")
    for name, options in OPTIONS.items():
        if inputs[name] is not None and inputs[name] not in options:
            raise ValueError("SSVC 입력값이 올바르지 않습니다: " + name)
    if any(value is None for value in inputs.values()):
        return None  # Product workflow state, never an additional SSVC tree value.
    table, _ = decision_table()
    return table[tuple(inputs[name] for name in OPTIONS)]


def fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def evidence_snapshot(run, revision, finding: dict) -> dict:
    return {"sbomSha256": run.sha256, "dataAsOf": revision.data_as_of,
            "sources": {key: value for key, value in (revision.data_sources or {}).items()
                        if key in {"bundleVersion", "grype", "nvd", "cisaKev", "dataAsOf"}},
            "finding": {key: finding[key] for key in (
                "id", "canonicalId", "aliases", "component", "version", "severity", "cvss", "kev",
                "kevDateAdded", "kevDueDate", "epssEvidence", "epssStatus", "epssScore", "epssDate", "fixedIn",
                "offlineReference", "source", "sourceKind", "cpeEvidence", "nvdCvss", "cwes", "cweStatus",
                "oracleHomeEvidence", "bomRef",
            ) if key in finding}}
