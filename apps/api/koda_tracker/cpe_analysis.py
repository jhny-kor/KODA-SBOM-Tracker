"""Augment native Grype results with supplied CPE identities and local NVD."""
from __future__ import annotations

import copy

from .offline_cpe import CONTRACT_VERSION, GLOBAL_PRODUCT, candidate_index, evaluate, prepare_inventory, product_key
from .sbom import iter_components
from .vulnerability import normalize_finding


def _severity(record: dict) -> str:
    scores = []
    cvss = record.get("cvss")
    for data in cvss.values() if isinstance(cvss, dict) else []:
        if isinstance(data, dict) and isinstance(data.get("baseScore"), (float, int)):
            scores.append(data["baseScore"])
    metrics = record.get("metrics")
    for entries in metrics.values() if isinstance(metrics, dict) else []:
        for entry in entries if isinstance(entries, list) else []:
            data = entry.get("cvssData", {}) if isinstance(entry, dict) else {}
            if isinstance(data.get("baseScore"), (float, int)):
                scores.append(data["baseScore"])
    score = max(scores, default=None)
    return "Unknown" if score is None else "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "Negligible"


def enrich_cpe_findings(components: list[dict], context, findings: list[dict]) -> tuple[list[dict], dict]:
    result = copy.deepcopy(findings)
    details = getattr(context, "nvd", {}) or {}
    summary = {"version": CONTRACT_VERSION, "status": "not_evaluated", "inputCpes": 0,
               "invalidCpes": 0, "evaluatedCves": 0, "unknownCves": 0,
               "unresolved": [],
               "affectedCves": 0, "addedFindings": 0, "matchedExisting": 0,
               "legacyDetailsOnly": sum(not bool(r.get("configurations")) for r in details.values()),
               "inventoryComplete": False}
    by_cpe = {}
    for component in iter_components(components):
        cpe = component.get("cpe")
        if not cpe:
            continue
        summary["inputCpes"] += 1
        try:
            product_key(cpe)
        except (TypeError, ValueError):
            summary["invalidCpes"] += 1
            continue
        by_cpe.setdefault(cpe, []).append(component)
    if not by_cpe:
        summary["reason"] = "No concrete CPE 2.3 identities supplied; no package-name inference performed"
        return result, summary
    summary["status"] = "completed" if details else "unavailable"
    index_issues = {}
    index = candidate_index(details, issues=index_issues)
    summary["indexIncompleteCves"] = len(index_issues)
    summary["unmatchedProducts"] = len({product_key(cpe) for cpe in by_cpe}.difference(index))
    candidates = set().union(index.get(GLOBAL_PRODUCT, set()), *(index.get(product_key(cpe), set()) for cpe in by_cpe))
    inventory = prepare_inventory(by_cpe)
    for identifier in sorted(candidates):
        record = details[identifier]
        if str(record.get("vulnStatus", "")).lower() == "rejected":
            continue
        summary["evaluatedCves"] += 1
        if identifier in index_issues:
            summary["unknownCves"] += 1
            if len(summary["unresolved"]) < 100:
                summary["unresolved"].append({"id": identifier, "reason": index_issues[identifier]})
            continue
        outcome = evaluate(record.get("configurations"), inventory)
        if outcome.status == "unknown":
            summary["unknownCves"] += 1
            if len(summary["unresolved"]) < 100:
                summary["unresolved"].append({"id": identifier, "reason": outcome.reason})
        if outcome.status != "affected":
            continue
        summary["affectedCves"] += 1
        for cpe in outcome.matched_cpes:
            for component in by_cpe[cpe]:
                component_id = component.get("purl") or component.get("name") or component.get("bom-ref")
                version = component.get("version", "")
                evidence = {**outcome.payload(), "cpe": cpe, "nvdId": identifier,
                            "dataAsOf": (getattr(context, "sources", {}).get("nvd") or {}).get("dataAsOf", "unknown")}
                existing = next((item for item in result if identifier in {item.get("canonicalId"), item.get("id"), *(item.get("aliases") or [])}
                                 and item.get("component") == component_id and item.get("version", "") == version), None)
                if existing is not None:
                    existing.setdefault("cpeEvidence", []).append(evidence)
                    summary["matchedExisting"] += 1
                    continue
                finding = normalize_finding({"id": identifier, "severity": _severity(record), "dataSource": "NVD_LOCAL_CPE"}, context)
                finding.update(component=component_id, version=version, fixedIn=[], sourceKind="nvd_cpe",
                               bomRef=component.get("bom-ref", ""), cpeEvidence=[evidence])
                result.append(finding)
                summary["addedFindings"] += 1
    if not candidates:
        summary["reason"] = "No indexed applicability conditions for supplied products; absence is not proof of safety"
    if details and (summary["invalidCpes"] or summary["unmatchedProducts"] or summary["unknownCves"]):
        summary["status"] = "incomplete"
    return result, summary
