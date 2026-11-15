"""Augment native Grype results with supplied CPE identities and local NVD."""
from __future__ import annotations

import copy
from collections import Counter

from .offline_cpe import (
    CONTRACT_VERSION, GLOBAL_PRODUCT, PreparedInventory, _attribute, _fields, _literal,
    candidate_index, evaluate, prepare_inventory, product_key,
)
from .oracle_evidence import LISTENER, read_oracle_home, scoped_oracle_component
from .sbom import iter_components
from .vulnerability import normalize_finding

MAX_IDENTITY_RECHECKS = 4096
MAX_ORACLE_HOME_RECHECKS = 4096
ORACLE_LISTENER_PRODUCT = ("a", "oracle", "rdbms_listener")


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


def _coverage_payload(evaluated: int, inconclusive: Counter, not_evaluated: Counter) -> dict:
    return {
        "evaluated": evaluated,
        "inconclusive": sum(inconclusive.values()),
        "notEvaluated": sum(not_evaluated.values()),
        "reasons": [{"code": code, "count": count} for code, count in sorted((inconclusive + not_evaluated).items())],
    }


def _single_vulnerable_leaf(configurations) -> dict | None:
    """Allow a narrowed inventory only when no environmental clause can change."""
    if len(configurations) != 1:
        return None
    node = configurations[0]
    while not node.get("negate"):
        children = [child for field in ("nodes", "children", "cpeMatch") for child in node.get(field, [])]
        if len(children) != 1:
            return None
        if node.get("cpeMatch"):
            return children[0] if children[0]["vulnerable"] else None
        node = children[0]
    return None


def _component_coverage(by_cpe, details, index, inventory, outcomes, not_evaluated, oracle_home_reasons) -> dict:
    """Count component rows once, without changing the findings or deduplication."""
    evaluated = rechecks = 0
    inconclusive = Counter()
    global_ids = index.get(GLOBAL_PRODUCT, set())
    unresolved_global = any(outcomes[identifier] is None for identifier in global_ids)
    global_matches = {identifier for identifier in global_ids if outcomes[identifier]}
    simple_conditions = {}
    # All affected variants are stored as sets to avoid per-row tuple searches.
    for key, variants in sorted(inventory.products.items()):
        candidates = index.get(key, set())
        has_unresolved = unresolved_global or any(outcomes[identifier] is None for identifier in candidates)
        candidate_ids = sorted(candidates | global_matches) if candidates and not has_unresolved else []
        for cpe, fields in sorted(variants):
            components = by_cpe[cpe]
            count = len(components)
            if _literal(fields[3]) in {None, "-"}:
                not_evaluated["nonconcrete_version"] += count
            elif not details:
                not_evaluated["nvd_unavailable"] += count
            else:
                if oracle_home_reasons:
                    for component in components:
                        ref = component.get("bom-ref")
                        if not isinstance(ref, str) or ref not in oracle_home_reasons:
                            continue
                        count -= 1
                        reason = oracle_home_reasons[ref]
                        if reason:
                            inconclusive[reason] += 1
                        elif candidates or global_matches:
                            evaluated += 1
                        else:
                            not_evaluated["no_indexed_product"] += 1
                if count == 0:
                    continue
                if not candidates:
                    not_evaluated["no_indexed_product"] += count
                    continue
                if has_unresolved:
                    inconclusive["unresolved_applicability"] += count
                    continue
                # A true result for one version must not hide an unresolved
                # comparison for another version of the same product.
                narrowed = None
                for identifier in candidate_ids:
                    matches = outcomes[identifier]
                    if not matches or cpe in matches:
                        continue
                    if identifier not in simple_conditions:
                        leaf = _single_vulnerable_leaf(details[identifier]["configurations"])
                        simple_conditions[identifier] = _fields(leaf["criteria"]) if leaf is not None else None
                    criteria = simple_conditions[identifier]
                    if criteria is not None:
                        if rechecks >= MAX_IDENTITY_RECHECKS:
                            inconclusive["coverage_limit"] += count
                            break
                        rechecks += 1
                        if any(_attribute(expected, actual) is False for expected, actual in zip(criteria[:3], fields[:3])):
                            continue
                        if narrowed is None:
                            narrowed = PreparedInventory({key: [(cpe, fields)]})
                        outcome = evaluate(details[identifier].get("configurations"), narrowed)
                        if outcome.status == "not_affected" or cpe in outcome.matched_cpes:
                            continue
                    inconclusive["unresolved_applicability"] += count
                    break
                else:
                    evaluated += count
    return _coverage_payload(evaluated, inconclusive, not_evaluated)


def enrich_cpe_findings(components: list[dict], context, findings: list[dict]) -> tuple[list[dict], dict]:
    result = copy.deepcopy(findings)
    details = getattr(context, "nvd", {}) or {}
    summary = {"version": CONTRACT_VERSION, "status": "not_evaluated", "inputCpes": 0,
               "invalidCpes": 0, "evaluatedCves": 0, "unknownCves": 0,
               "unresolved": [],
               "affectedCves": 0, "addedFindings": 0, "matchedExisting": 0,
               "legacyDetailsOnly": sum(not isinstance(r, dict) or not r.get("configurations") for r in details.values()),
               "inventoryComplete": False}
    by_cpe = {}
    not_evaluated = Counter()
    oracle_homes = {}
    oracle_listeners = {}
    home_cpes = {}
    shared_environment = set()
    home_reasons = {}
    listeners = {}
    entries = list(iter_components(components))
    oracle_refs = Counter(component.get("bom-ref") for component in entries if isinstance(component.get("bom-ref"), str)
                          and component["bom-ref"].startswith("SPDXRef-KODA-Oracle-"))
    for component in entries:
        cpe = component.get("cpe")
        home = read_oracle_home(component)
        if home and oracle_refs[component["bom-ref"]] != 1:
            home = None
        if home and component.get("name") == LISTENER:
            oracle_listeners[component["bom-ref"]] = (component, home)
        if cpe is None or cpe == "":
            reason = "oracle_listener_version_unconfirmed" if home and component.get("name") == LISTENER else "missing_cpe"
            not_evaluated[reason] += 1
            continue
        summary["inputCpes"] += 1
        try:
            key = product_key(cpe)
        except (TypeError, ValueError):
            summary["invalidCpes"] += 1
            not_evaluated["invalid_cpe"] += 1
            continue
        by_cpe.setdefault(cpe, []).append(component)
        if home:
            ref = component["bom-ref"]
            oracle_homes[ref] = home
            home_cpes.setdefault(home["homeId"], set()).add(cpe)
            if key == ORACLE_LISTENER_PRODUCT:
                home_reasons[ref] = ""
                listeners.setdefault(ref, (cpe, component))
        elif key[:2] != ("a", "oracle"):
            shared_environment.add(cpe)
    for finding in result:
        ref = finding.get("bomRef")
        if not isinstance(ref, str) or ref not in oracle_listeners:
            continue
        component, home = oracle_listeners[ref]
        scoped = scoped_oracle_component(component, home)
        if (finding.get("component") not in (LISTENER, scoped)
                or (finding.get("version") or "") != (component.get("version") or "")):
            continue
        finding.update(component=scoped, componentName=LISTENER, oracleHomeEvidence=home)
    if not by_cpe:
        summary["reason"] = "No concrete CPE 2.3 identities supplied; no package-name inference performed"
        summary["componentCoverage"] = _coverage_payload(0, Counter(), not_evaluated)
        return result, summary
    summary["status"] = "completed" if details else "unavailable"
    index_issues = {}
    index = candidate_index(details, issues=index_issues)
    summary["indexIncompleteCves"] = len(index_issues)
    summary["unmatchedProducts"] = len({product_key(cpe) for cpe in by_cpe}.difference(index))
    candidates = set().union(index.get(GLOBAL_PRODUCT, set()), *(index.get(product_key(cpe), set()) for cpe in by_cpe))
    inventory = prepare_inventory(by_cpe)
    outcomes = {}
    home_inventories = {}
    home_checks = 0
    global_ids = index.get(GLOBAL_PRODUCT, set())
    listener_ids = global_ids | index.get(ORACLE_LISTENER_PRODUCT, set()) if listeners else set()
    home_limit_reached = False
    nvd_source = (getattr(context, "sources", {}).get("nvd") or {}).get("dataAsOf", "unknown")

    def unresolved(identifier, reason, ref=None):
        if len(summary["unresolved"]) < 100:
            row = {"id": identifier, "reason": reason}
            if ref:
                row.update(oracleHomeId=oracle_homes[ref]["homeId"], bomRef=ref)
            summary["unresolved"].append(row)

    for identifier in sorted(candidates):
        record = details[identifier]
        if isinstance(record, dict) and str(record.get("vulnStatus", "")).lower() == "rejected":
            continue
        summary["evaluatedCves"] += 1
        if identifier in index_issues:
            outcomes[identifier] = None
            summary["unknownCves"] += 1
            unresolved(identifier, index_issues[identifier])
            continue
        outcome = evaluate(record.get("configurations"), inventory)
        outcomes[identifier] = None if outcome.status == "unknown" else frozenset(outcome.matched_cpes)
        had_unknown = outcome.status == "unknown"
        if outcome.status == "unknown":
            unresolved(identifier, outcome.reason)
        affected = False
        for cpe in outcome.matched_cpes:
            for component in by_cpe[cpe]:
                ref = component.get("bom-ref")
                if isinstance(ref, str) and ref in listeners:
                    continue
                _add_finding(result, summary, identifier, record, context, component, cpe, outcome, nvd_source)
                affected = True
        scoped_listeners = listeners.items() if identifier in listener_ids and not home_limit_reached else ()
        for ref, (cpe, component) in scoped_listeners:
            home = oracle_homes[ref]
            if home_checks >= MAX_ORACLE_HOME_RECHECKS:
                home_limit_reached = True
                unresolved(identifier, "Oracle Home applicability evaluation limit exceeded", ref)
                break
            home_checks += 1
            # A second Listener cannot establish this installation's match. Its
            # Home can provide prerequisites only from its own supplied CPEs.
            cache_key = (home["homeId"], cpe)
            if cache_key not in home_inventories:
                local = {value for value in home_cpes[home["homeId"]] if product_key(value) != ORACLE_LISTENER_PRODUCT}
                home_inventories[cache_key] = prepare_inventory(sorted(local | shared_environment | {cpe}))
            scoped = evaluate(record.get("configurations"), home_inventories[cache_key])
            if scoped.status == "unknown":
                home_reasons[ref] = "unresolved_applicability"
                had_unknown = True
                unresolved(identifier, scoped.reason, ref)
            elif cpe in scoped.matched_cpes:
                _add_finding(result, summary, identifier, record, context, component, cpe, scoped, nvd_source, home)
                affected = True
        had_unknown = had_unknown or (identifier in listener_ids and home_limit_reached)
        summary["affectedCves"] += affected
        summary["unknownCves"] += had_unknown
    # A globally invalid applicability record can affect each product. With
    # incomplete per-Home checks, only keep already established findings.
    if home_limit_reached or not index_issues.keys().isdisjoint(listener_ids):
        fallback = "coverage_limit" if home_limit_reached else "unresolved_applicability"
        for ref in home_reasons:
            home_reasons[ref] = home_reasons[ref] or fallback
    if not candidates:
        summary["reason"] = "No indexed applicability conditions for supplied products; absence is not proof of safety"
    if details and (summary["invalidCpes"] or summary["unmatchedProducts"] or summary["unknownCves"]):
        summary["status"] = "incomplete"
    summary["componentCoverage"] = _component_coverage(by_cpe, details, index, inventory, outcomes, not_evaluated, home_reasons)
    return result, summary


def _add_finding(result, summary, identifier, record, context, component, cpe, outcome, nvd_source, home=None):
    component_id = scoped_oracle_component(component, home) if home else (
        component.get("purl") or component.get("name") or component.get("bom-ref"))
    version = component.get("version", "")
    ref = component.get("bom-ref", "")
    evidence = {**outcome.payload(), "cpe": cpe, "nvdId": identifier, "dataAsOf": nvd_source}
    if home:
        evidence["oracleHomeId"] = home["homeId"]
    existing = next((item for item in result if identifier in {item.get("canonicalId"), item.get("id"), *(item.get("aliases") or [])}
                     and item.get("component") == component_id and item.get("version", "") == version), None)
    if existing is not None:
        existing.setdefault("cpeEvidence", []).append(evidence)
        if home:
            existing.update(componentName=component["name"], bomRef=ref, oracleHomeEvidence=home)
        summary["matchedExisting"] += 1
        return
    finding = normalize_finding({"id": identifier, "severity": _severity(record), "dataSource": "NVD_LOCAL_CPE"}, context)
    finding.update(component=component_id, version=version, fixedIn=[], sourceKind="nvd_cpe",
                   bomRef=ref, cpeEvidence=[evidence])
    if home:
        finding.update(componentName=component["name"], oracleHomeEvidence=home)
    result.append(finding)
    summary["addedFindings"] += 1
