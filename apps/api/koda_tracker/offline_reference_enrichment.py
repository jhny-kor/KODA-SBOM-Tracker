"""Join imported reference evidence without changing scanner verdicts or VEX approval."""
from __future__ import annotations

import copy
import re
from datetime import UTC, date, datetime

from .offline_intelligence import KINDS
from .offline_intelligence_store import reference_manifest
from .sbom import iter_components


def _key(purl, version=""):
    from .package_metadata import parse_purl
    try:
        package = parse_purl(purl, version).package_key
        # Distribution, architecture, repository and subpath are part of the
        # imported product identity, even when the registry cache uses a broad key.
        path, _, subpath = purl.partition("#")
        _, _, qualifiers = path.partition("?")
        return package, qualifiers, subpath
    except (ValueError, TypeError):
        return None


def _exact_product(record, component):
    purl = str(record.get("purl") or "")
    actual = str(component.get("purl") or "")
    if purl and actual and purl == actual:
        return True
    cpe = record.get("cpe")
    return bool(cpe and isinstance(cpe, str) and str(component.get("cpe") or "").lower() == cpe.lower())


def _lifecycle_matches(record, component):
    version = str(component.get("version") or "")
    cycle = str(record.get("cycle") or "")
    if not cycle or not (version == cycle or version.startswith(cycle + ".")):
        return False
    for identifier in record.get("identifiers", []):
        if not isinstance(identifier, dict):
            continue
        value = identifier.get("id") or identifier.get("value") or ""
        kind = identifier.get("type")
        if kind == "purl" and _key(value, version) is not None and _key(value, version) == _key(component.get("purl"), version):
            return True
        if kind in {"cpe", "cpe23"} and _exact_product({"cpe": value}, component):
            return True
    return False


def _licenses(component):
    result = set()
    for value in component.get("licenses", []):
        if isinstance(value, str):
            text = value
        elif isinstance(value, dict):
            text = value.get("expression") or (value.get("license") or {}).get("id") or ""
        else:
            continue
        result.update(token for token in re.findall(r"[A-Za-z0-9.+-]+", text) if token not in {"AND", "OR", "WITH"})
    return result


def enrich_reference_context(components, findings, document, *, at=None):
    at = at or datetime.now(UTC)
    components, findings = copy.deepcopy(components), copy.deepcopy(findings)
    datasets = document.get("datasets", {})
    sources = {(kind, source["id"]): {key: value for key, value in source.items() if key not in {"rawBase64", "sourceFile"}}
               for kind, dataset in datasets.items() for source in dataset.get("sources", [])}

    def evidence(kind, record):
        return {"kind": kind, "source": sources[(kind, record["sourceId"])], "record": copy.deepcopy(record)}

    def records(kind):
        return datasets.get(kind, {}).get("records", [])

    cwe_index, spdx_index, dictionary_index = {}, {}, {}
    lifecycle_index, lifecycle_cpes, metadata_index, match_index = {}, {}, {}, {}
    for record in records("cwe"):
        cwe_index.setdefault(str(record.get("id")).removeprefix("CWE-"), []).append(record)
    for record in records("spdx"):
        spdx_index.setdefault(record.get("id"), []).append(record)
    for record in records("cpe-dictionary"):
        dictionary_index.setdefault(str(record.get("cpeName", "")).lower(), []).append(record)
    for record in records("lifecycle"):
        for identifier in record.get("identifiers", []):
            if not isinstance(identifier, dict):
                continue
            value = identifier.get("id") or identifier.get("value") or ""
            if identifier.get("type") == "purl":
                key = _key(value, "0")
                if key:
                    lifecycle_index.setdefault(key, []).append(record)
            elif identifier.get("type") in {"cpe", "cpe23"}:
                lifecycle_cpes.setdefault(str(value).lower(), []).append(record)
    for record in records("package-metadata"):
        version = str(record.get("currentVersion") or "")
        key = _key(record.get("purl"), version)
        if key:
            metadata_index.setdefault((key, version), []).append(record)
    for record in records("cpe-match"):
        for item in record.get("matches", []):
            if isinstance(item, dict) and item.get("cpeName"):
                match_index.setdefault(str(item["cpeName"]).lower(), []).append(record)
    component_map = {}
    total_components, with_lifecycle, vex_conflicts, with_recommendations = 0, 0, 0, 0
    for component in iter_components(components):
        total_components += 1
        ref = {"lifecycle": [], "licenses": [], "cpe": [], "packageMetadata": [], "cpeMatch": []}
        version = str(component.get("version") or "")
        package_key = _key(component.get("purl"), version)
        cpe = str(component.get("cpe") or "")
        for record in lifecycle_index.get(package_key, []) + lifecycle_cpes.get(cpe.lower(), []):
            if _lifecycle_matches(record, component):
                row = evidence("lifecycle", record)
                eol = record.get("eolDate")
                row["endOfLife"] = record.get("isEol") is True or bool(isinstance(eol, str) and eol[:10] <= at.date().isoformat())
                ref["lifecycle"].append(row)
        with_lifecycle += bool(ref["lifecycle"])
        for identifier in sorted(_licenses(component)):
            matches = spdx_index.get(identifier, [])
            ref["licenses"].append({"id": identifier, "status": "known" if matches else "missing", "evidence": [evidence("spdx", value) for value in matches[:20]]})
        ref["cpe"] = [evidence("cpe-dictionary", value) for value in dictionary_index.get(cpe.lower(), [])[:20]]
        ref["cpeMatch"] = [evidence("cpe-match", record) for record in match_index.get(cpe.lower(), [])[:50]]
        ref["packageMetadata"] = [evidence("package-metadata", record) for record in metadata_index.get((package_key, version), []) if record.get("purl") == component.get("purl")]
        component["offlineReference"] = ref
        from .package_metadata import parse_date
        fresh_metadata = []
        for value in ref["packageMetadata"]:
            metadata_record = value["record"]
            fetched_at = parse_date(metadata_record.get("fetchedAt"))
            expires_at = parse_date(metadata_record.get("expiresAt"))
            if (value["source"].get("status") == "fresh" and metadata_record.get("status") == "fresh"
                    and fetched_at is not None and expires_at is not None
                    and fetched_at <= at < expires_at):
                fresh_metadata.append(value)
        if fresh_metadata:
            # Multiple disagreeing sources remain visible; no policy scalar is
            # injected until the source values agree.
            signatures = {(str(value["record"].get("latestVersion")), str(value["record"].get("currentVersionPublishedAt")), str(value["record"].get("versionDistance"))) for value in fresh_metadata}
            if len(signatures) == 1:
                selected = fresh_metadata[0]
                metadata = {**selected["record"], "status": "fresh", "offlineReferenceSource": selected["source"]}
                component.update(packageMetadata=metadata, metadataStatus="fresh")
                properties = [item for item in component.get("properties", []) if isinstance(item, dict)]
                injected = {"koda:latestVersion": metadata.get("latestVersion"), "koda:publishedAt": metadata.get("currentVersionPublishedAt"), "koda:versionDistance": metadata.get("versionDistance")}
                properties = [item for item in properties if item.get("name") not in injected]
                component["properties"] = properties + [{"name": key, "value": str(value)} for key, value in injected.items() if value is not None]
            else:
                component["offlineReference"]["packageMetadataConflict"] = True
        for identifier in (component.get("purl"), component.get("name"), component.get("bom-ref")):
            if identifier:
                key = (str(identifier), str(component.get("version") or ""))
                previous = component_map.get(key)
                if key in component_map and (previous is None or (previous.get("purl"), previous.get("cpe")) != (component.get("purl"), component.get("cpe"))):
                    component_map[key] = None
                else:
                    component_map[key] = component

    per_cve = {}
    for kind in ("vulnrichment", "csaf", "vex", "ubuntu-oval"):
        for record in records(kind):
            if kind == "ubuntu-oval":
                for cve in record.get("cves", []):
                    per_cve.setdefault(cve.upper(), []).append((kind, record))
            if isinstance(record.get("cve"), str):
                per_cve.setdefault(record["cve"].upper(), []).append((kind, record))
    oval_cache = {}
    flat_inventory = list(iter_components(components))
    for finding in findings:
        ids = {str(value).upper() for value in (finding.get("id"), finding.get("canonicalId"), *(finding.get("aliases") or [])) if value}
        component = component_map.get((str(finding.get("component") or ""), str(finding.get("version") or ""))) or {}
        ref = {"vulnrichment": [], "supplierVex": [], "cwe": [], "supplierVexConflict": False}
        entries = [item for identifier in sorted(ids) for item in per_cve.get(identifier, [])]
        ref["evidenceTruncated"] = len(entries) > 200
        entries = entries[:200]
        for kind, record in entries:
            if kind == "vulnrichment":
                ref["vulnrichment"].append(evidence(kind, record))
            elif _exact_product(record, component):
                row = evidence(kind, record)
                row["applicability"] = "exact_identity" if record.get("supported") is True else "unsupported"
                ref["supplierVex"].append(row)
                if record.get("status") in {"known_not_affected", "not_affected", "false_positive", "fixed", "resolved", "resolved_with_pedigree"}:
                    ref["supplierVexConflict"] = True
        for identifier in finding.get("cwes", []):
            matches = cwe_index.get(str(identifier).removeprefix("CWE-"), [])
            ref["cwe"].append({"id": identifier, "status": "known" if matches else "missing", "evidence": [evidence("cwe", value) for value in matches[:20]]})
        from .ubuntu_oval import evaluate_definition
        ref["ubuntuOval"] = []
        for kind, record in entries:
            if kind != "ubuntu-oval": continue
            key = (record["sourceId"], record.get("id"))
            if key not in oval_cache and len(oval_cache) < 20:
                oval_cache[key] = evaluate_definition(record, flat_inventory)
            result = oval_cache.get(key, {"status": "unknown", "reason": "context_evaluation_budget_exceeded"})
            ref["ubuntuOval"].append({**evidence(kind, record), "evaluation": result})
        suggestions, conflicts = {}, []
        for field in ("exploitation", "automatable"):
            candidates = [(value["record"].get(field), value) for value in ref["vulnrichment"] if value["source"].get("status") == "fresh"]
            values = {value for value, _ in candidates if value is not None}
            if len(values) == 1:
                value = next(iter(values))
                suggestions[field] = "public poc" if value == "poc" else value
            elif len(values) > 1:
                conflicts.append(field)
        if finding.get("kev") is True:
            if suggestions.get("exploitation") not in {None, "active"}:
                conflicts.append("kev_vs_vulnrichment")
            suggestions["exploitation"] = "active"
        if ref["evidenceTruncated"]:
            suggestions = {}
            conflicts.append("incomplete_reference_evidence")
        ref["ssvcRecommendation"] = {"inputs": suggestions, "conflicts": conflicts, "automaticDecision": False,
                                     "missingOrganizationalInputs": ["systemExposure", "humanImpact"],
                                     "reason": "신선한 반입 근거와 KEV를 참고하되 담당자가 입력·가정을 확인해야 합니다"}
        with_recommendations += bool(suggestions)
        vex_conflicts += ref["supplierVexConflict"]
        if component:
            ref["component"] = component["offlineReference"]
        finding["offlineReference"] = ref
    manifest = reference_manifest(document)
    summary = {**manifest, "kinds": {kind: {"status": "missing" if kind not in datasets else "fresh" if all(source.get("status") == "fresh" for source in datasets[kind]["sources"]) else "stale_or_incomplete",
                    "records": len(records(kind))} for kind in sorted(KINDS)},
               "components": total_components, "lifecycleMatches": with_lifecycle,
               "supplierVexConflicts": vex_conflicts, "ssvcRecommendations": with_recommendations,
               "automaticVexSuppression": False, "automaticSsvcDecision": False}
    return components, findings, summary
