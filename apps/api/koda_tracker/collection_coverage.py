"""Read bounded, self-reported KODA collection evidence from an uploaded SBOM."""

from __future__ import annotations

import json
import re

KEY = "koda:collection:coverage:v1"
SPDX_ROOT_KEY = KEY + ":spdx-root"
MAX_VALUE_LENGTH = 16384
MAX_ISSUE_CODES = 64
MAX_COUNT = 2_147_483_647
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DISTRO_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_DISTRO_VERSION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}")
_SOURCES = {"filesystem", "image-archive", "aix-evidence"}
_SPDX_ROOT_NAMES = {
    "SPDXRef-DocumentRoot-Directory-local-filesystem": "local-filesystem",
    "SPDXRef-DocumentRoot-Directory-IBM-AIX-evidence": "IBM AIX evidence",
}


def spdx_coverage_properties(document: dict) -> list[dict]:
    comment = document.get("comment")
    prefix = KEY + " "
    if not isinstance(comment, str) or not comment.startswith(prefix):
        return []
    value = comment[len(prefix):] if len(comment) <= len(prefix) + MAX_VALUE_LENGTH else ""
    properties = [{"name": KEY, "value": value}]
    roots = {
        relation["relatedSpdxElement"]
        for relation in document.get("relationships", [])
        if relation["spdxElementId"] == "SPDXRef-DOCUMENT"
        and relation["relationshipType"] == "DESCRIBES"
    }
    if len(roots) == 1 and (root := next(iter(roots))) in _SPDX_ROOT_NAMES:
        properties.append({"name": SPDX_ROOT_KEY, "value": root})
    return properties


def _properties(bom: dict, key: str) -> list:
    metadata = bom.get("metadata")
    return _property_values(metadata, key)


def _property_values(owner: object, key: str) -> list:
    properties = owner.get("properties") if isinstance(owner, dict) else None
    if not isinstance(properties, list):
        return []
    return [prop.get("value") for prop in properties if isinstance(prop, dict) and prop.get("name") == key]


def _nonnegative(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_COUNT


def _parse_claim(raw: object) -> dict:
    if not isinstance(raw, str) or len(raw) > MAX_VALUE_LENGTH:
        raise ValueError("invalid collection coverage size")

    def unique_object(items):
        result = dict(items)
        if len(items) != len(result):
            raise ValueError("duplicate collection coverage field")
        return result

    value = json.loads(raw, object_pairs_hook=unique_object)
    required = {"status", "sourceType", "componentCount", "excludedDirectoryCount", "issueCounts"}
    optional = {"omittedIssueCount", "excludedPatternCount"}
    if not isinstance(value, dict) or not required <= value.keys() <= required | optional:
        raise ValueError("invalid collection coverage fields")
    if value["status"] not in ("completed", "partial") or not isinstance(value["sourceType"], str) or value["sourceType"] not in _SOURCES:
        raise ValueError("invalid collection coverage status or source")
    if any(not _nonnegative(value[key]) for key in {"componentCount", "excludedDirectoryCount"} | (value.keys() & optional)):
        raise ValueError("invalid collection coverage count")
    issues = value["issueCounts"]
    if not isinstance(issues, list) or len(issues) > MAX_ISSUE_CODES:
        raise ValueError("invalid collection issue count")
    seen = set()
    for issue in issues:
        if not isinstance(issue, dict) or issue.keys() != {"code", "count"}:
            raise ValueError("invalid collection issue")
        code, count = issue["code"], issue["count"]
        if not isinstance(code, str) or not _CODE.fullmatch(code) or code in seen or not _nonnegative(count) or count == 0:
            raise ValueError("invalid collection issue code or count")
        seen.add(code)
    return value


def _syft_distro_ref(row: dict) -> str | None:
    if row.get("type") != "operating-system" or row.get("purl") or row.get("components"):
        return None
    name, version = row.get("name"), row.get("version", "")
    if not isinstance(name, str) or not _DISTRO_ID.fullmatch(name):
        return None
    if not isinstance(version, str) or (version and not _DISTRO_VERSION.fullmatch(version)):
        return None
    reference = f"os:{name}@{version}" if version else f"os:{name}"
    if row.get("bom-ref") != reference:
        return None
    if _property_values(row, "syft:distro:id") != [name]:
        return None
    if _property_values(row, "syft:distro:versionID") != ([version] if version else []):
        return None
    swid = row.get("swid")
    if not isinstance(swid, dict) or (swid.get("tagId"), swid.get("name"), swid.get("version", "")) != (name, name, version):
        return None
    return reference


def _has_koda_distro_row(bom: dict) -> bool:
    from .sbom import iter_components

    if bom.get("bomFormat") != "CycloneDX" or _properties(bom, "koda:source-format"):
        return False
    tools = bom["metadata"].get("tools")
    components = tools.get("components") if isinstance(tools, dict) else None
    if not isinstance(components, list) or len(components) != 1:
        return False
    tool = components[0]
    if not isinstance(tool, dict) or (tool.get("type"), tool.get("author"), tool.get("name")) != (
        "application", "anchore", "koda-sbom",
    ):
        return False
    if not isinstance(tool.get("version"), str) or not tool["version"].strip():
        return False
    top_level = bom.get("components", [])
    refs = [ref for row in top_level if (ref := _syft_distro_ref(row)) is not None]
    return len(refs) == 1 and sum(row.get("bom-ref") == refs[0] for row in iter_components(top_level)) == 1


def coverage_for_bom(bom: dict) -> tuple[dict, str | None]:
    """Return API evidence and the synthetic SPDX source root, when present."""
    from .sbom import iter_components

    claims = _properties(bom, KEY)
    if not claims:
        return {}, None
    try:
        if len(claims) != 1:
            raise ValueError("conflicting collection coverage")
        coverage = _parse_claim(claims[0])
        roots = _properties(bom, SPDX_ROOT_KEY)
        root = None
        if roots:
            if len(roots) != 1 or not isinstance(roots[0], str) or roots[0] not in _SPDX_ROOT_NAMES:
                raise ValueError("invalid SPDX collection root")
            root = roots[0]
            expected = ("SPDXRef-DocumentRoot-Directory-IBM-AIX-evidence" if coverage["sourceType"] == "aix-evidence"
                        else "SPDXRef-DocumentRoot-Directory-local-filesystem")
            if root != expected or _properties(bom, "koda:source-format") != ["SPDX-2.3"]:
                raise ValueError("invalid SPDX collection source")
            if not any(isinstance(row, dict) and row.get("bom-ref") == root for row in bom.get("components", [])):
                raise ValueError("SPDX collection root must be a top-level package")
        component_total = root_total = 0
        for row in iter_components(bom.get("components", [])):
            if root is not None and row.get("bom-ref") == root:
                if row.get("type") != "file" or row.get("name") != _SPDX_ROOT_NAMES[root] or any(
                    row.get(key) for key in ("purl", "cpe", "version", "components")
                ):
                    raise ValueError("invalid SPDX collection root identity")
                root_total += 1
            else:
                component_total += 1
        if root_total != int(root is not None):
            raise ValueError("collection count does not match BOM")
        if (
            root is None and coverage["sourceType"] in {"filesystem", "image-archive"}
            and component_total == coverage["componentCount"] + 1 and _has_koda_distro_row(bom)
        ):
            # The CycloneDX encoder appends distribution metadata after writing
            # the packages the collector counted. Keep that row for CPE analysis.
            component_total -= 1
        if coverage["componentCount"] != component_total:
            raise ValueError("collection count does not match BOM")
    except (ValueError, RecursionError):
        return {"collectionCoverageState": "invalid"}, None
    return {"collectionCoverage": coverage}, root
