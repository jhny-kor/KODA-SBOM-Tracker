"""Read bounded per-Home assertions from the koda-sbom Oracle inventory formats."""
from __future__ import annotations

import hashlib
import json
import re

from .offline_cpe import product_key

LISTENER = "Oracle RDBMS Listener"
_PRODUCTS = {LISTENER: "rdbms_listener", "Oracle Database Server": "database_server",
             "Oracle Grid Infrastructure": None}
_HOME = re.compile(r"oracle-home/[a-f0-9]{64}")
_HASH = re.compile(r"[a-f0-9]{64}")
ORACLE_COMPONENT_REF = re.compile(r"SPDXRef-KODA-Oracle-[a-f0-9]{64}")
_VERSION = re.compile(r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,5}")
_PATCH_ID = re.compile(r"[0-9]{4,12}")
_PATH = re.compile(r"(?:(?:homes/[1-8])/)?(?:opatch|listener)\.txt")
_FIELDS = ("homeId", "release", "observation", "versionSource", "inventoryStatus",
           "listenerExecutableObserved", "listenerReleaseBasis", "opatchEvidenceSha256",
           "listenerEvidenceSha256", "opatchInventoryPatchIdsTruncated", "listenerReleasePatchIdsTruncated")
_PATCH_FIELDS = ("opatchInventoryPatchIds", "listenerReleasePatchIds")
_SPDX_PROPERTY = "koda:spdx:package"


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate Oracle evidence field")
        value[key] = item
    return value


def _bounded_object(value, limit):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("invalid Oracle evidence size")
    decoded = json.loads(value, object_pairs_hook=_unique_object)
    if not isinstance(decoded, dict):
        raise ValueError("invalid Oracle evidence shape")
    return decoded


def _source(component, ref):
    properties = component.get("properties") or []
    if not isinstance(properties, list):
        raise ValueError("invalid Oracle properties")
    relevant = {}
    for prop in properties:
        key = prop.get("name") if isinstance(prop, dict) else None
        if not isinstance(key, str) or not (key == _SPDX_PROPERTY or key == "syft:package:foundBy"
                                             or key.startswith("syft:metadata:")):
            continue
        if key in relevant:
            raise ValueError("duplicate Oracle property")
        relevant[key] = prop.get("value")
    if _SPDX_PROPERTY in relevant:
        if len(relevant) != 1:
            raise ValueError("mixed Oracle evidence formats")
        package = _bounded_object(relevant[_SPDX_PROPERTY], 512_000)
        if package.get("SPDXID") != ref or package.get("name") != component.get("name") or package.get("versionInfo", "") != component.get("version", ""):
            raise ValueError("Oracle package does not match its evidence")
        return _bounded_object(package.get("comment"), 64_000)
    if relevant.get("syft:package:foundBy") != "koda-aix-oracle-inventory":
        raise ValueError("Oracle collector was not identified")
    result = {field: relevant[f"syft:metadata:{field}"] for field in _FIELDS if f"syft:metadata:{field}" in relevant}
    for field in ("listenerExecutableObserved", "opatchInventoryPatchIdsTruncated", "listenerReleasePatchIdsTruncated"):
        if result.get(field) in ("true", "false"):
            result[field] = result[field] == "true"
    for field in _PATCH_FIELDS:
        prefix = f"syft:metadata:{field}:"
        values = {key.removeprefix(prefix): value for key, value in relevant.items() if key.startswith(prefix)}
        if values:
            if len(values) <= 4096 and set(values) == {str(i) for i in range(len(values))}:
                result[field] = [values[str(i)] for i in range(len(values))]
            else:
                result[field + "Truncated"] = True
    evidence = component.get("evidence") or {}
    occurrences = evidence.get("occurrences", []) if isinstance(evidence, dict) else None
    if not isinstance(occurrences, list) or len(occurrences) > 8:
        raise ValueError("invalid Oracle occurrence evidence")
    result["evidencePaths"] = [item.get("location") if isinstance(item, dict) else None for item in occurrences]
    return result


def read_oracle_home(component: dict) -> dict | None:
    """Validate a claimed Oracle Home and expose only typed, bounded observations."""
    name, version, ref = (component.get(key) for key in ("name", "version", "bom-ref"))
    if (not isinstance(name, str) or name not in _PRODUCTS or not isinstance(ref, str)
            or not ORACLE_COMPONENT_REF.fullmatch(ref) or component.get("purl")):
        return None
    if version is None:
        version = ""
    if not isinstance(version, str) or (version and not _VERSION.fullmatch(version)):
        return None
    try:
        evidence = _source(component, ref)
        home = evidence.get("homeId")
        if not isinstance(home, str) or not _HOME.fullmatch(home):
            return None
        expected = hashlib.sha256(f"{home}\x00{name}\x00{version}".encode()).hexdigest()
        if ref != "SPDXRef-KODA-Oracle-" + expected:
            return None
        cpe = component.get("cpe")
        if cpe and (product_key(cpe) != ("a", "oracle", _PRODUCTS[name]) or cpe.split(":")[5] != version):
            return None
        paths = evidence.get("evidencePaths")
        if not isinstance(paths, list) or not paths or len(paths) > 8 or any(not isinstance(p, str) or not _PATH.fullmatch(p) for p in paths):
            return None
        if len({path.rpartition("/")[0] for path in paths}) != 1:
            return None
    except (ValueError, TypeError, RecursionError):
        return None
    result = {"homeId": home, "evidencePaths": sorted(set(paths)), "patchApplicability": "unverified"}
    if evidence.get("observation") in ("installed inventory", "listener executable observed; version unconfirmed"):
        result["observation"] = evidence["observation"]
    release = evidence.get("release")
    if isinstance(release, str) and _VERSION.fullmatch(release):
        result["release"] = release
    for field in _PATCH_FIELDS:
        values = evidence.get(field)
        if isinstance(values, list) and len(values) <= 4096 and all(isinstance(item, str) and _PATCH_ID.fullmatch(item) for item in values):
            result[field] = sorted(set(values), key=int)
        elif isinstance(values, list) and len(values) > 4096:
            result[field + "Truncated"] = True
        if evidence.get(field + "Truncated") is True:
            result[field + "Truncated"] = True
    for field in ("opatchEvidenceSha256", "listenerEvidenceSha256"):
        value = evidence.get(field)
        if isinstance(value, str) and _HASH.fullmatch(value):
            result[field] = value
    for field, allowed in (
        ("versionSource", ("opatch_inventory_ru", "opatch_inventory_base", "unverified")),
        ("inventoryStatus", ("completed", "partial", "unknown")),
        ("listenerReleaseBasis", ("database_ru", "grid_ru", "database_and_grid_ru")),
    ):
        if evidence.get(field) in allowed:
            result[field] = evidence[field]
    if isinstance(evidence.get("listenerExecutableObserved"), bool):
        result["listenerExecutableObserved"] = evidence["listenerExecutableObserved"]
    return result


def scoped_oracle_component(component: dict, evidence: dict) -> str:
    return f"{component['name']} [{evidence['homeId']}]"


def oracle_listener_identity(component: dict) -> str | None:
    if component.get("name") == LISTENER and (evidence := read_oracle_home(component)):
        return scoped_oracle_component(component, evidence)
    return None
