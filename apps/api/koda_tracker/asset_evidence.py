"""Validate collector observations without promoting them to vulnerability verdicts."""
from __future__ import annotations

import hashlib
import json

PREFIX = "koda:asset:"
KINDS = {"device", "firmware", "device-driver", "application", "library", "container", "operating-system"}


def _text(value, field, limit=1024):
    if not isinstance(value, str) or len(value) > limit or any(char in value for char in "\x00\r\n"):
        raise ValueError(f"Invalid KODA asset {field}")
    return value


def _spdx_id(identity):
    return "SPDXRef-KodaAsset-" + hashlib.sha256(identity.encode()).hexdigest()[:32]


def apply_spdx_asset(package, component):
    comment = package.get("comment")
    if not isinstance(comment, str) or not comment.startswith(PREFIX):
        return
    if len(comment) > 65536:
        raise ValueError("KODA asset evidence exceeds limit")
    try:
        asset = json.loads(comment[len(PREFIX):])
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid KODA asset evidence JSON") from exc
    if not isinstance(asset, dict):
        raise ValueError("KODA asset evidence must be an object")
    identity = _text(asset.get("id"), "id")
    kind = _text(asset.get("kind"), "kind")
    if not identity or _spdx_id(identity) != component["bom-ref"]:
        raise ValueError("KODA asset identity conflicts with SPDX package")
    purpose = {"device-driver": "OTHER", "operating-system": "OPERATING_SYSTEM"}.get(kind, kind.upper())
    if kind not in KINDS or package.get("primaryPackagePurpose") != purpose:
        raise ValueError("KODA asset kind conflicts with SPDX purpose")
    for key, target in (("name", "name"), ("version", "version"), ("purl", "purl"), ("cpe", "cpe")):
        if _text(asset.get(key, ""), key) != component.get(target, ""):
            raise ValueError("KODA asset identity conflicts with normalized package")
    sha = _text(asset.get("sha256", ""), "sha256")
    if sha and {"alg": "SHA-256", "content": sha.lower()} not in component.get("hashes", []):
        raise ValueError("KODA asset checksum conflicts with package")
    properties = {"original-id": identity}
    for key, target in (("source", "source"), ("observedAt", "observed-at"), ("model", "model"), ("revision", "revision")):
        val = _text(asset.get(key, ""), key)
        if val:
            properties[target] = val
    parent = _text(asset.get("parentId", ""), "parentId")
    if parent:
        properties["parent-id"] = _spdx_id(parent)
        properties["original-parent-id"] = parent
    evidence = asset.get("properties", {})
    if not isinstance(evidence, dict) or len(evidence) > 256:
        raise ValueError("Invalid KODA asset properties")
    for key, val in evidence.items():
        key = _text(key, "property name", 256)
        properties["evidence:" + key] = _text(val, "property value", 4096)
    component["type"] = kind
    vendor = _text(asset.get("vendor", ""), "vendor")
    if vendor:
        component["manufacturer"] = {"name": vendor}
    component["properties"].extend({"name": PREFIX + key, "value": val} for key, val in sorted(properties.items()))


def validate_asset_properties(document):
    """Preserve evidence values and require unambiguous in-document parent links."""
    if not isinstance(document, dict):
        return
    pending = list(document.get("components", []))
    identities, links = set(), []
    while pending:
        component = pending.pop()
        if not isinstance(component, dict):
            continue
        pending.extend(component.get("components", []))
        identity = component.get("bom-ref")
        if isinstance(identity, str):
            identities.add(identity)
        evidence = {}
        for prop in component.get("properties", []):
            if not isinstance(prop, dict) or not isinstance(prop.get("name"), str) or not prop["name"].startswith(PREFIX):
                continue
            name = _text(prop["name"], "property name", 256)
            val = _text(prop.get("value"), "property value", 4096)
            if name in evidence:
                raise ValueError("Duplicate KODA asset property")
            evidence[name] = val
        if evidence:
            if component.get("type") not in KINDS:
                raise ValueError("Invalid KODA asset component type")
            if len(evidence) > 272:
                raise ValueError("KODA asset property limit exceeded")
            parent = evidence.get(PREFIX + "parent-id")
            if parent:
                links.append((identity, parent))
    parents = dict(links)
    for child, parent in links:
        if parent not in identities or child == parent:
            raise ValueError("Invalid KODA asset parent reference")
    checked = set()
    for child, _ in links:
        seen = set()
        while child in parents and child not in checked:
            if child in seen:
                raise ValueError("Cyclic KODA asset parent reference")
            seen.add(child)
            child = parents[child]
        checked.update(seen)
