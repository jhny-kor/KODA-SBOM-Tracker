from __future__ import annotations

from collections.abc import Iterable

from .models import RunComponent


def compare_components(base: Iterable[RunComponent], target: Iterable[RunComponent]) -> list[dict]:
    left = {component.identity_key: component for component in base}
    right = {component.identity_key: component for component in target}
    changes: list[dict] = []
    for key in sorted(left.keys() | right.keys()):
        before = left.get(key)
        after = right.get(key)
        if before is None:
            kind = "added"
        elif after is None:
            kind = "removed"
        else:
            fields = []
            if before.version != after.version:
                fields.append("version")
            if before.sha256 != after.sha256:
                fields.append("sha256")
            if before.licenses != after.licenses:
                fields.append("licenses")
            if not fields:
                continue
            kind = "changed"
        current = after or before
        changes.append(
            {
                "change": kind,
                "fields": fields if before and after else [],
                "identityKey": key,
                "identityStatus": current.identity_status,
                "componentType": current.component_type,
                "group": current.group_name,
                "name": current.name,
                "purl": current.purl,
                "bomRef": current.bom_ref,
                "baseVersion": before.version if before else None,
                "targetVersion": after.version if after else None,
                "baseSha256": before.sha256 if before else None,
                "targetSha256": after.sha256 if after else None,
                "baseLicenses": before.licenses if before else [],
                "targetLicenses": after.licenses if after else [],
            }
        )
    return changes


def compare_records(base: list[dict], target: list[dict], *, keys: tuple[str, ...]) -> list[dict]:
    def key(value: dict) -> tuple:
        return tuple(str(value.get(name, "")).lower() for name in keys)

    left = {key(item): item for item in base}
    right = {key(item): item for item in target}
    result = []
    for identity in sorted(left.keys() | right.keys()):
        if identity not in left:
            result.append({"change": "added", "record": right[identity]})
        elif identity not in right:
            result.append({"change": "removed", "record": left[identity]})
        elif left[identity] != right[identity]:
            result.append({"change": "changed", "base": left[identity], "target": right[identity]})
    return result
