"""Local numeric distance and Maven ordering; no artifact execution or network.

The Maven item parsing/comparison follows Apache Maven ComparableVersion 3.9.11
(Apache-2.0), Copyright The Apache Software Foundation:
https://github.com/apache/maven/blob/maven-3.9.11/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import re
from functools import total_ordering
from itertools import zip_longest

_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}


def _qualifier(value: str) -> str:
    return str(_QUALIFIERS.index(value)) if value in _QUALIFIERS else f"{len(_QUALIFIERS)}-{value}"


def _string(value: str, followed_by_digit: bool = False) -> str:
    if followed_by_digit:
        value = {"a": "alpha", "b": "beta", "m": "milestone"}.get(value, value)
    return _ALIASES.get(value, value)


def _compare(left, right) -> int:
    if left is None:
        return -_compare(right, None) if right is not None else 0
    if isinstance(left, int):
        if right is None:
            return (left > 0) - (left < 0)
        if isinstance(right, int):
            return (left > right) - (left < right)
        return 1
    if isinstance(left, str):
        value = _qualifier(left)
        other = _qualifier("") if right is None else _qualifier(right) if isinstance(right, str) else None
        return (value > other) - (value < other) if other is not None else -1
    if right is None:
        for item in left:
            result = _compare(item, None)
            if result:
                return result
        return 0
    if isinstance(right, int):
        return -1
    if isinstance(right, str):
        return 1
    for a, b in zip_longest(left, right):
        result = _compare(a, b)
        if result:
            return result
    return 0


def _normalize(items: list) -> None:
    for index in range(len(items) - 1, -1, -1):
        value = items[index]
        if (isinstance(value, int) and value == 0) or (isinstance(value, str) and value == "") or (isinstance(value, list) and not value):
            items.pop(index)
        elif not isinstance(value, list):
            break


@total_ordering
class MavenVersion:
    """ComparableVersion's numeric/string/nested-list ordering, bounded to PURL versions."""
    def __init__(self, version: str):
        if not version or len(version) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!_~-]*", version):
            raise ValueError("Maven version syntax is unsupported")
        self.value = version
        self.items: list = []
        current = self.items
        stack = [current]
        digit, start = False, 0
        value = version.lower()
        def nested():
            nonlocal current
            child = []
            current.append(child)
            current = child
            stack.append(child)
        def item(part: str):
            return int(part) if digit else _string(part)
        for index, character in enumerate(value):
            if character in ".-":
                current.append(0 if index == start else item(value[start:index]))
                start = index + 1
                if character == "-":
                    nested()
            elif character.isdigit():
                if not digit and index > start:
                    if current:
                        nested()
                    current.append(_string(value[start:index], True))
                    start = index
                    nested()
                digit = True
            else:
                if digit and index > start:
                    current.append(int(value[start:index]))
                    start = index
                    nested()
                digit = False
        if len(value) > start:
            if not digit and current:
                nested()
            current.append(item(value[start:]))
        for entry in reversed(stack):
            _normalize(entry)

    def __eq__(self, other):
        return isinstance(other, MavenVersion) and _compare(self.items, other.items) == 0

    def __lt__(self, other):
        if not isinstance(other, MavenVersion):
            return NotImplemented
        return _compare(self.items, other.items) < 0


def maven_is_stable(version: str) -> bool:
    # Unknown vendor qualifiers are valid Maven releases; alpha/beta/etc. are
    # pre-releases. Maven's known aliases/short forms follow qualifier tokens.
    parts = re.findall(r"[a-z]+|\d+", version.lower())
    return not any(part in {"alpha", "beta", "milestone", "rc", "cr", "snapshot", "ea", "eap", "preview", "dev"} or
                   (part in {"a", "b", "m"} and index + 1 < len(parts) and parts[index + 1].isdigit())
                   for index, part in enumerate(parts))


def maven_distance(versions: list[str], current: str, latest: str) -> int:
    lower, upper = MavenVersion(current), MavenVersion(latest)
    candidates = sorted(MavenVersion(value) for value in versions if maven_is_stable(value))
    unique = []
    for value in candidates:
        if lower < value <= upper and (not unique or value != unique[-1]):
            unique.append(value)
    return len(unique)


def numeric_version_distance(current: str, latest: str) -> dict | None:
    """Absolute first different epoch/major/minor/patch; lower fields are -1.

    Qualifiers/build numbers do not create additional numeric distance. Unknown
    nonnumeric leading versions stay unavailable instead of inventing zero.
    """
    pattern = re.compile(r"^(?:(\d+):)?v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+_~].*|\.\d+.*)?$", re.I)
    parsed = []
    for value in (current, latest):
        match = pattern.fullmatch(value)
        if not match:
            return None
        parsed.append([int(part or 0) for part in match.groups()])
    result = {key: 0 for key in ("epoch", "major", "minor", "patch")}
    different = False
    for index, key in enumerate(result):
        if different:
            result[key] = -1
        else:
            result[key] = abs(parsed[1][index] - parsed[0][index])
            different = result[key] > 0
    return result
