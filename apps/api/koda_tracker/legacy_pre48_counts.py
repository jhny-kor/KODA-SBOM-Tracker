"""Pure pre-4.8 nonliteral evaluator counts, before the old ALL count gate.

Source behavior: 4.7.1 policy/{Severity,Cwe,License,LicenseGroup,Version,
ComponentHash}PolicyEvaluator.java in the upstream repository. No I/O occurs
here; registry UUIDs and component evidence come from the validated export.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from uuid import UUID

SUBJECTS = {"SEVERITY", "CWE", "LICENSE", "LICENSE_GROUP", "VERSION", "COMPONENT_HASH"}
OPERATORS = {"IS", "IS_NOT", "MATCHES", "NO_MATCH", "NUMERIC_GREATER_THAN", "NUMERIC_LESS_THAN", "NUMERIC_EQUAL", "NUMERIC_NOT_EQUAL", "NUMERIC_GREATER_THAN_OR_EQUAL", "NUMERIC_LESSER_THAN_OR_EQUAL", "CONTAINS_ALL", "CONTAINS_ANY"}
NUMERIC = {"NUMERIC_GREATER_THAN", "NUMERIC_LESS_THAN", "NUMERIC_EQUAL", "NUMERIC_NOT_EQUAL", "NUMERIC_GREATER_THAN_OR_EQUAL", "NUMERIC_LESSER_THAN_OR_EQUAL"}
HASH_FIELDS = {"MD5":"md5", "SHA-1":"sha1", "SHA-256":"sha256", "SHA-384":"sha384", "SHA-512":"sha512", "SHA3-256":"sha3_256", "SHA3-384":"sha3_384", "SHA3-512":"sha3_512", "BLAKE3":"blake3", "BLAKE2B-256":"blake2b_256", "BLAKE2B-384":"blake2b_384", "BLAKE2B-512":"blake2b_512"}
ASCII_TRIM = ''.join(chr(i) for i in range(33))
_COMMON_KEYS = {"subject", "operator", "value", "sourceMinor"}


def _uuid(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("구형 정책 라이선스 UUID가 올바르지 않습니다")
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError("구형 정책 라이선스 UUID가 올바르지 않습니다") from exc


def _text(value, *, nullable=True):
    if value is None and nullable:
        return
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("구형 정책 값은 2048자 이하 문자열이어야 합니다")


def prepare_condition(condition: dict, bundle: dict, minor: int) -> dict:
    """Resolve source registry identities without importing modern SPDX meaning."""
    subject = condition.get("subject")
    data = {"subject":subject, "operator":condition.get("operator"), "value":condition.get("value"), "sourceMinor":minor}
    if subject == "LICENSE":
        value = data["value"]
        if value != "unresolved":
            key = _uuid(value)
            known = {_uuid(entry["uuid"]) for entry in bundle.get("licenses", []) if isinstance(entry, dict) and entry.get("uuid")}
            data["licenseUuids"] = [key] if key in known else []
        else:
            data["licenseUuids"] = []
    elif subject == "LICENSE_GROUP":
        key = _uuid(data["value"])
        groups = [entry for entry in bundle.get("licenseGroups", []) if isinstance(entry, dict) and entry.get("uuid") and _uuid(entry["uuid"]) == key]
        if not groups:
            raise ValueError("구형 정책의 라이선스 그룹 정의가 없습니다")
        entries = groups[0].get("licenses") or []
        if not isinstance(entries, list) or len(entries) > 500:
            raise ValueError("구형 정책 라이선스 그룹은 최대 500개입니다")
        data["licenseUuids"] = sorted({_uuid(entry.get("uuid") if isinstance(entry, dict) else entry) for entry in entries})
    elif subject == "COMPONENT_HASH":
        value = data["value"]
        try:
            value = json.loads(value) if isinstance(value, str) else value
        except (ValueError, TypeError) as exc:
            raise ValueError("구형 해시 조건 JSON이 올바르지 않습니다") from exc
        if value is not None:
            if not isinstance(value, dict) or set(value) - {"algorithm", "value"}:
                raise ValueError("구형 해시 조건 구조가 올바르지 않습니다")
            value = {"algorithm":value.get("algorithm"), "value":value.get("value")}
        data["value"] = value
    validate_condition(data)
    return data


def validate_condition(data: dict) -> None:
    if not isinstance(data, dict) or data.get("subject") not in SUBJECTS:
        raise ValueError("지원하지 않는 구형 비문자열 조건입니다")
    subject = data["subject"]
    keys = _COMMON_KEYS | ({"licenseUuids"} if subject in {"LICENSE", "LICENSE_GROUP"} else set())
    if set(data) != keys or type(data["sourceMinor"]) is not int or not 0 <= data["sourceMinor"] <= 7 or data["operator"] not in OPERATORS:
        raise ValueError("구형 비문자열 조건 구조 또는 연산자가 올바르지 않습니다")
    if subject == "COMPONENT_HASH":
        value = data["value"]
        if value is not None:
            if not isinstance(value, dict) or set(value) != {"algorithm", "value"}:
                raise ValueError("구형 해시 조건 구조가 올바르지 않습니다")
            for field in value.values():
                _text(field)
            if value["algorithm"] is not None and value["value"] is not None and not value["value"].strip(ASCII_TRIM):
                raise ValueError("구형 원본의 빈 해시 값은 평가할 수 없습니다")
    else:
        _text(data["value"])
    if subject in {"LICENSE", "LICENSE_GROUP"}:
        entries = data["licenseUuids"]
        if not isinstance(entries, list) or len(entries) > 500 or any(_uuid(value) != value for value in entries) or entries != sorted(set(entries)):
            raise ValueError("구형 정책 라이선스 UUID 목록이 올바르지 않습니다")
        if subject == "LICENSE":
            if data["value"] == "unresolved":
                if entries:
                    raise ValueError("미확정 라이선스 조건에 UUID를 지정할 수 없습니다")
            elif entries not in ([], [_uuid(data["value"])]):
                raise ValueError("구형 라이선스 대상과 UUID가 일치하지 않습니다")
        else:
            _uuid(data["value"])


@lru_cache(maxsize=2048)
def _cwe_ids(value: str | None):
    if value is None:
        return False, frozenset()
    if value.strip(ASCII_TRIM) == "*":
        return True, frozenset()
    result = set()
    for part in value.split(','):
        part = part.strip(ASCII_TRIM)
        text = ''
        if part.startswith('CWE-') and ' ' in part:
            text = part[4:part.index(' ')]
        elif part.startswith('CWE-') and len(part) < 9:
            text = part[4:]
        elif len(part) < 5:
            text = part
        if re.fullmatch(r'[+-]?[0-9]+', text):
            number = int(text)
            if -2147483648 <= number <= 2147483647:
                result.add(number)
    return False, frozenset(result)


def _vulnerabilities(component):
    entries = component.get("vulnerabilities") or []
    if not isinstance(entries, list) or len(entries) > 100_000 or any(not isinstance(value, dict) for value in entries):
        raise ValueError("구형 정책의 취약점 목록 한도를 초과했거나 형식이 올바르지 않습니다")
    return [entry for entry in entries if entry.get("suppressed") is not True]


def _resolved_license(component):
    fields = component.get("legacyLiteralFields") or {}
    value = fields.get("resolvedLicenseUuid")
    if value is None:
        return None
    return _uuid(value)


def _version_count(data, component):
    from .legacy_policy import _generic_version_compare, _compare
    expected = data['value']
    if expected is None or data['operator'] not in NUMERIC:
        return 0
    fields = component.get('legacyLiteralFields') or component
    actual = fields.get('version')
    if actual is not None and (not isinstance(actual, str) or len(actual) > 64 * 1024):
        raise ValueError('구형 정책의 실제 버전 형식이 올바르지 않습니다')
    if actual is None:
        # ComponentVersion(null) has no parts. Only a single trailing zero is
        # equivalent to an empty parts list in the original compareTo method.
        text = expected.lower()
        debian = re.fullmatch(r'(?:[0-9]+:)?(.*)(-[^-]+ubuntu[^-]+)', text)
        if debian:
            text = debian[1]
        tokens = re.findall(r'[0-9]+[a-z]{1,3}$|[a-z]{1,3}[_-]?[0-9]+|[0-9]+|(?:rc|release|snapshot|beta|alpha)$', text, re.IGNORECASE)
        comparison = 0 if tokens == ['0'] else -1
    else:
        comparison = _generic_version_compare(actual, expected)
    return int(_compare(comparison, 0, data['operator']))


def _hash_count(data, component):
    value = data['value']
    if value is None or value['algorithm'] is None or value['value'] is None:
        return 0
    algorithm = value['algorithm'].upper()
    if algorithm not in HASH_FIELDS:
        return 0
    expected = value['value'].strip(ASCII_TRIM).lower()
    fields = component.get('legacyLiteralFields') or {}
    field = HASH_FIELDS[algorithm]
    if field in fields:
        actual = fields[field]
        return int(isinstance(actual, str) and actual.lower() == expected)
    hashes = component.get('hashes') or []
    if not isinstance(hashes, list) or len(hashes) > 128:
        raise ValueError('구형 정책 해시 목록 형식 또는 한도가 올바르지 않습니다')
    return int(any(isinstance(entry, dict) and isinstance(entry.get('alg'), str) and entry['alg'].upper() == algorithm and isinstance(entry.get('content'), str) and entry['content'].lower() == expected for entry in hashes))


def evaluate_count(data: dict, component: dict) -> int:
    subject, operator = data['subject'], data['operator']
    if subject == 'SEVERITY':
        expected = data['value']
        result = 0
        for vulnerability in _vulnerabilities(component):
            raw = vulnerability.get('severity')
            actual = raw.upper() if isinstance(raw, str) else 'UNASSIGNED'
            if actual not in {'CRITICAL','HIGH','MEDIUM','LOW','INFO'}:
                actual = 'UNASSIGNED'
            result += int(operator == 'IS' and actual == expected or operator == 'IS_NOT' and actual != expected)
        return result
    if subject == 'CWE':
        wildcard, wanted = _cwe_ids(data['value'])
        result = 0
        for vulnerability in _vulnerabilities(component):
            cwes = vulnerability.get('cwes')
            if cwes is None or vulnerability.get('legacyCwesNull') is True:
                continue
            if not isinstance(cwes, list) or len(cwes) > 4096 or any(type(value) is not int for value in cwes):
                raise ValueError('구형 정책 CWE 목록 형식 또는 한도가 올바르지 않습니다')
            result += int(wildcard or bool(wanted) and (operator == 'CONTAINS_ANY' and bool(wanted.intersection(cwes)) or operator == 'CONTAINS_ALL' and wanted.issubset(cwes)))
        return result
    if subject in {'LICENSE', 'LICENSE_GROUP'}:
        actual = _resolved_license(component)
        if subject == 'LICENSE' and data['value'] == 'unresolved':
            return int(operator == 'IS' and actual is None or operator == 'IS_NOT' and actual is not None)
        if subject == 'LICENSE' and (actual is None or not data['licenseUuids']):
            return 0
        matched = actual in data['licenseUuids']
        return int(operator == 'IS' and matched or operator == 'IS_NOT' and not matched)
    if subject == 'VERSION':
        return _version_count(data, component)
    if subject == 'COMPONENT_HASH':
        return _hash_count(data, component)
    raise ValueError('지원하지 않는 구형 비문자열 조건입니다')
