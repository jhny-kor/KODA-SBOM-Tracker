"""Value/count semantics of the pre-4.8 literal policy evaluators.

Counts matter: the old ALL engine compared raw evaluator result count with the
number of configured conditions, before deduplicating persistent violations.
"""
from __future__ import annotations

import hashlib
import json
import re

FIELDS = {'PACKAGE_URL':'purl', 'CPE':'cpe', 'SWID_TAGID':'swidTagId'}
BASE_SUBJECTS = {'COORDINATES','LICENSE_GROUP','LICENSE','PACKAGE_URL','CPE','SWID_TAGID'}
VERSION_OPERATOR = re.compile(r'^(>=|<=|==|!=|>|<)\s*(.*)$', re.DOTALL)
OPERATORS = {'>':'NUMERIC_GREATER_THAN','>=':'NUMERIC_GREATER_THAN_OR_EQUAL','==':'NUMERIC_EQUAL','!=':'NUMERIC_NOT_EQUAL','<':'NUMERIC_LESS_THAN','<=':'NUMERIC_LESSER_THAN_OR_EQUAL'}
ASCII_TRIM = ''.join(chr(i) for i in range(33))


def source_minor(version: str) -> int:
    match = re.match(r'^4\.(\d+)(?:[.-]|$)', version)
    if not match or not 0 <= int(match[1]) <= 7:
        raise ValueError('리터럴 정책은 원본 4.0~4.7 버전을 명시해야 합니다')
    return int(match[1])


def supported_subjects(minor: int) -> set[str]:
    result = set(BASE_SUBJECTS)
    if minor >= 1:
        result.add('SEVERITY')
    if minor >= 2:
        result.add('VERSION')
    if minor >= 6:
        result.update({'COMPONENT_HASH','CWE'})
    return result


def literal_spec(subject: str, value, operator: str, version: str) -> dict:
    if subject == 'COORDINATES':
        try:
            value = json.loads(value) if isinstance(value, str) else value
        except (ValueError, TypeError) as exc:
            raise ValueError('좌표 조건 JSON이 올바르지 않습니다') from exc
        if value is None:
            value = {}
        if not isinstance(value, dict) or set(value) - {'group','name','version'}:
            raise ValueError('리터럴 좌표 조건 구조가 올바르지 않습니다')
        value = {key:(value.get(key).strip(ASCII_TRIM) or None) if isinstance(value.get(key),str) else value.get(key) for key in ('group','name','version')}
    spec = {'subject':'LEGACY_LITERAL', 'sourceSubject':subject, 'sourceMinor':source_minor(version),
            'operator':operator, 'value':value}
    spec['id'] = 'compat-' + hashlib.sha256(json.dumps(spec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
    validate_spec(spec)
    return spec


def validate_spec(spec: dict) -> None:
    if set(spec) != {'id','subject','sourceSubject','sourceMinor','operator','value'} or spec['subject'] != 'LEGACY_LITERAL':
        raise ValueError('리터럴 helper 구조가 올바르지 않습니다')
    if type(spec['sourceMinor']) is not int or not 0 <= spec['sourceMinor'] <= 7:
        raise ValueError('리터럴 원본 minor 버전이 올바르지 않습니다')
    if spec['sourceSubject'] not in {*FIELDS, 'COORDINATES'} or spec['operator'] not in {'MATCHES','NO_MATCH'}:
        raise ValueError('리터럴 조건 subject 또는 연산자가 올바르지 않습니다')
    values = [spec['value']]
    if spec['sourceSubject'] == 'COORDINATES':
        if not isinstance(spec['value'], dict) or set(spec['value']) != {'group','name','version'}:
            raise ValueError('리터럴 좌표 조건이 올바르지 않습니다')
        values = list(spec['value'].values())
    if any((value is None and spec['sourceSubject'] != 'COORDINATES') or (value is not None and (not isinstance(value,str) or len(value)>2048)) for value in values):
        raise ValueError('리터럴 문자열은 2048자 이하 문자열이어야 합니다')


def coordinates_purl(purl: str) -> str:
    # Exported canonical PURLs encode reserved delimiters; coordinates retain
    # the version and remove only qualifiers and subpath, as the old API does.
    return purl.split('?',1)[0].split('#',1)[0]


def _coordinate_matches(expected, actual, operator):
    if expected is None and actual is None:
        return True
    if actual is not None and not isinstance(actual, str):
        raise ValueError('리터럴 좌표 대상은 문자열 또는 null이어야 합니다')
    actual = actual.strip(ASCII_TRIM) if actual is not None else None
    if not actual:
        return False
    matched = expected == '*' or (expected is not None and expected in actual)
    return not matched if operator == 'NO_MATCH' else matched


def evaluate_count(spec: dict, component: dict) -> int:
    fields = component.get('legacyLiteralFields') or component.get('legacyRegexFields') or component
    subject, expected, operator = spec['sourceSubject'], spec['value'], spec['operator']
    if subject == 'COORDINATES':
        for field in ('group','name','version'):
            pattern, actual = expected[field], fields.get(field)
            if field == 'version' and spec['sourceMinor'] >= 2:
                # The old evaluator attempts matcher(null) before a null test.
                # Preserve an explicit failure instead of manufacturing a pass.
                if pattern is None:
                    raise ValueError('원본 4.2~4.7의 null 좌표 버전 조건은 평가할 수 없습니다')
                comparison = VERSION_OPERATOR.match(pattern)
                if comparison:
                    if not isinstance(actual, str):
                        raise ValueError('원본 좌표 버전 비교에 실제 버전이 필요합니다')
                    from .legacy_policy import _generic_version_compare, _compare
                    matched = _compare(_generic_version_compare(actual, comparison[2]), 0, OPERATORS[comparison[1]])
                    if operator == 'NO_MATCH':
                        matched = not matched
                else:
                    matched = _coordinate_matches(pattern, actual, operator)
            else:
                matched = _coordinate_matches(pattern, actual, operator)
            if not matched:
                return 0
        return 1
    actual = fields.get(FIELDS[subject])
    if actual is None:
        return 0  # Missing identifiers yield no old NO_MATCH violations either.
    if not isinstance(actual, str):
        raise ValueError('리터럴 대상은 문자열 또는 null이어야 합니다')
    candidates = [actual]
    if subject == 'PACKAGE_URL':
        coordinate = fields.get('purlCoordinates') if 'purlCoordinates' in fields else coordinates_purl(actual)
        if coordinate is not None:
            if not isinstance(coordinate, str):
                raise ValueError('원본 좌표 PURL이 올바르지 않습니다')
            candidates.append(coordinate)
    matches = sum(expected in text for text in candidates)
    return matches if operator == 'MATCHES' else int(matches == 0)
