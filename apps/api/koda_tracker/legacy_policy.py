"""Bounded value helpers for imported calendar, SPDX and version-distance rules.

These produce JSON booleans consumed by ordinary CEL. They do not expose host
callbacks or evaluate arbitrary policy code. Java compatibility regexes use a
separate bounded JVM; all other helpers are pure value calculations.
Semantics checked against the 5.0.3 upstream policy compatibility tests:
https://github.com/DependencyTrack/dependency-track/tree/5.0.3/apiserver/src/main/java/org/dependencytrack/policy
Generic version token rules checked against versatile v0.18.3 ComponentVersion:
https://github.com/nscuro/versatile/blob/v0.18.3/versatile-core/src/main/java/io/github/nscuro/versatile/version/ext/ComponentVersion.java
"""
from __future__ import annotations

import calendar
from datetime import UTC, date, datetime, timedelta
import hashlib
from functools import lru_cache
import json
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

NUMERIC = {"NUMERIC_GREATER_THAN": ">", "NUMERIC_GREATER_THAN_OR_EQUAL": ">=", "NUMERIC_EQUAL": "==", "NUMERIC_NOT_EQUAL": "!=", "NUMERIC_LESSER_THAN_OR_EQUAL": "<=", "NUMERIC_LESS_THAN": "<"}
_PERIOD = re.compile(r"P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?", re.IGNORECASE)
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.+:-]*)")
# License families whose version aliases/ranges are defined in the upstream
# SPDX expression registry. The data is identifiers, not legal compatibility.
_FAMILY_TEXT = """
AFL:1.1,1.2,2.0,2.1,3.0
AGPL:1.0,3.0
Apache:1.0,1.1,2.0
APSL:1.0,1.1,1.2,2.0
Artistic:1.0,2.0
ASWF-Digital-Assets:1.0,1.1
BitTorrent:1.0,1.1
CC-BY:1.0,2.0,2.5,3.0,4.0
CC-BY-NC:1.0,2.0,2.5,3.0,4.0
CC-BY-NC-ND:1.0,2.0,2.5,3.0,4.0
CC-BY-NC-SA:1.0,2.0,2.5,3.0,4.0
CC-BY-ND:1.0,2.0,2.5,3.0,4.0
CC-BY-SA:1.0,2.0,2.5,3.0,4.0
CDDL:1.0,1.1
CECILL:1.0,1.1,2.0,2.1
DRL:1.0,1.1
ECL:1.0,2.0
EFL:1.0,2.0
EPL:1.0,2.0
EUPL:1.0,1.1,1.2
GFDL:1.1,1.2,1.3
GPL:1.0,2.0,3.0
HP:1986,1989
LGPL:2.0,2.1,3.0
LPL:1.0,1.02
LPPL:1.0,1.1,1.2,1.3a,1.3c
MPL:1.0,1.1,2.0
NPL:1.0,1.1
OFL:1.0,1.1
OLDAP:1.1,1.2,1.3,1.4,2.0,2.0.1,2.1,2.2,2.2.1,2.2.2,2.3,2.4,2.5,2.6,2.7,2.8
OSL:1.0,1.1,2.0,2.1,3.0
PHP:3.0,3.01
RPL:1.1,1.5
SGI-B:1.0,1.1,2.0
YPL:1.0,1.1
ZPL:1.1,2.0,2.1
Zimbra:1.3,1.4
bzip2:1.0.5,1.0.6
"""
_FAMILIES = {f"{family}-{version}".lower(): (family.lower(), index) for line in _FAMILY_TEXT.strip().splitlines() for family, versions in [line.split(":")] for index, version in enumerate(versions.split(","))}
_WITH_ALIASES = {f"gpl-{version}-with-{name}-exception": f"GPL-{version}-only WITH {target}" for version, name, target in [("2.0","autoconf","Autoconf-exception-2.0"),("2.0","bison","Bison-exception-2.2"),("2.0","classpath","Classpath-exception-2.0"),("2.0","font","Font-exception-2.0"),("2.0","gcc","GCC-exception-2.0"),("3.0","autoconf","Autoconf-exception-3.0"),("3.0","gcc","GCC-exception-3.1")]}


class LegacyDataUnavailable(ValueError):
    """Required source data or bounded evaluation is unavailable, never a pass."""


class LegacySyntaxError(ValueError):
    """Malformed SPDX syntax, preserving the source parser's non-match result."""


def _compare(left, right, operator):
    return {">": lambda: left > right, ">=": lambda: left >= right, "==": lambda: left == right, "!=": lambda: left != right, "<=": lambda: left <= right, "<": lambda: left < right}[NUMERIC[operator]]()


def parse_period(value):
    match = _PERIOD.fullmatch(str(value))
    if not match or not any(match.groups()):
        raise ValueError("AGE 기간은 양수 ISO-8601 달력 기간(PnYnMnWnD)이어야 합니다")
    years, months, weeks, days = (int(part or 0) for part in match.groups())
    if not any((years,months,weeks,days)) or any(part > 2147483647 for part in (years,months,weeks,days)):
        raise ValueError("AGE 기간은 양수 Java Period 범위여야 합니다")
    return years, months, weeks, days


def _distance_thresholds(value):
    if isinstance(value, str):
        try: value = json.loads(value)
        except ValueError as exc: raise ValueError("버전 거리 조건은 JSON 객체여야 합니다") from exc
    if not isinstance(value, dict) or set(value) - {"epoch", "major", "minor", "patch"}:
        raise ValueError("버전 거리 조건에는 epoch·major·minor·patch만 지정합니다")
    values = []
    for index, key in enumerate(("epoch", "major", "minor", "patch")):
        part = value.get(key, "0" if index == 0 else "?")
        text = str(part) if part not in (None, "") else ("0" if index == 0 else "?")
        if text != "?" and not re.fullmatch(r"\d{1,10}", text):
            raise ValueError("버전 거리 각 단위는 음이 아닌 정수 또는 ?여야 합니다")
        number = -1 if text == "?" else int(text)
        if number > 2147483647:
            raise ValueError("버전 거리 단위가 Java 정수 한도를 초과했습니다")
        values.append(number)
    result=[]
    for index, number in enumerate(values):
        if number > 0: result.append(tuple([0] * index + [number] + [-1] * (3-index)))
    return result or [(0, 0, 0, 0)]


def condition_spec(condition, *, licenses=None, source_version=None, source_timezone=None):
    subject, operator, value = condition.get("subject"), condition.get("operator"), condition.get("value")
    spec = {"subject":subject,"operator":operator,"value":value}
    major = int(str(source_version).split(".")[0]) if str(source_version or "").split(".")[0].isdigit() else 4
    if subject in {"AGE", "VERSION_DISTANCE", "VERSION"}:
        if operator not in NUMERIC: raise ValueError("지원하지 않는 숫자 조건 연산자입니다")
        if subject == "AGE":
            parse_period(value)
            timezone = "UTC" if major >= 5 else source_timezone
            if not timezone: raise ValueError("원본4 AGE는 원본 서버의 timeZone을 명시해야 합니다")
            try: ZoneInfo(timezone)
            except (ZoneInfoNotFoundError, ValueError) as exc: raise ValueError("AGE 원본 IANA 시간대가 올바르지 않습니다") from exc
            spec.update(timeZone=timezone, publicationField="currentVersionPublishedAt" if major >= 5 else "latestPublishedAt")
        elif subject == "VERSION_DISTANCE":
            _distance_thresholds(value)
            spec["directOnly"] = True
        elif not isinstance(value, str) or len(value) > 2048:
            raise ValueError("버전 비교 값은 2048자 이하 문자열이어야 합니다")
    elif subject in {"LICENSE", "LICENSE_GROUP"}:
        if operator not in {"IS", "IS_NOT"}: raise ValueError("라이선스 연산자는 IS 또는 IS_NOT이어야 합니다")
        if value != "unresolved" and not licenses: raise ValueError("원본 라이선스 정의가 없습니다")
        spec["licenses"] = licenses or []
    else:
        raise ValueError("고급 조건 helper가 지원하지 않는 subject입니다")
    spec["id"] = "compat-" + hashlib.sha256(json.dumps(spec,sort_keys=True,ensure_ascii=False).encode()).hexdigest()[:24]
    return spec


_JAVA_FIELDS = {"purl", "cpe", "swidTagId", "group", "name", "version"}
_JAVA_VERSION_OPERATOR = re.compile(r"^(>=|<=|==|!=|>|<)\s*(.*)$", re.DOTALL)
_JAVA_OPERATORS = {">":"NUMERIC_GREATER_THAN", ">=":"NUMERIC_GREATER_THAN_OR_EQUAL", "==":"NUMERIC_EQUAL", "!=":"NUMERIC_NOT_EQUAL", "<":"NUMERIC_LESS_THAN", "<=":"NUMERIC_LESSER_THAN_OR_EQUAL"}


def java_regex_spec(field, value, operator, *, coordinate=False):
    """Declarative 4.8+ Matcher input; never executable Java source."""
    spec = {"subject":"JAVA_REGEX", "field":field, "value":value, "operator":operator,
            "coordinate":coordinate, "regexDialect":"java21-legacy4"}
    spec["id"] = "compat-" + hashlib.sha256(json.dumps(spec,sort_keys=True,ensure_ascii=False).encode()).hexdigest()[:24]
    validate_legacy_conditions([spec])
    return spec


def validate_java_conditions(rules):
    patterns = set()
    for rule in rules:
        specs = rule.get('legacyConditions', []) if isinstance(rule, dict) else rule.legacyConditions
        for spec in specs:
            if spec['subject'] == 'JAVA_REGEX' and spec['value'] is not None:
                if spec['coordinate'] and spec['field'] == 'version' and _JAVA_VERSION_OPERATOR.match(spec['value']):
                    continue
                patterns.add(spec['value'])
    if patterns:
        from .java_regex import validate_patterns
        validate_patterns(sorted(patterns))


def _java_match_input(spec, component):
    # Preserve source nulls even when ordinary CEL supplies empty CPE/SWID values.
    original = component.get('legacyRegexFields') or component
    actual, pattern = original.get(spec['field']), spec['value']
    if actual is not None and not isinstance(actual, str):
        raise ValueError('Java 정규식 대상은 문자열 또는 null이어야 합니다')
    if spec['coordinate']:
        if actual is None and pattern is None:
            return True, None
        if spec['field'] == 'version' and (actual is None or pattern is None):
            return False, None
        comparison = _JAVA_VERSION_OPERATOR.match(pattern or '') if spec['field'] == 'version' else None
        if comparison:
            value = _compare(_generic_version_compare(actual, comparison[2]), 0, _JAVA_OPERATORS[comparison[1]])
            return (not value if spec['operator'] == 'NO_MATCH' else value), None
        actual = actual.strip(''.join(chr(i) for i in range(33))) if actual is not None else None
        if not actual:
            return False, None
    if actual is None or pattern is None:
        value = actual is None and pattern is None
        return (not value if spec['operator'] == 'NO_MATCH' else value), None
    return None, actual


def _prepare_java_results(rules, contexts):
    """Deduplicate and batch requests; regex work never runs in the API process."""
    specs = {s['id']:s for rule in rules for s in (rule.get('legacyConditions', []) if isinstance(rule, dict) else rule.legacyConditions) if s['subject'] == 'JAVA_REGEX'}
    results, queries, indexes = {}, [], {}
    evaluations = 0
    for spec in specs.values():
        for index, activation in enumerate(contexts.get('component', [])):
            evaluations += 1
            if evaluations > 100_000:
                raise ValueError('Java 정규식 평가 횟수가 100,000회 한도를 초과했습니다')
            fixed, actual = _java_match_input(spec, activation.get('component') or {})
            identity = (spec['id'], index)
            if fixed is not None:
                results[identity] = fixed
            else:
                key = (spec['value'], actual)
                if key not in indexes:
                    indexes[key] = len(queries)
                    queries.append({'pattern':spec['value'], 'value':actual, 'mode':'legacy'})
                results[identity] = (indexes[key], spec['operator'] == 'NO_MATCH')
    if queries:
        from .java_regex import evaluate_matches
        matched = evaluate_matches(queries)
        for key, value in results.items():
            if isinstance(value, tuple):
                results[key] = not matched[value[0]] if value[1] else matched[value[0]]
    return results


def validate_legacy_conditions(values):
    if not isinstance(values, list) or len(values) > 200: raise ValueError("legacyConditions는 최대 200개 목록입니다")
    ids=set()
    for value in values:
        if not isinstance(value,dict) or set(value)-{"id","subject","operator","value","timeZone","publicationField","directOnly","licenses","field","coordinate","regexDialect"}: raise ValueError("고급 조건 구조가 올바르지 않습니다")
        if not re.fullmatch(r"compat-[a-f0-9]{24}", str(value.get("id", ""))) or value["id"] in ids: raise ValueError("고급 조건 ID가 올바르지 않거나 중복입니다")
        ids.add(value["id"])
        canonical={key:item for key,item in value.items() if key!='id'}
        expected='compat-'+hashlib.sha256(json.dumps(canonical,sort_keys=True,ensure_ascii=False).encode()).hexdigest()[:24]
        if value['id']!=expected:raise ValueError('고급 조건 ID가 조건 내용과 일치하지 않습니다')
        subject=value.get("subject")
        if subject in {"AGE","VERSION_DISTANCE","VERSION"}:
            if value.get("operator") not in NUMERIC: raise ValueError("숫자 조건 연산자가 올바르지 않습니다")
            if subject=="AGE":
                parse_period(value.get("value"))
                try:ZoneInfo(value.get("timeZone", ""))
                except (ZoneInfoNotFoundError,ValueError,TypeError) as exc:raise ValueError("AGE 시간대가 올바르지 않습니다") from exc
                if value.get("publicationField") not in {"currentVersionPublishedAt","latestPublishedAt"}: raise ValueError("AGE 공개 시각 필드가 올바르지 않습니다")
            elif subject=="VERSION_DISTANCE":_distance_thresholds(value.get("value"))
            elif not isinstance(value.get("value"),str) or len(value["value"])>2048:raise ValueError("버전 값이 올바르지 않습니다")
        elif subject in {"LICENSE","LICENSE_GROUP"}:
            if value.get("operator") not in {"IS","IS_NOT"}:raise ValueError("라이선스 연산자가 올바르지 않습니다")
            entries=value.get("licenses")
            if not isinstance(entries,list) or len(entries)>500 or any(not isinstance(e,dict) or set(e)-{"id","name"} or any(not isinstance(v,str) or len(v)>4096 for v in e.values()) for e in entries):raise ValueError("라이선스 정의가 올바르지 않습니다")
        elif subject == "JAVA_REGEX":
            if set(value) != {"id","subject","operator","value","field","coordinate","regexDialect"} or value.get("field") not in _JAVA_FIELDS or type(value.get("coordinate")) is not bool or value.get("regexDialect") != "java21-legacy4":
                raise ValueError("Java 정규식 helper 구조가 올바르지 않습니다")
            if value.get("operator") not in {"MATCHES","NO_MATCH"} or (value.get("value") is not None and (not isinstance(value["value"],str) or len(value["value"])>2048)):
                raise ValueError("Java 정규식은 2048자 이하 문자열이어야 합니다")
            if value["coordinate"] != (value["field"] in {"group","name","version"}) or (value["value"] is None and not value["coordinate"]):
                raise ValueError("Java 정규식 좌표 필드가 올바르지 않습니다")
        else:raise ValueError("지원하지 않는 고급 조건입니다")
    return values


@lru_cache(maxsize=4096)
def _spdx(expression):
    expression=_WITH_ALIASES.get(expression.lower(),expression)
    if len(expression)>4096: raise LegacyDataUnavailable("SPDX 표현식 한도를 초과했습니다")
    tokens=[];offset=0
    while offset<len(expression):
        match=_TOKEN.match(expression,offset)
        if not match:
            if not expression[offset:].strip():break
            raise LegacySyntaxError("SPDX 표현식이 올바르지 않습니다")
        tokens.append(match[1]);offset=match.end()
        if len(tokens)>256:raise LegacyDataUnavailable("SPDX 토큰 한도를 초과했습니다")
    position=0
    def atom(depth):
        nonlocal position
        if depth>32:raise LegacyDataUnavailable("SPDX 중첩 깊이 한도를 초과했습니다")
        if position>=len(tokens):raise LegacySyntaxError("SPDX 표현식 구조가 올바르지 않습니다")
        token=tokens[position];position+=1
        if token=='(':
            node=disjunction(depth+1)
            if position>=len(tokens) or tokens[position]!=')':raise LegacySyntaxError("SPDX 괄호가 닫히지 않았습니다")
            position+=1;return node
        if token in {'AND','OR','WITH',')'}:raise LegacySyntaxError("SPDX 식별자가 필요합니다")
        node=_spdx(_WITH_ALIASES[token.lower()]) if token.lower() in _WITH_ALIASES else ('id', token)
        if position<len(tokens) and tokens[position]=='WITH':
            position+=1
            if position>=len(tokens) or tokens[position] in {'AND','OR','WITH','(',')'}:raise LegacySyntaxError("SPDX 예외 식별자가 필요합니다")
            node=('with',token,tokens[position]);position+=1
        return node
    def conjunction(depth):
        nonlocal position
        node=atom(depth)
        while position<len(tokens) and tokens[position]=='AND':position+=1;node=('and',node,atom(depth))
        return node
    def disjunction(depth):
        nonlocal position
        node=conjunction(depth)
        while position<len(tokens) and tokens[position]=='OR':position+=1;node=('or',node,conjunction(depth))
        return node
    node=disjunction(0)
    if position!=len(tokens):raise LegacySyntaxError("SPDX 뒤에 해석되지 않은 내용이 있습니다")
    return node


def _license_id(value):
    text=value.lower();later=text.endswith('+') or text.endswith('-or-later')
    text=text.removesuffix('+').removesuffix('-or-later')
    if text.endswith('-only') and text.removesuffix('-only') in _FAMILIES and text.split('-')[0] in {'agpl','gfdl','gpl','lgpl'}:text=text.removesuffix('-only')
    return text,later


def _id_match(actual,expected,allows):
    left,left_later=_license_id(actual);right,right_later=_license_id(expected)
    lp,rp=_FAMILIES.get(left),_FAMILIES.get(right)
    if lp is None or rp is None:return left==right
    if lp[0]!=rp[0]:return False
    if lp[1]==rp[1]:return True
    return allows and ((right_later and (left_later or lp[1]>=rp[1])) or (left_later and rp[1]>=lp[1]))


def _spdx_match(node,allowed,allows):
    kind=node[0]
    if kind in {'id','with'}:
        for choice in allowed:
            if kind=='with' and choice[0]=='with' and node[2].lower()==choice[2].lower() and _id_match(node[1],choice[1],True):return True
            if kind=='id' and choice[0]=='id' and _id_match(node[1],choice[1],allows):return True
        return False
    left,right=(_spdx_match(child,allowed,allows) for child in node[1:])
    return (left or right) if (kind=='or')==allows else (left and right)


def _effective_license(component):
    original=component.get('legacyLicense')
    if isinstance(original,dict):
        expression=next((original.get(k) for k in ('resolvedId','resolvedName','licenseExpression','licenseName') if original.get(k)), 'unresolved')
        unresolved=not original.get('hasResolved') and not original.get('licenseExpression') and not original.get('licenseName')
        return str(expression),unresolved
    licenses=component.get('licenses') or []
    values=[v if isinstance(v,str) else v.get('expression') or (v.get('license') or {}).get('id') or (v.get('license') or {}).get('name') for v in licenses if isinstance(v,(str,dict))]
    values=[v for v in values if v]
    return (' AND '.join('('+v+')' for v in values) if len(values)>1 else values[0] if values else 'unresolved'),not values


def _generic_version_compare(actual, expected):
    # The pinned generic version comparator tokenizes numeric and named parts,
    # compares signed-Java-int tokens numerically, otherwise lexicographically.
    # A single trailing zero is equivalent. This is deliberately not SemVer.
    pattern=re.compile(r"[0-9]+[a-z]{1,3}$|[a-z]{1,3}[_-]?[0-9]+|[0-9]+|(?:rc|release|snapshot|beta|alpha)$",re.IGNORECASE)
    def parts(value):
        text=str(value).lower()
        debian=re.fullmatch(r"(?:[0-9]+:)?(.*)(-[^-]+ubuntu[^-]+)",text)
        if debian:text=debian[1]
        result=[match[0] for match in pattern.finditer(text)]
        return result or [str(value)]
    left,right=parts(actual),parts(expected)
    for a,b in zip(left,right):
        if a==b:continue
        try:
            x,y=int(a),int(b)
            if not (-2147483648<=x<=2147483647 and -2147483648<=y<=2147483647):raise ValueError()
        except ValueError:x,y=a.encode("utf-16-be",errors="surrogatepass"),b.encode("utf-16-be",errors="surrogatepass")
        if x!=y:return 1 if x>y else -1
    if len(left)==len(right):return 0
    extra=left[len(right):] if len(left)>len(right) else right[len(left):]
    if extra==['0']:return 0
    return 1 if len(left)>len(right) else -1


def evaluate_condition(spec,component,at):
    subject=spec['subject']
    if subject=='VERSION':
        if not isinstance(component.get('version'),str):raise LegacyDataUnavailable('구성요소 버전 확인 필요')
        return _compare(_generic_version_compare(component['version'],spec['value']),0,spec['operator'])
    if subject=='AGE':
        metadata=component.get('packageMetadata') or {};field=spec['publicationField']
        raw=metadata.get(field)
        if component.get('metadataStatus')!='fresh' or not raw:raise LegacyDataUnavailable(field+' 확인 필요')
        # A file modified timestamp is not a publication timestamp.
        if metadata.get(field+'Basis')=='artifact_last_modified':raise LegacyDataUnavailable(field+' 최초 공개 시각 미확정')
        try:published=datetime.fromisoformat(str(raw).replace('Z','+00:00'))
        except ValueError as exc:raise LegacyDataUnavailable('공개 시각 형식 오류') from exc
        if published.tzinfo is None:raise LegacyDataUnavailable('공개 시각 시간대 누락')
        zone=ZoneInfo(spec['timeZone']);day=published.astimezone(zone).date();today=at.astimezone(zone).date()
        years,months,weeks,days=parse_period(spec['value']);total=day.year*12+day.month-1+years*12+months
        year,month=divmod(total,12);month+=1
        try:deadline=date(year,month,min(day.day,calendar.monthrange(year,month)[1]))+timedelta(days=weeks*7+days)
        except (OverflowError,ValueError) as exc:raise LegacyDataUnavailable('AGE 달력 범위를 초과했습니다') from exc
        return _compare(today,deadline,spec['operator'])
    if subject=='VERSION_DISTANCE':
        if component.get('isDirectDependency') is False:return False
        if component.get('isDirectDependency') is not True:raise LegacyDataUnavailable('직접 의존성 그래프 확인 필요')
        metadata=component.get('packageMetadata') or {};distance=metadata.get('versionDistanceParts')
        if component.get('metadataStatus')!='fresh' or not isinstance(distance,dict):raise LegacyDataUnavailable('versionDistanceParts 확인 필요')
        if any(type(distance.get(key)) is not int for key in ('epoch','major','minor','patch')):raise LegacyDataUnavailable('버전 거리 단위가 올바르지 않습니다')
        actual=tuple(distance[key] for key in ('epoch','major','minor','patch'))
        return any(_compare(actual,threshold,spec['operator']) for threshold in _distance_thresholds(spec['value']))
    expression,unresolved=_effective_license(component)
    if spec['value']=='unresolved':return unresolved if spec['operator']=='IS' else not unresolved
    entries=spec.get('licenses') or [];ids=[e.get('id','') for e in entries if e.get('id')];names=[e.get('name','') for e in entries if e.get('name')]
    exact=expression in ids+names
    if exact:return spec['operator']=='IS'
    try:parsed=_spdx(expression)
    except LegacySyntaxError:return spec['operator']=='IS_NOT'
    allowed=[]
    for value in ids:
        try:allowed.append(_spdx(value))
        except LegacySyntaxError:allowed.append(('id',value))
    if len(ids)*max(1,len(expression.split()))>16384:raise LegacyDataUnavailable('SPDX 조건 복잡도 한도를 초과했습니다')
    return _spdx_match(parsed,allowed,False) if spec['operator']=='IS' else not _spdx_match(parsed,allowed,True)


def prepare_legacy_contexts(rules,contexts,evaluated_at=None):
    """Populate shared component activations and return explicit data warnings."""
    at=evaluated_at or datetime.now(UTC);warnings=[];seen=set();evaluations=0
    for rule in rules:
        validate_legacy_conditions(rule.get("legacyConditions",[]) if isinstance(rule,dict) else rule.legacyConditions)
    java_results = _prepare_java_results(rules, contexts)
    for rule in rules:
        specs=getattr(rule,'legacyConditions',[]) if not isinstance(rule,dict) else rule.get('legacyConditions',[])
        validate_legacy_conditions(specs)
        rule_id=rule.id if not isinstance(rule,dict) else rule['id']
        for component_index, activation in enumerate(contexts.get('component',[])):
            component=activation.get('component') or {};component.setdefault('legacyConditions',{})
            for spec in specs:
                evaluations+=1
                if evaluations>100_000:raise ValueError('고급 조건 평가 횟수가 100,000회 한도를 초과했습니다')
                if spec['subject'] == 'JAVA_REGEX':
                    component['legacyConditions'][spec['id']] = java_results[(spec['id'], component_index)]
                    continue
                try:component['legacyConditions'][spec['id']]=evaluate_condition(spec,component,at)
                except LegacyDataUnavailable as exc:
                    component['legacyConditions'][spec['id']]=False
                    identity=str(component.get('purl') or component.get('name') or 'unknown');key=(rule_id,identity,str(exc))
                    if key not in seen:
                        seen.add(key);warnings.append({'ruleId':rule_id,'component':identity,'fields':[spec['subject']],'reason':str(exc)})
    return warnings
