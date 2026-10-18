"""Deterministic, evidence-based weighted SBOM quality scores.

Version 1 counts a component as one unit in identity/license/integrity. Graph
units measure presence, declared component refs, reference resolution, cycles,
and root reachability. Provenance has five document units. A domain's percent
is passed units / applicable units * 100. Its weighted contribution is that
percent * configured weight / sum of applicable positive weights. Missing
required information is a failed unit; only domains with no applicable units
are excluded. Empty documents and failed diagnostics have no overall score.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import re
from typing import Any

SCORE_VERSION = '1'
DEFAULT_SCORE_WEIGHTS = {'identity': 30, 'graph': 20, 'license': 20, 'provenance': 20, 'integrity': 10}
DOMAINS = tuple(DEFAULT_SCORE_WEIGHTS)
BLOCKING_RULES = frozenset({'identity.empty', 'graph.duplicate_ref', 'graph.unresolved_ref'})
FORMULA = 'sum(domainPassed/domainTotal * 100 * weight) / sum(applicableWeights)'
_COMPONENT_PATH = re.compile(r'^(\$\.components\[\d+\](?:\.components\[\d+\])*)')


def validate_score_weights(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != set(DOMAINS):
        raise ValueError('품질 가중치는 identity, graph, license, provenance, integrity 다섯 항목이어야 합니다')
    if any(type(v) is not int or not 0 <= v <= 100 for v in value.values()) or sum(value.values()) != 100:
        raise ValueError('품질 가중치는 0~100 정수이며 합계는 100이어야 합니다')
    return {domain: value[domain] for domain in DOMAINS}


def blocking_issue_count(issues: list[dict]) -> int:
    return len({(i.get('ruleId'), i.get('path')) for i in issues if i.get('ruleId') in BLOCKING_RULES})


def _rounded(value: Decimal) -> float:
    return float(value.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))


def _components(bom: dict) -> list[tuple[dict, str]]:
    result = []
    stack = [(bom.get('components', []), '$.components')]
    while stack:
        nodes, path = stack.pop()
        if not isinstance(nodes, list):
            raise ValueError(path + '는 배열이어야 합니다')
        for index, item in enumerate(nodes):
            if not isinstance(item, dict):
                raise ValueError(f'{path}[{index}]는 객체여야 합니다')
            component_path = f'{path}[{index}]'
            result.append((item, component_path))
            stack.append((item.get('components', []), component_path + '.components'))
    return result


def _meaningful(value: Any) -> bool:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str) and current.strip():
            return True
    return False


def _timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is not None
    except ValueError:
        return False


def _check(identity: str, passed: int, total: int) -> dict:
    return {'id': identity, 'numerator': passed, 'denominator': total}


def score_quality(bom: dict, issues: list[dict], summary: dict, weights: dict | None = None) -> dict:
    weights = validate_score_weights(DEFAULT_SCORE_WEIGHTS if weights is None else weights)
    blocking = blocking_issue_count(issues)
    if summary.get('state') != 'completed':
        return {'score': None, 'scoreVersion': SCORE_VERSION, 'blockingIssueCount': blocking,
                'scoreDetails': {'state': 'failed', 'formula': FORMULA, 'totalWeight': 100,
                                 'applicableWeight': None, 'excludedDomains': [], 'domains': {}}}
    components = _components(bom)
    component_paths = {path for _, path in components}
    rules = {str(issue.get('ruleId') or '') for issue in issues}
    failed = {domain: set() for domain in ('identity', 'license', 'integrity')}
    for issue in issues:
        domain = str(issue.get('ruleId') or '').split('.', 1)[0]
        if domain not in failed:
            continue
        match = _COMPONENT_PATH.match(str(issue.get('path') or ''))
        if match and match[1] in component_paths:
            failed[domain].add(match[1])
    count = len(components)
    checks = {domain: [_check('components', count - len(paths), count)] for domain, paths in failed.items()}

    metadata = bom.get('metadata') or {}
    root = metadata.get('component') or {}
    refs = [c.get('bom-ref') for c, _ in components]
    if root:
        refs.append(root.get('bom-ref'))
    usable_refs = [ref for ref in refs if isinstance(ref, str) and ref.strip()]
    counts = Counter(usable_refs)
    unique_refs = {ref for ref, n in counts.items() if n == 1}
    dependencies = bom.get('dependencies') or []
    graph: dict[str, set[str]] = {}
    mentions = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError('의존성 항목은 객체여야 합니다')
        targets = dependency.get('dependsOn', [])
        if not isinstance(targets, list):
            raise ValueError('dependsOn은 배열이어야 합니다')
        origin = dependency.get('ref')
        mentions.extend([origin, *targets])
        if isinstance(origin, str):
            graph.setdefault(origin, set()).update(t for t in targets if isinstance(t, str))
    # A repeated reference is the same resolution check, not extra evidence.
    mentioned_refs = set(mentions)
    reachable = set()
    root_ref = root.get('bom-ref')
    if isinstance(root_ref, str) and root_ref in unique_refs and root_ref in graph:
        todo = [root_ref]
        while todo:
            ref = todo.pop()
            if ref not in reachable:
                reachable.add(ref)
                todo.extend(graph.get(ref, ()))
    graph_present = bool(dependencies)
    checks['graph'] = [
        _check('graphPresent', int(graph_present), 1),
        _check('componentRefs', sum(isinstance(ref, str) and ref in unique_refs for ref in refs), len(refs)),
        _check('resolvedReferences', sum(isinstance(ref, str) and ref in unique_refs for ref in mentioned_refs), len(mentioned_refs)),
        _check('acyclic', int('graph.cycle' not in rules) if graph_present else 0, int(graph_present)),
        _check('rootConnectivity', sum(isinstance(c.get('bom-ref'), str) and c['bom-ref'] in reachable for c, _ in components), count),
    ]
    timestamp_ok = _timestamp(metadata.get('timestamp')) and not any(
        rule.startswith('provenance.timestamp_') or rule == 'provenance.stale' for rule in rules)
    checks['provenance'] = [
        _check('timestamp', int(timestamp_ok), 1),
        _check('tools', int(_meaningful(metadata.get('tools'))), 1),
        _check('authors', int(_meaningful(metadata.get('authors'))), 1),
        _check('supplier', int(_meaningful(root.get('supplier') or metadata.get('supplier'))), 1),
        _check('serialNumber', int(isinstance(bom.get('serialNumber'), str) and bool(bom['serialNumber'].strip())), 1),
    ]
    details = {}
    effective_weight = 0
    exact_scores = {}
    for domain in DOMAINS:
        domain_checks = checks[domain]
        passed = sum(c['numerator'] for c in domain_checks)
        total = sum(c['denominator'] for c in domain_checks)
        applicable = total > 0
        percent = Decimal(passed) * 100 / Decimal(total) if applicable else None
        if applicable:
            effective_weight += weights[domain]
            exact_scores[domain] = percent
        details[domain] = {'weight': weights[domain], 'applicable': applicable,
                           'numerator': passed, 'denominator': total,
                           'score': _rounded(percent) if percent is not None else None,
                           'weightedContribution': None, 'checks': domain_checks}
    exact_total = Decimal(0)
    if effective_weight:
        for domain, percent in exact_scores.items():
            contribution = percent * weights[domain] / effective_weight
            details[domain]['weightedContribution'] = _rounded(contribution)
            exact_total += contribution
    state = 'completed' if count and effective_weight else 'empty' if not count else 'no_applicable_weight'
    return {'score': _rounded(exact_total) if state == 'completed' else None,
            'scoreVersion': SCORE_VERSION, 'blockingIssueCount': blocking,
            'scoreDetails': {'state': state, 'formula': FORMULA, 'totalWeight': 100,
                             'applicableWeight': effective_weight,
                             'excludedDomains': [domain for domain in DOMAINS if not details[domain]['applicable']],
                             'domains': details}}
