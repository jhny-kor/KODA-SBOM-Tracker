from copy import deepcopy
from datetime import UTC, datetime

import pytest

from koda_tracker.quality import DEFAULT_PROFILE, diagnose
from koda_tracker.quality_scoring import DEFAULT_SCORE_WEIGHTS, blocking_issue_count, score_quality, validate_score_weights

AT = datetime(2026, 10, 18, 12, tzinfo=UTC)


def good_bom():
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'serialNumber': 'urn:uuid:sample',
            'metadata': {'timestamp': AT.isoformat(), 'tools': [{'name': 'generator'}], 'authors': [{'name': 'Author'}],
                         'component': {'bom-ref': 'root', 'name': 'app', 'supplier': {'name': 'Vendor'}}},
            'components': [{'name': 'a', 'version': '1', 'bom-ref': 'a', 'purl': 'pkg:npm/a@1',
                            'licenses': [{'license': {'id': 'MIT'}}], 'hashes': [{'alg': 'SHA-256', 'content': 'a' * 64}]}],
            'dependencies': [{'ref': 'root', 'dependsOn': ['a']}, {'ref': 'a', 'dependsOn': []}]}


def score(bom, weights=None):
    issues, summary = diagnose(bom, DEFAULT_PROFILE, AT)
    return score_quality(bom, issues, summary, weights)


def test_complete_document_scores_100_and_exposes_exact_check_denominators():
    result = score(good_bom())
    assert result['score'] == 100 and result['scoreVersion'] == '1'
    assert result['blockingIssueCount'] == 0
    assert result['scoreDetails']['state'] == 'completed'
    assert result['scoreDetails']['applicableWeight'] == 100
    for name, value in result['scoreDetails']['domains'].items():
        assert value['score'] == 100 and value['applicable'] is True
        assert value['numerator'] == value['denominator'] > 0
        assert value['weightedContribution'] == DEFAULT_SCORE_WEIGHTS[name]
    graph = result['scoreDetails']['domains']['graph']
    assert next(c for c in graph['checks'] if c['id'] == 'resolvedReferences')['denominator'] == 2


@pytest.mark.parametrize('domain', DEFAULT_SCORE_WEIGHTS)
def test_configured_weights_select_each_domain_without_implicit_normalization(domain):
    bom = good_bom()
    bom['components'][0].pop('hashes')
    weights = {name: 100 if name == domain else 0 for name in DEFAULT_SCORE_WEIGHTS}
    result = score(bom, weights)
    assert result['score'] == (0 if domain == 'integrity' else 100)
    assert result['scoreDetails']['domains']['integrity']['score'] == 0
    assert result['scoreDetails']['domains']['integrity']['applicable'] is True
    assert result['scoreDetails']['domains']['integrity']['weight'] == weights['integrity']


def test_missing_graph_is_measured_as_missing_and_never_100():
    bom = good_bom(); bom.pop('dependencies')
    result = score(bom)
    assert result['score'] == 90
    domain = result['scoreDetails']['domains']['graph']
    assert domain['score'] == 50 and domain['applicable'] is True
    assert domain['numerator'] == 2 and domain['denominator'] == 4


def test_nested_components_are_in_all_domain_denominators_and_reduce_score():
    bom = good_bom()
    bom['components'][0]['components'] = [{'name': 'b', 'version': '1', 'bom-ref': 'b'}]
    result = score(bom)
    assert result['score'] == 67.78
    for domain in ('identity', 'license', 'integrity'):
        assert result['scoreDetails']['domains'][domain]['denominator'] == 2
        assert result['scoreDetails']['domains'][domain]['score'] == 50


def test_repeated_issues_and_references_cannot_pad_or_multiply_evidence():
    bom = good_bom(); bom['components'][0].pop('hashes')
    issues, summary = diagnose(bom, DEFAULT_PROFILE, AT)
    first = score_quality(bom, issues, summary)
    assert score_quality(bom, issues * 10, summary) == first
    bom['dependencies'] *= 10
    repeated_issues, repeated_summary = diagnose(bom, DEFAULT_PROFILE, AT)
    assert score_quality(bom, repeated_issues, repeated_summary) == first


def test_empty_document_excludes_component_domains_and_has_no_overall_score():
    result = score({'components': []})
    assert result['score'] is None and result['scoreDetails']['state'] == 'empty'
    assert result['blockingIssueCount'] == 1
    for domain in ('identity', 'license', 'integrity'):
        value = result['scoreDetails']['domains'][domain]
        assert value['applicable'] is False and value['score'] is None and value['denominator'] == 0
        assert domain in result['scoreDetails']['excludedDomains']
    failed = score_quality({}, [], {'state': 'failed', 'componentCount': None})
    assert failed['score'] is None and failed['scoreDetails']['state'] == 'failed'
    assert failed['scoreDetails']['domains'] == {} and failed['scoreDetails']['excludedDomains'] == []
    assert failed['scoreDetails']['applicableWeight'] is None


def test_critical_graph_errors_are_reported_even_with_zero_graph_weight_and_100_score():
    bom = good_bom(); bom['dependencies'][0]['dependsOn'].append('missing')
    weights = {name: 100 if name == 'provenance' else 0 for name in DEFAULT_SCORE_WEIGHTS}
    result = score(bom, weights)
    assert result['score'] == 100 and result['blockingIssueCount'] == 1
    issues, _ = diagnose(bom, DEFAULT_PROFILE, AT)
    assert blocking_issue_count(issues * 20) == 1


def test_json_xml_equivalent_normalized_documents_get_identical_scores(tmp_path):
    from koda_tracker.sbom import parse_sbom_file
    bom = good_bom()
    xml = '''<bom xmlns="http://cyclonedx.org/schema/bom/1.6" serialNumber="urn:uuid:sample" version="1"><metadata><timestamp>2026-10-18T12:00:00+00:00</timestamp><tools><tool><name>generator</name></tool></tools><authors><author><name>Author</name></author></authors><component type="application" bom-ref="root"><supplier><name>Vendor</name></supplier><name>app</name></component></metadata><components><component type="library" bom-ref="a"><name>a</name><version>1</version><hashes><hash alg="SHA-256">''' + 'a' * 64 + '''</hash></hashes><licenses><license><id>MIT</id></license></licenses><purl>pkg:npm/a@1</purl></component></components><dependencies><dependency ref="root"><dependency ref="a"/></dependency><dependency ref="a"/></dependencies></bom>'''
    path = tmp_path / 'bom.xml'; path.write_text(xml)
    normalized, _ = parse_sbom_file(path)
    assert score(normalized) == score(bom)
    original = deepcopy(bom)
    assert score(bom) == score(bom)
    assert bom == original


@pytest.mark.parametrize('weights', [None, {}, {'identity': 100}, {**DEFAULT_SCORE_WEIGHTS, 'other': 0},
                                  {**DEFAULT_SCORE_WEIGHTS, 'identity': 29}, {**DEFAULT_SCORE_WEIGHTS, 'identity': True},
                                  {**DEFAULT_SCORE_WEIGHTS, 'identity': 30.0}, {**DEFAULT_SCORE_WEIGHTS, 'identity': -1},
                                  {**DEFAULT_SCORE_WEIGHTS, 'identity': float('nan')}])
def test_invalid_profile_weights_rejected(weights):
    with pytest.raises(ValueError):
        validate_score_weights(weights)
