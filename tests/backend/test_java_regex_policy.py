from __future__ import annotations
import json
import pytest
from test_migration import bundle, policy, evaluate_document, make_report
from koda_tracker.policies import PolicyDocument
from koda_tracker import java_regex


def converted(db, subject, pattern, operator='MATCHES'):
    raw = bundle([policy(subject, operator, pattern)])
    raw['source']['version'] = '4.13.4'
    report = make_report(db, raw)
    assert report['canApply'], report['blockers']
    return PolicyDocument(rules=[report['convertedPolicies'][0]['rule']])


# Share the existing SQLite migration fixture; every decision uses the actual JVM.
from test_migration import db  # noqa: E402,F401


@pytest.mark.parametrize('subject,pattern,component,expected', [
    ('PACKAGE_URL', r'(?<=pkg:pypi/)sample@1', {'name':'sample','purl':'pkg:pypi/sample@1'}, True),
    ('PACKAGE_URL', r'(?<!pypi/)sample@1', {'name':'sample','purl':'pkg:pypi/sample@1'}, False),
    ('PACKAGE_URL', r'(sample)\1', {'name':'sample','purl':'pkg:pypi/samplesample@1'}, True),
    ('PACKAGE_URL', r'(?<pkg>sample)\k<pkg>', {'name':'sample','purl':'pkg:pypi/samplesample@1'}, True),
    ('CPE', r'[a-z&&[^aeiou]]++', {'name':'sample','cpe':'cpe:2.3:a:xyz:product'}, True),
    ('CPE', r'^cpe:(?>2\.3):a:', {'name':'sample','cpe':'cpe:2.3:a:vendor:product'}, True),
    ('SWID_TAGID', r'(?iu)\p{IsGreek}++', {'name':'sample','swid':{'tagId':'urn:ΑΒΓ'}}, True),
    ('SWID_TAGID', r'\Qvendor.[one]\E', {'name':'sample','swid':{'tagId':'urn:vendor.[one]'}}, True),
    ('PACKAGE_URL', r'^sample$', {'name':'sample','purl':'pkg:pypi/sample@1'}, False),
    ('PACKAGE_URL', r'sample*', {'name':'sample','purl':'pkg:pypi/sample@1'}, True),
])
def test_java_specific_conditions_use_source_matcher_and_invert(db, subject, pattern, component, expected):
    for operator, wanted in [('MATCHES',expected),('NO_MATCH',not expected)]:
        document = converted(db,subject,pattern,operator)
        rows, metrics = evaluate_document(document,[component],[])
        assert bool(rows) is wanted
        assert metrics['policyDataComplete'] is True
        assert metrics['policyCompatibilityRuntimes'][0]['javaMajor'] == 21
        assert document.rules[0].legacyConditions[0]['regexDialect'] == 'java21-legacy4'


@pytest.mark.parametrize('operator,expected', [('MATCHES',False),('NO_MATCH',True)])
def test_missing_cpe_is_null_rather_than_empty_match(db, operator, expected):
    document=converted(db,'CPE','*',operator)
    assert bool(evaluate_document(document,[{'name':'sample'}],[])[0]) is expected


@pytest.mark.parametrize('operator,coordinates,component,expected', [
    ('MATCHES',{'group':r'(?<=org\.)acme','name':r'(?<n>sample)\k<n>','version':r'\d+\.\d+'}, {'group':' org.acme ','name':'samplesample','version':'1.2'},True),
    ('NO_MATCH',{'group':'wrong','name':'wrong','version':'9'}, {'group':'org.acme','name':'sample','version':'1'},True),
    # NO_MATCH negates each field, not the complete conjunction.
    ('NO_MATCH',{'group':'wrong','name':'sample','version':'9'}, {'group':'org.acme','name':'sample','version':'1'},False),
    ('NO_MATCH',{'name':'wrong','version':'9'}, {'name':'sample','version':'1'},True),
    ('MATCHES',{'name':'sample','version':'1'}, {'group':'','name':'sample','version':'1'},False),
    ('NO_MATCH',{'name':'wrong','version':'9'}, {'group':' ','name':'sample','version':'1'},False),
    ('NO_MATCH',{'group':'wrong','name':'wrong'}, {'group':'org.acme','name':'sample','version':'1'},False),
    ('MATCHES',{'name':'sample'}, {'name':'sample'},True),
    ('MATCHES',{'name':'sample','version':'>= 1.2'}, {'name':'sample','version':'1.3'},True),
    ('MATCHES',{'group':' org.example ','name':' sample ','version':' 1 '}, {'group':'org.example','name':'sample','version':'1'},True),
    ('MATCHES',{'name':'sample','version':'==foo'}, {'name':'sample','version':'foo '},False),
    ('NO_MATCH',{'name':'wrong','version':'>= 1.2'}, {'name':'sample','version':'1.1'},True),
])
def test_coordinate_per_field_inversion_null_trim_and_versions(db,operator,coordinates,component,expected):
    document=converted(db,'COORDINATES',json.dumps(coordinates),operator)
    assert bool(evaluate_document(document,[component],[])[0]) is expected


def test_invalid_java_pattern_blocks_staging_without_dropping_condition(db):
    raw=bundle([policy('PACKAGE_URL','NO_MATCH',r'(?<invalid')]);raw['source']['version']='4.13.4'
    report=make_report(db,raw)
    assert not report['canApply'] and 'Java' in report['blockers'][0]['reason']
    assert report['blockers'][0]['original']==raw['policies'][0]


def test_java_failure_never_becomes_a_no_match_violation_or_pass(db,monkeypatch):
    document=converted(db,'PACKAGE_URL',r'(?<=pkg:)pypi','NO_MATCH')
    def fail(*args,**kwargs):raise java_regex.JavaRegexError('bounded JVM failed')
    monkeypatch.setattr(java_regex,'evaluate_matches',fail)
    with pytest.raises(java_regex.JavaRegexError,match='bounded JVM failed'):
        evaluate_document(document,[{'name':'sample','purl':'pkg:pypi/sample@1'}],[])


def test_java_component_work_is_deduplicated_and_batched(db,monkeypatch):
    document=converted(db,'PACKAGE_URL',r'(?<=pkg:)pypi')
    original=java_regex.evaluate_matches;requests=[]
    def collect(items,**kwargs):requests.append(items);return original(items,**kwargs)
    monkeypatch.setattr(java_regex,'evaluate_matches',collect)
    rows,_=evaluate_document(document,[{'name':'one','purl':'pkg:pypi/same@1'},{'name':'two','purl':'pkg:pypi/same@1'}],[])
    assert rows and len(requests)==1 and len(requests[0])==1


def test_pre_java_literal_source_is_not_reinterpreted_as_regex(db):
    raw=bundle([policy('PACKAGE_URL','MATCHES',r'(?<=pkg:)pypi')]);raw['source']['version']='4.7.1'
    report=make_report(db,raw)
    assert report['canApply']
    document=PolicyDocument(rules=[report['convertedPolicies'][0]['rule']])
    assert document.rules[0].legacyConditions[0]['subject']=='LEGACY_LITERAL'
    assert not evaluate_document(document,[{'name':'sample','purl':'pkg:pypi/sample@1'}],[])[0]


@pytest.mark.parametrize('coordinate_version', ['4.13.4','4.7.1'])
def test_coordinate_package_version_never_changes_source_regex_dialect(db,coordinate_version):
    first=policy('COORDINATES','MATCHES',json.dumps({'name':'sample','version':coordinate_version}))
    second=policy('PACKAGE_URL','MATCHES',r'(?<=pkg:)pypi')['policyConditions'][0]
    first['policyConditions'].append(second)
    raw=bundle([first])  # source5 uses RE2 even when the package version starts4
    report=make_report(db,raw)
    assert not report['canApply']
    raw['policies'][0]['policyConditions'][1]['value']='^pkg:pypi/'
    report=make_report(db,raw)
    assert report['canApply']
    assert all(spec['subject']!='JAVA_REGEX' for spec in report['convertedPolicies'][0]['rule']['legacyConditions'])
