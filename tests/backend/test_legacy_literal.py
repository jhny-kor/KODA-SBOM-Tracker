from __future__ import annotations
import json
import pytest
from test_migration import bundle, policy, make_report, evaluate_document, db
from koda_tracker.legacy_literal import literal_spec, evaluate_count
from koda_tracker.policies import PolicyDocument
from koda_tracker.sbom import parse_sbom


def document(db,conditions,operator='ANY',version='4.7.1'):
    first=policy();first['operator']=operator;first['policyConditions']=conditions
    raw=bundle([first]);raw['source']['version']=version
    report=make_report(db,raw)
    assert report['canApply'], report['blockers']
    return PolicyDocument(rules=[report['convertedPolicies'][0]['rule']])


def condition(subject,value,operator='MATCHES'):
    return policy(subject,operator,value)['policyConditions'][0]


@pytest.mark.parametrize('subject,value,component,count', [
    ('PACKAGE_URL','sample',{'purl':'pkg:pypi/sample@1'},2),
    ('PACKAGE_URL','?arch=x86',{'purl':'pkg:pypi/sample@1?arch=x86#src'},1),
    ('PACKAGE_URL','^pkg:',{'purl':'pkg:pypi/sample@1'},0),
    ('PACKAGE_URL','*sample*',{'purl':'pkg:pypi/sample@1'},0),
    ('PACKAGE_URL','',{'purl':'pkg:pypi/sample@1'},2),
    ('PACKAGE_URL','SAMPLE',{'purl':'pkg:pypi/sample@1'},0),
    ('CPE','[abc]',{'cpe':'cpe:2.3:a:[abc]:product'},1),
    ('CPE','*',{'cpe':'cpe:2.3:a:vendor:product'},0),
    ('CPE','*',{'cpe':'cpe:2.3:a:vendor:product:*'},1),
    ('CPE','',{'cpe':''},1),
    ('SWID_TAGID',r'(?<=urn:)sample',{'swidTagId':'urn:sample'},0),
    ('SWID_TAGID','한국',{'swidTagId':'urn:한국'},1),
])
def test_literal_metacharacters_case_empty_and_raw_counts(subject,value,component,count):
    assert evaluate_count(literal_spec(subject,value,'MATCHES','4.7.1'),component)==count
    assert evaluate_count(literal_spec(subject,value,'NO_MATCH','4.7.1'),component)==int(count==0)


@pytest.mark.parametrize('subject', ['PACKAGE_URL','CPE','SWID_TAGID'])
@pytest.mark.parametrize('operator', ['MATCHES','NO_MATCH'])
def test_missing_identifiers_never_make_old_violations(subject,operator):
    assert evaluate_count(literal_spec(subject,'x',operator,'4.7.1'),{})==0


def test_source_coordinate_purl_is_preserved_and_version_retained():
    fields={'purl':'pkg:generic/a@1?arch=x86#src','purlCoordinates':'pkg:generic/a@1'}
    assert evaluate_count(literal_spec('PACKAGE_URL','a@1','MATCHES','4.7.1'),{'legacyLiteralFields':fields})==2
    fields['purlCoordinates']=None
    assert evaluate_count(literal_spec('PACKAGE_URL','a@1','MATCHES','4.7.1'),{'legacyLiteralFields':fields})==1


@pytest.mark.parametrize('version,expected', [('4.0.1',True),('4.1.0',False),('4.7.1',False)])
def test_all_preserves_optional_or_raw_count_gate(db,version,expected):
    doc=document(db,[condition('PACKAGE_URL','sample')],'ALL',version)
    rows,metrics=evaluate_document(doc,[{'name':'sample','purl':'pkg:pypi/sample@1'}],[])
    assert bool(rows) is expected
    assert metrics['policyCompatibilityRuntimes'][0]['allGate']=='rawConditionViolationCount'


@pytest.mark.parametrize('purl_pattern,cpe_pattern,expected', [
    ('sample','missing',True),  # two raw PURL matches compensate for false CPE
    ('?arch=x86','missing',False),
    ('sample','vendor',False),  # raw count3 differs from configured count2
])
def test_all_mixed_condition_raw_count_quirks(db,purl_pattern,cpe_pattern,expected):
    doc=document(db,[condition('PACKAGE_URL',purl_pattern),condition('CPE',cpe_pattern)],'ALL')
    assert bool(evaluate_document(doc,[{'name':'sample','purl':'pkg:pypi/sample@1?arch=x86','cpe':'vendor'}],[])[0]) is expected


@pytest.mark.parametrize('version,expected', [('4.0.1',False),('4.1.0',True),('4.7.1',True)])
def test_source40_caps_same_subject_at_one_result(db,version,expected):
    doc=document(db,[condition('CPE','vendor'),condition('CPE','product')],'ALL',version)
    assert bool(evaluate_document(doc,[{'name':'sample','cpe':'vendor:product'}],[])[0]) is expected


@pytest.mark.parametrize('version,coordinates,component,expected', [
    ('4.7.1',{'group':' org.example ','name':' sample ','version':'1'},{'group':'org.example','name':'sample','version':'1'},1),
    ('4.7.1',{'group':'*','name':'*','version':'*'},{'group':'org.example','name':'sample','version':'1'},1),
    ('4.7.1',{'group':None,'name':'sample','version':'1'},{'group':' ','name':'sample','version':'1'},0),
    ('4.7.1',{'name':'sample','version':'>= 1.1'},{'name':'sample','version':'1.2'},1),
    ('4.1.0',{'name':'sample','version':'>= 1.1'},{'name':'sample','version':'1.2'},0),
    ('4.1.0',{'name':'sample'},{'name':'sample'},1),
    ('4.7.1',{'group':'wrong','name':'sample'},{'group':'org.example','name':'sample'},0),
])
def test_coordinate_literal_and_comparator_version_boundaries(version,coordinates,component,expected):
    assert evaluate_count(literal_spec('COORDINATES',json.dumps(coordinates),'MATCHES',version),component)==expected


def test_source_null_coordinate_version_failure_is_explicit_when_reached():
    spec=literal_spec('COORDINATES',json.dumps({'name':'sample'}),'MATCHES','4.7.1')
    with pytest.raises(ValueError,match='null 좌표 버전'):
        evaluate_count(spec,{'name':'sample','version':'1'})


def test_xml_keeps_literal_cpe_swid_and_absent_fields(db):
    raw=b'''<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library" bom-ref="sample"><name>sample</name><cpe>cpe:2.3:a:vendor:[literal]:*</cpe><swid tagId="urn:vendor.[literal]" name="sample" version="1"><url>https://example.test/swid</url></swid></component></components></bom>'''
    bom,_=parse_sbom(raw);component=bom['components'][0]
    assert component['swid']['url']=='https://example.test/swid'
    assert 'group' not in component and 'version' not in component and 'purl' not in component
    for subject,value in [('CPE','[literal]'),('SWID_TAGID','[literal]')]:
        doc=document(db,[condition(subject,value)])
        assert evaluate_document(doc,[component],[])[0]


def test_invalid_old_profile_condition_is_not_silently_reinterpreted(db):
    raw=bundle([policy('EPSS','NUMERIC_GREATER_THAN','0.5')]);raw['source']['version']='4.7.1'
    report=make_report(db,raw)
    assert not report['canApply'] and '등록되지 않은' in report['blockers'][0]['reason']


@pytest.mark.parametrize('source_cwes,expected', [(None,False),([],True),([79],True)])
def test_old_cwe_wildcard_preserves_source_null_vs_empty_list(db,source_cwes,expected):
    from koda_tracker.migration import _finding
    doc=document(db,[condition('CWE','*','CONTAINS_ANY')])
    raw={'component':{'name':'sample','version':'1'},'vulnerability':{'vulnId':'CVE-2026-12345','severity':'HIGH','cwes':source_cwes}}
    finding=_finding(raw)
    assert bool(evaluate_document(doc,[{'name':'sample','version':'1'}],[finding])[0]) is expected
