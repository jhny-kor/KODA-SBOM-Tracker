from __future__ import annotations
import copy
import json
import uuid
import pytest
from koda_tracker.legacy_pre48_counts import prepare_condition,validate_condition,evaluate_count


def uid(value): return str(uuid.uuid5(uuid.NAMESPACE_URL,value))
LICENSE_A,LICENSE_B,GROUP=uid('a'),uid('b'),uid('group')
BUNDLE={'licenses':[{'uuid':LICENSE_A,'licenseId':'MIT'},{'uuid':LICENSE_B,'licenseId':'Apache-2.0'}], 'licenseGroups':[{'uuid':GROUP,'licenses':[{'uuid':LICENSE_A}]}]}


def condition(subject,value,operator='IS',bundle=None):
    return prepare_condition({'subject':subject,'operator':operator,'value':value},BUNDLE if bundle is None else bundle,7)


def component(license_uuid): return {'legacyLiteralFields':{'resolvedLicenseUuid':license_uuid}}


def test_severity_counts_each_matching_vulnerability_not_one_boolean():
    data=condition('SEVERITY','HIGH')
    actual={'vulnerabilities':[{'severity':'High'},{'severity':'HIGH'},{'severity':'Low'},{'severity':'HIGH','suppressed':True}]}
    assert evaluate_count(data,actual)==2
    assert evaluate_count(condition('SEVERITY','HIGH','IS_NOT'),actual)==1
    assert evaluate_count(condition('SEVERITY','high'),actual)==0
    assert evaluate_count(condition('SEVERITY','UNASSIGNED'),{'vulnerabilities':[{}, {'severity':'unknown'}]})==2


@pytest.mark.parametrize('value,operator,expected', [('CWE-79','CONTAINS_ANY',2),('79, 89','CONTAINS_ALL',1),(' * ','IS',3),('cwe-79','CONTAINS_ANY',0),('CWE-79 description','CONTAINS_ANY',2),('invalid','CONTAINS_ANY',0)])
def test_cwe_per_vulnerability_count_wildcard_and_original_parser(value,operator,expected):
    c={'vulnerabilities':[{'cwes':[79,89]},{'cwes':[79]},{'cwes':[]},{'cwes':None}]}
    assert evaluate_count(condition('CWE',value,operator),c)==expected


@pytest.mark.parametrize('subject,value,operator,actual,expected', [
    ('LICENSE',LICENSE_A,'IS',LICENSE_A,1),('LICENSE',LICENSE_A,'IS_NOT',LICENSE_B,1),
    ('LICENSE',LICENSE_A,'IS_NOT',None,0),('LICENSE',uid('missing'),'IS_NOT',LICENSE_A,0),
    ('LICENSE','unresolved','IS',None,1),('LICENSE','unresolved','IS_NOT',LICENSE_A,1),
    ('LICENSE_GROUP',GROUP,'IS',LICENSE_A,1),('LICENSE_GROUP',GROUP,'IS_NOT',LICENSE_B,1),
    ('LICENSE_GROUP',GROUP,'IS_NOT',None,1),('LICENSE_GROUP',GROUP,'IS',None,0),
])
def test_resolved_license_uuids_and_group_not_modern_spdx(subject,value,operator,actual,expected):
    c=component(actual);c['licenses']=['MIT OR Apache-2.0']
    assert evaluate_count(condition(subject,value,operator),c)==expected


def test_license_uuid_case_is_canonical_and_missing_group_definition_blocks():
    assert evaluate_count(condition('LICENSE',LICENSE_A.upper()),component(LICENSE_A.upper()))==1
    with pytest.raises(ValueError,match='그룹 정의'):
        condition('LICENSE_GROUP',uid('missing'))


@pytest.mark.parametrize('value,operator,actual,expected', [('1.2','NUMERIC_GREATER_THAN','1.3',1), ('0','NUMERIC_EQUAL',None,1),(' 0 ','NUMERIC_EQUAL',None,1),('0-1ubuntu1','NUMERIC_EQUAL',None,1),('0.0','NUMERIC_EQUAL',None,0),('1','NUMERIC_LESS_THAN',None,1),(None,'NUMERIC_EQUAL','1',0),('foo','NUMERIC_EQUAL','foo ',0),('1.0.0','NUMERIC_EQUAL','1.0',1)])
def test_original_version_comparison_and_null_parts(value,operator,actual,expected):
    assert evaluate_count(condition('VERSION',value,operator),{'legacyLiteralFields':{'version':actual}})==expected


@pytest.mark.parametrize('operator',['IS','IS_NOT','NO_MATCH'])
def test_hash_original_evaluator_ignores_operator(operator):
    data=condition('COMPONENT_HASH',json.dumps({'algorithm':'sHa-256','value':' ABCd '}),operator)
    assert evaluate_count(data,{'hashes':[{'alg':'SHA-256','content':'abcd'}]})==1
    assert evaluate_count(data,{'hashes':[{'alg':'SHA-256','content':'ffff'}]})==0
    assert evaluate_count(data,{'legacyLiteralFields':{'sha256':None},'hashes':[{'alg':'SHA-256','content':'abcd'}]})==0


def test_hash_unknown_missing_and_empty_values_preserve_failure_boundaries():
    assert evaluate_count(condition('COMPONENT_HASH',None),{})==0
    assert evaluate_count(condition('COMPONENT_HASH',json.dumps({'algorithm':'SHA256','value':'abcd'})),{'hashes':[{'alg':'SHA256','content':'abcd'}]})==0
    with pytest.raises(ValueError,match='빈 해시'):
        condition('COMPONENT_HASH',json.dumps({'algorithm':'MD5','value':'  '}))


@pytest.mark.parametrize('mutation', [lambda d:d.update(extra='x'),lambda d:d.update(sourceMinor=True),lambda d:d.update(operator='EXEC'),lambda d:d.update(value=12),lambda d:d.update(subject='EPSS')])
def test_normalized_metadata_validation_is_strict(mutation):
    data=condition('SEVERITY','HIGH');mutation(data)
    with pytest.raises(ValueError):validate_condition(data)


def test_invalid_group_or_registry_uuid_and_unbounded_evidence_fail_explicitly():
    with pytest.raises(ValueError):condition('LICENSE','not-a-uuid')
    with pytest.raises(ValueError):evaluate_count(condition('SEVERITY','HIGH'),{'vulnerabilities':[{}]*100_001})
    data=condition('LICENSE_GROUP',GROUP);data['licenseUuids']=[LICENSE_A,LICENSE_A]
    with pytest.raises(ValueError):validate_condition(data)
    with pytest.raises(ValueError):evaluate_count(condition('CWE','79','CONTAINS_ANY'),{'vulnerabilities':[{'cwes':[True]}]})
