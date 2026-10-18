from datetime import UTC, datetime

import pytest

from koda_tracker.legacy_policy import condition_spec, evaluate_condition, prepare_legacy_contexts, validate_legacy_conditions, LegacyDataUnavailable


def spec(subject, operator, value, **kwargs):
    return condition_spec({'subject':subject,'operator':operator,'value':value},source_version='5.0.3',**kwargs)


def metadata_component(**metadata):
    return {'name':'sample','purl':'pkg:npm/sample@1','metadataStatus':'fresh','packageMetadata':metadata,'isDirectDependency':True}


@pytest.mark.parametrize('published,period,now,expected',[
    ('2024-01-31T12:00:00Z','P1M','2024-02-29T00:00:00Z',True),
    ('2024-01-31T12:00:00Z','P1M','2024-02-28T23:59:59Z',False),
    ('2024-02-29T12:00:00Z','P1Y','2025-02-28T00:00:00Z',True),
    ('2023-01-31T00:00:00Z','P1Y1M','2024-02-29T00:00:00Z',True),
    ('2024-01-31T12:00:00Z','P2W','2024-02-14T00:00:00Z',True),
])
def test_age_matches_java_period_calendar_clamping(published,period,now,expected):
    value=spec('AGE','NUMERIC_EQUAL',period)
    assert evaluate_condition(value,metadata_component(currentVersionPublishedAt=published),datetime.fromisoformat(now)) is expected


def test_source_version_selects_publication_and_timezone_without_guessing():
    five=spec('AGE','NUMERIC_EQUAL','P1D',source_timezone='Asia/Seoul')
    assert five['timeZone']=='UTC' and five['publicationField']=='currentVersionPublishedAt'
    four=condition_spec({'subject':'AGE','operator':'NUMERIC_EQUAL','value':'P1D'},source_version='4.12.7',source_timezone='America/New_York')
    component=metadata_component(currentVersionPublishedAt='2000-01-01T00:00:00Z',latestPublishedAt='2024-03-09T23:30:00-05:00')
    assert four['publicationField']=='latestPublishedAt'
    assert evaluate_condition(four,component,datetime.fromisoformat('2024-03-10T23:00:00-04:00'))
    with pytest.raises(ValueError,match='timeZone'):
        condition_spec({'subject':'AGE','operator':'NUMERIC_EQUAL','value':'P1D'},source_version='4.12.7')


def test_last_modified_is_not_used_as_publication_for_age():
    component=metadata_component(currentVersionPublishedAt='2000-01-01T00:00:00Z',currentVersionPublishedAtBasis='artifact_last_modified')
    with pytest.raises(LegacyDataUnavailable,match='최초 공개'):
        evaluate_condition(spec('AGE','NUMERIC_GREATER_THAN','P1Y'),component,datetime.now(UTC))


@pytest.mark.parametrize('actual,value,operator,expected',[
    ((0,0,1,-1),{'major':'0','minor':'1','patch':'?'},'NUMERIC_EQUAL',True),
    ((0,0,1,-1),{'major':'0','minor':'1','patch':'?'},'NUMERIC_GREATER_THAN',False),
    ((0,2,-1,-1),{'major':'1','minor':'?','patch':'?'},'NUMERIC_GREATER_THAN',True),
    ((1,-1,-1,-1),{'epoch':'1','major':'1','minor':'?','patch':'?'},'NUMERIC_EQUAL',True),
    ((0,1,-1,-1),{'epoch':'1','major':'1','minor':'?','patch':'?'},'NUMERIC_EQUAL',True),
    ((0,0,0,0),{'major':'0','minor':'0','patch':'0'},'NUMERIC_EQUAL',True),
    ((0,2,-1,-1),{'major':'1','minor':'1','patch':'1'},'NUMERIC_EQUAL',False),
    ((0,0,0,0),{'epoch':'1','major':'1','minor':'?','patch':'?'},'NUMERIC_LESS_THAN',True),
])
def test_version_distance_matches_source_first_difference_and_or_thresholds(actual,value,operator,expected):
    component=metadata_component(versionDistanceParts=dict(zip(('epoch','major','minor','patch'),actual)))
    assert evaluate_condition(spec('VERSION_DISTANCE',operator,value),component,datetime.now(UTC)) is expected


def test_version_distance_uses_only_direct_components_and_never_scalar_release_count():
    value=spec('VERSION_DISTANCE','NUMERIC_GREATER_THAN',{'major':'0','minor':'0','patch':'0'})
    component=metadata_component(versionDistance=700)
    component['isDirectDependency']=False
    assert not evaluate_condition(value,component,datetime.now(UTC))
    component['isDirectDependency']=True
    with pytest.raises(LegacyDataUnavailable,match='versionDistanceParts'):
        evaluate_condition(value,component,datetime.now(UTC))
    component.pop('isDirectDependency')
    with pytest.raises(LegacyDataUnavailable,match='직접'):
        evaluate_condition(value,component,datetime.now(UTC))


@pytest.mark.parametrize('expression,condition,operator,expected',[
    ('MIT OR Apache-2.0','MIT','IS',False),
    ('MIT AND Apache-2.0','MIT','IS',True),
    ('MIT OR Apache-2.0','MIT','IS_NOT',False),
    ('MIT AND Apache-2.0','MIT','IS_NOT',True),
    ('GPL-2.0-only WITH Classpath-exception-2.0','GPL-2.0','IS',False),
    ('GPL-2.0-only WITH Classpath-exception-2.0','GPL-2.0-only WITH Classpath-exception-2.0','IS',True),
    ('GPL-2.0-with-classpath-exception','GPL-2.0-only WITH Classpath-exception-2.0','IS',True),
    ('GPL-2.0+','GPL-2.0-only','IS',True),
    ('GPL-2.0+','GPL-3.0-only','IS_NOT',False),
    ('GPL-3.0-only','GPL-2.0-or-later','IS_NOT',False),
    ('GPL-1.0+','GPL-2.0+','IS_NOT',False),
    ('GPL-1.0-only','GPL-2.0+','IS_NOT',True),
    ('MIT AND (GPL-2.0+ OR Apache-2.0)','MIT','IS',True),
])
def test_spdx_choice_and_atomic_with_or_later_semantics(expression,condition,operator,expected):
    value=spec('LICENSE',operator,'uuid',licenses=[{'id':condition,'name':condition}])
    assert evaluate_condition(value,{'licenses':[expression]},datetime.now(UTC)) is expected


def test_effective_source_license_precedence_and_custom_unresolved():
    value=spec('LICENSE','IS','uuid',licenses=[{'id':'MIT','name':'MIT License'}])
    component={'licenses':['GPL-3.0'], 'legacyLicense':{'hasResolved':True,'resolvedId':'MIT','resolvedName':'MIT License','licenseExpression':'GPL-3.0'}}
    assert evaluate_condition(value,component,datetime.now(UTC))
    unresolved=spec('LICENSE','IS','unresolved')
    assert not evaluate_condition(unresolved,component,datetime.now(UTC))
    assert evaluate_condition(unresolved,{'licenses':[]},datetime.now(UTC))
    custom=spec('LICENSE','IS','uuid',licenses=[{'id':'','name':'Acme Proprietary'}])
    assert evaluate_condition(custom,{'legacyLicense':{'hasResolved':True,'resolvedName':'Acme Proprietary'}},datetime.now(UTC))


def test_missing_helper_data_populates_false_and_deduplicated_warning():
    value=spec('AGE','NUMERIC_GREATER_THAN','P1M');rule={'id':'sample-rule','legacyConditions':[value]}
    component={'purl':'pkg:npm/sample@1','name':'sample','metadataStatus':'missing'}
    contexts={'component':[{'component':component},{'component':component}]}
    warnings=prepare_legacy_contexts([rule],contexts)
    assert len(warnings)==1 and warnings[0]['ruleId']=='sample-rule'
    assert component['legacyConditions'][value['id']] is False
    assert validate_legacy_conditions([value])==[value]


@pytest.mark.parametrize('subject,value', [('AGE','P0D'),('AGE','P-1M'),('AGE','P1DT1H'),('VERSION_DISTANCE',{'major':-1}),('VERSION_DISTANCE',{'major':'oops'})])
def test_invalid_advanced_values_fail_before_import(subject,value):
    with pytest.raises(ValueError):spec(subject,'NUMERIC_EQUAL',value)


@pytest.mark.parametrize('operator,expected,actual,matches',[
    ('NUMERIC_EQUAL','v1.2.3','v1.2.3',True),
    ('NUMERIC_EQUAL','v1.2.3','v1.2.4',False),
    ('NUMERIC_NOT_EQUAL','0.4.5-SNAPSHOT','0.4.5',True),
    ('NUMERIC_GREATER_THAN','0.4.5','0.5.5',True),
    ('NUMERIC_GREATER_THAN_OR_EQUAL','v0.4.5-SNAPSHOT','z0.4.5',True),
    ('NUMERIC_GREATER_THAN_OR_EQUAL','v0.4.5-SNAPSHOT','0.4.5',False),
    ('NUMERIC_GREATER_THAN_OR_EQUAL','v0.4.*','v0.4.1',True),
    ('NUMERIC_LESS_THAN','v0.4.*','v0.4.1',False),
    ('NUMERIC_LESS_THAN','v0.4.*','v0.3.1',True),
    ('NUMERIC_LESSER_THAN_OR_EQUAL','v0.4.*','v0.4.0',True),
    ('NUMERIC_LESSER_THAN_OR_EQUAL','v0.4.*','v0.4.2',False),
])
def test_generic_version_comparison_source_parity_cases(operator,expected,actual,matches):
    assert evaluate_condition(spec('VERSION',operator,expected),{'version':actual},datetime.now(UTC)) is matches


def test_helper_ids_cannot_alias_different_specs_and_evaluation_bound_is_global(monkeypatch):
    from koda_tracker import legacy_policy
    value=spec('VERSION','NUMERIC_EQUAL','1')
    tampered={**value,'value':'2'}
    with pytest.raises(ValueError,match='ID'):
        validate_legacy_conditions([tampered])
    monkeypatch.setattr(legacy_policy,'evaluate_condition',lambda *args:True)
    contexts={'component':[{'component':{'name':'test'}} for _ in range(1001)]}
    with pytest.raises(ValueError,match='100,000'):
        prepare_legacy_contexts([{'id':str(index),'legacyConditions':[value]} for index in range(100)],contexts)


@pytest.mark.parametrize('expression', [' AND '.join(['MIT']*130), '(' * 34 + 'MIT' + ')' * 34, 'MIT' + ' ' * 4096])
def test_spdx_resource_limits_emit_data_warning_instead_of_silently_passing(expression):
    from koda_tracker.policies import PolicyDocument,evaluate_document
    value=spec('LICENSE','IS','mit-uuid',licenses=[{'id':'MIT','name':'MIT License'}])
    document=PolicyDocument(rules=[{'id':'deny-mit','name':'Deny MIT','kind':'cel','target':'component','expression':f"component.legacyConditions['{value['id']}']",'legacyConditions':[value]}])
    rows,metrics=evaluate_document(document,[{'name':'library','version':'1','licenses':[{'expression':expression}]}],[])
    assert len(rows)==1 and rows[0]['type']=='data_unavailable' and rows[0]['action']=='warn'
    assert not metrics['policyDataComplete'] and metrics['policyStatus']=='warn'


@pytest.mark.parametrize('operator,expected',[('IS',False),('IS_NOT',True)])
def test_malformed_spdx_preserves_source_nonmatch_semantics_without_hiding_limits(operator,expected):
    value=spec('LICENSE',operator,'mit-uuid',licenses=[{'id':'MIT','name':'MIT License'}])
    contexts={'component':[{'component':{'name':'library','licenses':['MIT AND']}}]}
    assert prepare_legacy_contexts([{'id':'source-rule','legacyConditions':[value]}],contexts)==[]
    assert contexts['component'][0]['component']['legacyConditions'][value['id']] is expected
