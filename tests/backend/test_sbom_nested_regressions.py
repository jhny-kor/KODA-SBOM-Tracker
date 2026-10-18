from __future__ import annotations
import copy
import json
from types import SimpleNamespace
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from koda_tracker.db import Base
from koda_tracker.sbom import parse_sbom, normalized_identity, validate_component_count, SbomValidationError
from koda_tracker.policies import PolicyDocument, components_with_dependency_graph, evaluate_document
from koda_tracker.services import create_components
from koda_tracker.comparison import compare_components
from test_native_policy_engine import make_run


def nested_bom():
    child={'type':'library','bom-ref':'child','name':'child','version':'1.0.0','purl':'pkg:generic/child@1.0.0','licenses':[{'license':{'id':'GPL-3.0-only'}}]}
    parent={'type':'library','bom-ref':'parent','name':'parent','version':'1.0.0','purl':'pkg:generic/parent@1.0.0','licenses':[{'license':{'id':'MIT'}}],'components':[child]}
    return {'bomFormat':'CycloneDX','specVersion':'1.6','metadata':{'component':{'bom-ref':'app','name':'application'}},'components':[parent],'dependencies':[{'ref':'app','dependsOn':['parent']},{'ref':'parent','dependsOn':['child']}]}


def test_json_nested_policy_and_limit_include_every_component():
    bom,_=parse_sbom(json.dumps(nested_bom()).encode())
    original=copy.deepcopy(bom)
    components=components_with_dependency_graph(bom)
    rows,metrics=evaluate_document(PolicyDocument(rules=[{'id':'deny-gpl','name':'denyGPL','kind':'license_denied','values':['GPL-3.0-only']}]),components,[])
    assert metrics['componentCount']==2
    assert len(rows)==1 and rows[0]['component']=='pkg:generic/child@1.0.0'
    assert [c['isDirectDependency'] for c in components]==[True,False]
    assert bom==original
    with pytest.raises(SbomValidationError,match='구성요소'):
        validate_component_count(bom,1)


def test_xml_nested_children_and_their_licenses_are_preserved():
    xml=b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library" bom-ref="parent"><name>parent</name><version>1.0.0</version><components><component type="library" bom-ref="child"><name>child</name><version>1.0.0</version><purl>pkg:generic/child@1.0.0</purl><licenses><license><id>GPL-3.0-only</id></license></licenses></component></components></component></components></bom>'
    bom,_=parse_sbom(xml)
    assert bom['components'][0]['components'][0]['name']=='child'
    components=components_with_dependency_graph(bom)
    rows,metrics=evaluate_document(PolicyDocument(rules=[{'id':'deny-gpl','name':'denyGPL','kind':'license_denied','values':['GPL-3.0-only']}]),components,[])
    assert metrics['componentCount']==2 and len(rows)==1


def test_nested_rows_materialize_for_search_comparison_and_collection(tmp_path):
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    with Session(engine,expire_on_commit=False) as db:
        run=make_run(db,tmp_path,nested_bom()['components'])
        create_components(db,run)
        assert {row.name for row in run.components}=={'parent','child'}
        assert len(run.components)==2
    engine.dispose()


def test_scoped_npm_identity_preserves_scope_and_package_without_version():
    angular=normalized_identity({'purl':'pkg:npm/%40angular/core@1.0.0'})[0]
    angular_next=normalized_identity({'purl':'pkg:npm/@angular/core@2.0.0'})[0]
    types=normalized_identity({'purl':'pkg:npm/%40types/node@20.0.0'})[0]
    assert angular==angular_next and angular!=types
    assert angular=='purl:pkg:npm/@angular/core'


def test_scoped_npm_comparison_is_remove_add_for_distinct_packages():
    def component(purl,version,name):
        return SimpleNamespace(identity_key=normalized_identity({'purl':purl})[0],version=version,sha256='',licenses=[],identity_status='identified',component_type='library',group_name='',name=name,purl=purl,bom_ref='')
    first=component('pkg:npm/%40angular/core@1.0.0','1.0.0','core')
    second=component('pkg:npm/%40types/node@20.0.0','20.0.0','node')
    assert {r['change'] for r in compare_components([first],[second])}=={'removed','added'}
    updated=component('pkg:npm/%40angular/core@2.0.0','2.0.0','core')
    assert [r['change'] for r in compare_components([first],[updated])]==['changed']


def test_refresh_rebuilds_old_rows_and_loaded_relationship_without_touching_bom(tmp_path):
    engine=create_engine('sqlite://');Base.metadata.create_all(engine)
    with Session(engine,expire_on_commit=False) as db:
        bom=nested_bom();run=make_run(db,tmp_path,[{k:v for k,v in bom['components'][0].items() if k!='components'}])
        create_components(db,run)
        assert len(run.components)==1
        run.normalized_bom=copy.deepcopy(bom)
        expected=copy.deepcopy(run.normalized_bom)
        create_components(db,run,refresh=True)
        assert {row.name for row in run.components}=={'parent','child'}
        assert run.normalized_bom==expected
        create_components(db,run,refresh=True)
        assert len(run.components)==2
    engine.dispose()


def test_scoped_versionless_qualifiers_and_case_sensitive_coordinates():
    first=normalized_identity({'purl':'pkg:npm/%40angular/core?arch=amd64'})[0]
    versioned=normalized_identity({'purl':'pkg:npm/@angular/core@1.0.0?arch=amd64#src'})[0]
    assert first==versioned=='purl:pkg:npm/@angular/core?arch=amd64'
    assert normalized_identity({'purl':'pkg:maven/org.Example/Library@1'})[0] != normalized_identity({'purl':'pkg:maven/org.example/library@1'})[0]
    assert normalized_identity({'purl':'pkg:generic/internal%40name@1'})[0]=='purl:pkg:generic/internal@name'


def test_deep_component_walk_and_policy_scope_do_not_use_recursion():
    from koda_tracker.sbom import component_count
    bom={'components':[]};items=bom['components']
    for index in range(2000):
        child={'name':str(index),'components':[]};items.append(child);items=child['components']
    assert component_count(bom)==2000
    assert len(components_with_dependency_graph(bom))==2000
    with pytest.raises(SbomValidationError):
        validate_component_count(bom,1999)


@pytest.mark.parametrize('components', [[None,{'name':'should-not-be-hidden'}],[{'name':'parent','components':{}}]])
def test_invalid_nested_component_structures_fail_explicitly(components):
    with pytest.raises(SbomValidationError):
        parse_sbom(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','components':components}).encode())


def test_upload_service_quota_counts_nested_children(monkeypatch):
 from fastapi.testclient import TestClient
 from koda_tracker.main import app
 from koda_tracker.config import get_settings
 import uuid
 with TestClient(app) as client:
  login=client.post('/api/v1/auth/login',json={'username':'test-admin','password':'correct-horse-battery-staple'})
  headers={'X-CSRF-Token':login.json()['csrfToken']}
  service=client.post('/api/v1/services',json={'slug':'nested-quota-'+uuid.uuid4().hex[:8],'name':'Nested quota'},headers=headers).json()
  environment=client.get('/api/v1/environments').json()[0]
  monkeypatch.setattr(get_settings(),'max_service_components',1)
  response=client.post('/api/v1/sbom-runs',data={'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'1'},files={'sbom':('nested.json',json.dumps(nested_bom()).encode(),'application/json')},headers=headers)
  assert response.status_code==507,response.text
