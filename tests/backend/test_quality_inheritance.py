"""Parent/tag inheritance regression cases, including fail-closed ambiguous owners."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from koda_tracker.db import Base
from koda_tracker.models import Environment, ProcessingState, Release, Role, RolePolicy, SbomRun, Service
from koda_tracker.project_catalog_models import NativeProject, NativeReanalysisPending, ProjectRunLink
from koda_tracker.quality import (DEFAULT_PROFILE, QualityProfile, current_profile, effective_profile,
                                  evaluate_quality, profile_scope_key, queue_quality_changes)
from koda_tracker.quality_api import (ProfileInput, read_profile, read_tag_profiles, resolved_run_profile, write_profile)


@pytest.fixture
def db():
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine,expire_on_commit=False) as session:
        session.add_all([Service(id='s',slug='s',name='S'),Environment(id='e',slug='e',name='E'),RolePolicy(role=Role.ADMIN,permissions=[])])
        session.flush();session.add(Release(id='r',service_id='s',environment_id='e',version='1'));session.flush()
        session.add(SbomRun(id='run',release_id='r',round_number=1,original_filename='bom.json',media_type='application/json',spec_version='1.6',sha256='a'*64,size_bytes=2,artifact_path='/missing',normalized_bom={'components':[{'name':'demo','version':'1','purl':'pkg:npm/demo@1'}]}))
        session.flush();yield session
    engine.dispose()


def project(db,identity,source='source-a',parent=None,tags=None,version=None):
    p=NativeProject(id=identity,source_id=source,source_project_id=identity,service_id='s',environment_id='e',name=identity,version=version or identity,parent_project_id=parent,tags=tags or [],active=True)
    db.add(p);db.flush();return p


def bind(db,p):
    db.add(ProjectRunLink(run_id='run',project_id=p.id));db.flush()


def configure(db,*,project_id=None,source_id=None,tag=None,priority=0,inherit=False,name='Profile',mode='enforce'):
    p=current_profile(db,project_id,source_id=source_id,tag=tag)
    return write_profile(ProfileInput(expectedVersion=p['version'],name=name,mode=mode,priority=priority,inherit=inherit),
                         projectId=project_id,sourceId=source_id,tag=tag,db=db,principal=SimpleNamespace(username='admin'))


def test_per_level_precedence_local_tag_parent_direct_parent_tag_and_global(db):
    grand=project(db,'grand',tags=['baseline']);parent=project(db,'parent',parent=grand.id,tags=['parent-tag']);child=project(db,'child',parent=parent.id,tags=['critical']);bind(db,child)
    configure(db,source_id='source-a',tag='baseline',name='Grand tag')
    selected=effective_profile(db,db.get(SbomRun,'run'))
    assert selected['name']=='Grand tag' and selected['resolution']['kind']=='parent_tag' and selected['resolution']['depth']==2
    configure(db,project_id=parent.id,name='Parent direct')
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Parent direct'
    configure(db,source_id='source-a',tag='critical',name='Local tag')
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Local tag'
    configure(db,project_id=child.id,name='Child direct')
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Child direct'
    configure(db,project_id=child.id,inherit=True)
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Local tag'
    configure(db,source_id='source-a',tag='critical',inherit=True)
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Parent direct'
    configure(db,project_id=parent.id,inherit=True)
    configure(db,source_id='source-a',tag='parent-tag',name='Parent tag')
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Parent tag'
    configure(db,source_id='source-a',tag='parent-tag',inherit=True)
    configure(db,source_id='source-a',tag='baseline',inherit=True)
    assert effective_profile(db,db.get(SbomRun,'run'))['resolution']['kind']=='global'


def test_tag_priority_tie_ambiguity_and_same_level_direct_override(db):
    p=project(db,'p',tags=['high','low']);bind(db,p)
    configure(db,source_id='source-a',tag='high',priority=20,name='High')
    configure(db,source_id='source-a',tag='low',priority=10,name='Low')
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='High'
    configure(db,source_id='source-a',tag='low',priority=20,name='Tie')
    with pytest.raises(ValueError,match='우선순위'):effective_profile(db,db.get(SbomRun,'run'))
    failed=evaluate_quality(db,db.get(SbomRun,'run'),force=True)
    assert failed.state=='failed' and failed.summary['score'] is None
    configure(db,project_id=p.id,name='Explicit wins')
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Explicit wins'


def test_parent_tag_source_isolation_and_full_snapshot_immutability(db):
    parent=project(db,'parent',tags=['regulated']);child=project(db,'child',parent=parent.id);bind(db,child)
    configure(db,source_id='source-b',tag='regulated',name='Other source')
    assert effective_profile(db,db.get(SbomRun,'run'))['resolution']['kind']=='global'
    configure(db,source_id='source-a',tag='regulated',name='Our source')
    old=evaluate_quality(db,db.get(SbomRun,'run'));before=deepcopy(old.profile_snapshot)
    configure(db,source_id='source-a',tag='regulated',name='Changed')
    after=effective_profile(db,db.get(SbomRun,'run'))
    assert after!=before and old.profile_snapshot==before
    assert after['resolution']['kind']=='parent_tag' and after['resolution']['inheritedFrom']=='parent'
    assert after['resolution']['chain'][0]['projectId']=='child'
    assert after['resolution']['matchedTags'][0]['version']==2


def test_broken_hierarchy_cross_source_parent_and_dangling_run_link_fail(db):
    p=project(db,'p',parent='missing');bind(db,p);run=db.get(SbomRun,'run')
    project(db,'missing',source='other-source')
    with pytest.raises(ValueError,match='같은 원본'):effective_profile(db,run)
    p.parent_project_id='p';db.flush()
    with pytest.raises(ValueError,match='순환'):effective_profile(db,run)
    p.parent_project_id=None;p.active=False;db.flush()
    assert effective_profile(db,run)['resolution']['chain'][0]['active'] is False
    p.active=True;db.get(ProjectRunLink,'run').project_id='missing-project';db.flush()
    with pytest.raises(ValueError,match='연결된'):effective_profile(db,run)


def test_ordinary_upload_ambiguity_detects_parent_and_tag_rules(db):
    parent=project(db,'parent');a=project(db,'a',parent=parent.id,version='1');b=project(db,'b',source='source-b',version='1')
    configure(db,project_id=parent.id,name='Inherited')
    with pytest.raises(ValueError,match='모호'):effective_profile(db,db.get(SbomRun,'run'))
    bind(db,a)
    assert effective_profile(db,db.get(SbomRun,'run'))['name']=='Inherited'


def test_effective_scope_endpoint_and_tag_latest_version_pagination(db):
    p=project(db,'p',tags=['x']);bind(db,p)
    configure(db,source_id='source-a',tag='x',name='one')
    configure(db,source_id='source-a',tag='x',name='two')
    configure(db,source_id='source-b',tag='x',name='other')
    rows=read_tag_profiles(sourceId='source-a',page=1,size=1,db=db)
    assert rows['total']==1 and rows['items'][0]['version']==2 and rows['items'][0]['name']=='two'
    resolved=resolved_run_profile('run',db=db,principal=SimpleNamespace())
    assert resolved['project']['id']==p.id and resolved['profile']['resolution']['kind']=='tag'
    assert read_profile(sourceId='source-a',tag='x',db=db)['name']=='two'


@pytest.mark.parametrize('args',[{'sourceId':'source-a'},{'tag':'x'},{'sourceId':'source-a','tag':' x'},{'projectId':'p','sourceId':'source-a','tag':'x'}])
def test_invalid_scope_rejected(db,args):
    with pytest.raises(HTTPException) as error:read_profile(db=db,**args)
    assert error.value.status_code==422


def test_global_cannot_inherit_priority_only_on_tags_and_legacy_default_scoring(db):
    with pytest.raises(HTTPException) as error:configure(db,inherit=True)
    assert error.value.status_code==422
    with pytest.raises(HTTPException) as error:configure(db,priority=1)
    assert error.value.status_code==422
    db.add(QualityProfile(scope_key='default',version=1,document={'name':'Legacy','mode':'warn'},created_by='admin'));db.flush()
    profile=current_profile(db)
    assert profile['scoreWeights']=={'identity':30,'graph':20,'license':20,'provenance':20,'integrity':10} and profile['minScore'] is None
    profile['scoreWeights']['identity']=0
    assert DEFAULT_PROFILE['scoreWeights']['identity']==30


def test_catalog_change_queue_uses_snapshot_and_preserves_archived_runs(db):
    parent=project(db,'parent');child=project(db,'child',parent=parent.id,tags=['old']);bind(db,child)
    run=db.get(SbomRun,'run');evaluate_quality(db,run)
    assert queue_quality_changes(db,source_id='source-a')==0
    child.name='Renamed';child.is_latest=True;db.flush()
    assert queue_quality_changes(db,source_id='source-a')==0
    child.tags=['new'];db.flush()
    assert queue_quality_changes(db,source_id='source-a')==1
    assert db.scalar(select(NativeReanalysisPending.run_id))=='run'
    run.state=ProcessingState.ARCHIVED;run.archived_at=__import__('koda_tracker.models',fromlist=['now']).now();db.flush()
    assert queue_quality_changes(db,source_id='source-a')==0


def test_scope_key_unambiguous_and_bounded():
    assert len(profile_scope_key(source_id='s'*128,tag='x'*255))==64
    assert profile_scope_key(source_id='a:b',tag='c')!=profile_scope_key(source_id='a',tag='b:c')


def test_inactive_catalog_preserves_criteria_for_non_archived_runs(db):
    parent=project(db,'parent',tags=['legacy']);child=project(db,'child',parent=parent.id);bind(db,child)
    configure(db,source_id='source-a',tag='legacy',name='Retained source tag')
    parent.active=False;child.active=False;db.flush()
    row=evaluate_quality(db,db.get(SbomRun,'run'),force=True)
    assert row.state=='completed' and row.profile_snapshot['name']=='Retained source tag'
    assert row.profile_snapshot['resolution']['kind']=='parent_tag'
