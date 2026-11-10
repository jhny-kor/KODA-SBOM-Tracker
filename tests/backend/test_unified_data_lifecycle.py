from __future__ import annotations
import asyncio
import copy
import fcntl
import hashlib
import json
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select, func
from test_ssvc import setup
from test_offline_intelligence_formats import document
from koda_tracker.config import get_settings, Settings
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, _write_manifest, managed_state, assert_approved_release
from koda_tracker.models import User, Role, Job, JobState, SbomRun, AnalysisRevision, AuditEvent
from koda_tracker.offline_intelligence_models import OfflineReferenceSnapshot, OfflineResponseEvent
from koda_tracker.vulnerability_intelligence_models import VulnerabilityIntelligence
from koda_tracker.package_metadata_models import PackageMetadataCache
from koda_tracker.ssvc_models import SsvcAssessment
from koda_tracker import worker, data_updates


def fake_grype(command, **kwargs):
    if 'db' in command:
        cache = kwargs['env']['GRYPE_DB_CACHE_DIR']
        return SimpleNamespace(returncode=0,stderr='',stdout=json.dumps({'valid':True,'schemaVersion':'v5.1.9','path':cache+'/5/vulnerability.db'}))
    return SimpleNamespace(returncode=0,stderr='',stdout=json.dumps({'matches':[]}))

@pytest.fixture
def unified(setup, tmp_path, monkeypatch):
    db, client, run, revision = setup
    private = tmp_path/'key.pem'; public=tmp_path/'key.pub'
    subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(private)],capture_output=True,check=True)
    subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],capture_output=True,check=True)
    runtime=tmp_path/'runtime'
    monkeypatch.setenv('TRACKER_GRYPE_DB_DIR',str(runtime/'current'/'grype-db'))
    monkeypatch.setenv('TRACKER_DATA_UPDATE_SPOOL_DIR',str(runtime/'staging'))
    monkeypatch.setenv('TRACKER_DATA_UPDATE_VERIFY_KEY',str(public))
    monkeypatch.setenv('TRACKER_ARTIFACT_DIR',str(tmp_path/'artifacts'))
    monkeypatch.setenv('TRACKER_OFFLINE_MODE','true')
    get_settings.cache_clear()
    db.get(User,'u').role=Role.ADMIN; db.commit()
    from koda_tracker.main import app
    client.app.include_router(app.router)
    real_engine=DataUpdateEngine
    monkeypatch.setattr(data_updates,'DataUpdateEngine',lambda settings,**kwargs: real_engine(settings,runner=fake_grype,**kwargs))
    monkeypatch.setattr(worker,'SessionLocal',lambda:db)
    settings=get_settings()
    def archive(version='bundle-1', *, sign=True, tamper=False):
        root=tmp_path/version; root.mkdir()
        catalog=document(root)
        (root/'intelligence.json').write_text(json.dumps(catalog))
        (root/'grype-db'/'5').mkdir(parents=True)
        (root/'grype-db'/'5'/'vulnerability.db').write_bytes(b'synthetic-validation-db')
        (root/'grype-db'/'5'/'import.json').write_text('{}')
        (root/'nvd.json').write_text('{"vulnerabilities":[]}')
        (root/'kev.json').write_text('{"vulnerabilities":[]}')
        epss=b'#model_version:v2025.03.14,score_date:2026-10-19T00:00:00+0000\ncve,epss,percentile\nCVE-2026-12345,.8,.99\n'
        (root/'epss.csv').write_bytes(epss)
        (root/'collection.json').write_text('{"profile":"test","requiredKinds":["grype-db","nvd","kev","epss"]}')
        metadata={'BUNDLE_VERSION':version,'DATASET_TYPE':'unified','DATASET_DATE':'2026-10-19','GRYPE_DB_SCHEMA':'5','GRYPE_DATASET_DATE':'2026-10-19','NVD_INDEX':'nvd.json','NVD_DATASET_DATE':'2026-10-19','KEV_CATALOG':'kev.json','KEV_DATASET_DATE':'2026-10-19','EPSS_SNAPSHOT':'epss.csv','EPSS_DATASET_DATE':'2026-10-19','EPSS_SHA256':hashlib.sha256(epss).hexdigest(),'INTELLIGENCE_INDEX':'intelligence.json','INTELLIGENCE_SHA256':hashlib.sha256((root/'intelligence.json').read_bytes()).hexdigest()}
        (root/'metadata.env').write_text(''.join(f'{key}={value}\n' for key,value in metadata.items()))
        _write_manifest(root)
        if sign: subprocess.run(['openssl','dgst','-sha256','-sign',str(private),'-out',str(root/'manifest.sha256.sig'),str(root/'manifest.sha256')],check=True,capture_output=True)
        if tamper:(root/'nvd.json').write_text('{"vulnerabilities":[{"id":"tampered"}]}')
        target=tmp_path/(version+'.tar.gz')
        with tarfile.open(target,'w:gz') as tar:
            for file in sorted(root.rglob('*')):
                if file.is_file():tar.add(file,arcname=file.relative_to(root))
        return target
    yield db,client,run,revision,settings,archive
    get_settings.cache_clear()

HEADERS={'X-CSRF-Token':'csrf'}
ACTIVE_BASELINE='/api/v1/vulnerability-data-bundles/active-baseline'

def process(): assert asyncio.run(worker.process_data_update_one())

def apply(client, archive):
    upload=client.post('/api/v1/vulnerability-data-bundles/upload?kind=unified',content=archive.read_bytes(),headers=HEADERS)
    assert upload.status_code==202,upload.text
    process(); job=client.get('/api/v1/vulnerability-data-bundles/jobs/'+upload.json()['id']).json()
    assert job['state']=='completed',job
    action=client.post('/api/v1/vulnerability-data-bundles/jobs/'+job['id']+'/apply',headers=HEADERS)
    assert action.status_code==202,action.text
    process(); result=client.get('/api/v1/vulnerability-data-bundles/jobs/'+action.json()['id']).json()
    assert result['state']=='completed',result.get('error')
    return job, result


def test_signed_single_archive_upload_validation_apply_status_and_source_proof(unified):
    db,client,run,revision,settings,archive=unified
    root=settings.grype_db_dir.parent.parent
    assert client.get(ACTIVE_BASELINE).json()=={"cveDataAsOf":None}
    status=client.get('/api/v1/vulnerability-data-bundles/unified/status')
    assert status.status_code==200 and not status.json()['available']
    assert not root.exists() # read-only status creates no directory/lock
    source,result=apply(client,archive())
    status=client.get('/api/v1/vulnerability-data-bundles/unified/status').json()
    assert status['state']=='active' and status['available'] and status['currentVersion']=='bundle-1'
    assert {item['kind'] for item in status['datasets']}=={'grype-db','nvd','kev','epss'}
    assert all(item['status']=='available' for item in status['datasets'])
    with_viewer={"Cookie":"koda_session=viewer"}
    baseline=client.get(ACTIVE_BASELINE,headers=with_viewer)
    assert baseline.json()=={"cveDataAsOf":"2026-10-19"}
    assert baseline.headers["Cache-Control"]=="no-store"
    assert client.get('/api/v1/vulnerability-data-bundles/unified/status',headers=with_viewer).status_code==403
    assert len(status['referenceSources'])==11
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot))==11
    assert db.get(VulnerabilityIntelligence,'CVE-2026-12345').document['epss']==.8
    current=root/'current'; assert (current/'approved-manifest.sha256.sig').is_file()
    assert_approved_release(settings,current.resolve())
    (current/'nvd.json').write_text('{"vulnerabilities": [{"id":"changed"}]}')
    with pytest.raises(DataUpdateError,match='변경'):assert_approved_release(settings,current.resolve())
    assert not client.get('/api/v1/vulnerability-data-bundles/unified/status').json()['available']
    assert client.get(ACTIVE_BASELINE).json()=={"cveDataAsOf":None}


def test_missing_bad_signature_and_changed_bytes_never_activate(unified):
    db,client,run,revision,settings,archive=unified
    engine=DataUpdateEngine(settings,runner=fake_grype)
    for name,kwargs in [('unsigned',{'sign':False}),('changed',{'tamper':True})]:
        with pytest.raises(DataUpdateError):engine.stage(archive(name,**kwargs),'unified')
        assert engine.current() is None
    signed=archive('signed')
    settings.data_update_verify_key=Path('/not-a-registered-key')
    with pytest.raises(DataUpdateError,match='검증키'):engine.stage(signed,'unified')


def test_purge_preserves_operations_and_histories_blocks_fallback_and_stale_apply(unified):
    db,client,run,revision,settings,archive=unified
    original_bom=copy.deepcopy(run.normalized_bom); original_findings=copy.deepcopy(revision.findings)
    validated,_=apply(client,archive())
    # Apply requested reanalysis is deliberately cancelled by purge, never alters old results.
    from test_ssvc import post
    run = db.get(SbomRun,run.id); revision = db.get(AnalysisRevision,revision.id)
    run.analysis_state=JobState.COMPLETED; revision.data_sources={"bundleVersion":"bundle-1"}; db.commit()
    assessed=post(client); assert assessed.status_code==201,assessed.text
    ssid=assessed.json()['id']
    db.add(OfflineResponseEvent(id='response',run_id=run.id,revision_id=revision.id,service_id='s',environment_id='e',component='demo',component_version='1',vulnerability_id='CVE-1',target_key='x'*64,state='in_progress',owner='team',rationale='preserve',author='u'))
    db.add(Job(id='old-validated',kind='vulnerability_data_update',state=JobState.COMPLETED,payload={'kind':'unified','action':'validate','phase':'validated','stagedRoot':'obsolete'}));db.commit()
    wrong=client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'wrong'},headers=HEADERS)
    assert wrong.status_code==422
    assert client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'DELETE VULNERABILITY DATA'}).status_code==403
    response=client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'DELETE VULNERABILITY DATA','expectedBaseVersion':'bundle-1'},headers=HEADERS)
    assert response.status_code==202,response.text
    process()
    result=client.get('/api/v1/vulnerability-data-bundles/jobs/'+response.json()['id']).json()
    assert result['state']=='completed',result.get('error')
    status=client.get('/api/v1/vulnerability-data-bundles/unified/status').json()
    assert status['state']=='purged' and not status['available']
    db.expire_all()
    assert db.get(SbomRun,run.id).normalized_bom==original_bom and db.get(AnalysisRevision,revision.id).findings==original_findings
    assert db.get(SsvcAssessment,ssid) is not None and db.get(OfflineResponseEvent,'response').rationale=='preserve'
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot))==0
    assert db.scalar(select(func.count()).select_from(VulnerabilityIntelligence))==0
    assert db.scalar(select(func.count()).select_from(PackageMetadataCache))==0
    assert not (settings.grype_db_dir.parent.parent/'releases').exists()
    assert not (settings.artifact_dir/'offline-intelligence').exists()
    assert client.post('/api/v1/vulnerability-data-bundles/jobs/old-validated/apply',headers=HEADERS).status_code==409
    assert client.post('/api/v1/sbom-runs/run/analyses',headers=HEADERS).status_code==409
    assert client.post('/api/v1/vulnerability-intelligence/import',json={'format':'koda-vulnerability-intelligence-v1','exportedAt':'2026-10-19T00:00:00Z','items':[]},headers=HEADERS).status_code==409
    assert client.post('/api/v1/package-metadata/import',json={'format':'koda-package-metadata-v1','exportedAt':'2026-10-19T00:00:00Z','items':[]},headers=HEADERS).status_code==409
    # Even a legacy directory recreated after deletion cannot bypass the marker.
    settings.grype_db_dir.mkdir(parents=True);(settings.grype_db_dir/'vulnerability.db').write_bytes(b'legacy')
    with pytest.raises(DataUpdateError):assert_approved_release(settings,None)
    assert managed_state(settings)['state']=='purged'
    apply(client,archive('restored'))
    assert client.get('/api/v1/vulnerability-data-bundles/unified/status').json()['available']


def test_analysis_reader_lease_blocks_purge_and_existing_analysis_job_rejected(unified):
    db,client,run,revision,settings,archive=unified
    apply(client,archive())
    active=Job(kind='analyze',run_id=run.id,state=JobState.RUNNING);db.add(active);db.commit()
    assert client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'DELETE VULNERABILITY DATA'},headers=HEADERS).status_code==409
    active.state=JobState.COMPLETED;db.commit()
    lock=(settings.grype_db_dir.parent.parent/'.release.lock').open('rb');fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
    try:
        assert client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'DELETE VULNERABILITY DATA'},headers=HEADERS).status_code==409
        engine=DataUpdateEngine(settings,runner=fake_grype)
        with pytest.raises(DataUpdateError,match='분석'):engine.purge_files()
    finally:lock.close()
    assert engine.current() is not None


def test_offline_linux_without_approved_data_never_calls_grype(unified,monkeypatch):
    from koda_tracker import services
    db,client,run,revision,settings,archive=unified
    settings.environment='production'
    monkeypatch.setattr(data_updates.sys,'platform','linux')
    monkeypatch.setattr(services,'get_settings',lambda:settings)
    def forbidden(*args,**kwargs):pytest.fail('legacy Grype fallback executed')
    monkeypatch.setattr(services.subprocess,'run',forbidden)
    result=services.analyze_offline(db,run)
    assert result.state==JobState.FAILED and '승인' in result.error
    assert not result.findings and result.policy_state=='not_evaluated'
    assert result.data_sources['vulnerabilityDataStatus']['status']=='unavailable'
    from koda_tracker.main import _run_payload
    payload=_run_payload(run)
    assert payload['analysisAvailable'] is False and '승인' in payload['analysisUnavailableReason']
    from koda_tracker.main import compare_runs
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as denied:
        compare_runs(base_run_id=run.id,target_run_id=run.id,base_analysis_id=revision.id,target_analysis_id=result.id,db=db,_=None)
    assert denied.value.status_code==409
    historical=compare_runs(base_run_id=run.id,target_run_id=run.id,base_analysis_id=revision.id,target_analysis_id=revision.id,db=db,_=None)
    assert historical['base']['runId']==run.id


def test_proof_cache_reuses_unchanged_files_and_detects_same_size_restored_mtime(unified, monkeypatch):
    import os
    db,client,run,revision,settings,archive=unified
    apply(client,archive())
    root=(settings.grype_db_dir.parent.parent/'current').resolve()
    data_updates._verify_approved_files.cache_clear()
    calls=[]; real_hash=data_updates._sha256
    def counted(path):calls.append(str(path));return real_hash(path)
    monkeypatch.setattr(data_updates,'_sha256',counted)
    assert_approved_release(settings,root)
    assert calls
    calls.clear();assert_approved_release(settings,root)
    assert not calls
    unexpected=root/'grype-db'/'6'/'vulnerability.db';unexpected.parent.mkdir()
    unexpected.write_bytes(b'unsigned fallback')
    with pytest.raises(DataUpdateError,match='승인되지'):assert_approved_release(settings,root)
    unexpected.unlink();unexpected.parent.rmdir()
    path=root/'nvd.json';before=path.stat();raw=path.read_bytes()
    path.write_bytes(raw.replace(b'vulnerabilities',b'wulnerabilities'))
    os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
    with pytest.raises(DataUpdateError,match='변경'):assert_approved_release(settings,root)
    assert calls


def test_failed_purge_stays_blocked_and_retry_completes_without_losing_history(unified, monkeypatch):
    db,client,run,revision,settings,archive=unified
    apply(client,archive())
    real_purge=data_updates.purge_reference_database
    def interrupted(db,**kwargs):
        real_purge(db,**kwargs)
        raise RuntimeError('simulated crash after database delete before commit')
    monkeypatch.setattr(data_updates,'purge_reference_database',interrupted)
    response=client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'DELETE VULNERABILITY DATA'},headers=HEADERS)
    assert response.status_code==202;process()
    result=client.get('/api/v1/vulnerability-data-bundles/jobs/'+response.json()['id']).json()
    assert result['state']=='failed' and managed_state(settings)['state']=='purging'
    # Database rollback retained data, but no reader/import may use it as current.
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot))==11
    assert not client.get('/api/v1/vulnerability-data-bundles/unified/status').json()['available']
    assert client.post('/api/v1/sbom-runs/run/analyses',headers=HEADERS).status_code==409
    monkeypatch.setattr(data_updates,'purge_reference_database',real_purge)
    retry=client.post('/api/v1/vulnerability-data-bundles/unified/purge',json={'confirm':'DELETE VULNERABILITY DATA'},headers=HEADERS)
    assert retry.status_code==202;process()
    assert client.get('/api/v1/vulnerability-data-bundles/jobs/'+retry.json()['id']).json()['state']=='completed'
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot))==0
    assert db.get(AnalysisRevision,revision.id) is not None


@pytest.mark.parametrize("state", [None, JobState.FAILED, JobState.QUEUED, JobState.RUNNING])
@pytest.mark.parametrize("side", ["base", "target"])
def test_comparison_requires_completed_revision_without_source_marker(setup, state, side):
    from koda_tracker.main import app
    db, client, run, revision = setup
    db.get(User, "u").role = Role.ADMIN
    if state is not None:
        db.add(AnalysisRevision(id="incomplete", run_id=run.id, sequence=2, state=state,
                                error="승인된 통합 취약점 데이터가 없습니다", data_sources={}, findings=[]))
    db.commit()
    client.app.include_router(app.router)
    params = {"baseRunId": run.id, "targetRunId": run.id,
              "baseAnalysisId": revision.id, "targetAnalysisId": revision.id}
    params[f"{side}AnalysisId"] = "incomplete" if state is not None else "missing-revision"
    denied = client.get("/api/v1/comparisons", params=params)
    assert denied.status_code == 409, denied.text
    assert "완료" in denied.json()["detail"]
    # A failed latest revision must not invalidate explicitly selected immutable history.
    params[f"{side}AnalysisId"] = revision.id
    historical = client.get("/api/v1/comparisons", params=params)
    assert historical.status_code == 200, historical.text
    assert historical.json()["summary"]["vulnerabilitiesRemoved"] == 0
    if state is not None:
        params.pop(f"{side}AnalysisId")
        assert client.get("/api/v1/comparisons", params=params).status_code == 409
