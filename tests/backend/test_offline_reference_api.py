import copy
from datetime import UTC, datetime, timedelta
from sqlalchemy import select, func
from test_ssvc import setup, post
from test_offline_intelligence_formats import document, AT, PURL, CVE, CPE
from koda_tracker.offline_intelligence_api import router
from koda_tracker.offline_intelligence_models import OfflineReferenceSnapshot, OfflineResponseEvent
from koda_tracker.offline_intelligence_store import active_reference_document, import_reference_document
from koda_tracker.offline_reference_enrichment import enrich_reference_context
from koda_tracker.vulnerability_intelligence import enrich_findings
from koda_tracker.ubuntu_oval import evaluate_definition


def test_import_api_original_proof_atomic_epss_history_and_acl(setup, tmp_path):
    db, client, run, revision = setup
    client.app.include_router(router)
    from koda_tracker.models import User, Role
    db.get(User, "u").role = Role.ADMIN
    db.commit()
    value = document(tmp_path, inline=True)
    assert client.post('/api/v1/offline-intelligence/import', json=value).status_code == 403
    response = client.post('/api/v1/offline-intelligence/import', json=value, headers={'X-CSRF-Token':'csrf'})
    assert response.status_code == 200, response.text
    assert response.json()['importedSources'] == 11
    result = client.get('/api/v1/offline-intelligence').json()
    assert len(result['current']['sources']) == 11 and len(result['history']) == 11
    assert all('rawBase64' not in item for item in result['current']['sources'])
    assert enrich_findings(db, [{'id': CVE}], at=AT)[0]['epssScore'] == .8
    duplicate = client.post('/api/v1/offline-intelligence/import', json=value, headers={'X-CSRF-Token':'csrf'})
    assert duplicate.json()['skippedSources'] == 11
    forged = copy.deepcopy(value); forged['datasets']['vulnrichment']['records'][0]['exploitation'] = 'none'
    assert client.post('/api/v1/offline-intelligence/import', json=forged, headers={'X-CSRF-Token':'csrf'}).status_code == 422
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot)) == 11
    client.cookies.clear()
    assert client.get('/api/v1/offline-intelligence', headers={'Authorization':'Bearer token'}).status_code == 403


def test_exact_evidence_fresh_stale_supplier_conflict_and_oval(setup, tmp_path):
    db, client, run, revision = setup
    value = document(tmp_path, inline=True)
    import_reference_document(db, value, actor='operator', request_reanalysis=False)
    component = {'name':'demo', 'version':'1.0', 'purl':PURL, 'cpe':CPE, 'licenses':['MIT']}
    finding = {'component':PURL,'version':'1.0','id':CVE,'severity':'Critical','cwes':['CWE-79']}
    components, findings, summary = enrich_reference_context([component], [finding], active_reference_document(db, at=AT), at=AT)
    assert findings[0]['severity'] == 'Critical' and 'vex' not in findings[0]
    ref = findings[0]['offlineReference']
    assert ref['supplierVexConflict'] and ref['ssvcRecommendation']['inputs'] == {'exploitation':'active','automatable':'yes'}
    assert ref['cwe'][0]['status'] == 'known'
    assert components[0]['offlineReference']['lifecycle'][0]['endOfLife']
    assert components[0]['offlineReference']['licenses'][0]['status'] == 'known'
    assert components[0]['offlineReference']['cpe'] and components[0]['offlineReference']['cpeMatch']
    assert summary['automaticVexSuppression'] is False
    _, stale, _ = enrich_reference_context([component], [finding], active_reference_document(db, at=AT+timedelta(days=400)), at=AT+timedelta(days=400))
    assert stale[0]['offlineReference']['ssvcRecommendation']['inputs'] == {}
    oval = value['datasets']['ubuntu-oval']['records'][0]
    assert evaluate_definition(oval, [], comparator=lambda *args: True)['status'] == 'unknown'
    inventory = [{'purl':'pkg:deb/ubuntu/demo@1%3A1.0-0ubuntu1?distro=ubuntu-22.04'}]
    assert evaluate_definition(oval, inventory, comparator=lambda *args: True)['status'] == 'affected_review'
    assert evaluate_definition(oval, inventory, comparator=lambda *args: False)['status'] == 'not_affected_review'


def test_response_exact_target_append_history_impact_and_no_auto_resolution(setup):
    db, client, run, revision = setup; client.app.include_router(router)
    finding = revision.findings[0]
    payload = {'component':finding['component'], 'vulnerabilityId':finding['id'], 'expectedRevisionId':revision.id, 'state':'in_progress','owner':'security','rationale':'upgrade scheduled'}
    result = client.post('/api/v1/sbom-runs/run/responses', json=payload, headers={'X-CSRF-Token':'csrf'})
    assert result.status_code == 200, result.text
    assert client.post('/api/v1/sbom-runs/run/responses', json={**payload,'state':'resolved'}, headers={'X-CSRF-Token':'csrf'}).status_code == 422
    assert client.post('/api/v1/sbom-runs/run/responses', json={**payload,'state':'accepted'}, headers={'X-CSRF-Token':'csrf'}).status_code == 422
    assert client.post('/api/v1/sbom-runs/run/responses', json={**payload,'component':'other'}, headers={'X-CSRF-Token':'csrf'}).status_code == 422
    impact = client.get('/api/v1/offline-intelligence/impact').json()
    assert impact['uniqueVulnerabilities'] == 1 and impact['responseStates'] == {'in_progress':1}
    assert len(client.get('/api/v1/sbom-runs/run/responses').json()['items']) == 1
    context = client.get('/api/v1/sbom-runs/run/offline-intelligence')
    assert context.status_code == 200 and context.json()['snapshotChanged']


def test_worker_sync_failure_rolls_back_database_and_compensates_exact_activation(setup, monkeypatch, tmp_path):
    import asyncio
    from types import SimpleNamespace
    from koda_tracker import worker, data_updates, offline_intelligence_store
    from koda_tracker.models import Job, JobState
    db, client, run, revision = setup
    job = Job(id='sync-fail', kind='data_update', state=JobState.QUEUED, payload={'action':'apply','kind':'vuln-data','phase':'applying'})
    db.add(job); db.commit()
    release = tmp_path / 'release'; release.mkdir(); (release/'metadata.env').write_text('DATA_UPDATE_JOB_ID=sync-fail\n')
    restored = []
    class Engine:
        def __init__(self, *args): self.root = tmp_path
        def current(self): return SimpleNamespace(path=release, version='current')
        def exclusive_access(self):
            from contextlib import nullcontext
            return nullcontext()
        def compensate_activation(self, **kwargs): restored.append(kwargs); return True
    def fail(db, path, **kwargs):
        db.add(OfflineReferenceSnapshot(kind='cwe',source_id='temporary',source_version='1',data_as_of='2026-10-19',sha256='b'*64,record_count=0,document={},imported_by='test',origin='verified_bundle'))
        db.flush()
        raise ValueError('projection failed')
    monkeypatch.setattr(worker, 'SessionLocal', lambda: db)
    monkeypatch.setattr(data_updates, 'DataUpdateEngine', Engine)
    monkeypatch.setattr(offline_intelligence_store, 'sync_reference_bundle', fail)
    assert asyncio.run(worker.process_data_update_one())
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot)) == 0
    failed = db.get(Job,'sync-fail')
    assert failed.state == JobState.FAILED and 'activation restored' in failed.error
    assert restored == [{'release_version':'current','job_id':'sync-fail'}]


def test_analysis_persists_matched_reference_evidence_without_suppression(setup, tmp_path):
    from koda_tracker.policies import evaluate_revision
    db, client, run, revision = setup
    import_reference_document(db, document(tmp_path, inline=True), actor='operator', request_reanalysis=False)
    run.normalized_bom = {'bomFormat':'CycloneDX','components':[{'name':'demo','version':'1.0','purl':PURL,'cpe':CPE,'licenses':['MIT']}]}
    revision.findings = [{'id':CVE,'component':PURL,'version':'1.0','severity':'Critical','cwes':['CWE-79']}]
    evaluate_revision(db,run,revision)
    assert revision.policy_state == 'completed', revision.policy_error
    assert revision.data_sources['offlineIntelligence']['supplierVexConflicts'] == 1
    assert revision.findings[0]['offlineReference']['ssvcRecommendation']['automaticDecision'] is False
    assert revision.findings[0]['severity'] == 'Critical'


def test_signed_bundle_rollback_and_removal_retire_policy_epss_but_keep_history(setup, tmp_path):
    import json, hashlib
    from koda_tracker.offline_intelligence import normalize_source, FORMAT
    from koda_tracker.offline_intelligence_store import sync_reference_bundle
    from koda_tracker.vulnerability_intelligence_models import VulnerabilityIntelligence
    db, client, run, revision = setup
    def bundle(name, day, score):
        root = tmp_path/name; (root/'intelligence-sources').mkdir(parents=True)
        raw = f'#model_version:v1,score_date:2026-10-{day}T00:00:00+0000\ncve,epss,percentile\n{CVE},{score},.99\n'.encode()
        sha = hashlib.sha256(raw).hexdigest(); filename = f'intelligence-sources/{sha}.csv'; (root/filename).write_bytes(raw)
        data = normalize_source('epss', raw, {'id':'first','sourceUrl':'https://epss.cyentia.com/epss_scores-current.csv.gz','dataDate':f'2026-10-{day}','fetchedAt':'2026-10-19T00:00:00Z','sourceFile':filename})
        (root/'intelligence.json').write_text(json.dumps({'format':FORMAT,'createdAt':'2026-10-19T00:00:00Z','datasets':{'epss':data}}))
        return root
    newer, older = bundle('new','19','.8'), bundle('old','18','.6')
    sync_reference_bundle(db,newer,request_reanalysis=False); db.commit()
    first = db.scalar(select(OfflineReferenceSnapshot))
    from koda_tracker.offline_intelligence_store import verify_original
    source = first.document['datasets']['epss']['sources'][0]
    assert 'rawBase64' not in source and 'sourceFile' not in source
    import shutil
    shutil.rmtree(newer)
    assert verify_original(source).is_file()
    client.app.include_router(router)
    original = client.get(f'/api/v1/offline-intelligence/snapshots/{first.id}/original')
    assert original.status_code == 200 and hashlib.sha256(original.content).hexdigest() == source['sha256']
    import pytest
    with pytest.raises(ValueError): sync_reference_bundle(db,older,request_reanalysis=False)
    db.rollback()
    sync_reference_bundle(db,older,request_reanalysis=False,allow_older=True); db.commit()
    assert db.get(VulnerabilityIntelligence,CVE).document['date'] == '2026-10-18'
    assert enrich_findings(db,[{'id':CVE}])[0]['epssEvidence']['date'] == '2026-10-18'
    empty = tmp_path/'empty'; empty.mkdir()
    result = sync_reference_bundle(db,empty,request_reanalysis=False); db.commit()
    assert result['deactivatedSources'] == 1
    assert db.get(VulnerabilityIntelligence,CVE).state == 'superseded'
    assert 'epssScore' not in enrich_findings(db,[{'id':CVE}])[0]
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot)) == 2


def test_reference_metadata_and_lifecycle_never_cross_distribution_architecture_or_subpath():
    from koda_tracker.offline_intelligence import FORMAT
    source = {'id':'packages','status':'fresh','dataDate':'2026-10-19'}
    purl = 'pkg:deb/debian/openssl@1.0?arch=amd64&distro=debian-12#lib'
    components = [{'name':'openssl','version':'1.0','purl':value} for value in [purl, 'pkg:deb/debian/openssl@1.0?arch=arm64&distro=debian-11#lib', 'pkg:deb/debian/openssl@1.0?arch=amd64&distro=debian-12#other']]
    metadata = {'sourceId':'packages','purl':purl,'currentVersion':'1.0','latestVersion':'9.0','versionDistance':999,'status':'fresh','fetchedAt':AT.isoformat(),'expiresAt':(AT+timedelta(days=1)).isoformat()}
    lifecycle = {'sourceId':'packages','product':'openssl','cycle':'1','identifiers':[{'type':'purl','id':'pkg:deb/debian/openssl?arch=amd64&distro=debian-12#lib'}],'isEol':True}
    document = {'format':FORMAT,'datasets':{'package-metadata':{'sources':[source],'records':[metadata]},'lifecycle':{'sources':[source],'records':[lifecycle]}}}
    enriched, _, _ = enrich_reference_context(components,[],document,at=AT)
    assert enriched[0]['packageMetadata']['versionDistance'] == 999
    assert enriched[0]['offlineReference']['lifecycle']
    for component in enriched[1:]:
        assert 'packageMetadata' not in component and not component.get('properties')
        assert not component['offlineReference']['packageMetadata'] and not component['offlineReference']['lifecycle']


def test_bundle_rollback_preserves_newer_manual_pointer_and_epss_same_source_id(setup, tmp_path):
    import json, hashlib
    from koda_tracker.offline_intelligence import normalize_source, FORMAT
    from koda_tracker.offline_intelligence_store import sync_reference_bundle
    from koda_tracker.offline_intelligence_models import OfflineReferenceCurrent
    db, client, run, revision = setup
    (tmp_path/'manual').mkdir()
    manual = document(tmp_path/'manual', inline=True)
    manual['datasets'] = {'epss':manual['datasets']['epss']}
    imported = import_reference_document(db,manual,actor='manual',request_reanalysis=False)
    db.commit(); manual_id = imported['snapshotIds'][0]
    root = tmp_path/'old'; (root/'intelligence-sources').mkdir(parents=True)
    raw = f'#model_version:v1,score_date:2026-10-18T00:00:00+0000\ncve,epss,percentile\n{CVE},.2,.5\n'.encode()
    sha = hashlib.sha256(raw).hexdigest(); filename=f'intelligence-sources/{sha}.csv'; (root/filename).write_bytes(raw)
    dataset = normalize_source('epss',raw,{'id':'epss','sourceUrl':'https://vendor.test/epss','dataDate':'2026-10-18','fetchedAt':'2026-10-19T00:00:00Z','sourceFile':filename})
    (root/'intelligence.json').write_text(json.dumps({'format':FORMAT,'createdAt':'2026-10-19T00:00:00Z','datasets':{'epss':dataset}}))
    result = sync_reference_bundle(db,root,request_reanalysis=False,allow_older=True); db.commit()
    assert result['skippedSources'] == 1
    assert db.get(OfflineReferenceCurrent,('epss','epss')).snapshot_id == manual_id
    evidence = enrich_findings(db,[{'id':CVE}])[0]['epssEvidence']
    assert evidence['date'] == '2026-10-19' and evidence['epss'] == .8


def test_truncated_reference_evidence_never_generates_ssvc_recommendations():
    source = {'id':'cisa','status':'fresh'}
    records = [{'sourceId':'cisa','cve':CVE,'exploitation':'active','automatable':'yes'} for _ in range(201)]
    document = {'datasets':{'vulnrichment':{'sources':[source],'records':records}}}
    _, findings, _ = enrich_reference_context([], [{'id':CVE}], document, at=AT)
    reference = findings[0]['offlineReference']
    assert reference['evidenceTruncated'] and len(reference['vulnrichment']) == 200
    assert reference['ssvcRecommendation']['inputs'] == {}
    assert 'incomplete_reference_evidence' in reference['ssvcRecommendation']['conflicts']


def test_offline_metadata_expiry_excludes_policy_values_but_preserves_observation():
    from koda_tracker.offline_intelligence import FORMAT
    source = {"id":"packages","status":"fresh","dataDate":"2026-10-19"}
    component = {"name":"demo","version":"1.0","purl":PURL}
    record = {"sourceId":"packages","purl":PURL,"currentVersion":"1.0","latestVersion":"9.0","status":"fresh","fetchedAt":(AT-timedelta(days=1)).isoformat(),"expiresAt":AT.isoformat()}
    document = {"format":FORMAT,"datasets":{"package-metadata":{"sources":[source],"records":[record]}}}
    enriched, _, _ = enrich_reference_context([component], [], document, at=AT)
    assert enriched[0]["offlineReference"]["packageMetadata"][0]["record"]["latestVersion"] == "9.0"
    assert "packageMetadata" not in enriched[0] and not enriched[0].get("properties")
    record["expiresAt"] = (AT+timedelta(days=1)).isoformat()
    enriched, _, _ = enrich_reference_context([component], [], document, at=AT)
    assert enriched[0]["packageMetadata"]["latestVersion"] == "9.0"
    assert {value["name"]:value["value"] for value in enriched[0]["properties"]}["koda:latestVersion"] == "9.0"


def test_offline_metadata_invalid_or_missing_timestamps_do_not_become_policy_input():
    from koda_tracker.offline_intelligence import FORMAT
    source = {"id":"packages","status":"fresh","dataDate":"2026-10-19"}
    component = {"name":"demo","version":"1.0","purl":PURL}
    record = {"sourceId":"packages","purl":PURL,"currentVersion":"1.0","latestVersion":"9.0","status":"fresh","fetchedAt":AT.isoformat(),"expiresAt":(AT+timedelta(days=1)).isoformat()}
    document = {"format":FORMAT,"datasets":{"package-metadata":{"sources":[source],"records":[record]}}}
    for invalid in (None,"invalid","2026-10-20T00:00:00"):
        record["expiresAt"] = invalid
        enriched, _, _ = enrich_reference_context([component], [], document, at=AT)
        assert len(enriched[0]["offlineReference"]["packageMetadata"]) == 1
        assert "packageMetadata" not in enriched[0] and not enriched[0].get("properties")
    record["expiresAt"] = (AT+timedelta(days=2)).isoformat()
    for invalid in (None,"invalid",(AT+timedelta(days=1)).isoformat()):
        record["fetchedAt"] = invalid
        enriched, _, _ = enrich_reference_context([component], [], document, at=AT)
        assert "packageMetadata" not in enriched[0] and not enriched[0].get("properties")
