#!/usr/bin/env python3
"""Exercise weighted quality and inherited criteria against an isolated real stack."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from urllib.parse import urlencode
import uuid

spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('verify-native-runtime.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
WEIGHTS = {'identity':30, 'graph':20, 'license':20, 'provenance':20, 'integrity':10}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--base-url', default='http://127.0.0.1:18088')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    env = native.dotenv(args.env_file)
    report = {'checks':[], 'evidence':{}, 'at':datetime.now(UTC).isoformat()}
    token_id = None

    def client():
        c = native.Client(args.base_url)
        c.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME','admin'), env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
        return c
    c = client()

    def check(name, condition, evidence=None):
        if not condition:
            raise RuntimeError(name + ': ' + str(evidence))
        report['checks'].append({'name':name, 'passed':True})
        if evidence is not None:
            report['evidence'][name] = evidence
        print('PASS', name, flush=True)

    def wait(rid, after=0):
        end = time.monotonic() + 300
        while time.monotonic() < end:
            run = c.request('GET', '/api/v1/sbom-runs/' + rid)
            if run.get('analyses') and run['analyses'][0]['sequence'] > after and run['analysisState'] == 'completed' and not run.get('nativeReanalysisPending'):
                return run
            time.sleep(1)
        raise RuntimeError('analysis timeout ' + rid)

    def quality(rid):
        return c.request('GET', f'/api/v1/sbom-runs/{rid}/quality-revisions')['items'][0]

    def profile(scope, **fields):
        query = urlencode(scope)
        old = c.request('GET', '/api/v1/quality-profiles?' + query)
        allowed = ('name','mode','maxErrors','maxWarnings','maxMissingIdentityRatio','maxUnresolvedRefs','maxAgeDays','scoreWeights','minScore','inherit','priority')
        data = {key:old[key] for key in allowed}
        data.update(fields, expectedVersion=old['version'])
        return c.request('PUT', '/api/v1/quality-profiles?' + query, data=data)

    def patch(project, **fields):
        result = c.request('PATCH', '/api/v1/project-catalog/' + project['id'], data={'expectedRevision':project['revision'], **fields})
        project.update(result)
        return result

    try:
        check('Dependency-Track remains disabled', c.request('GET','/api/v1/dependency-track/status')['enabled'] is False)
        suffix = uuid.uuid4().hex[:8]
        source = 'quality-weight-' + suffix
        service = c.request('POST','/api/v1/services', expected=201, data={'slug':source,'name':'가중·상속 품질 검증 ' + suffix})
        environment = c.request('GET','/api/v1/environments')[0]
        def project(identity, version, parent=None, tags=None, source_id=source):
            return c.request('POST','/api/v1/project-catalog', expected=201, data={'sourceId':source_id,'sourceProjectId':identity,'serviceId':service['id'],'environmentId':environment['id'],'name':identity+' '+suffix,'version':version,'parentProjectId':parent,'tags':tags or []})
        parent = project('parent','parent',tags=['baseline'])
        child = project('child','weighted',parent='parent')
        profile({'projectId':parent['id']}, name='부모 엄격 기준', mode='enforce', minScore=95)
        bom = {'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,
               'metadata':{'timestamp':datetime.now(UTC).isoformat(),'tools':[{'name':'weighted-fixture','version':'1'}],'authors':[{'name':'Sample'}],
                           'component':{'type':'application','name':'quality-root','version':'1','bom-ref':'root','supplier':{'name':'KODA Sample'}}},
               'components':[{'type':'library','name':'weighted-child-'+suffix,'version':'1.0.0','purl':'pkg:generic/weighted-child-'+suffix+'@1.0.0','bom-ref':'child','licenses':[{'license':{'id':'MIT'}}]}],
               'dependencies':[{'ref':'root','dependsOn':['child']},{'ref':'child','dependsOn':[]}]}
        def upload(document, key):
            u = c.upload(json.dumps(document).encode(), {'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'weighted'}, idempotency_key=source+key)
            return wait(u['runId'])
        run = upload(bom,'-missing-hash'); rid = run['id']; original = quality(rid)
        check('actual Grype and inherited parent minimum', run['analyses'][0]['toolVersion'] not in ('unknown','test-grype') and original['profileSnapshot']['resolution']['kind']=='parent', {'toolVersion':run['analyses'][0]['toolVersion'],'profile':original['profileSnapshot']})
        check('default weighting measures missing hash as 90', original['summary']['score']==90 and original['summary']['scoreDetails']['domains']['integrity']['numerator']==0, original['summary'])
        gate = c.request('GET',f'/api/v1/sbom-runs/{rid}/gate')
        check('minimum score blocks real CI gate', not gate['allowed'] and 'quality_score_below_minimum' in gate['reasons'], gate)
        profile({'sourceId':source,'tag':'baseline'}, name='부모 태그 기준', mode='enforce', minScore=85, priority=1)
        seq = run['analyses'][0]['sequence']
        profile({'projectId':parent['id']}, inherit=True)
        run = wait(rid,seq); q = quality(rid)
        check('parent tag criteria inherit through child', q['profileSnapshot']['resolution']['kind']=='parent_tag' and q['summary']['minScore']==85 and q['summary']['qualityStatus']=='warn', q)
        profile({'sourceId':source,'tag':'local'}, name='자식 태그 엄격 기준', mode='enforce', minScore=95, priority=10)
        seq = run['analyses'][0]['sequence']; patch(child,tags=['local'])
        run = wait(rid,seq); q = quality(rid)
        check('catalog tag edit automatically reanalyzes local override', q['profileSnapshot']['resolution']['kind']=='tag' and q['summary']['qualityStatus']=='fail', q['profileSnapshot'])
        profile({'sourceId':source,'tag':'other'}, name='충돌 기준', mode='enforce', minScore=95, priority=10)
        seq = run['analyses'][0]['sequence']; patch(child,tags=['local','other'])
        # Failed quality remains independent of successful actual Grype analysis.
        run = wait(rid,seq); conflict = quality(rid)
        check('equal-priority tag conflict fails without fabricated score', conflict['state']=='failed' and conflict['summary']['score'] is None and '우선순위' in conflict['error'], conflict)
        check('ambiguous quality cannot pass CI', not c.request('GET',f'/api/v1/sbom-runs/{rid}/gate')['allowed'])
        seq = run['analyses'][0]['sequence']; profile({'sourceId':source,'tag':'other'}, priority=20, minScore=85)
        run = wait(rid,seq); q = quality(rid)
        check('explicit tag priority resolves conflict and retries', q['state']=='completed' and q['profileSnapshot']['tag']=='other' and q['summary']['qualityStatus']=='warn')
        # A direct override always takes precedence over local tags.
        seq = run['analyses'][0]['sequence']; profile({'projectId':child['id']}, name='자식 직접 기준', mode='enforce', minScore=95)
        run = wait(rid,seq); check('project override wins over tag and parent', quality(rid)['profileSnapshot']['resolution']['kind']=='project')
        seq = run['analyses'][0]['sequence']
        custom = {'identity':40,'graph':20,'license':20,'provenance':20,'integrity':0}
        profile({'projectId':child['id']}, scoreWeights=custom)
        run = wait(rid,seq); weighted = quality(rid)
        check('custom weights change score to 100 with evidence', weighted['summary']['score']==100 and weighted['summary']['scoreDetails']['domains']['integrity']['weight']==0 and c.request('GET',f'/api/v1/sbom-runs/{rid}/gate')['allowed'], weighted['summary'])
        retained = c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-export?revisionId='+original['id'])['revision']
        check('prior score and inheritance snapshot remain immutable', retained==original)
        # Critical structure cannot be hidden by giving graph zero weight or allowing many errors.
        seq = run['analyses'][0]['sequence']
        profile({'projectId':child['id']}, scoreWeights={'identity':100,'graph':0,'license':0,'provenance':0,'integrity':0}, maxErrors=100, maxUnresolvedRefs=100)
        run = wait(rid,seq)
        broken = deepcopy(bom); broken['dependencies'][0]['dependsOn'].append('missing')
        structural = upload(broken,'-structural'); sq = quality(structural['id'])
        check('100 points cannot hide structural errors', sq['summary']['score']==100 and sq['summary']['blockingIssueCount']==1 and sq['summary']['qualityStatus']=='fail', sq['summary'])
        sg = c.request('GET',f'/api/v1/sbom-runs/{structural["id"]}/gate')
        check('structural CI failure has explicit reason', 'quality_structural_error' in sg['reasons'])
        # Another source's identical tag name must not become this project's rule.
        profile({'sourceId':'foreign-'+suffix,'tag':'other'}, name='타 원본 기준', mode='enforce', minScore=100, priority=100000)
        resolved = c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-profile')
        check('resolved owner is child even when profile is inherited or shared', resolved['project']['id']==child['id'])
        seq = run['analyses'][0]['sequence']; profile({'projectId':child['id']}, inherit=True)
        run = wait(rid,seq); check('reset preserves version and returns to same-source tag', quality(rid)['profileSnapshot']['sourceId']==source and quality(rid)['summary']['minScore']==85)
        tags = c.request('GET','/api/v1/quality-tag-profiles?'+urlencode({'sourceId':source,'size':1}))
        check('tag profiles are source-scoped and paginated', tags['total']==3 and len(tags['items'])==1 and tags['items'][0]['sourceId']==source)
        # Both profile and catalog mutations use the same PostgreSQL transaction lock.
        c1, c2 = client(), client()
        old = c.request('GET','/api/v1/quality-profiles?projectId='+child['id'])
        body = {k:old[k] for k in ('name','mode','maxErrors','maxWarnings','maxMissingIdentityRatio','maxUnresolvedRefs','maxAgeDays','scoreWeights','minScore','inherit','priority')}
        body.update(expectedVersion=old['version'],inherit=False,mode='enforce',minScore=85,scoreWeights=WEIGHTS,maxErrors=0,maxUnresolvedRefs=0)
        command = 'from koda_tracker.db import SessionLocal; from koda_tracker.quality import quality_write_lock; import sys; db=SessionLocal(); quality_write_lock(db); print("LOCKED",flush=True); sys.stdin.readline(); db.commit(); db.close()'
        container = env.get('COMPOSE_PROJECT_NAME','koda-native-verify-20261017')+'-portal-api'
        lock = subprocess.Popen(['docker','exec','-i',container,'python','-u','-c',command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            readable,_,_ = select.select([lock.stdout],[],[],15)
            if not readable or lock.stdout.readline().strip()!='LOCKED':
                raise RuntimeError('PostgreSQL lock helper failed to initialize')
            seq = run['analyses'][0]['sequence']
            with ThreadPoolExecutor(max_workers=2) as pool:
                one = pool.submit(c1.request,'PUT','/api/v1/quality-profiles?projectId='+child['id'],data=body)
                two = pool.submit(c2.request,'PATCH','/api/v1/project-catalog/'+child['id'],data={'expectedRevision':child['revision'],'tags':['local']})
                time.sleep(.4)
                check('concurrent profile and catalog writes wait for shared database lock', not one.done() and not two.done())
                lock.stdin.write('\n');lock.stdin.flush();lock.wait(timeout=15)
                one.result(timeout=45);child.update(two.result(timeout=45))
        finally:
            if lock.poll() is None:
                lock.stdin.write('\n');lock.stdin.flush();lock.wait(timeout=15)
        run = wait(rid,seq)
        q = quality(rid); fresh = c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-profile')['profile']
        check('concurrent changes converge to final criteria automatically', q['profileSnapshot']==fresh and c.request('GET',f'/api/v1/sbom-runs/{rid}/gate')['allowed'])
        # The existing real CEL runtime can evaluate score and domain projections.
        preview = c.request('POST','/api/v1/sbom-policies/validate',data={'runId':rid,'target':'project','expression':'sbomQuality.score < 95.0 && sbomQuality.domainScores.integrity < 100.0'})
        check('real CEL sees score and domain score', preview['matchCount']==1, preview)
        token = c.request('POST','/api/v1/api-tokens',expected=201,data={'name':source+'-ci','serviceId':service['id']}); token_id=token['id']
        def cli(run_id):
            return subprocess.run([sys.executable,str(Path(__file__).with_name('check-sbom-gate.py')),run_id,'--timeout','15','--interval','1'],env={**os.environ,'KODA_TRACKER_URL':args.base_url,'KODA_TRACKER_TOKEN':token['token']},capture_output=True,text=True,timeout=25)
        check('actual CI command accepts score-qualified run', cli(rid).returncode==0)
        # The immediately preceding round is the structural sample, not the first upload.
        sr = c.request('GET','/api/v1/sbom-runs/'+structural['id'])
        c.request('POST',f'/api/v1/sbom-runs/{structural["id"]}/analyses',expected=202)
        wait(structural['id'],sr['analyses'][0]['sequence'])
        previous_round = quality(structural['id'])
        fixed = deepcopy(bom); fixed['components'][0]['hashes']=[{'alg':'SHA-256','content':'a'*64}]
        good = upload(fixed,'-perfect'); gq=quality(good['id'])
        check('complete next round scores 100', gq['summary']['score']==100 and all(d['score']==100 for d in gq['summary']['scoreDetails']['domains'].values()), gq['summary'])
        check('round score improvement uses the actual prior round', gq['comparison']['previousRunId']==structural['id'] and gq['comparison']['scoreDelta']==round(100-previous_round['summary']['score'],2) and gq['comparison']['scoreDelta']>0, gq['comparison'])
        check('actual CI command rejects structural run', cli(structural['id']).returncode==1)
        report['evidence']['fixtures']={'serviceId':service['id'],'sourceId':source,'parentId':parent['id'],'childId':child['id'],'scoreRunId':rid,'goodRunId':good['id'],'structuralRunId':structural['id']}
    finally:
        if token_id:
            c.request('POST','/api/v1/api-tokens/'+token_id+'/revoke')
        (args.output_dir/'runtime-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps({'passed':len(report['checks'])}))


if __name__ == '__main__':
    main()
