#!/usr/bin/env python3
"""Sample-only acceptance for literal source4.7.1 policy migration on real Docker.

Requires a disposable running source API. Creates sample projects/policies. API
keys come from private files; reports contain no credentials. --seed-only leaves
KODA unchanged and records the actual source PolicyEngine oracle.
"""
from __future__ import annotations
import argparse
import copy
from datetime import UTC, datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import uuid

_spec = importlib.util.spec_from_file_location('java_verify', Path(__file__).with_name('verify-java-regex-runtime.py'))
shared = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(shared)
native, SOURCE_REQUEST = shared.native, shared.SOURCE_REQUEST


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--env-file',type=Path,required=True)
    p.add_argument('--source-auth-file',type=Path,required=True)
    p.add_argument('--fixture-file',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--base-url',default='http://127.0.0.1:18088')
    p.add_argument('--api-container',default='koda-native-verify-20261017-portal-api')
    p.add_argument('--worker-container',default='koda-native-verify-20261017-portal-worker')
    p.add_argument('--source-container',default='koda-literal-source47')
    p.add_argument('--seed-only',action='store_true');a=p.parse_args()
    auth=json.loads(a.source_auth_file.read_text())
    def source(method,path,body=None,**extra):
        r=subprocess.run(['docker','exec','-i',a.api_container,'python','-c',SOURCE_REQUEST],input=json.dumps({'auth':auth,'method':method,'path':path,'body':body,**extra}),text=True,capture_output=True,check=True)
        q=json.loads(r.stdout)
        if q['status']>=300:raise RuntimeError(f'sample source {method} {path}: HTTP {q["status"]}')
        return q['data']
    def wait(fn,label,timeout=240):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            value=fn()
            if value:return value
            time.sleep(1)
        raise RuntimeError(label+' timeout')
    if a.fixture_file.exists():fixture=json.loads(a.fixture_file.read_text())
    else:
        name='KODA-literal47-'+uuid.uuid4().hex[:8]
        project=source('PUT','/project',{'name':name,'version':'1','active':True,'classifier':'APPLICATION'})
        bom=json.loads(native.make_bom('2.14.1','4.17.20'));bom['specVersion']='1.4'
        log4j=next(c for c in bom['components'] if c['name']=='log4j-core');log4j['group']='org.apache.logging.log4j';log4j['cpe']='cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'
        bom['components'] += [
            {'type':'library','group':' org.example ','name':'alpha.[x]*','version':'1.0','bom-ref':'literal-alpha','purl':'pkg:generic/alpha-alpha@1.0?arch=x86&test=one#src/child','licenses':[{'license':{'id':'MIT'}}],'swid':{'tagId':'com.example.alpha.[x].*','name':'alpha.[x]*','version':'1.0'}},
            {'type':'library','name':'no-identifiers','version':'1.0','bom-ref':'no-identifiers','licenses':[{'license':{'id':'MIT'}}]},
            {'type':'library','group':' ','name':'blank-group','version':'1.0','bom-ref':'blank-group','licenses':[{'license':{'id':'MIT'}}]},
        ]
        source('POST','/bom',bom=bom,project=project['uuid'])
        rows=wait(lambda:(x if len(x:=source('GET','/component/project/'+project['uuid']))==len(bom['components']) else None),'source47 BOM')
        definitions=[
            ('purl-substring','PACKAGE_URL','MATCHES','log4j-core','log4j-core',True),
            ('purl-regex-looking','PACKAGE_URL','MATCHES','log4j.*','log4j-core',False),
            ('purl-lookbehind-is-literal','PACKAGE_URL','MATCHES',r'(?<=log4j-)core','log4j-core',False),
            ('purl-star-literal','PACKAGE_URL','MATCHES','*','log4j-core',False),
            ('purl-case-sensitive','PACKAGE_URL','MATCHES','LOG4J','log4j-core',False),
            ('purl-qualified','PACKAGE_URL','MATCHES','arch=x86','alpha.[x]*',True),
            ('purl-coordinates','PACKAGE_URL','MATCHES','pkg:generic/alpha-alpha@1.0','alpha.[x]*',True),
            ('purl-no-match','PACKAGE_URL','NO_MATCH','absent','log4j-core',True),
            ('purl-null-no-match','PACKAGE_URL','NO_MATCH','absent','no-identifiers',False),
            ('cpe-literal','CPE','MATCHES','apache:log4j','log4j-core',True),
            ('cpe-regex-looking','CPE','MATCHES','apache.*','log4j-core',False),
            ('cpe-star-character','CPE','MATCHES','*','log4j-core',True),
            ('cpe-case-sensitive','CPE','MATCHES','APACHE','log4j-core',False),
            ('cpe-null-no-match','CPE','NO_MATCH','absent','lodash',False),
            ('cpe-no-match','CPE','NO_MATCH','absent','log4j-core',True),
            ('swid-literal-punctuation','SWID_TAGID','MATCHES','alpha.[x].*','alpha.[x]*',True),
            ('swid-regex-looking','SWID_TAGID','MATCHES','alpha.*','alpha.[x]*',False),
            ('swid-unbalanced-regex-is-literal','SWID_TAGID','MATCHES','[','alpha.[x]*',True),
            ('swid-literal-star','SWID_TAGID','MATCHES','*','alpha.[x]*',True),
            ('swid-case-sensitive','SWID_TAGID','MATCHES','ALPHA','alpha.[x]*',False),
            ('swid-null-no-match','SWID_TAGID','NO_MATCH','absent','log4j-core',False),
            ('swid-no-match','SWID_TAGID','NO_MATCH','absent','alpha.[x]*',True),
            ('coordinate-literal','COORDINATES','MATCHES',json.dumps({'group':'org.example','name':'alpha.[x]*','version':'1.0'}),'alpha.[x]*',True),
            ('coordinate-wildcards','COORDINATES','MATCHES',json.dumps({'group':'*','name':'*','version':'*'}),'log4j-core',True),
            ('coordinate-regex-looking','COORDINATES','MATCHES',json.dumps({'group':'*','name':'alpha.*','version':'*'}),'alpha.[x]*',False),
            ('coordinate-no-match-all','COORDINATES','NO_MATCH',json.dumps({'group':'different','name':'different','version':'9'}),'log4j-core',True),
            ('coordinate-no-match-one','COORDINATES','NO_MATCH',json.dumps({'group':'org.apache','name':'different','version':'9'}),'log4j-core',False),
            ('coordinate-null-group','COORDINATES','MATCHES',json.dumps({'name':'no-identifiers','version':'1.0'}),'no-identifiers',True),
            ('coordinate-normalized-blank-group','COORDINATES','MATCHES',json.dumps({'name':'blank-group','version':'1.0'}),'blank-group',True),
            ('coordinate-condition-trimmed','COORDINATES','MATCHES',json.dumps({'group':' org.example ','name':'*','version':'*'}),'alpha.[x]*',True),
            ('coordinate-version-substring','COORDINATES','MATCHES',json.dumps({'group':'*','name':'log4j','version':'2.14'}),'log4j-core',True),
            ('coordinate-version-regex-looking','COORDINATES','MATCHES',json.dumps({'group':'*','name':'log4j','version':r'2\.14'}),'log4j-core',False),
            ('coordinate-version-comparator','COORDINATES','MATCHES',json.dumps({'group':'*','name':'log4j','version':'>= 2.0'}),'log4j-core',True),
            ('coordinate-no-match-comparator','COORDINATES','NO_MATCH',json.dumps({'group':'absent','name':'absent','version':'>= 99'}),'log4j-core',True),
        ]
        cases=[]
        for label,subject,operator,value,component,expected in definitions:
            policy=source('PUT','/policy',{'name':name+'-'+label,'operator':'ANY' if subject=='PACKAGE_URL' else 'ALL','violationState':'FAIL'})
            source('POST','/policy',{'uuid':policy['uuid'],'name':name+'-'+label,'operator':'ANY' if subject=='PACKAGE_URL' else 'ALL','violationState':'FAIL'})
            source('PUT','/policy/'+policy['uuid']+'/condition',{'subject':subject,'operator':operator,'value':value})
            source('POST','/policy/'+policy['uuid']+'/project/'+project['uuid'])
            cases.append({'label':label,'policyId':policy['uuid'],'policyName':name+'-'+label,'component':component,'expected':expected,'policyOperator':'ANY' if subject=='PACKAGE_URL' else 'ALL'})
        extra=[
            ('all-purl-double-count','ALL',[('PACKAGE_URL','MATCHES','log4j-core')],'log4j-core',False),
            ('all-mixed-count-not-boolean-and','ALL',[('PACKAGE_URL','MATCHES','log4j-core'),('CPE','MATCHES','absent')],'log4j-core',True),
            ('all-purl-plus-cpe-three-count','ALL',[('PACKAGE_URL','MATCHES','log4j-core'),('CPE','MATCHES','apache')],'log4j-core',False),
            ('all-two-full-only-purls','ALL',[('PACKAGE_URL','MATCHES','arch=x86'),('PACKAGE_URL','MATCHES','test=one')],'alpha.[x]*',True),
            ('all-full-plus-double-purl','ALL',[('PACKAGE_URL','MATCHES','arch=x86'),('PACKAGE_URL','MATCHES','alpha-alpha')],'alpha.[x]*',False),
        ]
        for label,operator,conditions,component,expected in extra:
            policy=source('PUT','/policy',{'name':name+'-'+label,'operator':operator,'violationState':'FAIL'})
            source('POST','/policy',{'uuid':policy['uuid'],'name':name+'-'+label,'operator':operator,'violationState':'FAIL'})
            for subject,op,value in conditions:source('PUT','/policy/'+policy['uuid']+'/condition',{'subject':subject,'operator':op,'value':value})
            source('POST','/policy/'+policy['uuid']+'/project/'+project['uuid'])
            cases.append({'label':label,'policyId':policy['uuid'],'policyName':name+'-'+label,'component':component,'expected':expected,'policyOperator':operator})
        fixture={'name':name,'projectId':project['uuid'],'bom':bom,'components':rows,'cases':cases,'sourceVersion':'4.7.1'}
        a.fixture_file.parent.mkdir(parents=True,exist_ok=True);a.fixture_file.write_text(json.dumps(fixture,ensure_ascii=False,indent=2))
    source('POST','/bom',bom=fixture['bom'],project=fixture['projectId'])
    def answers():
        violations=source('GET','/violation/project/'+fixture['projectId']+'?suppressed=true&pageSize=1000')
        matches=[]
        for case in fixture['cases']:
            found=any(v.get('policyCondition',{}).get('policy',{}).get('uuid')==case['policyId'] and v.get('component',{}).get('name')==case['component'] for v in violations)
            matches.append(found==case['expected'])
        return violations if all(matches) and violations else None
    source_rows=wait(answers,'actual source47 policy oracle',300)
    fixture['sourceViolations']=source_rows;a.fixture_file.write_text(json.dumps(fixture,ensure_ascii=False,indent=2))
    if a.seed_only:print('PASS source47 oracle:',len(fixture['cases']),'cases,',len(source_rows),'source rows',flush=True);return
    env=native.dotenv(a.env_file);client=native.Client(a.base_url);client.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME','admin'),env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
    original=client.request('GET','/api/v1/sbom-policies');report={'startedAt':datetime.now(UTC).isoformat(),'checks':[],'evidence':{'sourceVersion':fixture['sourceVersion'],'projectId':fixture['projectId'],'cases':fixture['cases']}}
    def check(name,condition,evidence=None):
        if not condition:raise RuntimeError(name+': '+str(evidence))
        report['checks'].append({'name':name,'passed':True})
        if evidence is not None:report['evidence'][name]=evidence
        print('PASS',name,flush=True)
    def reanalyze(run_id):
        job=client.request('POST',f'/api/v1/sbom-runs/{run_id}/analyses',expected=202)
        result=wait(lambda:(x if (x:=client.request('GET','/api/v1/jobs/'+job['jobId']))['state'] in ('completed','failed') else None),'real Grype')
        check('real Grype worker completed '+job['jobId'],result['state']=='completed')
        return client.request('GET','/api/v1/sbom-runs/'+run_id)
    stopped=False
    try:
        check('native standalone deployment',client.request('GET','/api/v1/dependency-track/status')['enabled'] is False)
        check('actual source47 oracle matches all sample expectations',True,source_rows)
        request={'baseUrl':auth['baseUrl'],'apiKey':auth['apiKey'],'allowedOrigins':[auth['baseUrl']],'projectUuids':[fixture['projectId']]}
        staged=client.request('POST','/api/v1/legacy-migrations/export-stage',data=request,expected=201)
        check('actual source47 literal policies all convert',staged['report']['canApply'] and staged['report']['counts']['convertedPolicies']==len(fixture['cases']),staged['report'])
        bundle=client.request('GET','/api/v1/legacy-migrations/'+staged['id']+'/bundle');check('actual source47 version preserved',bundle['source']['version']=='4.7.1')
        current=client.request('GET','/api/v1/sbom-policies');applied=client.request('POST','/api/v1/legacy-migrations/'+staged['id']+'/apply',data={'expectedDigest':staged['digest'],'expectedPolicyVersion':current['version'],'trustSourceReviews':False});check('literal source import applies atomically',applied['state']=='applied')
        rid=applied['result']['runIds'][0];report['evidence']['runId']=rid
        subprocess.run(['docker','stop',a.source_container],capture_output=True,check=True);stopped=True
        detail=reanalyze(rid);check('real Grype and literal policy evaluation with source stopped',detail['analyses'][0]['toolVersion']=='0.109.1' and detail['policyState']=='completed' and detail['vulnerabilityCount']>=12,{'vulnerabilities':detail['vulnerabilityCount'],'metrics':detail['analysisMetrics'],'dataSources':detail['analysisDataSources']})
        rows=client.request('GET',f'/api/v1/sbom-runs/{rid}/policy-violations?size=100')['items'];check('literal results contain no missing-data warnings',not any(x['type']=='data_unavailable' for x in rows))
        names={x['policyId']:x['policyName'] for x in fixture['cases']}
        identity_names={x.get('purl') or (x['name']+'@'+x['version'] if x.get('version') else x['name']):x['name'] for x in fixture['components']}
        source_pairs={(names[x['policyCondition']['policy']['uuid']],x['component']['name']) for x in source_rows}
        native_pairs={(x['policyName'],identity_names.get(x['component'],x['component'])) for x in rows if x['policyName'] in names.values()}
        check('all source47 and native policy-component result pairs agree',source_pairs==native_pairs,{'source':sorted(source_pairs),'native':sorted(native_pairs),'sourceRawRows':len(source_rows)})
        for case in fixture['cases']:
            found=any(x['policyName']==case['policyName'] and identity_names.get(x['component'],x['component'])==case['component'] for x in rows)
            check('native literal '+case['label'],found==case['expected'])
        without_java=shared.runtime_failure_probe(a.api_container,rid)
        check('literal policy evaluation succeeds without Java runtime',without_java['analysisState']=='completed' and without_java['policyState']=='completed' and without_java['resultCount']>0,without_java)
        detail=client.request('GET','/api/v1/sbom-runs/'+rid)
        sha=hashlib.sha256(client.request('GET',f'/api/v1/sbom-runs/{rid}/artifact',as_bytes=True)).hexdigest();snapshot=detail['analyses'][0]['policySnapshot'];sequence=detail['analyses'][0]['sequence'];later=reanalyze(rid)
        check('literal reanalysis preserves old immutable snapshot',later['analyses'][0]['sequence']==sequence+1 and later['analyses'][1]['policySnapshot']==snapshot)
        subprocess.run(['docker','restart',a.worker_container],capture_output=True,check=True);persisted=client.request('GET','/api/v1/sbom-runs/'+rid)
        check('worker restart preserves literal result and artifact',persisted['analyses']==later['analyses'] and hashlib.sha256(client.request('GET',f'/api/v1/sbom-runs/{rid}/artifact',as_bytes=True)).hexdigest()==sha)
        report['evidence']['sourceStopped']=stopped
    finally:
        current=client.request('GET','/api/v1/sbom-policies');client.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':current['version'],'rules':original['rules'],'exceptions':original['exceptions']})
        if not stopped:subprocess.run(['docker','stop',a.source_container],capture_output=True)
        report['finishedAt']=datetime.now(UTC).isoformat();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print('PASS',len(report['checks']),'actual source47 literal checks',flush=True)


if __name__=='__main__':main()
