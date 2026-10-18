#!/usr/bin/env python3
"""Verify registry collection and legacy source migration on an isolated Docker stack.

No source server is modified. The source must already contain verification data.
Credentials are read from private local files and are never included in reports.
"""
from __future__ import annotations
import argparse, importlib.util, json, subprocess, time, uuid
from pathlib import Path
from datetime import UTC, datetime
spec=importlib.util.spec_from_file_location('native_verify',Path(__file__).with_name('verify-native-runtime.py'));native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

def main():
 p=argparse.ArgumentParser();p.add_argument('--env-file',type=Path,required=True);p.add_argument('--source-auth-file',type=Path,required=True);p.add_argument('--source-project',required=True);p.add_argument('--base-url',default='http://127.0.0.1:18088');p.add_argument('--api-container',default='koda-native-verify-20261017-portal-api');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 e=native.dotenv(a.env_file);auth=json.loads(a.source_auth_file.read_text());client=native.Client(a.base_url);client.login(e.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME','admin'),e['TRACKER_BOOTSTRAP_ADMIN_PASSWORD']);report={'startedAt':datetime.now(UTC).isoformat(),'checks':[],'evidence':{}}
 def check(name,condition,evidence=None):
  if not condition:raise RuntimeError(f'{name}: {evidence}')
  report['checks'].append({'name':name,'passed':True});print('PASS',name,flush=True)
  if evidence is not None:report['evidence'][name]=evidence
 def wait_analysis(run_id):
  deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   d=client.request('GET','/api/v1/sbom-runs/'+run_id)
   if d.get('analyses') and d['analyses'][0]['state'] in ('completed','failed'):return d
   time.sleep(1)
  raise RuntimeError('Grype analysis timeout')
 original=client.request('GET','/api/v1/sbom-policies')
 try:
  check('standalone mode',client.request('GET','/api/v1/dependency-track/status')['enabled'] is False)
  # Real public registries, automatic upload enqueue and separate collector.
  suffix=uuid.uuid4().hex[:10];service=client.request('POST','/api/v1/services',data={'slug':'registry-live-'+suffix,'name':'Registry live verification '+suffix},expected=201);env=client.request('GET','/api/v1/environments')[0]
  packages=[('npm','lodash','4.17.20','pkg:npm/lodash@4.17.20'),('pypi','requests','2.25.0','pkg:pypi/requests@2.25.0'),('maven','log4j-core','2.14.1','pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'),('nuget','Newtonsoft.Json','12.0.1','pkg:nuget/Newtonsoft.Json@12.0.1'),('golang','text','v0.3.0','pkg:golang/golang.org/x/text@v0.3.0'),('cargo','serde','1.0.100','pkg:cargo/serde@1.0.100')]
  components=[{'type':'library','name':name,'version':version,'purl':purl,'bom-ref':purl,'licenses':[{'license':{'id':'MIT'}}]} for _,name,version,purl in packages]
  bom=json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'serialNumber':'urn:uuid:'+str(uuid.uuid4()),'components':components}).encode()
  upload=client.upload(bom,{'serviceId':service['id'],'environmentId':env['id'],'releaseVersion':'registry-live'},idempotency_key=suffix);rid=upload['runId'];d=wait_analysis(rid);check('real Grype on six ecosystems',d['analyses'][0]['state']=='completed',{'runId':rid,'metrics':d.get('analysisMetrics')})
  deadline=time.monotonic()+300;metadata=None
  while time.monotonic()<deadline:
   metadata=client.request('GET',f'/api/v1/sbom-runs/{rid}/package-metadata?size=100')
   if len(metadata['items'])==6 and all(v['metadata']['status']=='fresh' for v in metadata['items']):break
   time.sleep(2)
  check('automatic real registry collection for six ecosystems',len(metadata['items'])==6 and all(v['metadata']['status']=='fresh' for v in metadata['items']),metadata)
  check('latest versions have public source provenance',all(v['metadata'].get('latestVersion') and v['metadata'].get('sourceUrls') for v in metadata['items']))
  check('publication timestamps collected or explicitly qualified',all(v['metadata'].get('currentVersionPublishedAt') for v in metadata['items']),metadata)
  report['evidence']['metadataRunId']=rid
  # A live metadata-dependent rule is evaluated in the real isolated Grype worker.
  rule={'id':'registry-age-'+suffix,'name':'Live registry publication check','kind':'cel','target':'component','action':'fail','enabled':True,'values':[],'serviceIds':[service['id']],'expression':'has(component.ageDays) && component.ageDays > 365 && has(component.latestVersion) && component.latestVersion != component.version'}
  current=client.request('GET','/api/v1/sbom-policies');client.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':current['version'],'rules':[rule],'exceptions':[]})
  job=client.request('POST',f'/api/v1/sbom-runs/{rid}/analyses',expected=202);deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   j=client.request('GET','/api/v1/jobs/'+job['jobId'])
   if j['state'] in ('completed','failed'):break
   time.sleep(1)
  d=client.request('GET','/api/v1/sbom-runs/'+rid);check('real collected dates drive native CEL policy',j['state']=='completed' and d['analysisMetrics']['policyFailCount']>=5,d)
  # Standard source API export performed inside Docker (source network has no host route).
  request={'baseUrl':auth['baseUrl'],'apiKey':auth['apiKey'],'allowedOrigins':[auth['baseUrl']],'projectUuids':[a.source_project]}
  staged=client.request('POST','/api/v1/legacy-migrations/export-stage',data=request,expected=201)
  check('real source API export and conversion',staged['report']['canApply'],staged)
  bundle=client.request('GET','/api/v1/legacy-migrations/'+staged['id']+'/bundle');report['evidence']['sourceCounts']={'projects':len(bundle['projects']),'policies':len(bundle['policies']),'findings':sum(len((x['findings'] or {}).get('findings') or []) for x in bundle['projects'])}
  current=client.request('GET','/api/v1/sbom-policies');applied=client.request('POST','/api/v1/legacy-migrations/'+staged['id']+'/apply',data={'expectedDigest':staged['digest'],'expectedPolicyVersion':current['version'],'trustSourceReviews':False})
  check('atomic source data and policy import',applied['state']=='applied',applied)
  again=client.request('POST','/api/v1/legacy-migrations/'+staged['id']+'/apply',data={'expectedDigest':staged['digest'],'expectedPolicyVersion':current['version'],'trustSourceReviews':False})
  check('repeat apply is idempotent',again['result']==applied['result'])
  imported_id=applied['result']['runIds'][0]
  imported=client.request('GET','/api/v1/sbom-runs/'+imported_id)
  native_rows=client.request('GET',f'/api/v1/sbom-runs/{imported_id}/policy-violations?size=100')['items']
  legacy_rows=[r for r in native_rows if r.get('policyId','').startswith('legacy-')]
  check('source findings and historical analysis preserved',imported['analyses'][0]['toolVersion']=='legacy-import' and imported['analysisMetrics']['vulnerabilityCount']==2,imported)
  check('all three actual source policies preserve action and component semantics',len(legacy_rows)==3 and {r['action'] for r in legacy_rows}=={'fail','warn','info'},legacy_rows)
  reviews=client.request('GET',f'/api/v1/sbom-runs/{imported_id}/reviews')['items']
  check('source review history safely imported without invented approval',len(reviews)==2 and all(r['status']=='submitted' for r in reviews),reviews)
  history_id=imported['analyses'][0]['id']
  j=client.request('POST',f'/api/v1/sbom-runs/{imported_id}/analyses',expected=202);deadline=time.monotonic()+180
  while time.monotonic()<deadline:
   state=client.request('GET','/api/v1/jobs/'+j['jobId'])
   if state['state'] in ('completed','failed'):break
   time.sleep(1)
  rechecked=client.request('GET','/api/v1/sbom-runs/'+imported_id)
  check('imported SBOM reanalyzes using real Grype while preserving source revision',state['state']=='completed' and rechecked['analyses'][0]['toolVersion']=='0.109.1' and any(a['id']==history_id for a in rechecked['analyses']),rechecked)
  report['evidence']['importedRunId']=imported_id

  report['evidence']['migrationId']=staged['id'];report['evidence']['bundleDigest']=staged['digest']
  report['evidence']['importResult']=applied['result']
  # Keep a private raw source bundle separate from public verification output.
  private=a.env_file.parent/'migration-export.json';private.write_text(json.dumps(bundle));private.chmod(0o600)
 finally:
  current=client.request('GET','/api/v1/sbom-policies');client.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':current['version'],'rules':original['rules'],'exceptions':original['exceptions']})
  report['finishedAt']=datetime.now(UTC).isoformat();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2))
 print(json.dumps({'checks':len(report['checks']),'output':str(a.output)}))
if __name__=='__main__':main()
