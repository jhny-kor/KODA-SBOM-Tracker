#!/usr/bin/env python3
"""Real isolated Docker acceptance for advanced conditions and dynamic project sync.

Creates named sample projects/policies on a disposable source server. Never use
with operating data. Keys come from private files and are absent from reports.
"""
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json, subprocess, time, uuid
from datetime import UTC, datetime
from pathlib import Path
spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('verify-native-runtime.py'));native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
SOURCE_REQUEST = '''import sys,json,httpx
x=json.load(sys.stdin);a=x['auth'];args={'headers':{'X-Api-Key':a['apiKey']},'timeout':30,'follow_redirects':False,'trust_env':False}
with httpx.Client(**args) as c:
 if x.get('bom') is not None:r=c.post(a['baseUrl']+'/api/v1/bom',data={'project':x['project']},files={'bom':('sample.cdx.json',json.dumps(x['bom']).encode(),'application/json')})
 else:r=c.request(x['method'],a['baseUrl']+'/api/v1'+x['path'],json=x.get('body'))
 print(json.dumps({'status':r.status_code,'data':r.json() if r.content and r.headers.get('content-type','').startswith('application/json') else None}))
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--env-file',type=Path,required=True);p.add_argument('--source-auth-file',type=Path,required=True);p.add_argument('--base-url',default='http://127.0.0.1:18088');p.add_argument('--api-container',default='koda-native-verify-20261017-portal-api');p.add_argument('--source-container',default='koda-migration-source');p.add_argument('--source-origin');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 e=native.dotenv(a.env_file);auth=json.loads(a.source_auth_file.read_text());auth['baseUrl']=a.source_origin or 'http://'+a.source_container+':8080'
 c=native.Client(a.base_url);c.login(e.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME','admin'),e['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
 report={'startedAt':datetime.now(UTC).isoformat(),'checks':[],'evidence':{}}
 def check(name,condition,evidence=None):
  if not condition:raise RuntimeError(name+': '+str(evidence))
  report['checks'].append({'name':name,'passed':True});print('PASS',name,flush=True)
  if evidence is not None:report['evidence'][name]=evidence
 def source(method,path,body=None,**extra):
  r=subprocess.run(['docker','exec','-i',a.api_container,'python','-c',SOURCE_REQUEST],input=json.dumps({'auth':auth,'method':method,'path':path,'body':body,**extra}),text=True,capture_output=True,check=True)
  payload=json.loads(r.stdout)
  if payload['status']>=300:raise RuntimeError(f'source {method} {path}: HTTP {payload["status"]}')
  return payload['data']
 def wait(predicate,label,timeout=180):
  stop=time.monotonic()+timeout
  while time.monotonic()<stop:
   value=predicate()
   if value:return value
   time.sleep(1)
  raise RuntimeError(label+' timeout')
 def reanalyze(rid):
  j=c.request('POST',f'/api/v1/sbom-runs/{rid}/analyses',expected=202)
  result=wait(lambda: (x if (x:=c.request('GET','/api/v1/jobs/'+j['jobId']))['state'] in ('completed','failed') else None),'Grype')
  assert result['state']=='completed',result.get('error')
  return c.request('GET','/api/v1/sbom-runs/'+rid)
 def catalog():return c.request('GET','/api/v1/project-catalog?size=200')['items']
 def rules(rid):return c.request('GET',f'/api/v1/sbom-runs/{rid}/policy-violations?size=100')['items']
 original=c.request('GET','/api/v1/sbom-policies');sync_id=None;source_off=False
 try:
  check('standalone native deployment',not c.request('GET','/api/v1/dependency-track/status')['enabled'])
  suffix=uuid.uuid4().hex[:8];name='KODA-complete-'+suffix
  projects=[]
  for label,version,latest,tags in [('root','1',True,['root']),('child','1',False,['old']),('child','2',True,['prod'])]:
   body={'name':name+'-'+label,'version':version,'classifier':'APPLICATION','active':True,'isLatest':latest,'tags':[{'name':v} for v in tags]}
   if projects:body['parent']={'uuid':projects[0]['uuid']}
   projects.append(source('PUT','/project',body))
  bom=json.loads(native.make_bom('2.14.1','4.17.20'));bom['metadata']={'component':{'type':'application','name':name,'bom-ref':'root-app'}}
  bom['components'].append({'type':'library','name':'requests','version':'2.25.0','purl':'pkg:pypi/requests@2.25.0','bom-ref':'requests','licenses':[{'expression':'GPL-2.0-only WITH Classpath-exception-2.0'}]})
  bom['dependencies']=[{'ref':'root-app','dependsOn':[x['bom-ref'] for x in bom['components']]}]
  for project in projects:source('POST','/bom',bom=bom,project=project['uuid'])
  for project in projects:wait(lambda: (rows if len(rows:=source('GET','/component/project/'+project['uuid']))==3 else None),'source BOM')
  mit=source('GET','/license/MIT');group=source('PUT','/licenseGroup',{'name':name+'-allowed'})
  source('POST',f"/licenseGroup/{group['uuid']}/license/{mit['uuid']}")
  definitions=[
   ('CWE','FAIL',[{'subject':'CWE','operator':'CONTAINS_ANY','value':'502'}]),
   ('EPSS','FAIL',[{'subject':'EPSS','operator':'NUMERIC_GREATER_THAN','value':'0.5'}]),
   ('AGE','WARN',[{'subject':'AGE','operator':'NUMERIC_GREATER_THAN','value':'P1Y2M'}]),
   ('DISTANCE','FAIL',[{'subject':'VERSION_DISTANCE','operator':'NUMERIC_GREATER_THAN','value':json.dumps({'epoch':'0','major':'0','minor':'1','patch':'?'})}]),
   ('SPDX','WARN',[{'subject':'LICENSE_GROUP','operator':'IS_NOT','value':group['uuid']}]),
   ('MIXED','FAIL',[{'subject':'LICENSE','operator':'IS_NOT','value':mit['uuid']},{'subject':'SEVERITY','operator':'IS','value':'CRITICAL'}]),
   ('VERSION','INFO',[{'subject':'VERSION','operator':'NUMERIC_GREATER_THAN','value':'2.0.0'}]),
   ('REGEX','INFO',[{'subject':'PACKAGE_URL','operator':'MATCHES','value':'(?i)^pkg:maven/.*log4j-core@2\\.14\\.1$'}]),
   ('TAG-LATEST','INFO',[{'subject':'PACKAGE_URL','operator':'MATCHES','value':'^pkg:maven/.*'}]),
  ]
  policy_ids={}
  for label,action,conditions in definitions:
   policy=source('PUT','/policy',{'name':name+'-'+label,'operator':'ALL','violationState':action,'global':False,'includeChildren':label!='TAG-LATEST','onlyLatestProjectVersion':label=='TAG-LATEST'})
   source('POST','/policy',{**policy,'includeChildren':label!='TAG-LATEST','onlyLatestProjectVersion':label=='TAG-LATEST'})
   for condition in conditions:source('PUT',f"/policy/{policy['uuid']}/condition",condition)
   if label=='TAG-LATEST':source('POST',f"/tag/prod/policy",[policy['uuid']])
   else:source('POST',f"/policy/{policy['uuid']}/project/{projects[0]['uuid']}")
   policy_ids[label]=policy['uuid']
  check('actual source sample accepts advanced condition definitions',len(policy_ids)==9,{'projectIds':[x['uuid'] for x in projects],'policyIds':policy_ids})
  body={'name':name,'baseUrl':auth['baseUrl'],'apiKey':auth['apiKey'],'allowedOrigins':[auth['baseUrl']],'enabled':True,'intervalMinutes':5}
  connector=c.request('POST','/api/v1/project-sync-sources',data=body,expected=201);sync_id=connector['id']
  synced=wait(lambda: (s if (s:=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id))['state'] in ('idle','blocked','failed') and s.get('lastSuccessAt') else None),'automatic source sync',300)
  check('automatic source sync imports hierarchy tags latest and policies',synced['state']=='idle',synced)
  records={x['sourceProjectId']:x for x in catalog() if x['sourceId']==synced['sourceId']}
  root,old,latest=[records[x['uuid']] for x in projects];rid=latest['currentRunId']
  report['evidence'].update({'runId':rid,'latestProjectId':latest['id'],'oldProjectId':old['id'],'sourceId':synced['sourceId'],'connectorId':sync_id})
  check('native catalog retains parent tags latest',latest['parentProjectId']==projects[0]['uuid'] and latest['tags']==['prod'] and latest['isLatest'] and not old['isLatest'])
  c.request('POST',f'/api/v1/sbom-runs/{rid}/package-metadata/refresh',expected=202)
  metadata=wait(lambda: (m if (m:=c.request('GET',f'/api/v1/sbom-runs/{rid}/package-metadata?size=100'))['total']==3 and all(x['metadata']['status']=='fresh' and x['metadata'].get('versionDistanceParts') for x in m['items']) else None),'fresh enhanced metadata',300)
  check('real registries supply release count and structured distance',all(x['metadata'].get('versionDistance') is not None for x in metadata['items']),metadata)
  maven=next(x['metadata'] for x in metadata['items'] if x['metadata']['ecosystem']=='maven')
  check('Maven exact official index date replaces file fallback',maven.get('currentVersionPublishedAtBasis')!='artifact_last_modified' and bool(maven['currentVersionPublishedAt']),maven)
  d=reanalyze(rid);time.sleep(3);d=reanalyze(rid)
  check('actual Grype DB plus current intelligence completes policy evaluation',d['analyses'][0]['toolVersion']=='0.109.1' and d['policyState']=='completed',d['analysisMetrics'])
  rows=rules(rid);names={x['policyName'] for x in rows if x['type']!='data_unavailable'}
  for label in ['CWE','EPSS','AGE','DISTANCE','SPDX','MIXED','VERSION','REGEX','TAG-LATEST']:
   check('native real-result policy '+label,name+'-'+label in names)
  spdxrows=[x for x in rows if x['policyName']==name+'-SPDX']
  check('SPDX WITH component participates in mixed license conditions',any('requests' in x['component'] for x in spdxrows),spdxrows)
  findings=c.request('GET',f'/api/v1/sbom-runs/{rid}/findings?size=100')['items']
  check('real CWE and FIRST EPSS evidence retained',any(x.get('cwes') and x.get('epssScore') is not None and x.get('epssEvidence',{}).get('sourceKind')=='first_epss' for x in findings),[{k:x.get(k) for k in ('canonicalId','cwes','epssScore','epssDate')} for x in findings])
  before_count=len(d['analyses']);before_sha=d['sha256'];before_snapshot=copy.deepcopy(d['analyses'][-1].get('policySnapshot'))
  c.request('POST',f'/api/v1/project-sync-sources/{sync_id}/run-now',expected=202)
  last=synced['lastSuccessAt'];wait(lambda: (s if (s:=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id)).get('lastSuccessAt')!=last and s['state']=='idle' else None),'repeat sync',300)
  again=next(x for x in catalog() if x['id']==latest['id']);after=c.request('GET','/api/v1/sbom-runs/'+rid)
  check('repeat real export ignores generated timestamps without new run or revision',again['currentRunId']==rid and len(after['analyses'])==before_count and after['sha256']==before_sha)
  # Native edits remain effective after the original server is stopped.
  tag_before_sequence=after['analyses'][0]['sequence']
  source('PATCH','/project/'+projects[2]['uuid'],{'tags':[{'name':'qa'}],'isLatest':True})
  c.request('POST',f'/api/v1/project-sync-sources/{sync_id}/run-now',expected=202)
  wait(lambda: (x if 'qa' in (x:=next(v for v in catalog() if v['id']==latest['id']))['tags'] else None),'source tag propagation',300)
  check('source tag changes automatically update dynamic scope',True)
  d=wait(lambda: (x if (x:=c.request('GET','/api/v1/sbom-runs/'+rid))['analysisState']=='completed' and x['analyses'][0]['sequence']>tag_before_sequence and x['analyses'][0]['toolVersion']=='0.109.1' else None),'automatic sync Grype',300)
  check('source scope changes automatically create native Grype revision',d['policyState']=='completed')
  check('tag policy stops matching after actual source sync',not any(x['policyName']==name+'-TAG-LATEST' for x in rules(rid)))
  # Trigger a durable network failure and recover by the ordinary API retry.
  wait(lambda: (s if (s:=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id))['state']=='idle' else None),'sync idle')
  subprocess.run(['docker','stop',a.source_container],check=True,capture_output=True);source_off=True
  c.request('POST',f'/api/v1/project-sync-sources/{sync_id}/run-now',expected=202)
  failed=wait(lambda: (s if (s:=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id))['state']=='retrying' else None),'durable retry')
  check('source outage yields durable retry with future attempt',failed['attempts']==1 and failed['nextRunAt'] is not None,failed)
  latest=next(x for x in catalog() if x['id']==latest['id'])
  latest=c.request('PATCH','/api/v1/project-catalog/'+latest['id'],data={'expectedRevision':latest['revision'],'tags':['prod'],'parentProjectId':None,'isLatest':True})
  d=reanalyze(rid);names={x['policyName'] for x in rules(rid) if x['type']!='data_unavailable'}
  check('native tag updates work with source stopped',name+'-TAG-LATEST' in names)
  check('native hierarchy detachment excludes parent scoped rules',name+'-DISTANCE' not in names and name+'-CWE' not in names)
  old=next(x for x in catalog() if x['id']==old['id'])
  c.request('PATCH','/api/v1/project-catalog/'+old['id'],data={'expectedRevision':old['revision'],'isLatest':True,'tags':['prod']})
  d=reanalyze(rid);check('latest version switch excludes previous latest run',not any(x['policyName']==name+'-TAG-LATEST' for x in rules(rid)))
  check('past analysis and original artifact remain unchanged',d['sha256']==before_sha and d['analyses'][-1].get('policySnapshot')==before_snapshot)
  subprocess.run(['docker','start',a.source_container],check=True,capture_output=True);source_off=False
  # Ready check uses the source version endpoint, never logs its credentials.
  wait(lambda: subprocess.run(['docker','exec',a.api_container,'python','-c',"import httpx;raise SystemExit(httpx.get('http://"+a.source_container+":8080/api/version',timeout=5).status_code!=200)"],capture_output=True).returncode==0,'source ready',180)
  recovery_baseline=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id)['lastSuccessAt']
  c.request('POST',f'/api/v1/project-sync-sources/{sync_id}/run-now',expected=202)
  recovered=wait(lambda: (s if (s:=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id))['state']=='idle' and s['attempts']==0 and s['lastSuccessAt']!=recovery_baseline else None),'recovery',300)
  check('source recovery retry succeeds and restores source catalog',recovered['lastError'] is None,recovered)
  restored=next(x for x in catalog() if x['id']==latest['id'])
  check('source recovery restores parent and latest source values',restored['parentProjectId']==projects[0]['uuid'] and restored['isLatest'] and restored['tags']==['qa'],restored)
  events=c.request('GET',f'/api/v1/project-sync-sources/{sync_id}/events')['items']
  check('durable success and retry audit events persist',any(x['state']=='retrying' for x in events) and any(x['state']=='completed' for x in events),events)
 finally:
  if source_off:subprocess.run(['docker','start',a.source_container],capture_output=True)
  if sync_id:
   try:
    s=next(x for x in c.request('GET','/api/v1/project-sync-sources')['items'] if x['id']==sync_id)
    if s['state']!='running':c.request('PATCH','/api/v1/project-sync-sources/'+sync_id,data={'expectedVersion':s['version'],'enabled':False})
   except Exception:pass
  current=c.request('GET','/api/v1/sbom-policies');c.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':current['version'],'rules':original['rules'],'exceptions':original['exceptions']})
  report['finishedAt']=datetime.now(UTC).isoformat();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2))
 print(json.dumps({'checks':len(report['checks']),'output':str(a.output)}))
if __name__=='__main__':main()
