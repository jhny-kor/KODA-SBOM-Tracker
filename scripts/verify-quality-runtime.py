#!/usr/bin/env python3
"""Isolated Docker acceptance of offline SBOM quality, project criteria and CI/CEL."""
from __future__ import annotations
import argparse,copy,importlib.util,json,time,uuid,subprocess,os
from datetime import UTC,datetime
from pathlib import Path

spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('verify-native-runtime.py'));native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--env-file',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);p.add_argument('--base-url',default='http://127.0.0.1:18088');a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=True)
 env=native.dotenv(a.env_file);c=native.Client(a.base_url);c.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME','admin'),env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD']);checks=[];evidence={};token_id=None;original_policy=None
 def check(name,condition,value=None):
  if not condition:raise RuntimeError(name+': '+str(value))
  checks.append({'name':name,'passed':True});print('PASS',name,flush=True)
  if value is not None:evidence[name]=value
 def wait(rid,after=0):
  end=time.monotonic()+300
  while time.monotonic()<end:
   r=c.request('GET','/api/v1/sbom-runs/'+rid)
   if r.get('analyses') and r['analyses'][0]['sequence']>after and r['analysisState']=='completed' and not r.get('nativeReanalysisPending'):return r
   time.sleep(1)
  raise RuntimeError('analysis timeout '+rid)
 def profile(project,mode,maxwarnings=None):
  old=c.request('GET','/api/v1/quality-profiles?projectId='+project['id'])
  return c.request('PUT','/api/v1/quality-profiles?projectId='+project['id'],data={'expectedVersion':old['version'],'name':'Docker 품질 기준','mode':mode,'maxErrors':0,'maxWarnings':maxwarnings,'maxMissingIdentityRatio':0,'maxUnresolvedRefs':0,'maxAgeDays':365})
 def quality(rid):return c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-revisions')['items'][0]
 try:
  suffix=uuid.uuid4().hex[:8];service=c.request('POST','/api/v1/services',expected=201,data={'slug':'quality-'+suffix,'name':'SBOM 품질 검증 '+suffix});environment=c.request('GET','/api/v1/environments')[0]
  project=c.request('POST','/api/v1/project-catalog',expected=201,data={'sourceId':'quality-docker-'+suffix,'sourceProjectId':'sample','name':'품질 기준 샘플 '+suffix,'version':'quality','serviceId':service['id'],'environmentId':environment['id']})
  project_profile=profile(project,'warn')
  root={'type':'application','bom-ref':'root','name':'quality-app','version':'1.0.0','supplier':{'name':'KODA Sample'}}
  child={'type':'library','bom-ref':'child','name':'quality-child-'+suffix,'version':'1.0.0','purl':'pkg:generic/quality-child-'+suffix+'@1.0.0','licenses':[{'license':{'id':'MIT'}}],'hashes':[{'alg':'SHA-256','content':'a'*64}]}
  good={'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':{'timestamp':datetime.now(UTC).isoformat(),'tools':[{'vendor':'KODA','name':'quality-fixture','version':'1'}],'authors':[{'name':'Sample Author'}],'component':root},'components':[child],'dependencies':[{'ref':'root','dependsOn':['child']},{'ref':'child','dependsOn':[]}]}
  bad=copy.deepcopy(good);bad['components'][0]['components']=[{'type':'library','bom-ref':'nested','name':'missing-identity','version':'1.0.0'}];bad['dependencies'][0]['dependsOn'].append('missing-ref')
  raw=json.dumps(bad).encode();u=c.upload(raw,{'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'quality'},idempotency_key='quality-bad-'+suffix);r=wait(u['runId']);rid=r['id'];q1=quality(rid)
  check('real Grype completed alongside offline quality',r['analyses'][0]['state']=='completed' and r['analyses'][0]['toolVersion'] not in ('unknown','test-grype'),{'toolVersion':r['analyses'][0]['toolVersion'],'dataAsOf':r['dataAsOf']})
  check('nested quality source location and denominator',q1['summary']['componentCount']==2 and q1['summary']['missingIdentityRatio']==.5,q1)
  issues=c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-issues?size=1');check('server-side issue pagination',issues['total']>1 and len(issues['items'])==1)
  filtered=c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-issues?ruleId=identity.missing');check('nested issue remediation',any('.components[0].components[0]' in i['path'] and i['remediation'] for i in filtered['items']),filtered)
  gate=c.request('GET',f'/api/v1/sbom-runs/{rid}/gate');check('warn profile retains nonblocking rollout',q1['summary']['qualityStatus']=='warn' and gate['allowed'],gate)
  strict=profile(project,'enforce');r=wait(rid,r['analyses'][0]['sequence']);q2=quality(rid);gate=c.request('GET',f'/api/v1/sbom-runs/{rid}/gate');check('project enforce criteria blocks CI after automatic reanalysis',q2['summary']['qualityStatus']=='fail' and not gate['allowed'] and 'quality_threshold_exceeded' in gate['reasons'],gate)
  prior=c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-export?revisionId='+q1['id']);check('profile changes preserve old evidence',prior['revision']==q1 and prior['revision']['profileSnapshot']['mode']=='warn')
  csv=c.request('GET',f'/api/v1/sbom-runs/{rid}/quality-export?format=csv',as_bytes=True).decode('utf-8-sig');check('CSV diagnostic export','ruleId,severity,path' in csv and 'graph.unresolved_ref' in csv)
  u2=c.upload(json.dumps(good).encode(),{'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'quality'},idempotency_key='quality-good-'+suffix);fixed=wait(u2['runId']);qgood=quality(fixed['id']);gate=c.request('GET',f'/api/v1/sbom-runs/{fixed["id"]}/gate');check('corrected next round passes project criteria',qgood['summary']['errorCount']==0 and qgood['summary']['warningCount']==0 and gate['allowed'],qgood)
  check('round comparison reports improvement',qgood.get('comparison') and qgood['comparison']['errorDelta']<0,qgood.get('comparison'))
  xml=f'''<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1" serialNumber="{good['serialNumber']}"><metadata><timestamp>{good['metadata']['timestamp']}</timestamp><tools><tool><vendor>KODA</vendor><name>quality-fixture</name><version>1</version></tool></tools><authors><author><name>Sample Author</name></author></authors><component type="application" bom-ref="root"><supplier><name>KODA Sample</name></supplier><name>quality-app</name><version>1.0.0</version></component></metadata><components><component type="library" bom-ref="child"><name>{child['name']}</name><version>1.0.0</version><hashes><hash alg="SHA-256">{'a'*64}</hash></hashes><licenses><license><id>MIT</id></license></licenses><purl>{child['purl']}</purl></component></components><dependencies><dependency ref="root"><dependency ref="child"/></dependency><dependency ref="child"/></dependencies></bom>'''.encode()
  xu=c.upload(xml,{'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'quality'},idempotency_key='quality-xml-'+suffix);xr=wait(xu['runId']);xq=quality(xr['id']);check('real XML and JSON quality evidence agree',xq['summary']==qgood['summary'],xq)
  # An explicit project context is not required for the default warn rollout.
  other=c.upload(json.dumps(bad).encode(),{'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'unconfigured'},idempotency_key='quality-default-'+suffix);other=wait(other['runId']);check('project criteria do not leak to unconfigured release',quality(other['id'])['profileSnapshot']['mode']=='warn')
  token=c.request('POST','/api/v1/api-tokens',expected=201,data={'name':'quality-ci-'+suffix,'serviceId':service['id']});token_id=token['id'];cli_env={**os.environ,'KODA_TRACKER_URL':a.base_url,'KODA_TRACKER_TOKEN':token['token']}
  def cli(run):return subprocess.run([os.sys.executable,str(Path(__file__).with_name('check-sbom-gate.py')),run,'--timeout','10','--interval','1'],env=cli_env,text=True,capture_output=True)
  check('CI command exits 1 for quality violation',cli(rid).returncode==1)
  check('CI command exits 0 for accepted artifact',cli(fixed['id']).returncode==0)
  # CEL project rules see immutable quality evidence and can reject warning-mode issues.
  original_policy=c.request('GET','/api/v1/sbom-policies');rule={'id':'quality-cel-'+suffix,'name':'품질 오류 차단','kind':'cel','target':'project','expression':'sbomQuality.state != "completed" || sbomQuality.errorCount > 0','action':'fail','enabled':True,'serviceIds':[service['id']]}
  validated=c.request('POST','/api/v1/sbom-policies/validate',data={'expression':rule['expression'],'target':'project','runId':other['id']});check('real CEL quality preview',validated['matchCount']==1,validated)
  c.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':original_policy['version'],'rules':[*original_policy['rules'],rule],'exceptions':original_policy['exceptions']});c.request('POST',f'/api/v1/sbom-runs/{other["id"]}/analyses',expected=202);other=wait(other['id'],other['analyses'][0]['sequence']);violations=c.request('GET',f'/api/v1/sbom-runs/{other["id"]}/policy-violations?size=100');check('CEL quality condition produces native policy violation',any(i.get('policyId')==rule['id'] for i in violations['items']),violations)
  check('CEL failure blocks CI',cli(other['id']).returncode==1)
  evidence['fixtures']={'serviceId':service['id'],'projectId':project['id'],'badRunId':rid,'goodRunId':fixed['id'],'defaultRunId':other['id']}
 finally:
  if original_policy:
   current=c.request('GET','/api/v1/sbom-policies');c.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':current['version'],'rules':original_policy['rules'],'exceptions':original_policy['exceptions']})
  if token_id:c.request('POST','/api/v1/api-tokens/'+token_id+'/revoke')
  (a.output_dir/'runtime-report.json').write_text(json.dumps({'checks':checks,'evidence':evidence,'at':datetime.now(UTC).isoformat()},ensure_ascii=False,indent=2))
 print(json.dumps({'passed':len(checks)},ensure_ascii=False))
if __name__=='__main__':main()
