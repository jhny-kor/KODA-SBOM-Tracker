#!/usr/bin/env python3
"""Seed old-version defect cases, then verify upgraded Docker using real Grype."""
from __future__ import annotations
import argparse,importlib.util,json,time,uuid
from pathlib import Path
from datetime import UTC,datetime
spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('verify-native-runtime.py'));native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['seed','verify']);p.add_argument('--env-file',type=Path,required=True);p.add_argument('--base-url',default='http://127.0.0.1:18088');p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args();a.output_dir.mkdir(parents=True,exist_ok=True)
 env=native.dotenv(a.env_file);c=native.Client(a.base_url);c.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME','admin'),env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
 def wait(rid,after=0):
  end=time.monotonic()+300
  while time.monotonic()<end:
   row=c.request('GET','/api/v1/sbom-runs/'+rid)
   if row.get('analyses') and row['analyses'][0]['sequence']>after and row['analysisState']=='completed' and not row.get('nativeReanalysisPending'):return row
   time.sleep(1)
  raise RuntimeError('analysis timeout '+rid)
 path=a.output_dir/'seed.json'
 if a.phase=='seed':
  suffix=uuid.uuid4().hex[:8];original=c.request('GET','/api/v1/sbom-policies');service=c.request('POST','/api/v1/services',data={'slug':'corrections-'+suffix,'name':'SBOM 정확성 회귀 '+suffix},expected=201);environment=c.request('GET','/api/v1/environments')[0]
  rule={'id':'nested-gpl-'+suffix,'name':'중첩 GPL 금지','kind':'license_denied','values':['GPL-3.0-only'],'enabled':True,'action':'fail','serviceIds':[service['id']]}
  c.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':original['version'],'rules':[*original['rules'],rule],'exceptions':original['exceptions']})
  child={'type':'library','bom-ref':'child','name':'internal-child-'+suffix,'version':'1.0.0','purl':f'pkg:generic/internal-child-{suffix}@1.0.0','licenses':[{'license':{'id':'GPL-3.0-only'}}]}
  parent={'type':'library','bom-ref':'parent','name':'internal-parent-'+suffix,'version':'1.0.0','purl':f'pkg:generic/internal-parent-{suffix}@1.0.0','licenses':[{'license':{'id':'MIT'}}],'components':[child]}
  bom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[parent]}
  xml=f'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components><component type="library" bom-ref="parent"><name>internal-parent-{suffix}</name><version>1.0.0</version><licenses><license><id>MIT</id></license></licenses><purl>pkg:generic/internal-parent-{suffix}@1.0.0</purl><components><component type="library" bom-ref="child"><name>internal-child-{suffix}</name><version>1.0.0</version><licenses><license><id>GPL-3.0-only</id></license></licenses><purl>pkg:generic/internal-child-{suffix}@1.0.0</purl></component></components></component></components></bom>'.encode()
  runs={}
  for label,raw in [('nested-json',json.dumps(bom).encode()),('nested-xml',xml)]:
   upload=c.upload(raw,{'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':label},idempotency_key=suffix+label);runs[label]=wait(upload['runId'])
  for label,name,scope,version in [('npm-a','core','angular','1.0.0'),('npm-b','node','types','20.0.0')]:
   raw=json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[{'type':'library','bom-ref':label,'name':name,'group':'@'+scope,'version':version,'purl':f'pkg:npm/%40{scope}/{name}@{version}','licenses':[{'license':{'id':'MIT'}}]}]}).encode()
   upload=c.upload(raw,{'serviceId':service['id'],'environmentId':environment['id'],'releaseVersion':'npm'},idempotency_key=suffix+label);runs[label]=wait(upload['runId'])
  seed={'suffix':suffix,'originalPolicy':original,'service':service,'environment':environment,'ruleId':rule['id'],'runs':runs,'startedAt':datetime.now(UTC).isoformat()};path.write_text(json.dumps(seed,ensure_ascii=False,indent=2));print(json.dumps({'seeded':list(runs),'nestedOldCounts':[runs[x]['componentCount'] for x in ('nested-json','nested-xml')]},ensure_ascii=False));return
 seed=json.loads(path.read_text());report={'checks':[],'evidence':{},'startedAt':datetime.now(UTC).isoformat()}
 def check(name,condition,evidence=None):
  if not condition:raise RuntimeError(name+': '+str(evidence))
  report['checks'].append({'name':name,'passed':True});print('PASS',name,flush=True)
  if evidence is not None:report['evidence'][name]=evidence
 try:
  for label in ('nested-json','nested-xml'):
   old=seed['runs'][label];current=wait(old['id'],old['analyses'][0]['sequence']);components=c.request('GET',f'/api/v1/sbom-runs/{old["id"]}/components?size=100');policies=c.request('GET',f'/api/v1/sbom-runs/{old["id"]}/policy-violations?size=100')
   check(label+' recovered both components',current['componentCount']==2 and components['total']==2,current)
   check(label+' nested GPL produces policy violation',any(row.get('policyId')==seed['ruleId'] and 'internal-child' in row.get('component','') for row in policies['items']),policies)
   check(label+' prior analysis remains immutable',next(x for x in current['analyses'] if x['id']==old['analyses'][0]['id'])==old['analyses'][0])
   import hashlib
   check(label+' original artifact SHA preserved',hashlib.sha256(c.request('GET',f'/api/v1/sbom-runs/{old["id"]}/artifact',as_bytes=True)).hexdigest()==old['sha256'])
  first,second=[seed['runs'][x] for x in ('npm-a','npm-b')]
  diff=c.request('GET',f'/api/v1/comparisons?baseRunId={first["id"]}&targetRunId={second["id"]}')
  check('scoped npm replacement is add and remove',{row['change'] for row in diff['components']}=={'added','removed'},diff)
  # Two catalogs sharing one coordinate must not claim ordinary uploads.
  source='mapping-'+uuid.uuid4().hex[:8]
  mapping_version=source
  mapping_bom=json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[{'type':'library','name':'mapping-sample','version':'1.0.0','licenses':[{'license':{'id':'MIT'}}]}]}).encode()
  mapping=c.upload(mapping_bom,{'serviceId':seed['service']['id'],'environmentId':seed['environment']['id'],'releaseVersion':mapping_version},idempotency_key=source)
  mapping_run=wait(mapping['runId'])
  def project(identity,source_id,version,parent=None,logic='NONE'):
   return c.request('POST','/api/v1/project-catalog',expected=201,data={'sourceId':source_id,'sourceProjectId':identity,'serviceId':seed['service']['id'],'environmentId':seed['environment']['id'],'name':identity,'version':version,'parentProjectId':parent,'collectionLogic':logic})
  parent=project('root',source+'-A','collection',logic='AGGREGATE_DIRECT_CHILDREN')
  child=project('child',source+'-A',mapping_version,'root');other=project('other',source+'-B',mapping_version)
  def metrics(row):return c.request('GET',f'/api/v1/project-catalog/{row["id"]}/metrics')
  ambiguous=metrics(parent)
  check('cross-source ordinary run is excluded with ambiguous coverage',ambiguous['coverage']['ambiguousProjectCount']==1 and not ambiguous['coverage']['complete'] and ambiguous['totals']['componentCount']==0,ambiguous)
  c.request('POST',f'/api/v1/project-catalog/{child["id"]}/runs',data={'expectedRevision':child['revision'],'runId':mapping_run['id']})
  assigned=metrics(parent);foreign=metrics(other)
  check('explicit run ownership fixes only chosen collection',assigned['projects'][0]['runId']==mapping_run['id'] and assigned['totals']['componentCount']==1 and foreign['totals']['componentCount']==0,{'owner':assigned,'otherSource':foreign})
  # Real public NuGet API through the actual dedicated metadata worker.
  components=[{'type':'library','name':name,'version':version,'purl':f'pkg:nuget/{name}@{version}','licenses':[{'license':{'id':'MIT'}}]} for name,version in [('Serilog','2.0.0'),('Microsoft.Extensions.DependencyInjection','11.0.0-rc.2.26504.105')]]
  raw=json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':components}).encode()
  upload=c.upload(raw,{'serviceId':seed['service']['id'],'environmentId':seed['environment']['id'],'releaseVersion':'nuget'},idempotency_key='nuget-'+seed['suffix'])
  wait(upload['runId']);end=time.monotonic()+300;items=[]
  while time.monotonic()<end:
   items=c.request('GET',f'/api/v1/sbom-runs/{upload["runId"]}/package-metadata')['items']
   if len(items)==2 and all(x['metadata'].get('status')=='fresh' for x in items):break
   time.sleep(2)
  values={x['component']['name']:x['metadata'] for x in items};serilog=values['Serilog'];preview=values['Microsoft.Extensions.DependencyInjection']
  check('real NuGet registry collects more than eight pages',serilog.get('status')=='fresh' and serilog.get('nugetRegistrationApi')=='RegistrationsBaseUrl/3.6.0' and serilog.get('registrationPageCount',0)>8 and serilog.get('registrationVersionCount',0)>512,serilog)
  check('real NuGet SemVer2 current publication date resolves',preview.get('status')=='fresh' and preview.get('currentVersionMissing') is False and bool(preview.get('currentVersionPublishedAt')) and preview.get('latestIsPrerelease') is False,preview)
  check('NuGet source evidence uses discovered SemVer2 hive',all(any('registration5-gz-semver2' in url for url in value.get('sourceUrls',[])) for value in (serilog,preview)))
  report['finishedAt']=datetime.now(UTC).isoformat()
 finally:
  current=c.request('GET','/api/v1/sbom-policies');o=seed['originalPolicy'];c.request('PUT','/api/v1/sbom-policies',data={'expectedVersion':current['version'],'rules':o['rules'],'exceptions':o['exceptions']});(a.output_dir/'runtime-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
