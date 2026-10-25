#!/usr/bin/env python3
"""Sample-only Docker acceptance: collection rollups and private advisories.

Uses actual queued Grype analyses. Creates isolated sample records, restores the
policy document, leaves withdrawn advisories/history as inspectable evidence.
Credentials are read from a private env file and never written to the report.
"""
from __future__ import annotations
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import uuid
from datetime import UTC, datetime

spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('verify-native-runtime.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--base-url', default='http://127.0.0.1:18088')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--restart', action='store_true', help='Restart isolated Compose services and verify persistence')
    args = parser.parse_args()
    env = native.dotenv(args.env_file)
    client = native.Client(args.base_url)
    client.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME', 'admin'), env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
    report = {'startedAt': datetime.now(UTC).isoformat(), 'checks': [], 'evidence': {}}
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def check(name, condition, evidence=None):
        if not condition:
            raise RuntimeError(f'{name}: {evidence}')
        report['checks'].append({'name': name, 'passed': True})
        if evidence is not None:
            report['evidence'][name] = evidence
        print('PASS', name, flush=True)

    def wait(fn, label):
        until = time.monotonic() + args.timeout
        while time.monotonic() < until:
            value = fn()
            if value:
                return value
            time.sleep(1)
        raise RuntimeError(f'{label} timed out')

    def detail(rid):
        return client.request('GET', '/api/v1/sbom-runs/' + rid)

    def analyzed(rid, after=0):
        row = detail(rid)
        analysis = row['analyses'][0] if row['analyses'] else None
        return row if analysis and analysis['sequence'] > after and row['analysisState'] == 'completed' and not row.get('nativeReanalysisPending') else None

    def findings(rid, analysis_id=None):
        return client.request('GET', f'/api/v1/sbom-runs/{rid}/findings?size=100' + (f'&analysisId={analysis_id}' if analysis_id else ''))['items']

    def metrics(project):
        return client.request('GET', f'/api/v1/project-catalog/{project["id"]}/metrics')

    def patch(project, **values):
        changed = client.request('PATCH', '/api/v1/project-catalog/' + project['id'], data={'expectedRevision': project['revision'], **values})
        project.update(changed)
        return changed

    def private_body(row):
        return {k: row[k] for k in ('advisoryId', 'title', 'description', 'severity', 'cvssScore', 'cwes', 'aliases', 'references', 'state', 'affected')}

    original_policy = client.request('GET', '/api/v1/sbom-policies')
    private = None
    try:
        suffix = uuid.uuid4().hex[:8]
        private_id = 'KODA-INTERNAL-' + suffix.upper()
        package = 'koda-private-' + suffix
        source = 'collection-test-' + suffix
        service = client.request('POST', '/api/v1/services', data={'slug': source, 'name': 'Collection·사내 취약점 Docker 검증 ' + suffix}, expected=201)
        environment = client.request('GET', '/api/v1/environments')[0]
        rule = {'id': 'private-' + suffix, 'name': '사내 High 취약점 차단', 'kind': 'severity', 'values': ['high'], 'action': 'fail', 'enabled': True}
        client.request('PUT', '/api/v1/sbom-policies', data={'expectedVersion': original_policy['version'], 'rules': [*original_policy['rules'], rule], 'exceptions': original_policy['exceptions']})

        def project(identity, name, version='', run=None, parent=None, **extra):
            return client.request('POST', '/api/v1/project-catalog', expected=201, data={
                'sourceId': source, 'sourceProjectId': identity, 'serviceId': service['id'], 'environmentId': environment['id'],
                'name': name, 'version': version, 'parentProjectId': parent, **({'runId': run} if run else {}), **extra})

        parent = project('parent', '부모 Collection', collectionLogic='AGGREGATE_DIRECT_CHILDREN')
        runs, children = [], []
        for index, version in enumerate(('1.0.0', '2.0.0')):
            bom = json.loads(native.make_bom('2.14.1' if index == 0 else '2.25.3', '4.17.20' if index == 0 else '4.17.21'))
            bom['components'].append({'type': 'library', 'name': package, 'version': version, 'purl': f'pkg:generic/{package}@{version}', 'bom-ref': f'internal-{index}', 'licenses': [{'license': {'id': 'MIT'}}]})
            uploaded = client.upload(json.dumps(bom).encode(), {'serviceId': service['id'], 'environmentId': environment['id'], 'releaseVersion': version}, idempotency_key=f'{source}-{index}')
            current = wait(lambda: analyzed(uploaded['runId']), 'initial Grype')
            runs.append(current)
            children.append(project('child-' + str(index), '버전 자식', version, current['id'], 'parent', tags=['prod' if index else 'old'], isLatest=bool(index)))
        report['evidence'].update(serviceId=service['id'], parent=parent, runs=[r['id'] for r in runs], children=children)
        check('actual Grype DB produces public CVEs', runs[0]['vulnerabilityCount'] > 0 and runs[0]['analyses'][0]['toolVersion'].startswith(('0.', 'v0.')), {'version': runs[0]['analyses'][0]['toolVersion'], 'dataAsOf': runs[0]['analyses'][0]['dataAsOf']})
        initial = metrics(parent)
        check('direct child totals equal actual analysis sums', initial['coverage']['complete'] and initial['coverage']['selectedProjectCount'] == 2 and initial['totals']['componentCount'] == 6 and initial['totals']['vulnerabilityCount'] == sum(r['analysisMetrics']['effectiveVulnerabilityCount'] for r in runs), initial)
        patch(parent, collectionLogic='AGGREGATE_LATEST_VERSION_CHILDREN')
        latest = metrics(parent)
        check('latest child aggregation', latest['coverage']['selectedProjectCount'] == 1 and latest['projects'][0]['runId'] == runs[1]['id'], latest)
        patch(parent, collectionLogic='AGGREGATE_DIRECT_CHILDREN_WITH_TAG', collectionTag='old')
        tagged = metrics(parent)
        check('tagged child aggregation', tagged['coverage']['selectedProjectCount'] == 1 and tagged['projects'][0]['runId'] == runs[0]['id'], tagged)
        nested = project('nested', '중첩 Collection', parent='parent', collectionLogic='AGGREGATE_DIRECT_CHILDREN')
        missing = project('missing', '미분석 자식', parent='nested')
        patch(parent, collectionLogic='AGGREGATE_DIRECT_CHILDREN')
        incomplete = metrics(parent)
        check('nested collection missing coverage is explicit', incomplete['coverage']['selectedProjectCount'] == 3 and incomplete['coverage']['missingProjectCount'] == 1 and incomplete['coverage']['complete'] is False, incomplete)
        patch(missing, active=False)
        patch(parent, collectionLogic='AGGREGATE_ALL_DESCENDANTS')
        check('all descendant aggregation excludes inactive children', metrics(parent)['coverage']['selectedProjectCount'] == 2)

        body = {'advisoryId': private_id, 'title': '사내 패키지 접근 제어 오류', 'description': 'Docker 샘플 검증용. 영향 버전 1.x, 2.0.0 수정.', 'severity': 'High', 'cvssScore': 8.1, 'cwes': [862], 'aliases': [], 'references': ['https://example.invalid/internal-advisory'], 'state': 'draft', 'affected': [{'purl': f'pkg:generic/{package}', 'versions': [], 'ranges': [{'scheme': 'semver', 'introduced': '1.0.0', 'fixed': '2.0.0'}], 'fixedVersions': ['2.0.0']}]}
        private = client.request('POST', '/api/v1/private-vulnerabilities', data=body, expected=201)
        check('draft advisory has no analysis impact', private['affectedRunsQueued'] == 0 and not any(f.get('id') == private_id for f in findings(runs[0]['id'])))
        before_sequence = runs[0]['analyses'][0]['sequence']
        private = client.request('PUT', '/api/v1/private-vulnerabilities/' + private['id'], data={**body, 'state': 'published', 'expectedRevision': private['revision']})
        check('publication durably queues only affected runs', private['affectedRunsQueued'] == 1, private)
        published = wait(lambda: analyzed(runs[0]['id'], before_sequence), 'automatic private analysis')
        matched = [f for f in findings(published['id']) if f.get('id') == private_id]
        check('private internal ID shown with match evidence and fixed version', len(matched) == 1 and matched[0]['canonicalId'] == private_id and matched[0]['source'] == 'KODA_PRIVATE' and matched[0]['fixedIn'] == ['2.0.0'], matched)
        check('fixed version is not vulnerable', not any(f.get('id') == private_id for f in findings(runs[1]['id'])))
        rows = client.request('GET', f'/api/v1/sbom-runs/{published["id"]}/policy-violations?size=100')['items']
        check('private vulnerability causes real policy violation', any(p['policyId'] == rule['id'] and p['vulnerabilityId'] == private_id and not p.get('suppressed') for p in rows), [p for p in rows if p.get('vulnerabilityId') == private_id])
        snapshot = published['analyses'][0]['dataSources']['privateVulnerabilityDb']
        check('analysis pins private DB revision and digest', any(x['id'] == private['id'] and x['revision'] == 2 for x in snapshot['advisories']) and len(snapshot['sha256']) == 64, snapshot)
        after_publish = metrics(parent)
        check('collection reflects new private finding', after_publish['coverage']['complete'] and after_publish['totals']['vulnerabilityCount'] == initial['totals']['vulnerabilityCount'] + 1, after_publish)
        historic = copy.deepcopy(published['analyses'][0])
        client.request('PUT', '/api/v1/private-vulnerabilities/' + private['id'], data={**body, 'expectedRevision': 1}, expected=409)
        check('stale advisory write rejected', True)
        private = client.request('DELETE', f'/api/v1/private-vulnerabilities/{private["id"]}?expectedRevision={private["revision"]}')
        withdrawn = wait(lambda: analyzed(runs[0]['id'], published['analyses'][0]['sequence']), 'withdrawal reanalysis')
        check('withdrawal automatically removes private current finding', not any(f.get('id') == private_id for f in findings(withdrawn['id'])))
        old = next(r for r in withdrawn['analyses'] if r['id'] == historic['id'])
        check('previous analysis and private snapshot remain immutable', old == historic)
        check('collection returns to original counts after withdrawal', metrics(parent)['totals']['vulnerabilityCount'] == initial['totals']['vulnerabilityCount'])
        history = client.request('GET', f'/api/v1/private-vulnerabilities/{private["id"]}/history')
        check('draft publish withdraw history preserved', [x['document']['state'] for x in history['items']] == ['withdrawn', 'published', 'draft'], history)
        # A private record may reference a public CVE for the same package.
        # Both identities must remain independently selectable in VEX.
        public = next(f for f in findings(runs[0]['id']) if 'log4j-core' in str(f.get('component')) and str(f.get('canonicalId', '')).startswith('CVE-'))
        alias_id = private_id + '-ALIAS'
        alias = client.request('POST', '/api/v1/private-vulnerabilities', expected=201, data={
            **body, 'advisoryId': alias_id, 'state': 'published', 'aliases': [public['canonicalId']],
            'affected': [{'purl': 'pkg:maven/org.apache.logging.log4j/log4j-core', 'versions': ['2.14.1'], 'fixedVersions': ['2.25.3']}]})
        aliased = wait(lambda: analyzed(runs[0]['id'], withdrawn['analyses'][0]['sequence']), 'private CVE alias analysis')
        alias_finding = next(f for f in findings(runs[0]['id']) if f.get('id') == alias_id)
        check('private CVE alias retains distinct internal identity', alias_finding['canonicalId'] == alias_id and public['canonicalId'] in alias_finding['aliases'])
        reviews = [client.request('POST', f'/api/v1/sbom-runs/{runs[0]["id"]}/reviews', expected=201, data={
            'component': public['component'], 'vulnerabilityId': vid, 'state': 'in_triage', 'detail': '공개 CVE와 사내 별칭의 독립 검토 대상 검증'}) for vid in (public['canonicalId'], alias_id)]
        check('public and private VEX reviews select distinct exact targets', {r['vulnerabilityId'] for r in reviews} == {public['canonicalId'], alias_id}, reviews)
        client.request('DELETE', f'/api/v1/private-vulnerabilities/{alias["id"]}?expectedRevision={alias["revision"]}')
        wait(lambda: analyzed(runs[0]['id'], aliased['analyses'][0]['sequence']), 'alias withdrawal analysis')
        check('alias withdrawal restores collection metrics', metrics(parent)['totals']['vulnerabilityCount'] == initial['totals']['vulnerabilityCount'])
        report['evidence'].update(private=private, publishedAnalysisId=historic['id'], finalCollection=metrics(parent))
        if args.restart:
            result = subprocess.run(['docker', 'compose', '--env-file', str(args.env_file), 'restart'], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('Compose restart failed: ' + result.stderr[-1000:])
            def healthy():
                try:
                    return native.Client(args.base_url).request('GET', '/api/v1/healthz').get('status') == 'ok'
                except Exception:
                    return False
            wait(healthy, 'gateway restart')
            client = native.Client(args.base_url)
            client.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME', 'admin'), env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
            persisted = client.request('GET', f'/api/v1/private-vulnerabilities/{private["id"]}/history')
            check('restart preserves authoring history and collection metrics', persisted == history and metrics(parent)['totals'] == report['evidence']['finalCollection']['totals'])
        report['finishedAt'] = datetime.now(UTC).isoformat()
    finally:
        current = client.request('GET', '/api/v1/sbom-policies')
        if current['rules'] != original_policy['rules'] or current['exceptions'] != original_policy['exceptions']:
            client.request('PUT', '/api/v1/sbom-policies', data={'expectedVersion': current['version'], 'rules': original_policy['rules'], 'exceptions': original_policy['exceptions']})
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
