#!/usr/bin/env python3
"""Verify native CEL, reviews, VEX, inbox and full-SBOM scheduling on an isolated real-Grype stack."""
from __future__ import annotations
import argparse
from datetime import UTC, datetime, timedelta
import importlib.util
import json
from pathlib import Path
import secrets
import time
import uuid

spec = importlib.util.spec_from_file_location('native_verify', Path(__file__).with_name('verify-native-runtime.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--base-url', default='http://127.0.0.1:18088')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    env = base.dotenv(args.env_file)
    client = base.Client(args.base_url)
    user = client.login(env.get('TRACKER_BOOTSTRAP_ADMIN_USERNAME', 'admin'), env['TRACKER_BOOTSTRAP_ADMIN_PASSWORD'])
    original = client.request('GET', '/api/v1/sbom-policies')
    schedule = client.request('GET', '/api/v1/reanalysis-schedule')
    report = {'startedAt': datetime.now(UTC).isoformat(), 'checks': [], 'evidence': {}}
    def check(name, condition, evidence=None):
        if not condition:
            raise RuntimeError(f'{name}: {evidence}')
        report['checks'].append({'name': name, 'passed': True})
        if evidence is not None: report['evidence'][name] = evidence
        print('PASS', name, flush=True)
    def wait_job(job):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = client.request('GET', '/api/v1/jobs/' + job['id'])
            if result['state'] in ('completed', 'failed'):
                check('real Grype worker completed ' + job['id'], result['state'] == 'completed', result)
                return
            time.sleep(1)
        raise RuntimeError('worker timed out')
    def detail(run_id): return client.request('GET', '/api/v1/sbom-runs/' + run_id)
    def analyze(run_id):
        wait_job({'id': client.request('POST', f'/api/v1/sbom-runs/{run_id}/analyses', expected=202)['jobId']})
        return detail(run_id)
    unique = uuid.uuid4().hex[:10]
    reviewer_id = None
    try:
        check('native advanced permissions', all(p in user['permissions'] for p in ('vex.manage', 'vex.approve', 'reanalysis.manage', 'notifications.manage')))
        check('Dependency-Track disabled', client.request('GET', '/api/v1/dependency-track/status')['enabled'] is False)
        service = client.request('POST', '/api/v1/services', data={'slug': 'advanced-' + unique, 'name': '고급 기능 실검증 ' + unique}, expected=201)
        environment = client.request('GET', '/api/v1/environments')[0]
        rule = {'id': 'cel-' + unique, 'name': '프로젝트 전용 KEV·수정버전 조건', 'kind': 'cel', 'target': 'vulnerability', 'expression': 'vulnerability.kev && size(vulnerability.fixedIn) > 0 && component.name == "log4j-core"', 'enabled': True, 'action': 'fail', 'values': [], 'serviceIds': [service['id']], 'environmentIds': [environment['id']], 'releaseVersions': ['1.0']}
        client.request('POST', '/api/v1/sbom-policies/validate', data={'expression': 'vulnerability.kev &&', 'target': 'vulnerability'}, expected=422)
        check('invalid real CEL rejected before save', True)
        valid = client.request('POST', '/api/v1/sbom-policies/validate', data={'expression': rule['expression'], 'target': 'vulnerability'})
        check('real CEL compile', valid['valid'], valid)
        policy = client.request('PUT', '/api/v1/sbom-policies', data={'expectedVersion': original['version'], 'rules': [rule], 'exceptions': []})
        fields = {'serviceId': service['id'], 'environmentId': environment['id'], 'releaseVersion': '1.0'}
        first = client.upload(base.make_bom('2.14.1', '4.17.20'), fields, idempotency_key=unique + '-1')
        check('upload accepted', bool(first.get('runId')), first)
        run_id = first['runId']
        # Upload response includes jobs; wait by polling the actual revision.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            before = detail(run_id)
            if before.get('analyses') and before['analyses'][0]['state'] in ('completed', 'failed'): break
            time.sleep(1)
        check('Grype real DB yields native scoped CEL violations', before['analysisMetrics']['policyFailCount'] >= 2, before)
        preview = client.request('POST', '/api/v1/sbom-policies/validate', data={'expression': rule['expression'], 'target': 'vulnerability', 'runId': run_id})
        check('CEL real-result preview', preview['matchCount'] >= 2, preview)
        other = client.upload(base.make_bom('2.14.1', '4.17.20'), {**fields, 'releaseVersion': '2.0'}, idempotency_key=unique + '-2')
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            scoped = detail(other['runId'])
            if scoped.get('analyses') and scoped['analyses'][0]['state'] in ('completed', 'failed'): break
            time.sleep(1)
        check('release scope excludes other project release', scoped['analysisMetrics']['policyViolationCount'] == 0, scoped['analysisMetrics'])
        target = {'component': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'vulnerabilityId': 'CVE-2021-44228', 'state': 'not_affected', 'justification': 'code_not_reachable', 'detail': '격리된 테스트 환경의 검토 증거: 이 테스트가 호출 경로 검토와 승인 분리를 확인합니다.', 'response': ['workaround_available'], 'expiresAt': (datetime.now(UTC) + timedelta(days=1)).isoformat()}
        review = client.request('POST', f'/api/v1/sbom-runs/{run_id}/reviews', data=target, expected=201)
        check('VEX initially submitted', review['status'] == 'submitted', review)
        client.request('POST', f'/api/v1/reviews/{review["id"]}/decision', data={'decision': 'approved', 'reason': 'self approval forbidden'}, expected=403)
        check('self approval denied', True)
        unchanged = analyze(run_id)
        check('unapproved review does not suppress', unchanged['analysisMetrics']['policyFailCount'] == before['analysisMetrics']['policyFailCount'])
        reviewer_password = secrets.token_urlsafe(24)
        reviewer_user = client.request('POST', '/api/v1/users', data={'username': 'advanced-reviewer-' + unique, 'password': reviewer_password, 'role': 'admin'}, expected=201)
        reviewer_id = reviewer_user['id']
        reviewer = base.Client(args.base_url)
        reviewer.login(reviewer_user['username'], reviewer_password)
        reviewer.request('POST', f'/api/v1/reviews/{review["id"]}/events', data={'comment': '독립 검토자로 근거 확인'}, expected=201)
        decision = reviewer.request('POST', f'/api/v1/reviews/{review["id"]}/decision', data={'decision': 'approved', 'reason': '독립 검토 승인: 정확한 구성요소 버전과 CVE 범위를 확인'})
        check('different reviewer approved', decision['status'] == 'approved')
        after = analyze(run_id)
        check('approved VEX suppresses CEL violation only on new revision', after['analysisMetrics']['policyFailCount'] == before['analysisMetrics']['policyFailCount'] - 1 and after['analysisMetrics']['vexSuppressedCount'] == 1, after)
        check('raw CVEs retained after VEX', after['analysisMetrics']['vulnerabilityCount'] == before['analysisMetrics']['vulnerabilityCount'])
        historic = next(a for a in after['analyses'] if a['id'] == before['analyses'][0]['id'])
        check('historical policy snapshot unchanged', historic['analysisMetrics']['policyFailCount'] == before['analysisMetrics']['policyFailCount'])
        vex = client.request('GET', f'/api/v1/sbom-runs/{run_id}/vex')
        check('CycloneDX VEX export', vex['specVersion'] == '1.6' and len(vex['vulnerabilities']) == 1, vex)
        imported = client.request('POST', f'/api/v1/sbom-runs/{run_id}/vex-import', data=vex, expected=201)
        check('VEX import remains unapproved', imported['imported'] == 1 and imported['items'][0]['status'] == 'submitted')
        events = client.request('GET', f'/api/v1/reviews/{review["id"]}/events')
        check('review audit events persisted', len(events['items']) >= 3, events)
        inbox = client.request('GET', '/api/v1/notifications?size=100')
        event = next(e for e in inbox['items'] if e['runId'] == run_id)
        client.request('POST', '/api/v1/notifications/' + event['id'] + '/read')
        check('inbox read receipt persists', next(e for e in client.request('GET', '/api/v1/notifications?size=100')['items'] if e['id'] == event['id'])['read'])
        # Scope this real test cycle to both retained rounds of this service.
        current = client.request('GET', '/api/v1/reanalysis-schedule')
        configured = client.request('PUT', '/api/v1/reanalysis-schedule', data={'expectedVersion': current['version'], 'enabled': True, 'intervalMinutes': 1440, 'onDataUpdate': True, 'latestOnly': False, 'serviceIds': [service['id']], 'environmentIds': []})
        cycle = client.request('POST', '/api/v1/reanalysis-schedule/run-now', data={}, expected=202)
        duplicate = client.request('POST', '/api/v1/reanalysis-schedule/run-now', data={}, expected=202)
        check('cycle deduplicates concurrent trigger', cycle['id'] == duplicate['id'])
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            completed = next(c for c in client.request('GET', '/api/v1/reanalysis-cycles')['items'] if c['id'] == cycle['id'])
            if completed['state'] in ('completed', 'partial'): break
            time.sleep(2)
        check('all stored SBOM cycle completed through real Grype worker', completed['state'] == 'completed' and completed['completedCount'] == 2, completed)
        report['evidence']['runId'] = run_id
        report['evidence']['otherRunId'] = other['runId']
        report['evidence']['serviceId'] = service['id']
        report['evidence']['cycleId'] = cycle['id']
        report['evidence']['policyVersion'] = policy['version']
    finally:
        current = client.request('GET', '/api/v1/sbom-policies')
        client.request('PUT', '/api/v1/sbom-policies', data={'expectedVersion': current['version'], 'rules': original['rules'], 'exceptions': original['exceptions']})
        current = client.request('GET', '/api/v1/reanalysis-schedule')
        client.request('PUT', '/api/v1/reanalysis-schedule', data={'expectedVersion': current['version'], **{key: schedule[key] for key in ('enabled', 'intervalMinutes', 'onDataUpdate', 'latestOnly', 'serviceIds', 'environmentIds')}})
        if reviewer_id: client.request('PATCH', '/api/v1/users/' + reviewer_id, data={'active': False})
        report['finishedAt'] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({'checks': len(report['checks']), 'output': str(args.output)}))

if __name__ == '__main__': main()
