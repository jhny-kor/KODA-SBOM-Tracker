from types import SimpleNamespace
from koda_tracker.main import get_run_findings


def test_kev_cvss_severity_component_order_before_pagination():
    findings = [
        dict(canonicalId='CVE-2026-0001', component='z', cvssScore=9.9, severity='critical'),
        dict(canonicalId='CVE-2026-0002', component='b', cvssScore=7, severity='high', kev=True),
        dict(canonicalId='CVE-2026-0003', component='a', cvssScore='7.0', severity='high', kev=True),
        dict(canonicalId='CVE-2026-0004', component='c', cvssScore=7, severity='critical', kev=True),
        dict(canonicalId='CVE-2026-0005', component='x', cvssScore=None, severity='critical', kev=True),
    ]
    revision = SimpleNamespace(id='analysis', findings=findings)
    db = SimpleNamespace(get=lambda *args: object(), scalar=lambda *args: revision)
    pages = [get_run_findings('run', analysis_id=None, page=p, size=2, db=db) for p in (1,2,3)]
    assert [f['canonicalId'] for page in pages for f in page['items']] == [
        'CVE-2026-0004', 'CVE-2026-0003', 'CVE-2026-0002', 'CVE-2026-0005', 'CVE-2026-0001']
    assert pages[0]['total'] == 5
