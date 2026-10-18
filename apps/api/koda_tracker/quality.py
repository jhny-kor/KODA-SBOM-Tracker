"""Offline SBOM quality diagnostics and immutable project-profile evidence."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import re
from urllib.parse import unquote

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base
from .models import SbomRun, new_id, now
from .project_catalog_models import NativeProject, ProjectRunLink
from .sbom import normalized_identity, parse_sbom_file

ENGINE_VERSION = '1'
DEFAULT_PROFILE = {'name': '기본 품질 기준', 'mode': 'warn', 'maxErrors': 0, 'maxWarnings': None,
                   'maxMissingIdentityRatio': 0.0, 'maxUnresolvedRefs': 0, 'maxAgeDays': 365}


class QualityProfile(Base):
    __tablename__ = 'sbom_quality_profiles'
    __table_args__ = (UniqueConstraint('scope_key', 'version'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scope_key: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class QualityRevision(Base):
    __tablename__ = 'sbom_quality_revisions'
    __table_args__ = (UniqueConstraint('run_id', 'sequence'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey('sbom_runs.id', ondelete='CASCADE'), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16))
    original_sha256: Mapped[str] = mapped_column(String(64))
    engine_version: Mapped[str] = mapped_column(String(32), default=ENGINE_VERSION)
    profile_snapshot: Mapped[dict] = mapped_column(JSON)
    summary: Mapped[dict] = mapped_column(JSON)
    comparison: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class QualityIssue(Base):
    __tablename__ = 'sbom_quality_issues'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    revision_id: Mapped[str] = mapped_column(ForeignKey('sbom_quality_revisions.id', ondelete='CASCADE'), index=True)
    ordinal: Mapped[int] = mapped_column(Integer)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    document: Mapped[dict] = mapped_column(JSON)


def iso(value):
    if value is None:
        return None
    return value.replace(tzinfo=UTC).isoformat() if value.tzinfo is None else value.isoformat()


def profile_payload(row: QualityProfile | None, project_id=None):
    return {**(row.document if row else DEFAULT_PROFILE), 'id': row.id if row else None,
            'projectId': project_id, 'version': row.version if row else 0,
            'createdAt': iso(row.created_at) if row else None}


def current_profile(db: Session, project_id: str | None = None):
    key = project_id or 'default'
    row = db.scalar(select(QualityProfile).where(QualityProfile.scope_key == key).order_by(QualityProfile.version.desc()).limit(1))
    return profile_payload(row, project_id)


def effective_profile(db: Session, run: SbomRun):
    link = db.get(ProjectRunLink, run.id)
    if link:
        project = db.get(NativeProject, link.project_id)
        candidates = [project] if project else []
    else:
        release = run.release
        candidates = list(db.scalars(select(NativeProject).where(
            NativeProject.service_id == release.service_id,
            NativeProject.environment_id == release.environment_id,
            NativeProject.version == release.version)))
    if len(candidates) == 1:
        candidate = current_profile(db, candidates[0].id)
        if candidate['version']:
            return candidate
    elif len(candidates) > 1:
        if any(current_profile(db, p.id)['version'] for p in candidates):
            raise ValueError('프로젝트 품질 기준의 소유가 모호합니다. 회차를 프로젝트에 명시적으로 연결하세요')
    return current_profile(db)


def revision_payload(row: QualityRevision):
    return {'id': row.id, 'runId': row.run_id, 'sequence': row.sequence, 'state': row.state,
            'originalSha256': row.original_sha256, 'engineVersion': row.engine_version,
            'normalizationVersion': 2, 'profileSnapshot': row.profile_snapshot, 'summary': row.summary,
            'comparison': row.comparison, 'error': row.error, 'createdAt': iso(row.created_at), 'createdBy': row.created_by}


def latest_revision(db: Session, run_id: str):
    return db.scalar(select(QualityRevision).where(QualityRevision.run_id == run_id).order_by(QualityRevision.sequence.desc()).limit(1))


def latest_quality(db: Session, run_id: str):
    row = latest_revision(db, run_id)
    return revision_payload(row) if row else None


def _date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except ValueError:
        return None


def diagnose(bom: dict, profile: dict, evaluated_at: datetime):
    """Return deterministic issues and measured denominators, never guessed values."""
    issues = []
    def issue(rule, severity, path, message, observed, expected, remediation, component=None):
        issues.append({'ruleId': rule, 'severity': severity, 'path': path,
                       'bomRef': component.get('bom-ref') if component else None,
                       'componentName': component.get('name') if component else None,
                       'message': message, 'observed': observed, 'expected': expected, 'remediation': remediation})
    def add(rule, severity, path, message, observed, expected, component=None):
        issue(rule, severity, path, message, observed, expected, '원본 SBOM 생성 설정과 해당 필드 값을 확인하고 다시 생성하세요', component)
    components = []
    stack = [(bom.get('components', []), '$.components')]
    while stack:
        nodes, path = stack.pop()
        if not isinstance(nodes, list):
            raise ValueError(path + '는 배열이어야 합니다')
        for index, component in enumerate(nodes):
            p = f'{path}[{index}]'
            if not isinstance(component, dict):
                raise ValueError(p + '는 객체여야 합니다')
            components.append((component, p))
            stack.append((component.get('components', []), p + '.components'))
    if not components:
        add('identity.empty', 'error', '$.components', '분석할 구성요소가 없습니다', 0, '하나 이상의 구성요소')
    identities = {}; refs = {}; missing_identity = missing_license = missing_hash = 0
    hash_sizes = {'MD5':32,'SHA-1':40,'SHA-256':64,'SHA-384':96,'SHA-512':128,'SHA3-256':64,'SHA3-384':96,'SHA3-512':128,'BLAKE2b-256':64,'BLAKE2b-384':96,'BLAKE2b-512':128,'BLAKE3':64}
    for c, p in components:
        for field in ('name', 'version'):
            if not isinstance(c.get(field), str) or not c[field].strip():
                add('identity.' + field + '_missing', 'warning', p + '.' + field, field + ' 값이 없습니다', c.get(field), '비어 있지 않은 문자열', c)
        purl, cpe, swid = c.get('purl'), c.get('cpe'), c.get('swid')
        valid_purl = isinstance(purl, str) and bool(re.fullmatch(r'pkg:[a-z][a-z0-9.+-]*/[^\s?#]+(?:\?[^\s#]*)?(?:#[^\s]*)?', purl)) and not re.search(r'%(?![0-9a-fA-F]{2})', purl)
        if valid_purl:
            coordinate = purl.split('?', 1)[0].split('#', 1)[0].split('/', 1)[1]
            final_name = coordinate.rsplit('/', 1)[-1]
            valid_purl = bool(final_name) and not final_name.endswith('@') and final_name.count('@') <= 1 and all(part not in {'', '.', '..'} for part in coordinate.split('/'))
        valid_cpe = isinstance(cpe, str) and ((cpe.startswith('cpe:2.3:') and len(re.split(r'(?<!\\):', cpe)) == 13 and re.split(r'(?<!\\):', cpe)[2] in {'a','h','o'} and all(re.split(r'(?<!\\):', cpe)[2:])) or bool(re.fullmatch(r'cpe:/[aho](?::[^\s]*){1,6}', cpe)))
        valid_swid = isinstance(swid, dict) and isinstance(swid.get('tagId'), str) and bool(swid['tagId'].strip()) and isinstance(swid.get('name'), str) and bool(swid['name'].strip())
        if not any((valid_purl, valid_cpe, valid_swid)):
            missing_identity += 1
            add('identity.missing', 'warning', p, '사용 가능한 패키지 식별자가 없습니다', None, '올바른 PURL, CPE 또는 SWID', c)
        if purl and not valid_purl:
            add('identity.purl_invalid', 'error', p + '.purl', 'PURL 구문이 올바르지 않습니다', purl, 'Package URL', c)
        if cpe and not valid_cpe:
            add('identity.cpe_invalid', 'error', p + '.cpe', 'CPE 구문이 올바르지 않습니다', cpe, 'CPE 2.2 URI 또는 2.3 formatted string', c)
        if swid and not valid_swid:
            add('identity.swid_invalid', 'error', p + '.swid', 'SWID 식별 정보가 올바르지 않습니다', swid, 'tagId와 name이 있는 SWID 객체', c)
        if valid_purl:
            coordinate = purl.split('?',1)[0].split('#',1)[0]
            pos = coordinate.rfind('@')
            if pos > coordinate.rfind('/') and c.get('version') and unquote(coordinate[pos+1:]) != str(c['version']):
                add('identity.version_conflict', 'error', p + '.purl', 'PURL과 구성요소 버전이 다릅니다', unquote(coordinate[pos+1:]), c['version'], c)
        identity = (normalized_identity(c)[0], str(c.get('version') or ''))
        if identity in identities:
            add('identity.duplicate', 'warning', p, '같은 패키지 좌표가 중복됩니다', identity, '의도한 중복인지 확인', c)
        identities[identity] = p
        ref = c.get('bom-ref')
        if ref:
            if ref in refs:
                add('graph.duplicate_ref', 'error', p + '.bom-ref', 'bom-ref가 중복됩니다', ref, '문서 내 유일한 bom-ref', c)
            refs[ref] = p
        licenses = c.get('licenses') or []
        known = False
        from .legacy_policy import _spdx
        for index, entry in enumerate(licenses):
            if not isinstance(entry, dict):
                add('license.invalid', 'error', f'{p}.licenses[{index}]', '라이선스 형식이 올바르지 않습니다', entry, 'license 또는 expression', c)
                continue
            expression = entry.get('expression')
            license_value = entry.get('license') or {}
            value = expression or license_value.get('id') or license_value.get('name')
            if value and str(value).lower() not in {'unknown','noassertion','none','unlicensed','unspecified'}:
                known = True
            if expression:
                try:
                    _spdx(expression)
                except (ValueError, TypeError):
                    known = False
                    add('license.expression_invalid', 'error', f'{p}.licenses[{index}].expression', '라이선스 표현식 문법 오류', expression, 'SPDX 표현식 문법', c)
        if not known:
            missing_license += 1
            add('license.missing', 'warning', p + '.licenses', '확인 가능한 라이선스가 없습니다', licenses, '라이선스 ID/이름/표현식', c)
        hashes = c.get('hashes') or []
        if not hashes:
            missing_hash += 1
            add('integrity.hash_missing', 'warning', p + '.hashes', '구성요소 해시가 없습니다', None, '검증 가능한 알고리즘과 해시', c)
        seen_hash = {}
        for index, h in enumerate(hashes):
            if not isinstance(h, dict):
                add('integrity.hash_invalid','error', f'{p}.hashes[{index}]','해시 형식 오류',h,'alg/content 객체',c);continue
            alg, content = h.get('alg'), h.get('content')
            if alg not in hash_sizes or not isinstance(content, str) or len(content) != hash_sizes.get(alg) or not re.fullmatch(r'[0-9a-fA-F]+', content):
                add('integrity.hash_invalid','error',f'{p}.hashes[{index}]','해시 알고리즘 또는 값 형식 오류',h,'지원 알고리즘의 정확한 16진수 길이',c)
            normalized_content = content.lower() if isinstance(content, str) else content
            if alg in seen_hash:
                add('integrity.hash_conflict' if seen_hash[alg] != normalized_content else 'integrity.hash_duplicate','error' if seen_hash[alg] != normalized_content else 'warning',f'{p}.hashes[{index}]','동일 알고리즘 해시 중복/상충',h,'알고리즘별 하나의 해시',c)
            seen_hash[alg] = normalized_content
    metadata = bom.get('metadata') or {}
    root = metadata.get('component') or {}
    if root.get('bom-ref'):
        if root['bom-ref'] in refs:
            add('graph.duplicate_ref','error','$.metadata.component.bom-ref','루트 bom-ref가 중복됩니다',root['bom-ref'],'문서 내 유일한 bom-ref')
        refs[root['bom-ref']] = '$.metadata.component'
    dependencies = bom.get('dependencies')
    unresolved = 0
    graph = {}; edge_count = 0
    if not dependencies:
        add('graph.missing','warning','$.dependencies','의존성 그래프가 없습니다',dependencies,'구성요소 관계 그래프')
    for index, dep in enumerate(dependencies or []):
        if not isinstance(dep, dict) or not isinstance(dep.get('dependsOn', []), list):
            raise ValueError('의존성 항목은 ref와 dependsOn 배열을 가진 객체여야 합니다')
        origin = dep.get('ref')
        targets = dep.get('dependsOn', [])
        graph.setdefault(origin, set()).update(targets)
        for field, ref in [('ref',origin), *[(f'dependsOn[{i}]',r) for i,r in enumerate(targets)]]:
            if ref not in refs:
                unresolved += 1
                add('graph.unresolved_ref','error',f'$.dependencies[{index}].{field}','존재하지 않는 구성요소 참조',ref,'문서에 존재하는 bom-ref')
        edge_count += len(targets)
    # Iterative color DFS avoids recursion limits on large valid graphs.
    colors = {}; cyclic = False
    for start in graph:
        if colors.get(start):
            continue
        colors[start] = 1; todo = [(start, iter(graph.get(start, ())))]
        while todo:
            node, children = todo[-1]
            nxt = next(children, None)
            if nxt is None:
                colors[node] = 2; todo.pop();continue
            if colors.get(nxt) == 1:
                cyclic = True
            elif not colors.get(nxt):
                colors[nxt] = 1;todo.append((nxt, iter(graph.get(nxt, ()))))
    if cyclic:
        add('graph.cycle','warning','$.dependencies','의존성 순환이 있습니다',True,'생태계의 허용 여부 확인')
    if dependencies and root.get('bom-ref'):
        reached = set(); todo = [root['bom-ref']]
        while todo:
            node = todo.pop()
            if node not in reached:
                reached.add(node);todo.extend(graph.get(node, ()))
        disconnected = len(set(refs) - reached)
        if disconnected:
            add('graph.disconnected','warning','$.dependencies','루트와 연결되지 않은 구성요소가 있습니다',disconnected,0)
    timestamp = metadata.get('timestamp'); parsed = _date(timestamp)
    if parsed is None:
        add('provenance.timestamp_missing' if timestamp is None else 'provenance.timestamp_invalid','warning','$.metadata.timestamp','생성 시각이 없거나 시간대 포함 형식이 아닙니다',timestamp,'시간대가 포함된 ISO 8601')
    elif parsed > evaluated_at:
        add('provenance.timestamp_future','warning','$.metadata.timestamp','생성 시각이 미래입니다',timestamp,'현재 시각 이하')
    elif (evaluated_at - parsed).total_seconds() > profile['maxAgeDays'] * 86400:
        add('provenance.stale','warning','$.metadata.timestamp','SBOM이 신선도 기준을 초과합니다',timestamp,f"{profile['maxAgeDays']}일 이내")
    def meaningful(value):
        if isinstance(value, dict):
            return any(meaningful(v) for v in value.values())
        if isinstance(value, list):
            return any(meaningful(v) for v in value)
        return isinstance(value, str) and bool(value.strip())
    for field, present in [('tools',meaningful(metadata.get('tools'))),('authors',meaningful(metadata.get('authors'))),('supplier',meaningful(root.get('supplier') or metadata.get('supplier')))]:
        if not present:
            add('provenance.' + field + '_missing','warning','$.metadata.' + field,'출처 정보가 없습니다',None,field)
    if not bom.get('serialNumber'):
        add('provenance.serial_missing','warning','$.serialNumber','문서 식별자가 없습니다',None,'serialNumber')
    errors = sum(i['severity']=='error' for i in issues); warnings = len(issues)-errors
    count = len(components); ratio = missing_identity/count if count else None
    violations = errors > profile['maxErrors'] or (profile['maxWarnings'] is not None and warnings > profile['maxWarnings']) or (ratio is not None and ratio > profile['maxMissingIdentityRatio']) or unresolved > profile['maxUnresolvedRefs']
    status = 'fail' if violations and profile['mode']=='enforce' else 'warn' if violations or issues else 'pass'
    return issues, {'componentCount':count,'errorCount':errors,'warningCount':warnings,'missingIdentityCount':missing_identity,
                    'missingIdentityRatio':ratio,'missingLicenseCount':missing_license,'missingHashCount':missing_hash,
                    'unresolvedRefCount':unresolved,'edgeCount':edge_count,'score':None,'qualityStatus':status,'state':'completed',
                    'criteriaViolated':violations,'fieldStatus':{'identity':'available' if count else 'not_applicable',
                    'graph':'available' if dependencies else 'missing','timestamp':'available' if parsed else 'missing' if timestamp is None else 'invalid',
                    'integrity':'declared_only','license':'syntax_only'}}


def evaluate_quality(db: Session, run: SbomRun, actor='worker', force=False):
    # Serialize sequence allocation with the same run lock as normal analysis.
    db.scalar(select(SbomRun.id).where(SbomRun.id == run.id).with_for_update())
    prior = latest_revision(db, run.id)
    profile = current_profile(db)
    error = None
    try:
        profile = effective_profile(db, run)
        if not force and prior and prior.state == 'completed' and prior.engine_version == ENGINE_VERSION and prior.original_sha256 == run.sha256 and prior.profile_snapshot == profile:
            return prior
        bom = run.normalized_bom
        from pathlib import Path
        import hashlib
        artifact = Path(run.artifact_path)
        source_basis = 'stored_normalized_json'
        if 'xml' in run.media_type or artifact.exists():
            with artifact.open('rb') as source:
                actual_sha256 = hashlib.file_digest(source, 'sha256').hexdigest()
            if actual_sha256 != run.sha256:
                raise ValueError('원본 SBOM SHA-256 불일치')
            bom, _ = parse_sbom_file(artifact)
            source_basis = 'verified_original_artifact'
        issues, summary = diagnose(bom, profile, now())
        summary['sourceBasis'] = source_basis
        state = 'completed'
    except Exception as exc:
        issues = []; state = 'failed'; error = str(exc)[:2000]
        summary = {'state':'failed','qualityStatus':'failed','componentCount':None,'errorCount':None,'warningCount':None,'missingIdentityRatio':None,'unresolvedRefCount':None,'score':None}
    comparison = None
    comparison_prior = prior
    if comparison_prior is None:
        previous_run = db.scalar(select(SbomRun).where(SbomRun.release_id == run.release_id, SbomRun.round_number < run.round_number).order_by(SbomRun.round_number.desc()).limit(1))
        comparison_prior = latest_revision(db, previous_run.id) if previous_run else None
    if comparison_prior and state == 'completed' and comparison_prior.state == 'completed':
        comparison = {'previousRevisionId':comparison_prior.id,'previousRunId':comparison_prior.run_id,'errorDelta':summary['errorCount']-comparison_prior.summary['errorCount'],'warningDelta':summary['warningCount']-comparison_prior.summary['warningCount']}
    row = QualityRevision(run_id=run.id, sequence=(prior.sequence if prior else 0)+1, state=state, original_sha256=run.sha256,
                          engine_version=ENGINE_VERSION,profile_snapshot=profile,summary=summary,comparison=comparison,error=error,created_by=actor)
    db.add(row);db.flush()
    db.add_all([QualityIssue(revision_id=row.id,ordinal=i,rule_id=issue['ruleId'],severity=issue['severity'],document=issue) for i,issue in enumerate(issues)])
    db.flush()
    return row
