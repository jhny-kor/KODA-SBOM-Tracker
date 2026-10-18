"""Native project scopes and optional forward-only source synchronization.

The catalog can be edited after the source server has been retired. Run links are
separate so editing tags/parents/latest never rewrites historical SBOM evidence.
"""
from __future__ import annotations
import copy
from datetime import UTC, datetime, timedelta
import uuid
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from .config import get_settings
from .models import AuditEvent, Job, JobState, ProcessingState, Release, SbomRun, SbomPolicyRevision, now
from .project_catalog_models import NativeProject, ProjectRunLink, ProjectSyncSource, ProjectSyncEvent, NativeReanalysisPending


class CatalogError(ValueError):
    pass


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def tags_of(values: list) -> list[str]:
    if not isinstance(values, list) or len(values) > 100:
        raise CatalogError("태그는 최대 100개입니다")
    result = []
    for value in values:
        tag = value.get("name") if isinstance(value, dict) else value
        if not isinstance(tag, str) or not tag.strip() or len(tag) > 255:
            raise CatalogError("태그 형식이 올바르지 않습니다")
        result.append(tag.strip())
    return sorted(set(result))


def validate_hierarchy(projects: list[dict]) -> None:
    parents = {p["id"]: p.get("parent") for p in projects}
    for identity in parents:
        visited = set()
        current = identity
        while current is not None:
            if current in visited:
                raise CatalogError("프로젝트 부모 계층에 순환이 있습니다")
            visited.add(current)
            if len(visited) > 1000:
                raise CatalogError("프로젝트 계층 깊이가 제한을 초과했습니다")
            current = parents.get(current)


def upsert_source_projects(db: Session, bundle: dict, plan: dict) -> list[NativeProject]:
    """Called before imported revisions are evaluated, inside import transaction."""
    source_id = bundle["source"]["id"]
    existing = {p.source_project_id: p for p in db.scalars(select(NativeProject).where(NativeProject.source_id == source_id))}
    incoming = {}
    for item in bundle["projects"]:
        project = item["project"]
        parent = project.get("parent")
        parent = parent.get("uuid") if isinstance(parent, dict) else parent
        incoming[project["uuid"]] = {"name": str(project.get("name") or project["uuid"])[:255], "version": str(project.get("version") or "unversioned")[:255], "parent_project_id": parent, "tags": tags_of(project.get("tags") or []), "is_latest": project.get("isLatest") is True, "active": project.get("active") is not False}
    complete = bundle["source"].get("projectSnapshotComplete") is True
    if complete:
        # A complete source snapshot may retire absent projects. Partial/older
        # bundles never infer deletion from an omitted project.
        for values in incoming.values():
            if values["parent_project_id"] not in incoming:
                values["parent_project_id"] = None
        for identity, project in existing.items():
            if identity not in incoming:
                if project.active or project.is_latest or project.parent_project_id is not None:
                    db.add(AuditEvent(actor="source-sync", action="project_catalog.source_retire", target_type="project", target_id=project.id, detail={"sourceId": source_id, "sourceProjectId": identity, "previous": project_payload(project)}))
                    project.active, project.is_latest, project.parent_project_id = False, False, None
                    project.revision += 1
    validate_hierarchy([{"id": k, "parent": incoming.get(k, {}).get("parent_project_id", p.parent_project_id)} for k, p in existing.items()] + [{"id": k, "parent": v["parent_project_id"]} for k, v in incoming.items() if k not in existing])
    result = []
    for identity, values in incoming.items():
        target = plan[identity]
        project = existing.get(identity)
        if project is None:
            project = NativeProject(id=str(uuid.uuid5(uuid.NAMESPACE_URL, "koda-project:" + source_id + ":" + identity)), source_id=source_id, source_project_id=identity, service_id=target["serviceId"], environment_id=target["environmentId"], revision=1, **values)
            db.add(project)
        else:
            changed = any(getattr(project, k) != v for k, v in values.items()) or project.current_run_id != target["runId"]
            for key, value in values.items():
                setattr(project, key, value)
            if changed:
                project.revision += 1
        project.current_run_id = target["runId"]
        # Release creation happens later in apply_migration; resolve lazily.
        from .migration import _id
        existing_run = db.get(SbomRun, target["runId"])
        project.release_id = existing_run.release_id if existing_run else _id(source_id, "release", identity + ":" + (values["version"] or "unversioned"))
        link = db.get(ProjectRunLink, target["runId"])
        if link is None:
            db.add(ProjectRunLink(run_id=target["runId"], project_id=project.id))
        elif link.project_id != project.id:
            raise CatalogError("동일한 회차를 여러 프로젝트에 연결할 수 없습니다")
        result.append(project)
    latest_names = [p.name for p in result if p.is_latest]
    if len(latest_names) != len(set(latest_names)):
        raise CatalogError("같은 프로젝트 이름에 최신 버전이 여러 개 지정되었습니다")
    for p in result:
        if p.is_latest:
            set_latest(db, p, True)
    db.flush()
    return result


def project_for_run(db: Session, run_id: str) -> NativeProject | None:
    link = db.get(ProjectRunLink, run_id)
    if link:
        return db.get(NativeProject, link.project_id)
    run = db.get(SbomRun, run_id)
    if run is None:
        return None
    release = db.get(Release, run.release_id)
    if release is None:
        return None
    # New ordinary uploads in an already catalogued release inherit that project.
    candidates = list(db.scalars(select(NativeProject).where(NativeProject.service_id == release.service_id, NativeProject.environment_id == release.environment_id, NativeProject.version == release.version).limit(2)))
    return candidates[0] if len(candidates) == 1 else None


def catalog_context_for_run(db: Session, run_id: str) -> dict | None:
    project = project_for_run(db, run_id)
    if project is None:
        return None
    ancestors, seen, parent = [], {project.source_project_id}, project.parent_project_id
    while parent and parent not in seen and len(seen) <= 1000:
        ancestors.append(parent)
        seen.add(parent)
        node = db.scalar(select(NativeProject).where(NativeProject.source_id == project.source_id, NativeProject.source_project_id == parent))
        parent = node.parent_project_id if node else None
    run = db.get(SbomRun, run_id)
    release = db.get(Release, run.release_id) if run else None
    version = release.version if release else project.version
    return {**project_payload(project), "projectId": project.source_project_id, "ancestorIds": ancestors,
            "catalogVersion": project.version, "version": version,
            "isLatest": project.is_latest and version == project.version}


def project_context_for_run(db: Session, run_id: str) -> dict | None:
    return catalog_context_for_run(db, run_id)


def project_scope_matches(scope: dict, context: dict | None) -> bool:
    if not context or context.get("sourceId") != scope.get("sourceId") or not context.get("active", True):
        return False
    if (scope.get("onlyLatest") or scope.get("latestOnly")) and not context.get("isLatest"):
        return False
    assigned, tags = set(scope.get("projectIds") or []), set(scope.get("tags") or [])
    applies = not assigned and not tags or context.get("projectId") in assigned or bool(tags.intersection(context.get("tags") or []))
    return applies or bool(scope.get("includeChildren") and assigned.intersection(context.get("ancestorIds") or []))


def scoped_run_matches(db: Session, run_id: str, scope: dict) -> bool:
    return project_scope_matches(scope, catalog_context_for_run(db, run_id))


def project_payload(p: NativeProject) -> dict:
    return {"id": p.id, "sourceId": p.source_id, "sourceProjectId": p.source_project_id, "serviceId": p.service_id, "environmentId": p.environment_id, "releaseId": p.release_id, "currentRunId": p.current_run_id, "name": p.name, "version": p.version, "parentProjectId": p.parent_project_id, "tags": p.tags, "isLatest": p.is_latest, "active": p.active, "revision": p.revision, "updatedAt": utc(p.updated_at).isoformat() if p.updated_at else None}


def link_run(db: Session, project: NativeProject, run: SbomRun) -> None:
    release = db.get(Release, run.release_id)
    if release is None or (release.service_id, release.environment_id, release.version) != (project.service_id, project.environment_id, project.version):
        raise CatalogError("프로젝트와 회차의 서비스·환경·버전이 다릅니다")
    old = db.get(ProjectRunLink, run.id)
    if old and old.project_id != project.id:
        raise CatalogError("다른 프로젝트에 이미 연결된 회차입니다")
    if old is None:
        db.add(ProjectRunLink(run_id=run.id, project_id=project.id))
    project.release_id, project.current_run_id = release.id, run.id


def set_latest(db: Session, project: NativeProject, value: bool) -> None:
    if value:
        for other in db.scalars(select(NativeProject).where(NativeProject.source_id == project.source_id, NativeProject.name == project.name, NativeProject.id != project.id).with_for_update()):
            if other.is_latest:
                other.is_latest = False
                other.revision += 1
    project.is_latest = value


def _fernet() -> Fernet:
    key = get_settings().ldap_encryption_key.strip()
    if not key:
        raise CatalogError("암호화 키 TRACKER_LDAP_ENCRYPTION_KEY가 필요합니다")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise CatalogError("암호화 키 형식이 올바르지 않습니다") from exc


def encrypt_key(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode("ascii")


def decrypt_key(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode()
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise CatalogError("저장한 원본 인증정보를 현재 암호화 키로 읽을 수 없습니다") from exc


def sync_payload(s: ProjectSyncSource) -> dict:
    return {"id": s.id, "name": s.name, "baseUrl": s.base_url, "allowedOrigins": s.allowed_origins, "projectUuids": s.project_uuids, "sourceTimeZone": s.source_timezone, "sourceId": s.source_id, "credentialConfigured": bool(s.key_ciphertext), "enabled": s.enabled, "intervalMinutes": s.interval_minutes, "version": s.version, "state": s.state, "attempts": s.attempts, "nextRunAt": utc(s.next_run_at).isoformat() if s.next_run_at else None, "lastSuccessAt": utc(s.last_success_at).isoformat() if s.last_success_at else None, "lastError": s.last_error, "lastMigrationId": s.last_migration_id}


def _check_local_policy_conflicts(db: Session, source_id: str, current: SbomPolicyRevision) -> None:
    from .migration_models import LegacyObjectMap
    rules = {r["id"]: r for r in (current.document.get("rules") or [])} if current else {}
    for mapping in db.scalars(select(LegacyObjectMap).where(LegacyObjectMap.source_id == source_id, LegacyObjectMap.object_type == "policy")):
        expected = mapping.provenance.get("rule")
        if rules.get(mapping.target_id) != expected:
            raise CatalogError("KODA에서 변경하거나 삭제한 원본 정책이 있어 자동 덮어쓰기를 중단했습니다")



def request_native_reanalysis(db: Session, source_id: str, run_ids: list[str], *, reason: str = "source_sync", at: datetime | None = None) -> int:
    """Persist reanalysis intent in the same transaction as imported changes."""
    at = at or now()
    count = 0
    for run_id in sorted(set(run_ids)):
        run = db.scalar(select(SbomRun).where(SbomRun.id == run_id).with_for_update(skip_locked=True))
        if run is None:
            # A locked, existing run is still eligible; the drainer retries it.
            if db.get(SbomRun, run_id) is None:
                continue
        elif run.archived_at or run.state == ProcessingState.ARCHIVED:
            continue
        item = db.get(NativeReanalysisPending, (source_id, run_id))
        if item is None:
            db.add(NativeReanalysisPending(source_id=source_id, run_id=run_id, requested_at=at, reason=reason))
        else:
            item.requested_at, item.reason = at, reason
        if run is not None:
            running = db.scalar(select(Job.id).where(Job.run_id == run_id, Job.kind.in_(["analyze", "process_run"]), Job.state == JobState.RUNNING).limit(1))
            run.analysis_state = JobState.RUNNING if running else JobState.QUEUED
            run.state = ProcessingState.PROCESSING if running else ProcessingState.QUEUED
        count += 1
    db.flush()
    return count


def drain_native_reanalysis(db: Session, *, batch_size: int = 25) -> int:
    """Move bounded durable intents to worker jobs, without dropping full queues.

    An already RUNNING job may have read the old catalog, so intent remains until
    it finishes. A QUEUED analysis has not consumed inputs and can safely satisfy
    the latest intent under its row lock. Missing/archived runs are terminal.
    """
    capacity = max(0, get_settings().max_queued_jobs - (db.scalar(select(func.count()).select_from(Job).where(Job.state.in_([JobState.QUEUED, JobState.RUNNING]))) or 0))
    pending = list(db.scalars(select(NativeReanalysisPending).order_by(NativeReanalysisPending.requested_at, NativeReanalysisPending.run_id).with_for_update(skip_locked=True).limit(batch_size)))
    enqueued = 0
    for item in pending:
        run = db.scalar(select(SbomRun).where(SbomRun.id == item.run_id).with_for_update(skip_locked=True))
        if run is None:
            if db.get(SbomRun, item.run_id) is None:
                db.delete(item)
            continue
        if run.archived_at or run.state == ProcessingState.ARCHIVED:
            db.delete(item)
            continue
        active = list(db.scalars(select(Job).where(Job.run_id == run.id, Job.kind.in_(["analyze", "process_run"]), Job.state.in_([JobState.QUEUED, JobState.RUNNING])).with_for_update(skip_locked=True)))
        if any(job.state == JobState.RUNNING for job in active):
            run.analysis_state, run.state = JobState.RUNNING, ProcessingState.PROCESSING
            continue
        queued = next((job for job in active if job.state == JobState.QUEUED), None)
        if queued is None:
            # A worker may own an active job row skipped by the lock query.
            if db.scalar(select(Job.id).where(Job.run_id == run.id, Job.kind.in_(["analyze", "process_run"]), Job.state.in_([JobState.QUEUED, JobState.RUNNING])).limit(1)):
                continue
            if not capacity:
                run.analysis_state, run.state = JobState.QUEUED, ProcessingState.QUEUED
                continue
            queued = Job(kind="analyze", run_id=run.id, payload={})
            db.add(queued)
            capacity -= 1
        request = {"sourceId": item.source_id, "requestedAt": utc(item.requested_at).isoformat(), "reason": item.reason}
        payload = queued.payload or {}
        requests = {value["sourceId"]: value for value in payload.get("sourceSyncRequests", []) if isinstance(value, dict) and value.get("sourceId")}
        if isinstance(payload.get("sourceSync"), dict) and payload["sourceSync"].get("sourceId"):
            requests.setdefault(payload["sourceSync"]["sourceId"], payload["sourceSync"])
        requests[item.source_id] = request
        queued.payload = {**payload, "sourceSync": request, "sourceSyncRequests": [requests[key] for key in sorted(requests)]}
        run.analysis_state, run.state = JobState.QUEUED, ProcessingState.QUEUED
        db.delete(item)
        # Production sessions disable autoflush. Make this job visible to the
        # next pending source for the same run inside this transaction.
        db.flush()
        enqueued += 1
    db.flush()
    return enqueued


def _source_reanalysis_runs(db: Session, source_id: str) -> list[str]:
    projects = select(NativeProject.id).where(NativeProject.source_id == source_id)
    linked = list(db.scalars(select(ProjectRunLink.run_id).where(ProjectRunLink.project_id.in_(projects))))
    # Include ordinary uploads automatically associated with a catalog release.
    ordinary = list(db.scalars(select(SbomRun.id).join(Release, Release.id == SbomRun.release_id).join(NativeProject, (NativeProject.service_id == Release.service_id) & (NativeProject.environment_id == Release.environment_id) & (NativeProject.version == Release.version)).where(NativeProject.source_id == source_id)))
    return sorted(set(linked + ordinary))

def project_sync_tick(db: Session, *, at: datetime | None = None) -> dict | None:
    """Run one durable sync. Call with a dedicated Session, not an API transaction.

    A committed 10-minute lease prevents duplicate exporters; failed workers are
    reclaimable after lease expiry. Up to five transient failures back off, while
    semantic and local-policy conflicts need an explicit administrator retry.
    """
    from .migration import LegacyExporter, MigrationError, apply_migration, stage_bundle
    from .policies import get_policy_document
    at = at or now()
    # Flush pending imports even when sources are disabled/not due. Requests are
    # durable independently of the next periodic export or connector lifetime.
    drain_native_reanalysis(db)
    db.commit()
    source = db.scalar(select(ProjectSyncSource).where(ProjectSyncSource.enabled.is_(True), ProjectSyncSource.next_run_at <= at, or_(ProjectSyncSource.state != "running", ProjectSyncSource.lease_until <= at)).order_by(ProjectSyncSource.next_run_at).with_for_update(skip_locked=True).limit(1))
    if source is None:
        return None
    if source.state == "running":
        for interrupted in db.scalars(select(ProjectSyncEvent).where(ProjectSyncEvent.source_id == source.id, ProjectSyncEvent.state == "running")):
            interrupted.state, interrupted.finished_at = "failed", at
            interrupted.detail = {"error": "동기화 작업 임대가 만료되어 재시도합니다"}
        if source.attempts >= 5:
            source.state, source.lease_until, source.next_run_at = "failed", None, None
            source.last_error = "동기화 작업 임대 만료 재시도 한도를 초과했습니다"
            db.commit()
            return sync_payload(source)
    source.state, source.lease_until = "running", at + timedelta(minutes=10)
    source.attempts += 1
    event = ProjectSyncEvent(source_id=source.id, attempt=source.attempts, started_at=at)
    db.add(event)
    db.flush()
    source_id, event_id, lease = source.id, event.id, source.lease_until
    db.commit()
    key = ""
    exporter = None
    try:
        key = decrypt_key(source.key_ciphertext)
        exporter = LegacyExporter(source.base_url, key, source.allowed_origins, source_timezone=source.source_timezone)
        bundle = exporter.export(source.project_uuids)
        db.expire_all()
        source = db.scalar(select(ProjectSyncSource).where(ProjectSyncSource.id == source_id).with_for_update())
        if not source or source.state != "running" or utc(source.lease_until) != utc(lease):
            raise CatalogError("동기화 임대 또는 설정이 변경되었습니다")
        if source.source_id and source.source_id != bundle["source"]["id"]:
            raise CatalogError("원본 시스템 식별자가 이전 수집과 다릅니다")
        # Hold the same policy revision lock used by policy mutations from
        # baseline comparison through apply. Never re-read a newer revision and
        # accidentally accept a concurrent local edit as an import baseline.
        policy = db.scalar(select(SbomPolicyRevision).order_by(SbomPolicyRevision.version.desc()).limit(1).with_for_update())
        if policy is None:
            policy = get_policy_document(db)
        policy_version = policy.version
        _check_local_policy_conflicts(db, bundle["source"]["id"], policy)
        batch = stage_bundle(db, bundle, source.actor_name)
        db.flush()
        if not batch.report["canApply"]:
            # Persist the blocked source bundle and report for human review.
            source.last_migration_id = batch.id
            source.state, source.lease_until, source.next_run_at = "blocked", None, None
            source.last_error = "원본 정책 변환 검사에서 적용 차단 사유가 발견되었습니다"
            event = db.get(ProjectSyncEvent, event_id)
            event.state, event.finished_at, event.migration_id = "blocked", at, batch.id
            event.detail = {"blockers": batch.report["blockers"]}
            db.commit()
            return sync_payload(source)
        source_identity = bundle["source"]["id"]
        before_catalog = {p.id: p.revision for p in db.scalars(select(NativeProject).where(NativeProject.source_id == source_identity))}
        already_applied = getattr(batch, "state", None) == "applied"
        applied = apply_migration(db, batch.id, expected_digest=batch.digest, expected_policy_version=policy_version, actor=source.actor_name, actor_id=source.actor_id, trust_source_reviews=False)
        if already_applied:
            # Manual bundle apply stays immutable/idempotent. An explicit source
            # poll is authoritative for mutable catalog state even when its
            # previously applied bundle bytes are unchanged.
            upsert_source_projects(db, applied.bundle, applied.report["projectPlan"])
        after_catalog = {p.id: p.revision for p in db.scalars(select(NativeProject).where(NativeProject.source_id == source_identity))}
        changed_catalog = before_catalog != after_catalog
        changed_policies = not already_applied and applied.result.get("policyVersion", policy_version) != policy_version
        changed_analysis = not already_applied and applied.result.get("analysisRevisionsCreated", 0) > 0
        affected = _source_reanalysis_runs(db, source_identity) if changed_catalog or changed_policies else applied.result.get("runIds", []) if changed_analysis else []
        native_pending = request_native_reanalysis(db, source_identity, affected, at=at)
        native_queued = drain_native_reanalysis(db)
        source.source_id = source_identity
        source.last_migration_id, source.last_success_at = applied.id, at
        source.state, source.attempts, source.lease_until, source.last_error = "idle", 0, None, None
        source.next_run_at = at + timedelta(minutes=source.interval_minutes)
        event = db.get(ProjectSyncEvent, event_id)
        event.state, event.finished_at, event.migration_id, event.detail = "completed", at, applied.id, {"result": copy.deepcopy(applied.result), "nativeReanalysisRequested": native_pending, "nativeReanalysisEnqueued": native_queued}
        db.commit()
        return sync_payload(source)
    except Exception as exc:
        db.rollback()
        source = db.scalar(select(ProjectSyncSource).where(ProjectSyncSource.id == source_id).with_for_update())
        event = db.get(ProjectSyncEvent, event_id)
        if source and source.state == "running" and source.lease_until and utc(source.lease_until) == utc(lease):
            source.last_error = str(exc).replace(key, "[redacted]")[:2000] if key else str(exc)[:2000]
            terminal = isinstance(exc, CatalogError) or source.attempts >= 5
            source.state = "blocked" if isinstance(exc, CatalogError) else "failed" if terminal else "retrying"
            source.lease_until = None
            source.next_run_at = None if terminal else at + timedelta(seconds=min(3600, 60 * 2 ** (source.attempts - 1)))
            event.state, event.finished_at, event.detail = source.state, at, {"error": source.last_error}
            db.commit()
        return sync_payload(source) if source else None
    finally:
        if exporter:
            exporter.close()


def main() -> None:
    import time
    from .db import SessionLocal
    while True:
        with SessionLocal() as db:
            project_sync_tick(db)
        time.sleep(5)


if __name__ == "__main__":
    main()
