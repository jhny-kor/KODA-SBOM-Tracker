"""Native project scopes and durable analysis intents preserve SBOM history."""
from __future__ import annotations
from datetime import UTC, datetime
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from .collection_metrics import collection_config
from .config import get_settings
from .models import Job, JobState, ProcessingState, Release, SbomRun, now
from .project_catalog_models import NativeProject, ProjectRunLink, NativeReanalysisPending


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
    return {**collection_config(p), "id": p.id, "sourceId": p.source_id, "sourceProjectId": p.source_project_id, "serviceId": p.service_id, "environmentId": p.environment_id, "releaseId": p.release_id, "currentRunId": p.current_run_id, "name": p.name, "version": p.version, "parentProjectId": p.parent_project_id, "tags": p.tags, "isLatest": p.is_latest, "active": p.active, "revision": p.revision, "updatedAt": utc(p.updated_at).isoformat() if p.updated_at else None}


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
    from .data_updates import reference_import_allowed
    try: reference_import_allowed(get_settings())
    except ValueError: return 0
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
