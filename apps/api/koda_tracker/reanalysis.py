"""Durable, bounded reanalysis of stored SBOMs; independent of Dependency-Track."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from sqlalchemy import JSON, Boolean, DateTime, Integer, String, func, insert, literal, select
from sqlalchemy.orm import Mapped, Session, mapped_column
from .db import Base
from .models import Job, JobState, ProcessingState, Release, SbomRun, new_id, now
from .config import get_settings
from .vulnerability import active_bundle


class ReanalysisSchedule(Base):
    __tablename__ = 'reanalysis_schedule'
    id: Mapped[str] = mapped_column(String(16), primary_key=True, default='default')
    version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    on_data_update: Mapped[bool] = mapped_column(Boolean, default=True)
    latest_only: Mapped[bool] = mapped_column(Boolean, default=False)
    service_ids: Mapped[list] = mapped_column(JSON, default=list)
    environment_ids: Mapped[list] = mapped_column(JSON, default=list)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_data_revision: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rerun_requested: Mapped[bool] = mapped_column(Boolean, default=False)


class ReanalysisCycle(Base):
    __tablename__ = 'reanalysis_cycles'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # A nullable unique key is the cross-process single-active-cycle guard.
    active_key: Mapped[str | None] = mapped_column(String(16), unique=True, nullable=True)
    reason: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(16), default='queued')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReanalysisTask(Base):
    __tablename__ = 'reanalysis_tasks'
    cycle_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # Keep audit references without preventing deletion of an upload/job.
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    state: Mapped[str] = mapped_column(String(16), default='pending', index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def get_schedule(db: Session) -> ReanalysisSchedule:
    item = db.get(ReanalysisSchedule, 'default')
    if item is None:
        item = ReanalysisSchedule(id='default', next_run_at=now() + timedelta(days=1))
        db.add(item)
        db.flush()
    return item


def active_cycle(db: Session) -> ReanalysisCycle | None:
    return db.scalar(select(ReanalysisCycle).where(ReanalysisCycle.active_key == 'default'))


def start_cycle(db: Session, schedule: ReanalysisSchedule, reason: str, *, at: datetime | None = None) -> ReanalysisCycle:
    at = at or now()
    existing = active_cycle(db)
    if existing:
        return existing
    cycle = ReanalysisCycle(reason=reason, created_at=at, active_key='default')
    db.add(cycle)
    db.flush()
    candidates = select(SbomRun.id).join(Release).where(SbomRun.archived_at.is_(None), SbomRun.state != ProcessingState.ARCHIVED)
    if schedule.service_ids:
        candidates = candidates.where(Release.service_id.in_(schedule.service_ids))
    if schedule.environment_ids:
        candidates = candidates.where(Release.environment_id.in_(schedule.environment_ids))
    if schedule.latest_only:
        latest = select(SbomRun.release_id, func.max(SbomRun.round_number).label('round')).where(SbomRun.archived_at.is_(None), SbomRun.state != ProcessingState.ARCHIVED).group_by(SbomRun.release_id).subquery()
        candidates = candidates.join(latest, (latest.c.release_id == SbomRun.release_id) & (latest.c.round == SbomRun.round_number))
    ids = candidates.subquery()
    db.execute(insert(ReanalysisTask).from_select(['cycle_id', 'run_id', 'state'], select(literal(cycle.id), ids.c.id, literal('pending'))))
    schedule.last_run_at = at
    schedule.next_run_at = at + timedelta(minutes=schedule.interval_minutes) if schedule.enabled else None
    return cycle


def cycle_payload(db: Session, cycle: ReanalysisCycle) -> dict:
    counts = dict(db.execute(select(ReanalysisTask.state, func.count()).where(ReanalysisTask.cycle_id == cycle.id).group_by(ReanalysisTask.state)).all())
    return {'id': cycle.id, 'reason': cycle.reason, 'state': cycle.state, 'createdAt': utc(cycle.created_at).isoformat(), 'finishedAt': utc(cycle.finished_at).isoformat() if cycle.finished_at else None, 'totalCount': sum(counts.values()), **{f'{key}Count': counts.get(key, 0) for key in ('pending', 'enqueued', 'completed', 'failed', 'skipped')}}


def schedule_payload(db: Session, schedule: ReanalysisSchedule) -> dict:
    cycle = active_cycle(db)
    return {'version': schedule.version, 'enabled': schedule.enabled, 'intervalMinutes': schedule.interval_minutes, 'onDataUpdate': schedule.on_data_update, 'latestOnly': schedule.latest_only, 'serviceIds': schedule.service_ids, 'environmentIds': schedule.environment_ids, 'nextRunAt': utc(schedule.next_run_at).isoformat() if schedule.next_run_at else None, 'lastRunAt': utc(schedule.last_run_at).isoformat() if schedule.last_run_at else None, 'activeCycle': cycle_payload(db, cycle) if cycle else None}


def recover_analysis_jobs(db: Session, *, at: datetime | None = None) -> int:
    at = at or now()
    jobs = list(db.scalars(select(Job).where(Job.kind.in_(['analyze', 'process_run']), Job.state == JobState.RUNNING, Job.updated_at < at - timedelta(minutes=15)).with_for_update(skip_locked=True).limit(100)))
    for job in jobs:
        run = db.scalar(select(SbomRun).where(SbomRun.id == job.run_id).with_for_update(skip_locked=True)) if job.run_id else None
        if run is None and job.run_id and db.scalar(select(SbomRun.id).where(SbomRun.id == job.run_id)):
            continue
        job.state = JobState.FAILED if job.attempts >= 3 else JobState.QUEUED
        job.error = '분석 작업 임대가 만료되었습니다' if job.state == JobState.FAILED else None
        job.updated_at = at
        if run is not None:
            run.analysis_state = job.state
            run.state = ProcessingState.FAILED if job.state == JobState.FAILED else ProcessingState.QUEUED
        if job.state == JobState.FAILED:
            from .workflows import notify_job_failure
            notify_job_failure(db, job, run)
    return len(jobs)


def scheduler_tick(db: Session, *, data_revision: str | None = None, at: datetime | None = None, batch_size: int = 25) -> None:
    at = at or now()
    schedule = db.scalar(select(ReanalysisSchedule).where(ReanalysisSchedule.id == 'default').with_for_update(skip_locked=True))
    if schedule is None:
        return
    recover_analysis_jobs(db, at=at)
    if data_revision is None:
        bundle = active_bundle(get_settings())
        data_revision = f'{bundle.version}:{bundle.manifest_sha256}' if bundle else 'unavailable'
    changed = schedule.last_data_revision is not None and schedule.last_data_revision != data_revision
    schedule.last_data_revision = data_revision
    cycle = active_cycle(db)
    if changed and schedule.enabled and schedule.on_data_update:
        schedule.rerun_requested = True
    due = schedule.enabled and schedule.next_run_at is not None and utc(schedule.next_run_at) <= at
    if cycle is None and (schedule.rerun_requested or due):
        cycle = start_cycle(db, schedule, 'data_update' if schedule.rerun_requested else 'scheduled', at=at)
        schedule.rerun_requested = False
    if cycle is None:
        return
    # Refresh enqueued tasks in bounded batches, using SQL joins for terminal jobs.
    terminal = list(db.execute(select(ReanalysisTask, Job.state).outerjoin(Job, Job.id == ReanalysisTask.job_id).where(ReanalysisTask.cycle_id == cycle.id, ReanalysisTask.state == 'enqueued', (Job.state.in_([JobState.COMPLETED, JobState.FAILED])) | Job.id.is_(None)).limit(batch_size * 4)))
    for task, state in terminal:
        task.state = 'completed' if state == JobState.COMPLETED else 'failed' if state == JobState.FAILED else 'skipped'
    capacity = max(0, get_settings().max_queued_jobs - (db.scalar(select(func.count()).select_from(Job).where(Job.state.in_([JobState.QUEUED, JobState.RUNNING]))) or 0))
    busy = select(Job.id).where(Job.run_id == ReanalysisTask.run_id, Job.state.in_([JobState.QUEUED, JobState.RUNNING])).exists()
    tasks = list(db.scalars(select(ReanalysisTask).where(ReanalysisTask.cycle_id == cycle.id, ReanalysisTask.state == 'pending', ~busy).limit(min(batch_size, capacity))))
    for task in tasks:
        run = db.scalar(select(SbomRun).where(SbomRun.id == task.run_id).with_for_update(skip_locked=True))
        if run is None:
            # A locked row is deferred; a deleted row is terminal.
            if db.scalar(select(SbomRun.id).where(SbomRun.id == task.run_id)) is None:
                task.state = 'skipped'
            continue
        # Recheck after the run lock: a manual request may have committed after
        # candidate selection and before this lock was acquired.
        if db.scalar(select(Job.id).where(Job.run_id == run.id, Job.state.in_([JobState.QUEUED, JobState.RUNNING])).limit(1)):
            continue
        if run.archived_at or run.state == ProcessingState.ARCHIVED:
            task.state = 'skipped'
            continue
        job = Job(kind='analyze', run_id=run.id, payload={'reanalysisCycleId': cycle.id})
        db.add(job)
        db.flush()
        task.job_id, task.state = job.id, 'enqueued'
        run.analysis_state, run.state = JobState.QUEUED, ProcessingState.QUEUED
    db.flush()
    remaining = db.scalar(select(func.count()).select_from(ReanalysisTask).where(ReanalysisTask.cycle_id == cycle.id, ReanalysisTask.state.in_(['pending', 'enqueued'])))
    if not remaining:
        failed = db.scalar(select(func.count()).select_from(ReanalysisTask).where(ReanalysisTask.cycle_id == cycle.id, ReanalysisTask.state == 'failed'))
        cycle.state, cycle.finished_at, cycle.active_key = 'partial' if failed else 'completed', at, None
    else:
        cycle.state = 'running'
