from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from koda_tracker.db import Base
from koda_tracker.models import Environment, Job, JobState, ProcessingState, Release, SbomRun, Service
from koda_tracker import reanalysis, workflow_models  # register notification tables before isolated create_all
from koda_tracker.reanalysis import ReanalysisCycle, ReanalysisTask, active_cycle, cycle_payload, get_schedule, recover_analysis_jobs, scheduler_tick, start_cycle, utc

AT = datetime(2030, 1, 1, tzinfo=UTC)


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(reanalysis, "get_settings", lambda: SimpleNamespace(max_queued_jobs=100))
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def schedule(db):
    item = get_schedule(db)
    item.enabled = False
    item.next_run_at = None
    db.flush()
    return item


def release(db, suffix="a"):
    service = Service(slug=f"service-{suffix}", name=suffix)
    environment = Environment(slug=f"env-{suffix}", name=suffix)
    db.add_all([service, environment])
    db.flush()
    item = Release(service_id=service.id, environment_id=environment.id, version="1")
    db.add(item)
    db.flush()
    return item


def run(db, rel, round_number=1, **kwargs):
    item = SbomRun(release_id=rel.id, round_number=round_number, state=ProcessingState.COMPLETED, analysis_state=JobState.COMPLETED, original_filename="bom.json", media_type="application/json", spec_version="1.6", sha256="a" * 64, size_bytes=2, artifact_path="/tmp/unused-bom.json", normalized_bom={}, **kwargs)
    db.add(item)
    db.flush()
    return item


def tick(db, **kwargs):
    scheduler_tick(db, at=AT, data_revision="db-1", **kwargs)
    db.flush()


def tasks(db, cycle):
    return list(db.scalars(select(ReanalysisTask).where(ReanalysisTask.cycle_id == cycle.id)))


def finish_cycle_jobs(db, cycle, data_revision="db-1"):
    for task in tasks(db, cycle):
        if task.job_id:
            db.get(Job, task.job_id).state = JobState.COMPLETED
    db.flush()
    scheduler_tick(db, at=AT, data_revision=data_revision)
    db.flush()


def test_all_rounds_default_excludes_both_archive_forms_and_honors_scopes(db):
    item = schedule(db)
    first, second = release(db), release(db, "b")
    old, latest = run(db, first, 1), run(db, first, 2)
    archived = run(db, first, 3, archived_at=AT)
    archived_state = run(db, first, 4)
    archived_state.state = ProcessingState.ARCHIVED
    unrelated = run(db, second)
    item.service_ids = [first.service_id]
    item.environment_ids = [first.environment_id]
    cycle = start_cycle(db, item, "manual")
    assert {task.run_id for task in tasks(db, cycle)} == {old.id, latest.id}
    assert not item.latest_only
    assert not {archived.id, archived_state.id, unrelated.id}.intersection(task.run_id for task in tasks(db, cycle))


def test_latest_only_means_latest_unarchived_round_per_release(db):
    item = schedule(db)
    item.latest_only = True
    first, second = release(db), release(db, "b")
    run(db, first, 1)
    latest = run(db, first, 2)
    run(db, first, 3, archived_at=AT)
    other = run(db, second, 1)
    cycle = start_cycle(db, item, "manual")
    assert {task.run_id for task in tasks(db, cycle)} == {latest.id, other.id}


def test_queue_backpressure_and_busy_run_are_deferred_without_duplicate_job(db, monkeypatch):
    item = schedule(db)
    rel = release(db)
    busy, available = run(db, rel, 1), run(db, rel, 2)
    existing = Job(kind="analyze", run_id=busy.id, state=JobState.RUNNING, updated_at=AT)
    db.add(existing)
    db.flush()
    monkeypatch.setattr(reanalysis, "get_settings", lambda: SimpleNamespace(max_queued_jobs=1))
    cycle = start_cycle(db, item, "manual")
    tick(db)
    assert {task.state for task in tasks(db, cycle)} == {"pending"}
    existing.state = JobState.COMPLETED
    db.flush()
    tick(db)
    assert sum(task.state == "enqueued" for task in tasks(db, cycle)) == 1
    tick(db)
    assert len(list(db.scalars(select(Job)))) == 2
    assert cycle.state == "running"


def test_busy_run_deferral_does_not_starve_other_pending_work(db):
    item = schedule(db)
    rel = release(db)
    busy, available = run(db, rel, 1), run(db, rel, 2)
    db.add(Job(kind="process_run", run_id=busy.id, state=JobState.QUEUED))
    db.flush()
    cycle = start_cycle(db, item, "manual")
    tick(db, batch_size=1)
    states = {task.run_id: task.state for task in tasks(db, cycle)}
    assert states == {busy.id: "pending", available.id: "enqueued"}


def test_single_active_cycle_and_run_dedup_are_database_guarded(db):
    item = schedule(db)
    run(db, release(db))
    first = start_cycle(db, item, "manual")
    assert start_cycle(db, item, "scheduled") is first
    assert len(tasks(db, first)) == 1
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(ReanalysisCycle(active_key="default", reason="manual"))
            db.flush()
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(ReanalysisTask(cycle_id=first.id, run_id=tasks(db, first)[0].run_id))
            db.flush()
    tick(db)
    tick(db)
    assert len(list(db.scalars(select(Job)))) == 1


def test_terminal_jobs_and_deleted_jobs_reconcile_to_completed_partial_and_skipped(db):
    item = schedule(db)
    rel = release(db)
    for number in range(1, 4):
        run(db, rel, number)
    cycle = start_cycle(db, item, "manual")
    tick(db)
    items = tasks(db, cycle)
    db.get(Job, items[0].job_id).state = JobState.COMPLETED
    db.get(Job, items[1].job_id).state = JobState.FAILED
    db.delete(db.get(Job, items[2].job_id))
    db.flush()
    tick(db)
    assert {task.state for task in tasks(db, cycle)} == {"completed", "failed", "skipped"}
    assert cycle.state == "partial" and cycle.active_key is None and cycle.finished_at == AT
    payload = cycle_payload(db, cycle)
    assert payload["totalCount"] == 3 and payload["failedCount"] == payload["skippedCount"] == 1


def test_deleted_or_newly_archived_pending_runs_are_skipped(db):
    item = schedule(db)
    rel = release(db)
    deleted, archived = run(db, rel, 1), run(db, rel, 2)
    cycle = start_cycle(db, item, "manual")
    db.delete(deleted)
    archived.archived_at = AT
    db.flush()
    tick(db)
    assert {task.state for task in tasks(db, cycle)} == {"skipped"}
    assert cycle.state == "completed" and active_cycle(db) is None


def test_periodic_due_data_changes_coalesce_to_one_followup_cycle(db):
    item = schedule(db)
    item.enabled = item.on_data_update = True
    item.next_run_at = AT
    item.last_data_revision = "db-0"
    run(db, release(db))
    tick(db)
    first = active_cycle(db)
    assert first.reason == "data_update"
    scheduler_tick(db, at=AT, data_revision="db-2")
    scheduler_tick(db, at=AT, data_revision="db-3")
    db.flush()
    assert active_cycle(db) is first and item.rerun_requested
    finish_cycle_jobs(db, first, "db-3")
    assert first.state == "completed"
    scheduler_tick(db, at=AT, data_revision="db-3")
    db.flush()
    second = active_cycle(db)
    assert second and second.id != first.id and second.reason == "data_update"
    assert not item.rerun_requested
    finish_cycle_jobs(db, second, "db-3")
    scheduler_tick(db, at=AT, data_revision="db-3")
    db.flush()
    assert active_cycle(db) is None
    assert len(list(db.scalars(select(ReanalysisCycle)))) == 2


def test_unchanged_data_disabled_updates_and_not_due_do_not_start_cycles(db):
    item = schedule(db)
    item.enabled = True
    item.next_run_at = AT + timedelta(minutes=1)
    tick(db)
    tick(db)
    assert active_cycle(db) is None
    item.on_data_update = False
    scheduler_tick(db, at=AT, data_revision="db-2")
    db.flush()
    assert not item.rerun_requested and active_cycle(db) is None
    item.enabled = False
    item.on_data_update = True
    scheduler_tick(db, at=AT, data_revision="db-3")
    db.flush()
    assert not item.rerun_requested and active_cycle(db) is None


def test_due_schedule_and_empty_cycle_complete_without_queueing(db):
    item = schedule(db)
    item.enabled = True
    item.next_run_at = AT - timedelta(seconds=1)
    tick(db)
    cycle = db.scalar(select(ReanalysisCycle))
    assert cycle.reason == "scheduled" and cycle.state == "completed"
    assert utc(item.next_run_at) > AT
    assert not list(db.scalars(select(Job)))


def test_expired_running_analysis_leases_retry_until_three_attempts(db):
    schedule(db)
    stale = AT - timedelta(minutes=16)
    retry = Job(kind="analyze", state=JobState.RUNNING, attempts=2, updated_at=stale, error="old")
    failed = Job(kind="process_run", state=JobState.RUNNING, attempts=3, updated_at=stale)
    recent = Job(kind="analyze", state=JobState.RUNNING, attempts=1, updated_at=AT - timedelta(minutes=14))
    unrelated = Job(kind="sync_dtrack", state=JobState.RUNNING, attempts=1, updated_at=stale)
    db.add_all([retry, failed, recent, unrelated])
    db.flush()
    assert recover_analysis_jobs(db, at=AT) == 2
    assert retry.state == JobState.QUEUED and retry.error is None
    assert failed.state == JobState.FAILED and "임대" in failed.error
    assert recent.state == unrelated.state == JobState.RUNNING
    assert retry.updated_at == AT
    assert recover_analysis_jobs(db, at=AT) == 0


def test_exhausted_lease_updates_run_analysis_state(db):
    schedule(db)
    item = run(db, release(db))
    item.state, item.analysis_state = ProcessingState.PROCESSING, JobState.RUNNING
    db.add(Job(kind="analyze", run_id=item.id, state=JobState.RUNNING, attempts=3, updated_at=AT - timedelta(minutes=16)))
    db.flush()
    recover_analysis_jobs(db, at=AT)
    assert item.analysis_state == JobState.FAILED
    assert item.state in {ProcessingState.FAILED, ProcessingState.PARTIAL}


def test_schedule_api_version_scope_validation_and_disable_clears_followup(db):
    from koda_tracker.reanalysis_api import ScheduleRequest, update_schedule
    item = schedule(db)
    rel = release(db)
    principal = SimpleNamespace(username="admin")
    values = {"expectedVersion": item.version, "enabled": True, "intervalMinutes": 30, "serviceIds": [rel.service_id], "environmentIds": [rel.environment_id]}
    with pytest.raises(HTTPException) as error:
        update_schedule(ScheduleRequest(**{**values, "expectedVersion": 999}), db, principal, None)
    assert error.value.status_code == 409
    with pytest.raises(HTTPException) as error:
        update_schedule(ScheduleRequest(**{**values, "serviceIds": ["missing"]}), db, principal, None)
    assert error.value.status_code == 422
    result = update_schedule(ScheduleRequest(**values), db, principal, None)
    assert result["enabled"] and result["version"] == 2 and result["intervalMinutes"] == 30
    assert result["serviceIds"] == [rel.service_id] and result["nextRunAt"]
    item.rerun_requested = True
    result = update_schedule(ScheduleRequest(**{**values, "expectedVersion": 2, "enabled": False}), db, principal, None)
    assert not result["enabled"] and result["nextRunAt"] is None and not item.rerun_requested


def test_manual_enqueue_between_candidate_selection_and_run_lock_is_deferred(db, monkeypatch):
    item = schedule(db)
    current = run(db, release(db))
    cycle = start_cycle(db, item, "manual")
    original_scalar = db.scalar
    manual_job = None

    def enqueue_at_run_lock(statement, *args, **kwargs):
        nonlocal manual_job
        descriptions = getattr(statement, "column_descriptions", [])
        if manual_job is None and descriptions and descriptions[0].get("entity") is SbomRun:
            # Reproduce a manual request committed after the pending candidate
            # query, immediately before the scheduler acquires this run's lock.
            manual_job = Job(kind="analyze", run_id=current.id, state=JobState.QUEUED)
            db.add(manual_job)
            db.flush()
        return original_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(db, "scalar", enqueue_at_run_lock)
    tick(db)
    assert manual_job is not None
    jobs = list(db.scalars(select(Job).where(Job.run_id == current.id)))
    assert len(jobs) == 1 and jobs[0].id == manual_job.id
    task = tasks(db, cycle)[0]
    assert task.state == "pending" and task.job_id is None
    manual_job.state = JobState.COMPLETED
    db.flush()
    tick(db)
    assert task.state == "enqueued" and task.job_id != manual_job.id


@pytest.mark.parametrize(("kind", "state"), [("analyze", JobState.QUEUED), ("process_run", JobState.RUNNING)])
def test_manual_analysis_api_reuses_existing_analysis_job(db, monkeypatch, kind, state):
    from koda_tracker import main
    current = run(db, release(db))
    existing = Job(kind=kind, run_id=current.id, state=state)
    db.add(existing)
    db.flush()
    monkeypatch.setattr(main, "get_settings", lambda: SimpleNamespace(max_queued_jobs=0))
    response = main.create_analysis(current.id, db, SimpleNamespace(username="admin"), None)
    assert response == {"jobId": existing.id, "runId": current.id}
    assert len(list(db.scalars(select(Job)))) == 1


def test_manual_analysis_api_honors_global_queue_capacity(db, monkeypatch):
    from koda_tracker import main
    current = run(db, release(db))
    db.add(Job(kind="data_update", state=JobState.QUEUED))
    db.flush()
    monkeypatch.setattr(main, "get_settings", lambda: SimpleNamespace(max_queued_jobs=1))
    with pytest.raises(HTTPException) as error:
        main.create_analysis(current.id, db, SimpleNamespace(username="admin"), None)
    assert error.value.status_code == 429
    assert len(list(db.scalars(select(Job)))) == 1
    assert current.analysis_state == JobState.COMPLETED
