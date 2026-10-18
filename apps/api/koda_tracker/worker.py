from __future__ import annotations

import asyncio
import argparse
import fcntl
import logging
import time
from pathlib import Path

from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal
from .models import Job, JobState, ProcessingState, SbomRun
from .services import analyze_offline, sync_dependency_track

DATA_UPDATE_KINDS = {"data_update", "vulnerability_data_update"}


async def process_data_update_one() -> bool:
    """Process only administrator-enqueued offline data update jobs."""
    from .config import get_settings
    from .data_updates import DataUpdateEngine, Package, _metadata, _validate_tree

    with SessionLocal() as db:
        job = db.scalar(select(Job).where(Job.state == JobState.QUEUED, Job.kind.in_(DATA_UPDATE_KINDS)).order_by(Job.created_at).with_for_update(skip_locked=True))
        if not job:
            return False
        job.state = JobState.RUNNING
        job.attempts += 1
        db.commit()
        try:
            payload = job.payload or {}
            action = payload.get("action", "validate")
            kind = payload.get("kind")
            engine = DataUpdateEngine(get_settings())
            if kind not in {"grype-db", "vuln-data"}:
                raise RuntimeError("데이터 갱신 작업의 종류가 없습니다")
            if action == "validate":
                archive = payload.get("archive")
                if not archive:
                    raise RuntimeError("검증할 파일이 없습니다")
                package = engine.stage(archive, kind, expected_base_version=payload.get("expectedBaseVersion"))
                next_payload = dict(payload)
                next_payload.update({"phase": "validated", "stagedRoot": str(package.root), "version": package.version, "manifestSha256": package.manifest_sha256, "dataAsOf": package.metadata.get("DATASET_DATE", package.metadata.get("NVD_DATASET_DATE"))})
                next_payload.pop("archive", None)
                job.payload = next_payload
            elif action == "apply":
                staged = Path(str(payload.get("stagedRoot", ""))).resolve()
                staging_root = (engine.root / "staging").resolve()
                if payload.get("phase") == "applying":
                    current = engine.current()
                    if current and _metadata(current.path / "metadata.env").get("DATA_UPDATE_JOB_ID") == job.id:
                        job.payload = {**payload, "phase": "applied", "releaseVersion": current.version}
                        job.state = JobState.COMPLETED
                        job.error = None
                        db.commit()
                        return True
                if staging_root not in staged.parents or not staged.is_dir():
                    raise RuntimeError("검증된 스테이징 경로가 없습니다")
                metadata, digest = _validate_tree(staged, kind)
                if payload.get("manifestSha256") and digest != payload["manifestSha256"]:
                    raise RuntimeError("검증 후 스테이징 패키지 매니페스트가 변경되었습니다")
                metadata[f"{kind.upper().replace('-', '_')}_VERSION"] = payload.get("version") or metadata["BUNDLE_VERSION"]
                package = Package(kind, metadata["BUNDLE_VERSION"], staged, metadata, digest)
                job.payload = {**payload, "phase": "applying"}
                db.commit()
                release = engine.apply(package, expected_base_version=payload.get("expectedBaseVersion"), job_id=job.id)
                job.payload = {**job.payload, "phase": "applied", "releaseVersion": release.version}
            elif action == "rollback":
                current = engine.current()
                if payload.get("phase") == "applying" and current and _metadata(current.path / "metadata.env").get("DATA_UPDATE_JOB_ID") == job.id:
                    job.payload = {**payload, "phase": "applied", "releaseVersion": current.version}
                    job.state = JobState.COMPLETED
                    job.error = None
                    db.commit()
                    return True
                job.payload = {**payload, "phase": "applying"}
                db.commit()
                release = engine.rollback(kind, version=payload.get("version"), job_id=job.id)
                job.payload = {**job.payload, "phase": "applied", "releaseVersion": release.version}
            else:
                raise RuntimeError("알 수 없는 데이터 갱신 작업입니다")
            job.state = JobState.COMPLETED
            job.error = None
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = str(exc)[-2000:]
        db.commit()
        if action == "validate" and payload.get("archive"):
            archive = Path(str(payload["archive"]))
            spool = get_settings().data_update_spool_dir.resolve()
            if spool in archive.resolve().parents:
                archive.unlink(missing_ok=True)
        return True


def recover_data_update_jobs() -> int:
    """Requeue abandoned jobs after a worker restart; active jobs are untouched."""
    with SessionLocal() as db:
        jobs = list(db.scalars(select(Job).where(Job.kind.in_(DATA_UPDATE_KINDS), Job.state == JobState.RUNNING)))
        for job in jobs:
            job.state = JobState.QUEUED
        db.commit()
        return len(jobs)


async def process_one() -> bool:
    with SessionLocal() as db:
        job = db.scalar(select(Job).where(Job.state == JobState.QUEUED, ~Job.kind.in_(DATA_UPDATE_KINDS)).order_by(Job.created_at).with_for_update(skip_locked=True))
        if not job:
            return False
        job.state = JobState.RUNNING
        job.attempts += 1
        db.commit()
        # Serialize revisions and archive/delete operations on this run across
        # worker processes; different runs can still be analyzed concurrently.
        run = db.scalar(select(SbomRun).where(SbomRun.id == job.run_id).with_for_update()) if job.run_id else None
        try:
            if not run:
                raise RuntimeError("작업의 SBOM 회차가 존재하지 않습니다")
            if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
                raise RuntimeError("보관된 회차는 다시 처리할 수 없습니다")
            revision = None
            if job.kind in {"process_run", "analyze"}:
                revision = analyze_offline(db, run)
            if job.kind in {"process_run", "sync_dependency_track"} and get_settings().dependency_track_enabled:
                await sync_dependency_track(db, run)
            if revision is not None and (revision.state == JobState.FAILED or revision.policy_state == "failed"):
                job.state = JobState.FAILED
                job.error = revision.error or revision.policy_error
            else:
                job.state = JobState.COMPLETED
                job.error = None
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = str(exc)[-2000:]
            if run is not None:
                run.analysis_state, run.state = JobState.FAILED, ProcessingState.FAILED
            from .workflows import notify_job_failure
            notify_job_failure(db, job, run)
        db.commit()
        return True


def run(*, data_updates: bool = False) -> None:
    # Keep retention active for long-running workers; API startup pruning alone
    # would leave a continuously running installation past its 90-day window.
    from .main import _prune_scheduled_runs

    next_prune = 0.0
    next_scheduler = 0.0
    updater_lock = None
    if data_updates:
        from .config import get_settings
        from .data_updates import DataUpdateEngine
        # Process ownership and activation use different locks: apply takes the latter.
        updater_lock = open(DataUpdateEngine(get_settings()).root / ".updater-worker.lock", "a+")
        fcntl.flock(updater_lock.fileno(), fcntl.LOCK_EX)
        recover_data_update_jobs()
    try:
        while True:
            now = time.monotonic()
            if not data_updates and now >= next_prune:
                _prune_scheduled_runs()
                next_prune = now + 3600
            if not data_updates and now >= next_scheduler:
                from .reanalysis import scheduler_tick
                from .workflows import deliver_notifications
                for maintenance in (scheduler_tick, deliver_notifications):
                    try:
                        with SessionLocal() as db:
                            maintenance(db)
                            db.commit()
                    except Exception:
                        logging.getLogger(__name__).exception("Native workflow maintenance failed")
                next_scheduler = now + 10
            if data_updates:
                did_work = asyncio.run(process_data_update_one())
            else:
                did_work = asyncio.run(process_one())
            if not did_work:
                time.sleep(2)
    finally:
        if updater_lock is not None:
            updater_lock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-updates", action="store_true", help="run the isolated vulnerability-data updater")
    run(data_updates=parser.parse_args().data_updates)
