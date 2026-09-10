from __future__ import annotations

import asyncio
import time

from sqlalchemy import select

from .db import SessionLocal
from .models import Job, JobState, ProcessingState, SbomRun
from .services import analyze_offline, sync_dependency_track


async def process_one() -> bool:
    with SessionLocal() as db:
        job = db.scalar(select(Job).where(Job.state == JobState.QUEUED).order_by(Job.created_at).with_for_update(skip_locked=True))
        if not job:
            return False
        job.state = JobState.RUNNING
        job.attempts += 1
        db.commit()
        run = db.get(SbomRun, job.run_id) if job.run_id else None
        try:
            if not run:
                raise RuntimeError("작업의 SBOM 회차가 존재하지 않습니다")
            if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
                raise RuntimeError("보관된 회차는 다시 처리할 수 없습니다")
            if job.kind in {"process_run", "analyze"}:
                analyze_offline(db, run)
            if job.kind in {"process_run", "sync_dependency_track"}:
                await sync_dependency_track(db, run)
            job.state = JobState.COMPLETED
            job.error = None
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = str(exc)[-2000:]
        db.commit()
        return True


def run() -> None:
    # Keep retention active for long-running workers; API startup pruning alone
    # would leave a continuously running installation past its 90-day window.
    from .main import _prune_scheduled_runs

    next_prune = 0.0
    while True:
        now = time.monotonic()
        if now >= next_prune:
            _prune_scheduled_runs()
            next_prune = now + 3600
        if not asyncio.run(process_one()):
            time.sleep(2)


if __name__ == "__main__":
    run()
