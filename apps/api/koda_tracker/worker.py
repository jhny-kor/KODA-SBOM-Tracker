from __future__ import annotations

import asyncio
import argparse
import fcntl
import logging
import time
from pathlib import Path
from contextlib import ExitStack

from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal
from .models import Job, JobState, ProcessingState, SbomRun
from .services import analyze_offline
from .sbom_normalization import prepare_run, normalization_tick

DATA_UPDATE_KINDS = {"data_update", "vulnerability_data_update"}


def _reset_unified_live_references(db):
    from sqlalchemy import delete
    from .offline_intelligence_models import OfflineReferenceCurrent
    from .vulnerability_intelligence_models import VulnerabilityIntelligence, IntelligenceCursor
    from .package_metadata_models import PackageMetadataCache, PackageMetadataCursor
    # An approved unified release is authoritative for live external evidence.
    # Immutable imported snapshots and every operational history remain intact.
    for model in (OfflineReferenceCurrent,VulnerabilityIntelligence,IntelligenceCursor,PackageMetadataCache,PackageMetadataCursor):
        db.execute(delete(model))
    db.flush()


def _sync_bundle_epss(db, root):
    from .data_updates import _metadata
    from .epss_snapshot import parse_snapshot, import_snapshot
    metadata = _metadata(root / "metadata.env")
    filename = metadata.get("EPSS_SNAPSHOT")
    if filename:
        intelligence = root / "intelligence.json"
        if intelligence.is_file():
            import json
            if (json.loads(intelligence.read_text()).get("datasets") or {}).get("epss"):
                return  # The unified source carries its own stricter per-source TTL.
        info, rows = parse_snapshot((root / filename).read_bytes())
        import_snapshot(db, info, rows, actor="verified-unified-bundle")


async def process_data_update_one() -> bool:
    """Process only administrator-enqueued offline data update jobs."""
    from .config import get_settings
    from .data_updates import DataUpdateEngine, Package, _metadata, _validate_tree
    from .offline_intelligence_store import sync_reference_bundle

    with SessionLocal() as db, ExitStack() as leases:
        job = db.scalar(select(Job).where(Job.state == JobState.QUEUED, Job.kind.in_(DATA_UPDATE_KINDS)).order_by(Job.created_at).with_for_update(skip_locked=True))
        if not job:
            return False
        job.state = JobState.RUNNING
        job.attempts += 1
        db.commit()
        activated = None
        write_access = None
        engine = None
        action = None
        payload = {}
        try:
            payload = job.payload or {}
            action = payload.get("action", "validate")
            kind = payload.get("kind")
            engine = DataUpdateEngine(get_settings())
            if kind not in {"grype-db", "vuln-data", "unified"}:
                raise RuntimeError("데이터 갱신 작업의 종류가 없습니다")
            if action in {"apply", "rollback", "purge"}:
                if db.scalar(select(Job.id).where(Job.kind.in_(["analyze", "process_run"]), Job.state == JobState.RUNNING).limit(1)):
                    raise RuntimeError("분석이 진행 중입니다. 완료 후 데이터 작업을 재시도하십시오")
                write_access = engine.exclusive_access()
                leases.enter_context(write_access)
            if action == "purge":
                from .data_updates import purge_reference_database
                from .offline_intelligence_store import active_reference_document, reference_manifest
                from .models import AuditEvent
                from shutil import rmtree
                current = engine.current()
                expected = payload.get("expectedBaseVersion")
                marker = engine.root / ".managed.json"
                if expected is not None and (current is None or current.version != expected):
                    # A retried purge already removed the matching release only
                    # when the persisted marker identifies this exact job.
                    from .data_updates import managed_state
                    if (managed_state(get_settings()) or {}).get("jobId") != job.id:
                        raise RuntimeError("현재 데이터가 변경되었습니다. 상태를 새로 조회하십시오")
                evidence = reference_manifest(active_reference_document(db, _include_unavailable=True))
                engine.write_managed("purging", job_id=job.id)
                result = purge_reference_database(db, job_id=job.id)
                engine.purge_files(job_id=job.id)
                originals = get_settings().artifact_dir / "offline-intelligence"
                if originals.is_symlink(): originals.unlink()
                elif originals.is_dir(): rmtree(originals)
                spool = get_settings().data_update_spool_dir
                if spool.resolve() != (engine.root / "staging").resolve() and spool.is_dir():
                    for archive in spool.glob("upload-*.tar.gz"): archive.unlink(missing_ok=True)
                job.payload = {**payload, "phase":"purged", "result":result}
                db.add(AuditEvent(actor="data-update-worker",action="vuln_data.purge.complete",target_type="vulnerability_data_job",target_id=job.id,detail={"deleted":result,"sourceManifest":evidence,"preserved":["users","projects","sbom","analysis_results","ssvc","responses","vex","private_vulnerabilities"]}))
            elif action == "validate":
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
                        activated = current.version
                        if kind == "unified": _reset_unified_live_references(db)
                        sync_reference_bundle(db, current.path)
                        _sync_bundle_epss(db, current.path)
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
                activated = release.version
                if kind == "unified": _reset_unified_live_references(db)
                sync_reference_bundle(db, release.path)
                _sync_bundle_epss(db, release.path)
                job.payload = {**job.payload, "phase": "applied", "releaseVersion": release.version}
            elif action == "rollback":
                current = engine.current()
                if payload.get("phase") == "applying" and current and _metadata(current.path / "metadata.env").get("DATA_UPDATE_JOB_ID") == job.id:
                    activated = current.version
                    if kind == "unified": _reset_unified_live_references(db)
                    sync_reference_bundle(db, current.path, allow_older=True)
                    job.payload = {**payload, "phase": "applied", "releaseVersion": current.version}
                    job.state = JobState.COMPLETED
                    job.error = None
                    db.commit()
                    return True
                job.payload = {**payload, "phase": "applying"}
                db.commit()
                release = engine.rollback(kind, version=payload.get("version"), job_id=job.id)
                activated = release.version
                if kind == "unified": _reset_unified_live_references(db)
                sync_reference_bundle(db, release.path, allow_older=True)
                _sync_bundle_epss(db, release.path)
                job.payload = {**job.payload, "phase": "applied", "releaseVersion": release.version}
            else:
                raise RuntimeError("알 수 없는 데이터 갱신 작업입니다")
            job.state = JobState.COMPLETED
            job.error = None
            db.commit()
        except Exception as exc:
            job_id = job.id
            db.rollback()
            compensation = ""
            if activated and engine:
                try:
                    restored = engine.compensate_activation(release_version=activated, job_id=job_id)
                    compensation = "; activation restored" if restored else "; current owned by another activation"
                except Exception as recovery_error:
                    compensation = "; activation recovery required: " + str(recovery_error)
            job = db.get(Job, job_id)
            job.state = JobState.FAILED
            job.error = (str(exc) + compensation)[-2000:]
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
                prepare_run(db, run)
                revision = analyze_offline(db, run)
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
    next_normalization = 0.0
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
                from .project_catalog import drain_native_reanalysis
                for maintenance in (scheduler_tick, drain_native_reanalysis, deliver_notifications):
                    try:
                        with SessionLocal() as db:
                            maintenance(db)
                            db.commit()
                    except Exception:
                        logging.getLogger(__name__).exception("Native workflow maintenance failed")
                next_scheduler = now + 10
            if not data_updates and now >= next_normalization:
                try:
                    with SessionLocal() as db:
                        normalization_tick(db)
                        db.commit()
                except Exception:
                    logging.getLogger(__name__).exception("SBOM normalization maintenance failed")
                next_normalization = now + 10
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
