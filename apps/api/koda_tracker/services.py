from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .dtrack import DependencyTrackClient
from .models import (
    AnalysisRevision,
    AuditEvent,
    Job,
    JobState,
    ProcessingState,
    RunComponent,
    SbomRun,
)
from .sbom import licenses_for, normalized_identity, sha256_for
from .vulnerability import load_context, normalize_finding


def create_components(db: Session, run: SbomRun) -> None:
    if db.scalar(select(func.count()).select_from(RunComponent).where(RunComponent.run_id == run.id)):
        return
    raw_components = run.normalized_bom.get("components", [])
    identities = [normalized_identity(raw)[0] for raw in raw_components]
    duplicates = Counter(identities)
    for index, raw in enumerate(raw_components):
        identity, status = normalized_identity(raw)
        if duplicates[identity] > 1:
            bom_ref = str(raw.get("bom-ref") or "")
            identity = f"{identity}|bom-ref:{bom_ref}" if bom_ref else f"{identity}|ambiguous:{index}"
            status = "review_required"
        db.add(
            RunComponent(
                run_id=run.id,
                identity_key=identity,
                identity_status=status,
                component_type=str(raw.get("type") or "library"),
                group_name=str(raw.get("group") or ""),
                name=str(raw.get("name") or raw.get("bom-ref") or "unknown"),
                version=str(raw.get("version") or ""),
                purl=str(raw.get("purl") or ""),
                bom_ref=str(raw.get("bom-ref") or ""),
                sha256=sha256_for(raw),
                licenses=licenses_for(raw),
                properties=list(raw.get("properties") or []),
            )
        )
    db.flush()


def analyze_offline(db: Session, run: SbomRun) -> AnalysisRevision:
    sequence = int(db.scalar(select(func.max(AnalysisRevision.sequence)).where(AnalysisRevision.run_id == run.id)) or 0) + 1
    revision = AnalysisRevision(run_id=run.id, sequence=sequence, state=JobState.RUNNING)
    db.add(revision)
    db.flush()
    findings: list[dict] = []
    settings = get_settings()
    context = load_context(settings)
    env = os.environ.copy()
    env["GRYPE_DB_CACHE_DIR"] = str(settings.grype_db_dir)
    env["GRYPE_DB_AUTO_UPDATE"] = "false"
    env["GRYPE_DB_VALIDATE_AGE"] = "false"
    try:
        process = subprocess.run(
            [settings.grype_binary, f"sbom:{run.artifact_path}", "-o", "json"],
            text=True,
            capture_output=True,
            timeout=300,
            env=env,
            check=False,
        )
        if process.returncode == 0:
            payload = json.loads(process.stdout)
            for match in payload.get("matches", []):
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                findings.append(
                    {
                        **normalize_finding(vuln, context),
                        "component": artifact.get("purl") or artifact.get("name"),
                        "version": artifact.get("version"),
                        "fixedIn": [
                            str(item.get("version") if isinstance(item, dict) else item)
                            for item in vuln.get("fix", {}).get("versions", [])
                            if item
                        ],
                    }
                )
            revision.state = JobState.COMPLETED
            revision.tool_version = str(payload.get("descriptor", {}).get("version", "grype"))
        else:
            revision.state = JobState.FAILED
            revision.error = process.stderr[-2000:] or "Grype 분석 실패"
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        revision.state = JobState.FAILED
        revision.error = str(exc)
    revision.findings = findings
    revision.data_sources = context.sources
    revision.data_as_of = context.bundle.data_as_of if context.bundle else "unknown"
    if context.bundle is None:
        metadata_path = settings.grype_db_dir.parent / "metadata.env"
        revision.data_as_of = _metadata_value(metadata_path, "DATASET_DATE") or "unknown"
    run.analysis_state = revision.state
    db.flush()
    return revision


def _metadata_value(path: Path, key: str) -> str | None:
    if not path.is_file():
        return None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return None


async def sync_dependency_track(db: Session, run: SbomRun) -> None:
    client = DependencyTrackClient()
    if not client.configured:
        run.dtrack_state = JobState.FAILED
        run.dtrack_error = "Dependency-Track 연결이 구성되지 않았습니다"
        _derive_state(run)
        return
    release = run.release
    try:
        if not release.service.dtrack_collection_uuid:
            release.service.dtrack_collection_uuid = await client.ensure_collection(
                f"KODA::{release.service.slug}"
            )
            db.flush()
        payload = await client.upload(
            project_name=f"KODA::{release.service.slug}::{release.environment.slug}",
            project_version=f"{release.version}::r{run.round_number}",
            artifact=Path(run.artifact_path),
            parent_uuid=release.service.dtrack_collection_uuid,
            tags=["koda", f"env:{release.environment.slug}", f"run:{run.id}"],
        )
        run.dtrack_token = str(payload.get("token") or "")
        run.dtrack_project_uuid = str(payload.get("project") or payload.get("projectUuid") or "")
        if run.dtrack_token:
            await client.wait_for_token(run.dtrack_token)
        if not run.dtrack_project_uuid:
            project = await client.lookup_project(
                f"KODA::{release.service.slug}::{release.environment.slug}",
                f"{release.version}::r{run.round_number}",
            )
            run.dtrack_project_uuid = str(project["uuid"])
        run.dtrack_metrics, run.dtrack_policies = await client.project_snapshot(run.dtrack_project_uuid)
        latest_analysis = max(run.analyses, key=lambda item: item.sequence, default=None)
        if latest_analysis is not None:
            latest_analysis.policies = run.dtrack_policies
        run.dtrack_state = JobState.COMPLETED
        run.dtrack_error = None
        _derive_state(run)
        if run.state == ProcessingState.COMPLETED:
            latest_round = db.scalar(
                select(func.max(SbomRun.round_number)).where(
                    SbomRun.release_id == run.release_id,
                    SbomRun.analysis_state == JobState.COMPLETED,
                    SbomRun.dtrack_state == JobState.COMPLETED,
                    SbomRun.archived_at.is_(None),
                )
            )
            if latest_round == run.round_number:
                await client.promote_latest(run.dtrack_project_uuid)
    except Exception as exc:
        run.dtrack_state = JobState.FAILED
        run.dtrack_error = str(exc)[-2000:]
    _derive_state(run)
    db.flush()


def _derive_state(run: SbomRun) -> None:
    if run.analysis_state == JobState.COMPLETED and run.dtrack_state == JobState.COMPLETED:
        run.state = ProcessingState.COMPLETED
    elif run.analysis_state == JobState.FAILED and run.dtrack_state == JobState.FAILED:
        run.state = ProcessingState.FAILED
    elif JobState.FAILED in {run.analysis_state, run.dtrack_state}:
        run.state = ProcessingState.PARTIAL
    else:
        run.state = ProcessingState.PROCESSING


def audit(db: Session, actor: str, action: str, target_type: str, target_id: str, detail: dict | None = None) -> None:
    db.add(AuditEvent(actor=actor, action=action, target_type=target_type, target_id=target_id, detail=detail or {}))


def enqueue(db: Session, kind: str, run_id: str) -> Job:
    job = Job(kind=kind, run_id=run_id)
    db.add(job)
    db.flush()
    return job
