"""Read-only, fail-closed CI decision over immutable analysis and quality evidence."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import AnalysisRevision, ApiToken, Job, JobState, ProcessingState, SbomRun
from .policies import get_policy_document
from .project_catalog_models import NativeReanalysisPending
from .security import require_permission

router = APIRouter(prefix="/api/v1")


def gate_result(db: Session, run: SbomRun) -> dict:
    from .quality import ENGINE_VERSION, latest_quality, effective_profile

    result = {"runId": run.id, "status": "blocked", "allowed": False,
              "reasons": [], "analysisId": None, "qualityRevisionId": None}
    reasons = result["reasons"]
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        reasons.append("run_archived")
        return result
    pending = db.scalar(select(Job.id).where(Job.run_id == run.id, Job.kind.in_(["process_run", "analyze"]),
                                           Job.state.in_([JobState.QUEUED, JobState.RUNNING])).limit(1))
    pending = pending or db.scalar(select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id == run.id).limit(1))
    if pending:
        result["status"] = "pending"
        reasons.append("analysis_pending")
        return result
    analysis = db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == run.id).order_by(AnalysisRevision.sequence.desc()).limit(1))
    if analysis is None:
        result["status"] = "pending" if run.analysis_state in {JobState.QUEUED, JobState.RUNNING} else "blocked"
        reasons.append("analysis_missing")
        return result
    result["analysisId"] = analysis.id
    if analysis.state != JobState.COMPLETED or run.analysis_state != JobState.COMPLETED:
        reasons.append("analysis_incomplete")
    if analysis.policy_state != "completed":
        reasons.append("policy_incomplete")
    if analysis.policy_version != get_policy_document(db).version:
        reasons.append("policy_stale")
    metrics = analysis.metrics or {}
    if metrics.get("policyStatus") not in {"pass", "warn", "fail"} or metrics.get("policyDataComplete") is not True:
        reasons.append("policy_data_incomplete")
    if metrics.get("policyStatus") == "fail":
        reasons.append("policy_violation")
    quality = latest_quality(db, run.id)
    if quality is None:
        reasons.append("quality_missing")
    else:
        result["qualityRevisionId"] = quality["id"]
        if quality["state"] != "completed":
            reasons.append("quality_failed")
        if quality["engineVersion"] != ENGINE_VERSION:
            reasons.append("quality_engine_stale")
        if quality["originalSha256"] != run.sha256:
            reasons.append("quality_artifact_mismatch")
        bound = (analysis.data_sources or {}).get("sbomQuality") or {}
        if bound.get("revisionId") != quality["id"]:
            reasons.append("quality_analysis_mismatch")
        try:
            profile = effective_profile(db, run)
            if quality["profileSnapshot"] != profile:
                reasons.append("quality_profile_stale")
        except ValueError:
            reasons.append("quality_profile_ambiguous")
        summary = quality["summary"]
        result["qualityStatus"] = summary.get("qualityStatus")
        if summary.get("sourceBasis") != "verified_original_artifact":
            reasons.append("quality_original_unverified")
        if summary.get("qualityStatus") not in {"pass", "warn", "fail"}:
            reasons.append("quality_data_incomplete")
        if summary.get("qualityStatus") == "fail":
            reasons.append("quality_threshold_exceeded")
    if not reasons:
        result["status"], result["allowed"] = "pass", True
    return result


@router.get("/sbom-runs/{run_id}/gate")
def read_gate(run_id: str, response: Response, db: Session = Depends(get_db),
              principal=Depends(require_permission("runs.view", allow_service_token=True))):
    run = db.get(SbomRun, run_id)
    if run is None or (isinstance(principal, ApiToken) and not (
        principal.service_id == run.release.service_id or
        (principal.service_id is None and run.idempotency_actor == f"token:{principal.id}")
    )):
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    response.headers["Cache-Control"] = "no-store"
    return gate_result(db, run)
