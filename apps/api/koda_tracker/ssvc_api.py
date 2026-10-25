"""Authenticated, offline SSVC assessments. Every save appends an immutable decision."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import JobState, SbomRun, User, now
from .security import current_principal, require_csrf, require_permission
from .ssvc import MODEL, OPTIONS, decision_table, evaluate, evidence_snapshot, fingerprint
from .ssvc_models import SsvcAssessment
from .offline_intelligence_store import active_reference_document
from .vulnerability import active_bundle
from .vulnerability_intelligence import enrich_findings
from .workflows import audit, identity, iso, resolve_target, utc

router = APIRouter(prefix="/api/v1", tags=["ssvc"])


def authenticated_csrf(principal: User = Depends(current_principal), csrf: None = Depends(require_csrf)):
    """Authentication sets the session before CSRF is checked."""


class Inputs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exploitation: Literal["none", "public poc", "active"] | None = None
    systemExposure: Literal["small", "controlled", "open"] | None = None
    automatable: Literal["no", "yes"] | None = None
    humanImpact: Literal["low", "medium", "high", "very high"] | None = None


class AssessmentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = Field(min_length=1, max_length=4096)
    vulnerabilityId: str = Field(min_length=1, max_length=255)
    expectedRevisionId: str = Field(min_length=1, max_length=36)
    inputs: Inputs
    rationale: str = Field(min_length=1, max_length=10000)
    references: list[str] = Field(default_factory=list, max_length=20)
    reviewAt: datetime | None = None

    @field_validator("rationale")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("판단 근거 또는 미평가 사유가 필요합니다")
        return value.strip()

    @field_validator("references")
    @classmethod
    def bounded_references(cls, values):
        if any(not value.strip() or len(value) > 2048 for value in values):
            raise ValueError("근거 참조는 비어 있지 않은 최대 2048자 문자열이어야 합니다")
        return [value.strip() for value in values]


def load_run(db, run_id):
    run = db.get(SbomRun, run_id)
    if run is None:
        raise HTTPException(404, "SBOM을 찾을 수 없습니다")
    return run


def current_revision(run):
    return max(run.analyses, key=lambda revision: revision.sequence, default=None)


def analysis_ready(run, revision):
    return bool(revision and revision.state == JobState.COMPLETED and run.analysis_state == JobState.COMPLETED)


def current_evidence(db, run, revision, finding):
    from .offline_intelligence_store import active_reference_document
    from .offline_reference_enrichment import enrich_reference_context
    _, findings, _ = enrich_reference_context((run.normalized_bom or {}).get("components", []), enrich_findings(db, [finding]), active_reference_document(db))
    value = evidence_snapshot(run, revision, findings[0])
    bundle = active_bundle(get_settings())
    value["activeBundleVersion"] = bundle.version if bundle else None
    return value


def analysis_data_current(evidence):
    active = evidence["activeBundleVersion"]
    return active is None or active == evidence["sources"].get("bundleVersion")


def assessment_dict(db, row, run, revision):
    reasons = []
    _, provenance = decision_table()
    if row.model != MODEL or row.table_sha256 != provenance["sha256"]:
        reasons.append("model_changed")
    if not analysis_ready(run, revision) or row.revision_id != revision.id:
        reasons.append("analysis_changed")
    else:
        finding = next((value for value in revision.findings or []
                        if identity(value) == (row.component, row.component_version, row.vulnerability_id)), None)
        evidence = current_evidence(db, run, revision, finding) if finding is not None else None
        if evidence is None or fingerprint(evidence) != row.evidence_sha256:
            reasons.append("evidence_changed")
        if evidence is not None and not analysis_data_current(evidence):
            reasons.append("analysis_data_outdated")
    if row.review_at and utc(row.review_at) <= now():
        reasons.append("review_due")
    newer = db.scalar(select(SsvcAssessment.id).where(
        SsvcAssessment.run_id == row.run_id, SsvcAssessment.target_key == row.target_key,
        or_(SsvcAssessment.created_at > row.created_at,
            (SsvcAssessment.created_at == row.created_at) & (SsvcAssessment.id > row.id))).limit(1))
    return {"id": row.id, "runId": row.run_id, "revisionId": row.revision_id,
            "serviceId": row.service_id, "environmentId": row.environment_id, "releaseId": row.release_id,
            "component": row.component, "componentVersion": row.component_version,
            "vulnerabilityId": row.vulnerability_id, "model": row.model, "tableSha256": row.table_sha256,
            "inputs": row.inputs, "outcome": row.outcome,
            "state": "assessed" if row.outcome else "unassessed", "stale": bool(reasons), "staleReasons": reasons,
            "superseded": newer is not None, "rationale": row.rationale, "references": row.references,
            "evidence": row.evidence, "author": row.author, "createdAt": iso(row.created_at), "reviewAt": iso(row.review_at)}


@router.get("/ssvc/model")
def model(principal: User = Depends(require_permission("ssvc.view", "ssvc.manage"))):
    _, provenance = decision_table()
    return {**provenance, "inputs": OPTIONS, "runtimeNetworkRequired": False}


@router.get("/sbom-runs/{run_id}/ssvc")
def list_assessments(run_id: str, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100),
                     db: Session = Depends(get_db), principal: User = Depends(require_permission("ssvc.view", "ssvc.manage"))):
    run = load_run(db, run_id)
    revision = current_revision(run)
    query = select(SsvcAssessment).where(SsvcAssessment.run_id == run.id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(SsvcAssessment.created_at.desc(), SsvcAssessment.id.desc())
                      .offset((page - 1) * size).limit(size)).all()
    return {"items": [assessment_dict(db, row, run, revision) for row in rows], "total": total,
            "page": page, "size": size, "model": MODEL,
            "revisionId": revision.id if revision else None,
            "analysisReady": analysis_ready(run, revision), "archived": bool(run.archived_at)}


@router.post("/sbom-runs/{run_id}/ssvc", status_code=201, dependencies=[Depends(authenticated_csrf)])
def submit_assessment(run_id: str, body: AssessmentBody, db: Session = Depends(get_db),
                      principal: User = Depends(require_permission("ssvc.manage"))):
    run = load_run(db, run_id)
    revision = current_revision(run)
    if run.archived_at:
        raise HTTPException(409, "보관된 SBOM에는 SSVC 판단을 추가할 수 없습니다")
    if not analysis_ready(run, revision) or revision.id != body.expectedRevisionId:
        raise HTTPException(409, "분석 결과가 변경되었거나 완료되지 않았습니다. 새로고침 후 평가하세요")
    key = resolve_target(run, body.component, body.vulnerabilityId)
    finding = next(value for value in revision.findings if identity(value) == key)
    values = body.inputs.model_dump()
    if finding.get("kev") is True and values["exploitation"] not in {None, "active"}:
        raise HTTPException(422, "KEV 악용 근거가 있는 취약점은 active 또는 미평가로 기록해야 합니다")
    if body.reviewAt and (body.reviewAt.tzinfo is None or body.reviewAt <= now()):
        raise HTTPException(422, "재평가 기한은 시간대가 있는 미래 시각이어야 합니다")
    evidence = current_evidence(db, run, revision, finding)
    if not analysis_data_current(evidence):
        raise HTTPException(409, "취약점 자료가 갱신되었습니다. 새 자료로 재분석한 후 평가하세요")
    _, provenance = decision_table()
    row = SsvcAssessment(run_id=run.id, revision_id=revision.id, service_id=run.release.service_id,
                         environment_id=run.release.environment_id, release_id=run.release_id,
                         target_key=fingerprint({"component": key[0], "version": key[1], "vulnerability": key[2]}),
                         component=key[0], component_version=key[1], vulnerability_id=key[2],
                         model=MODEL, table_sha256=provenance["sha256"], inputs=values, outcome=evaluate(values),
                         evidence=evidence, evidence_sha256=fingerprint(evidence), rationale=body.rationale,
                         references=body.references, author=principal.username, review_at=body.reviewAt)
    db.add(row)
    db.flush()
    audit(db, principal.username, "ssvc.assess", row.id,
          {"runId": run.id, "revisionId": revision.id, "model": MODEL, "outcome": row.outcome})
    db.commit()
    return assessment_dict(db, row, run, revision)
