"""Permission-scoped offline reference evidence and append-only response tracking."""
from datetime import datetime
from fastapi.responses import FileResponse
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from .db import get_db
from .data_updates import reference_access
from .models import JobState, SbomRun, Release, User, now
from .security import require_permission, run_scope
from .ssvc_api import authenticated_csrf, load_run, current_revision, analysis_ready
from .offline_intelligence_models import OfflineReferenceSnapshot, OfflineResponseEvent
from .offline_intelligence_store import active_reference_document, import_reference_document, reference_manifest
from .offline_reference_enrichment import enrich_reference_context
from .sbom import iter_components
from .workflows import audit, identity, iso, resolve_target, utc
from .ssvc import fingerprint

router = APIRouter(prefix="/api/v1", tags=["offline-intelligence"])

@router.get("/offline-intelligence")
def status(db=Depends(get_db), principal=Depends(require_permission("metadata.view", "metadata.manage"))):
    document = active_reference_document(db)
    rows = db.scalars(select(OfflineReferenceSnapshot).order_by(OfflineReferenceSnapshot.imported_at.desc()).limit(100)).all()
    from .offline_intelligence import KINDS
    return {"current": reference_manifest(document), "missingKinds": sorted(KINDS - document["datasets"].keys()), "history": [{"id": r.id, "kind": r.kind, "sourceId": r.source_id, "dataDate": r.data_as_of, "sha256": r.sha256, "records": r.record_count, "author": r.imported_by, "origin": r.origin, "importedAt": iso(r.imported_at)} for r in rows]}

@router.get("/offline-intelligence/snapshots/{snapshot_id}")
def snapshot(snapshot_id: str, offset: int = Query(0, ge=0), size: int = Query(200, ge=1, le=500), db=Depends(get_db), principal=Depends(require_permission("metadata.view", "metadata.manage"))):
    row = db.get(OfflineReferenceSnapshot, snapshot_id)
    if row is None: raise HTTPException(404, "자료 이력을 찾을 수 없습니다")
    # Raw originals are kept in storage; API evidence never exposes large base64 blobs.
    return {"id": row.id, "manifest": reference_manifest(row.document), "datasets": {kind: {"records": data["records"][offset:offset+size], "total": len(data["records"]), "offset": offset} for kind, data in row.document["datasets"].items()}}

@router.get("/offline-intelligence/snapshots/{snapshot_id}/original")
def snapshot_original(snapshot_id: str, db=Depends(get_db), principal=Depends(require_permission("metadata.view", "metadata.manage"))):
    from .offline_intelligence_store import verify_original
    row = db.get(OfflineReferenceSnapshot, snapshot_id)
    if row is None: raise HTTPException(404, "자료 이력을 찾을 수 없습니다")
    source = row.document["datasets"][row.kind]["sources"][0]
    try: path = verify_original(source)
    except ValueError as exc: raise HTTPException(409, str(exc)) from exc
    return FileResponse(path, media_type="application/octet-stream", filename=source["sha256"] + ".bin")

@router.post("/offline-intelligence/import", dependencies=[Depends(authenticated_csrf), Depends(reference_access)])
def import_document(document: dict, db=Depends(get_db), principal=Depends(require_permission("metadata.manage"))):
    try:
        result = import_reference_document(db, document, actor=principal.username)
        audit(db, principal.username, "offline_reference.import", result["sha256"], result)
        db.commit()
        return result
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "동시에 반입 자료가 변경되었습니다. 현재 이력을 새로 조회하십시오") from exc
    except (ValueError, TypeError, KeyError) as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc


def current_context(db, run):
    revision = current_revision(run)
    components, findings, summary = enrich_reference_context((run.normalized_bom or {}).get("components", []), revision.findings if revision else [], active_reference_document(db))
    captured = ((revision.data_sources or {}).get("offlineIntelligence") or {}).get("sha256") if revision else None
    return {"revisionId": revision.id if revision else None, "analysisReady": analysis_ready(run, revision), "snapshotChanged": captured != summary["sha256"], "summary": summary, "components": components, "findings": findings}

@router.get("/sbom-runs/{run_id}/offline-intelligence")
def run_context(run_id: str, db=Depends(get_db), principal=Depends(require_permission("metadata.view", "metadata.manage"))):
    return current_context(db, load_run(db, run_id))


def event_dict(row):
    return {"id": row.id, "runId": row.run_id, "revisionId": row.revision_id, "component": row.component, "componentVersion": row.component_version, "vulnerabilityId": row.vulnerability_id, "state": row.state, "owner": row.owner, "dueAt": iso(row.due_at), "rationale": row.rationale, "ticket": row.ticket, "author": row.author, "createdAt": iso(row.created_at)}

class ResponseBody(BaseModel):
    component: str = Field(min_length=1, max_length=4096)
    vulnerabilityId: str = Field(min_length=1, max_length=255)
    expectedRevisionId: str
    state: str
    owner: str = Field(min_length=1, max_length=255)
    rationale: str = Field(min_length=1, max_length=10000)
    dueAt: datetime | None = None
    ticket: str = Field(default="", max_length=2048)

@router.get("/sbom-runs/{run_id}/responses")
def responses(run_id: str, db=Depends(get_db), principal=Depends(require_permission("vex.view", "vex.manage"))):
    run = load_run(db, run_id)
    revision = current_revision(run)
    rows = db.scalars(select(OfflineResponseEvent).where(OfflineResponseEvent.run_id == run_id).order_by(OfflineResponseEvent.created_at.desc()).limit(1000)).all()
    return {"items": [{**event_dict(row), "stale": not analysis_ready(run, revision) or row.revision_id != revision.id or bool(row.due_at and utc(row.due_at) <= now())} for row in rows]}

@router.post("/sbom-runs/{run_id}/responses", dependencies=[Depends(authenticated_csrf)])
def save_response(run_id: str, body: ResponseBody, db=Depends(get_db), principal=Depends(require_permission("vex.manage"))):
    run = load_run(db, run_id); revision = current_revision(run)
    if run.archived_at or not analysis_ready(run, revision) or revision.id != body.expectedRevisionId: raise HTTPException(409, "현재 완료된 분석을 새로 조회하십시오")
    if body.state not in {"open", "triaged", "in_progress", "mitigated", "accepted", "verification_requested"}: raise HTTPException(422, "지원하지 않는 대응 상태입니다")
    if not body.rationale.strip() or not body.owner.strip(): raise HTTPException(422, "담당자와 대응 근거가 필요합니다")
    if body.dueAt and (body.dueAt.tzinfo is None or utc(body.dueAt) <= now()): raise HTTPException(422, "기한은 시간대가 있는 미래 시각이어야 합니다")
    if body.state == "accepted" and not body.dueAt: raise HTTPException(422, "위험 수용에는 재검토 기한이 필요합니다")
    component, version, vuln = resolve_target(run, body.component, body.vulnerabilityId)
    row = OfflineResponseEvent(run_id=run.id, revision_id=revision.id, service_id=run.release.service_id, environment_id=run.release.environment_id, component=component, component_version=version, vulnerability_id=vuln, target_key=fingerprint([component, version, vuln]), state=body.state, owner=body.owner.strip(), rationale=body.rationale.strip(), due_at=body.dueAt, ticket=body.ticket, author=principal.username)
    db.add(row); db.flush(); audit(db, principal.username, "response.record", row.id, event_dict(row)); db.commit()
    return event_dict(row)

@router.get("/offline-intelligence/impact")
def impact(page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200), db=Depends(get_db), principal=Depends(require_permission("metadata.view", "metadata.manage"))):
    ranked = select(SbomRun.id, func.row_number().over(partition_by=SbomRun.release_id, order_by=(SbomRun.round_number.desc(), SbomRun.created_at.desc(), SbomRun.id.desc())).label("rank")).where(SbomRun.archived_at.is_(None), run_scope(principal)).subquery()
    latest_ids = select(ranked.c.id).where(ranked.c.rank == 1)
    total = db.scalar(select(func.count()).select_from(ranked).where(ranked.c.rank == 1)) or 0
    runs = db.scalars(select(SbomRun).where(SbomRun.id.in_(latest_ids)).order_by(SbomRun.created_at.desc(), SbomRun.id).offset((page-1)*size).limit(size).options(selectinload(SbomRun.analyses), selectinload(SbomRun.release).selectinload(Release.service), selectinload(SbomRun.release).selectinload(Release.environment))).all()
    response_rows = db.scalars(select(OfflineResponseEvent).where(OfflineResponseEvent.run_id.in_([run.id for run in runs])).order_by(OfflineResponseEvent.created_at.desc(), OfflineResponseEvent.id.desc())).all()
    by_run = {}
    for event in response_rows: by_run.setdefault(event.run_id, []).append(event)
    latest = {}; rows = []; unique = set(); state_counts = {}
    for run in runs:
        if run.release_id in latest: continue
        latest[run.release_id] = run
        revision = current_revision(run); findings = revision.findings if revision else []
        events = by_run.get(run.id, [])
        current = {}
        for event in events: current.setdefault((event.component, event.component_version, event.vulnerability_id), event)
        counts = {}; overdue = 0
        for finding in findings or []:
            key = identity(finding); unique.add(key[2]); event = current.get(key); state = ("review_required" if not analysis_ready(run, revision) or event.revision_id != revision.id or (event.due_at and utc(event.due_at) <= now()) else event.state) if event else "open"
            counts[state] = counts.get(state, 0) + 1; state_counts[state] = state_counts.get(state, 0) + 1
            overdue += bool(event and event.due_at and utc(event.due_at) <= now())
        rows.append({"runId": run.id, "service": run.release.service.name, "environment": run.release.environment.name, "release": run.release.version, "analysisState": str(run.analysis_state.value), "findings": len(findings or []), "responseStates": counts, "overdue": overdue})
    return {"projects": rows, "uniqueVulnerabilities": len(unique), "responseStates": state_counts, "scope": "latest_run_per_release_page", "coverage": {"page": page, "size": size, "totalProjects": total, "returnedProjects": len(rows), "summaryScope": "page"}, "supplierVexAutoSuppression": False}
