"""Read-only integrations use credentials separate from legacy upload tokens."""
from datetime import UTC, datetime, timedelta
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base, get_db
from .models import AnalysisRevision, Environment, JobState, ProcessingState, Release, SbomRun, Service, new_id, now
from .security import digest, require_csrf, require_permission
from .services import audit


class ExternalReadToken(Base):
    __tablename__ = "external_read_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    environment_id: Mapped[str | None] = mapped_column(ForeignKey("environments.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    serviceId: str
    environmentId: str | None = None
    days: int = Field(default=30, ge=1, le=90)


router = APIRouter(prefix="/api/v1/integrations/external", tags=["External read API"])
_manage = require_permission("tokens.manage")
_read_bearer = HTTPBearer(scheme_name="TrackerReadToken", bearerFormat="koda_read_", auto_error=False)


def _token_info(token):
    return {"id": token.id, "name": token.name, "serviceId": token.service_id,
            "environmentId": token.environment_id, "expiresAt": token.expires_at,
            "revokedAt": token.revoked_at}


@router.post("/tokens", status_code=201, dependencies=[Depends(_manage), Depends(require_csrf)])
def issue_token(body: TokenRequest, response: Response, db: Session = Depends(get_db), user=Depends(_manage)):
    service = db.get(Service, body.serviceId)
    environment = db.get(Environment, body.environmentId) if body.environmentId else None
    if not service or not service.active or (body.environmentId and (not environment or not environment.active)):
        raise HTTPException(404, "활성 서비스 또는 환경을 찾을 수 없습니다")
    raw = "koda_read_" + secrets.token_urlsafe(36)
    token = ExternalReadToken(name=body.name, token_hash=digest(raw), service_id=service.id,
                              environment_id=environment.id if environment else None,
                              expires_at=now() + timedelta(days=body.days))
    db.add(token)
    db.flush()
    audit(db, user.username, "external_token.create", "external_read_token", token.id,
          {"serviceId": token.service_id, "environmentId": token.environment_id})
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return {**_token_info(token), "token": raw}


@router.get("/tokens", dependencies=[Depends(_manage)])
def list_tokens(db: Session = Depends(get_db)):
    return [_token_info(t) for t in db.scalars(select(ExternalReadToken).order_by(ExternalReadToken.id))]


@router.post("/tokens/{token_id}/revoke", dependencies=[Depends(_manage), Depends(require_csrf)])
def revoke_token(token_id: str, db: Session = Depends(get_db), user=Depends(_manage)):
    token = db.get(ExternalReadToken, token_id)
    if not token:
        raise HTTPException(404, "연동 토큰을 찾을 수 없습니다")
    token.revoked_at = now()
    audit(db, user.username, "external_token.revoke", "external_read_token", token.id, {})
    db.commit()
    return _token_info(token)


def read_token(credentials: HTTPAuthorizationCredentials | None = Depends(_read_bearer), db: Session = Depends(get_db)):
    raw = credentials.credentials if credentials else ""
    token = db.scalar(select(ExternalReadToken).where(ExternalReadToken.token_hash == digest(raw),
                                                       ExternalReadToken.revoked_at.is_(None))) if raw.startswith("koda_read_") else None
    if not token or token.expires_at.replace(tzinfo=UTC) <= now():
        raise HTTPException(401, "유효한 외부 조회 토큰이 필요합니다")
    service = db.get(Service, token.service_id)
    env = db.get(Environment, token.environment_id) if token.environment_id else None
    if not service or not service.active or (token.environment_id and (not env or not env.active)):
        raise HTTPException(403, "연동 대상이 비활성 상태입니다")
    return token


def scoped_runs(token):
    query = select(SbomRun).join(Release).join(Environment).where(
        Release.service_id == token.service_id, Environment.active.is_(True), SbomRun.archived_at.is_(None),
        SbomRun.state != ProcessingState.ARCHIVED)
    return query.where(Release.environment_id == token.environment_id) if token.environment_id else query


def require_run(db, token, run_id):
    # Keep the authorized run in its service/environment until the response data has been read.
    run = db.scalar(scoped_runs(token).where(SbomRun.id == run_id).with_for_update(read=True, of=SbomRun))
    if not run:
        raise HTTPException(404, "회차를 찾을 수 없습니다")
    return run


def _run_info(run):
    return {"id": run.id, "serviceId": run.release.service_id, "environmentId": run.release.environment_id,
            "releaseVersion": run.release.version, "roundNumber": run.round_number,
            "state": run.state, "analysisState": run.analysis_state, "observedAt": run.created_at}


Page = Annotated[int, Query(ge=1)]
Size = Annotated[int, Query(ge=1, le=100)]


@router.get("/scope")
def read_scope(db: Session = Depends(get_db), token=Depends(read_token)):
    service = db.get(Service, token.service_id)
    query = select(Environment).where(Environment.active.is_(True))
    if token.environment_id:
        query = query.where(Environment.id == token.environment_id)
    return {"service": {"id": service.id, "name": service.name},
            "environments": [{"id": env.id, "name": env.name} for env in db.scalars(query.order_by(Environment.sort_order, Environment.id))]}


@router.get("/runs")
def read_runs(page: Page = 1, size: Size = 20, db: Session = Depends(get_db), token=Depends(read_token)):
    query = scoped_runs(token)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(SbomRun.created_at.desc(), SbomRun.id).offset((page - 1) * size).limit(size))
    return {"items": [_run_info(r) for r in rows], "total": total, "page": page, "size": size}


@router.get("/runs/{run_id}/components")
def read_components(run_id: str, page: Page = 1, size: Size = 20, db: Session = Depends(get_db), token=Depends(read_token)):
    from .main import get_run_components

    require_run(db, token, run_id)
    result = get_run_components(run_id, q=None, page=page, size=size, db=db, _=token)
    result["items"] = [{key: item[key] for key in ("identityStatus", "group", "name", "version", "purl")}
                       for item in result["items"]]
    return result


@router.get("/runs/{run_id}/findings")
def read_findings(run_id: str, page: Page = 1, size: Size = 20, db: Session = Depends(get_db), token=Depends(read_token)):
    from .main import get_run_findings

    require_run(db, token, run_id)
    result = get_run_findings(run_id, analysis_id=None, page=page, size=size, db=db, _=token)
    analysis = db.get(AnalysisRevision, result["analysisId"]) if result["analysisId"] else None
    result["analysisState"] = analysis.state if analysis else None
    result["dataAsOf"] = analysis.data_as_of if analysis and analysis.data_as_of != "unknown" else None
    result["dataAvailable"] = bool(analysis and analysis.state == JobState.COMPLETED and
                                   ((analysis.data_sources or {}).get("vulnerabilityDataStatus") or {}).get("status") != "unavailable")
    fields = ("canonicalId", "id", "severity", "component", "version", "installedVersion", "fixedIn")
    result["items"] = [{key: item[key] for key in fields if key in item} for item in result["items"]]
    return result


@router.get("/comparison")
def read_comparison(baseRunId: str, targetRunId: str, db: Session = Depends(get_db), token=Depends(read_token)):
    from .main import compare_runs

    require_run(db, token, baseRunId)
    require_run(db, token, targetRunId)
    result = compare_runs(baseRunId, targetRunId, base_analysis_id=None, target_analysis_id=None, db=db, _=token)
    return {"baseRunId": baseRunId, "targetRunId": targetRunId, "summary": result["summary"]}


@router.get("/runs/{run_id}")
def read_run(run_id: str, db: Session = Depends(get_db), token=Depends(read_token)):
    return _run_info(require_run(db, token, run_id))
