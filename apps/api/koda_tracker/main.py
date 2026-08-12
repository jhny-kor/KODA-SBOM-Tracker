from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import secrets
import tempfile
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, inspect, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .config import get_settings, session_cookie_name
from .comparison import compare_components, compare_records
from .db import Base, SessionLocal, engine, get_db, ensure_postgres_manager_enum
from .dtrack import DependencyTrackClient
from .models import (
    AnalysisRevision,
    ApiToken,
    AuditEvent,
    Environment,
    Job,
    JobState,
    ProcessingState,
    Release,
    Role,
    RolePolicy,
    SbomRun,
    Service,
    User,
    UserSession,
    VulnerabilityDataBundle,
)
from .sbom import SbomValidationError, parse_sbom, store_artifact, validate_with_cyclonedx_cli
from .security import (
    current_principal,
    digest,
    hash_password,
    issue_session,
    require_csrf,
    require_permission,
    rotate_csrf,
    verify_password,
    DEFAULT_ROLE_PERMISSIONS,
    PERMISSION_CATALOG,
)
from .services import audit, create_components, enqueue
from .vulnerability import active_bundle, scan_bundle_releases


class LoginRequest(BaseModel):
    username: str
    password: str
    useLdap: bool = False


class ServiceRequest(BaseModel):
    slug: str
    name: str


class EnvironmentRequest(BaseModel):
    slug: str
    name: str
    sortOrder: int = 0


class UserRequest(BaseModel):
    username: str
    password: str
    role: Role


class UserPatch(BaseModel):
    role: Role | None = None
    active: bool | None = None


class TokenRequest(BaseModel):
    name: str
    serviceId: str


class ServicePatch(BaseModel):
    name: str | None = None
    active: bool | None = None


class EnvironmentPatch(BaseModel):
    name: str | None = None
    sortOrder: int | None = None


class ArchiveRequest(BaseModel):
    reason: str


class RolePolicyRequest(BaseModel):
    permissions: list[str]


class RolePoliciesRequest(BaseModel):
    roles: dict[Role, list[str]]


def problem(status: int, title: str, detail: str, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "type": "about:blank",
            "title": title,
            "status": status,
            "detail": detail,
            "instance": str(request.url.path),
        },
        media_type="application/problem+json",
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    if settings.environment.lower() == "production" and (
        not settings.secure_cookies or not settings.public_origin.startswith("https://")
    ):
        raise RuntimeError("production Tracker requires HTTPS public_origin and secure cookies")
    ensure_postgres_manager_enum(engine)
    Base.metadata.create_all(engine)
    # v1 uses create_all for a fresh install, but keep the one additive field
    # introduced by the vulnerability-data lifecycle backward compatible with
    # an already initialized portal database.
    if "data_sources" not in {column["name"] for column in inspect(engine).get_columns("analysis_revisions")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE analysis_revisions ADD COLUMN data_sources JSON"))
    with SessionLocal() as db:
        for slug, name, order in [
            ("dev", "개발", 10),
            ("qa", "검증", 20),
            ("stage", "스테이징", 30),
            ("prod", "운영", 40),
        ]:
            if not db.scalar(select(Environment).where(Environment.slug == slug)):
                db.add(Environment(slug=slug, name=name, sort_order=order))
        for role, permissions in DEFAULT_ROLE_PERMISSIONS.items():
            if db.get(RolePolicy, role) is None:
                db.add(RolePolicy(role=role, permissions=sorted(permissions)))
        if settings.bootstrap_admin_password and not db.scalar(select(User).where(User.username == settings.bootstrap_admin_username)):
            db.add(
                User(
                    username=settings.bootstrap_admin_username,
                    password_hash=hash_password(settings.bootstrap_admin_password),
                    role=Role.ADMIN,
                )
            )
        db.commit()
    yield


app = FastAPI(title="KODA SBOM Tracker API", version="0.1.0", lifespan=lifespan)
_login_attempts: dict[str, deque[datetime]] = defaultdict(deque)
_round_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


async def _read_upload_stream(upload: UploadFile, max_bytes: int) -> tuple[bytes, str]:
    """Read an upload through a bounded temporary stream before validation.

    UploadFile may be backed by memory or disk depending on the multipart
    parser. Keeping our own bounded temporary stream ensures hashing and the
    size check happen incrementally before the artifact is committed.
    """
    total = 0
    hasher = hashlib.sha256()
    with tempfile.TemporaryFile() as staged:
        while chunk := await upload.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(413, "SBOM 파일이 업로드 제한을 초과했습니다")
            hasher.update(chunk)
            staged.write(chunk)
        staged.seek(0)
        return staged.read(), hasher.hexdigest()


@app.exception_handler(HTTPException)
async def http_problem(request: Request, exc: HTTPException):
    return problem(exc.status_code, "요청을 처리할 수 없습니다", str(exc.detail), request)


@app.exception_handler(RequestValidationError)
async def validation_problem(request: Request, exc: RequestValidationError):
    return problem(422, "입력값 검증 실패", str(exc.errors()), request)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/v1/dependency-track/status")
async def dependency_track_status(
    _=Depends(require_permission("dtrack.settings")),
) -> dict:
    return await DependencyTrackClient().status()


@app.post("/api/v1/auth/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    if body.useLdap:
        return JSONResponse(status_code=501, content={"code": "ldap_not_configured", "detail": "LDAP 로그인은 아직 지원되지 않습니다"})
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    client = forwarded or (request.client.host if request.client else "unknown")
    bucket = f"{client}:{body.username.strip().lower()}"
    current = datetime.now(UTC)
    attempts = _login_attempts[bucket]
    while attempts and (current - attempts[0]).total_seconds() > 300:
        attempts.popleft()
    if len(attempts) >= 10:
        raise HTTPException(429, "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요")
    user = db.scalar(select(User).where(User.username == body.username))
    if not user or not user.active or not verify_password(user.password_hash, body.password):
        attempts.append(current)
        raise HTTPException(401, "사용자 이름 또는 비밀번호가 올바르지 않습니다")
    attempts.clear()
    raw, csrf = issue_session(db, user)
    cookie_name = session_cookie_name()
    response.set_cookie(
        cookie_name,
        raw,
        httponly=True,
        secure=get_settings().secure_cookies,
        samesite="strict",
        max_age=get_settings().session_ttl_seconds,
        path="/",
    )
    if cookie_name != "koda_session":
        response.delete_cookie("koda_session", path="/", samesite="strict", secure=get_settings().secure_cookies)
    policy = db.get(RolePolicy, user.role)
    return {"user": {"id": user.id, "username": user.username, "role": user.role, "active": user.active, "permissions": sorted(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(user.role, ()))}, "csrfToken": csrf}


def _identity_display(username: str) -> str:
    if not isinstance(username, str) or not username or len(username) > 128:
        raise ValueError("username codepoint bound exceeded")
    encoded = username.encode("utf-8")
    if len(encoded) > 512:
        raise ValueError("username byte bound exceeded")
    value = base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")
    if len(value) > 683:
        raise ValueError("username encoded bound exceeded")
    return value


def _session_from_cookie(request: Request, db: Session) -> tuple[UserSession, User] | None:
    # Cookie-session-only endpoint: callers reject Authorization explicitly.
    preferred = request.cookies.get("__Host-koda_session")
    if preferred is not None:
        names = [("__Host-koda_session", preferred)]
    else:
        legacy = request.cookies.get("koda_session")
        names = [("koda_session", legacy)] if legacy is not None else []
    for name, raw in names:
        session = db.get(UserSession, digest(raw))
        expires = session.expires_at if session else None
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        user = db.get(User, session.user_id) if session else None
        if session and expires and expires > datetime.now(UTC) and user and user.active:
            return session, user
    return None


@app.get("/api/v1/auth/session", status_code=204)
def auth_session(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    if request.headers.get("authorization"):
        raise HTTPException(401, "쿠키 세션만 사용할 수 있습니다")
    try:
        authenticated = _session_from_cookie(request, db)
        if authenticated is None:
            raise HTTPException(401, "인증이 필요합니다")
        session, user = authenticated
        try:
            display = _identity_display(user.username)
            identity = str(uuid.UUID(str(user.id)))
        except (ValueError, AttributeError, TypeError):
            raise HTTPException(503, "인증 주체 정보가 올바르지 않습니다")
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        response.headers.update({
            "X-KODA-Identity-ID": identity,
            "X-KODA-Identity-Expires": expires.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "X-KODA-Identity-Display": display,
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "Vary": "Cookie",
        })
        response.status_code = 204
        return response
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(503, "인증 서비스를 사용할 수 없습니다") from exc


def _logout_origin_allowed(request: Request) -> bool:
    configured = get_settings().public_origin.rstrip("/")
    if get_settings().environment.lower() == "production":
        expected = configured
    else:
        expected = configured or f"{request.url.scheme}://{request.url.netloc}"
    return bool(expected) and expected == request.headers.get("origin", "").rstrip("/")


@app.post("/api/v1/auth/logout-current", status_code=204)
def logout_current(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    if request.headers.get("authorization"):
        raise HTTPException(401, "쿠키 세션만 사용할 수 있습니다")
    if request.headers.get("content-length", "0") not in ("", "0"):
        raise HTTPException(403, "로그아웃 요청 본문은 비어 있어야 합니다")
    if not _logout_origin_allowed(request) or request.headers.get("sec-fetch-site") != "same-origin" or request.headers.get("sec-fetch-mode") != "cors" or request.headers.get("x-koda-logout") != "current-browser":
        raise HTTPException(403, "브라우저 로그아웃 요청 검증에 실패했습니다")
    try:
        authenticated = _session_from_cookie(request, db)
        if authenticated is None:
            raise HTTPException(401, "인증이 필요합니다")
        db.delete(authenticated[0])
        db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(503, "로그아웃 서비스를 사용할 수 없습니다") from exc
    secure = get_settings().secure_cookies
    for name in ("__Host-koda_session", "koda_session"):
        response.delete_cookie(name, path="/", samesite="strict", secure=secure)
    response.status_code = 204
    return response


@app.get("/api/v1/auth/me")
def me(request: Request, db: Session = Depends(get_db), principal=Depends(current_principal)) -> dict:
    if isinstance(principal, ApiToken):
        return {"token": {"id": principal.id, "name": principal.name}}
    csrf = rotate_csrf(db, request.state.session)
    policy = db.get(RolePolicy, principal.role)
    return {"user": {"id": principal.id, "username": principal.username, "role": principal.role, "active": principal.active, "permissions": sorted(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))}, "csrfToken": csrf}


@app.post("/api/v1/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _principal=Depends(current_principal),
    _csrf=Depends(require_csrf),
) -> Response:
    session = getattr(request.state, "session", None)
    if session is not None:
        db.delete(session)
        db.commit()
    for name in ("__Host-koda_session", "koda_session"):
        response.delete_cookie(name, path="/", samesite="strict", secure=get_settings().secure_cookies)
    response.status_code = 204
    return response


def _policy_invariant(db: Session, overrides: dict[Role, set[str]] | None = None) -> None:
    policies = {item.role: set(item.permissions or []) for item in db.scalars(select(RolePolicy))}
    if overrides:
        policies.update(overrides)
    if not any(user.active and policies.get(user.role, set()) >= {"roles.manage", "users.manage"} for user in db.scalars(select(User))):
        raise HTTPException(422, "roles.manage 및 users.manage 권한을 가진 활성 사용자가 최소 한 명 필요합니다")


def _validate_permissions(permissions: list[str]) -> list[str]:
    if len(permissions) != len(set(permissions)) or any(item not in PERMISSION_CATALOG for item in permissions):
        raise HTTPException(422, "알 수 없거나 중복된 권한입니다")
    return sorted(permissions)

@app.get("/api/v1/role-policies")
def list_role_policies(db: Session = Depends(get_db), _=Depends(require_permission("roles.manage"))) -> dict:
    return {"catalog": list(PERMISSION_CATALOG), "roles": [{"role": role.value, "permissions": sorted((db.get(RolePolicy, role) or RolePolicy(role=role, permissions=[])).permissions or [])} for role in Role]}

@app.put("/api/v1/role-policies/{role}")
def update_role_policy(role: Role, body: RolePolicyRequest, db: Session = Depends(get_db), principal=Depends(require_permission("roles.manage")), _csrf=Depends(require_csrf)) -> dict:
    permissions = _validate_permissions(body.permissions)
    item = db.get(RolePolicy, role)
    before = sorted(item.permissions) if item and item.permissions else []
    if item is None:
        item = RolePolicy(role=role, permissions=[])
        db.add(item)
    item.permissions = permissions
    _policy_invariant(db, {role: set(item.permissions)})
    audit(db, principal.username, "role_policy.update", "role_policy", role.value, {"before": before, "after": item.permissions})
    db.commit()
    return {"role": role.value, "permissions": item.permissions}


@app.put("/api/v1/role-policies")
def update_role_policies(
    body: RolePoliciesRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("roles.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    updates = {role: _validate_permissions(permissions) for role, permissions in body.roles.items()}
    _policy_invariant(db, {role: set(permissions) for role, permissions in updates.items()})
    result = []
    for role, permissions in updates.items():
        item = db.get(RolePolicy, role)
        before = sorted(item.permissions) if item and item.permissions else []
        if item is None:
            item = RolePolicy(role=role, permissions=[])
            db.add(item)
        item.permissions = permissions
        audit(db, principal.username, "role_policy.update", "role_policy", role.value, {"before": before, "after": permissions})
        result.append({"role": role.value, "permissions": permissions})
    db.commit()
    return {"roles": result}

@app.get("/api/v1/users")
def list_users(db: Session = Depends(get_db), _=Depends(require_permission("users.manage"))) -> list[dict]:
    principal = _
    policy = db.get(RolePolicy, principal.role)
    can_roles = "roles.manage" in set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
    return [
        {"id": item.id, "username": item.username, "role": item.role, "active": item.active}
        for item in db.scalars(select(User).order_by(User.username))
        if can_roles or item.role not in {Role.ADMIN, Role.MANAGER}
    ]


@app.post("/api/v1/users", status_code=201)
def create_user(
    body: UserRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("users.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    if len(body.password) < 12:
        raise HTTPException(422, "비밀번호는 12자 이상이어야 합니다")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    if body.role in {Role.ADMIN, Role.MANAGER}:
        policy = db.get(RolePolicy, principal.role)
        if "roles.manage" not in set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ())):
            raise HTTPException(403, "관리자 역할 변경에는 roles.manage 권한이 필요합니다")
    try:
        db.add(user)
        db.flush()
        _policy_invariant(db)
        audit(db, principal.username, "user.create", "user", user.id, {"username": user.username, "role": user.role})
        db.commit()
    except IntegrityError as exc:
        raise HTTPException(409, "이미 존재하는 사용자입니다") from exc
    return {"id": user.id, "username": user.username, "role": user.role}


@app.patch("/api/v1/users/{user_id}")
def patch_user(
    user_id: str,
    body: UserPatch,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("users.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "사용자를 찾을 수 없습니다")
    if user.id == principal.id and body.active is False:
        raise HTTPException(422, "현재 로그인한 관리자 계정은 비활성화할 수 없습니다")
    if user.role in {Role.ADMIN, Role.MANAGER} or body.role in {Role.ADMIN, Role.MANAGER}:
        policy = db.get(RolePolicy, principal.role)
        if "roles.manage" not in set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ())):
            raise HTTPException(403, "관리자 계정 변경에는 roles.manage 권한이 필요합니다")
    if body.role is not None:
        user.role = body.role
    if body.active is not None:
        user.active = body.active
    db.flush()
    _policy_invariant(db)
    audit(db, principal.username, "user.update", "user", user.id, {"role": user.role, "active": user.active})
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role, "active": user.active}


@app.post("/api/v1/api-tokens", status_code=201)
def create_api_token(
    body: TokenRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("tokens.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    if not body.serviceId:
        raise HTTPException(422, "서비스 범위 토큰에는 serviceId가 필요합니다")
    if not db.get(Service, body.serviceId):
        raise HTTPException(404, "서비스를 찾을 수 없습니다")
    raw = f"koda_{secrets.token_urlsafe(36)}"
    item = ApiToken(name=body.name, token_hash=digest(raw), service_id=body.serviceId)
    db.add(item)
    db.flush()
    audit(db, principal.username, "api_token.create", "api_token", item.id, {"serviceId": body.serviceId})
    db.commit()
    return {"id": item.id, "name": item.name, "token": raw, "serviceId": item.service_id}


@app.get("/api/v1/api-tokens")
def list_api_tokens(
    db: Session = Depends(get_db),
    _=Depends(require_permission("tokens.manage")),
) -> list[dict]:
    return [
        {
            "id": item.id,
            "name": item.name,
            "serviceId": item.service_id,
            "active": item.active,
            "createdAt": item.created_at.isoformat(),
        }
        for item in db.scalars(select(ApiToken).order_by(ApiToken.created_at.desc()))
    ]


@app.post("/api/v1/api-tokens/{token_id}/revoke")
def revoke_api_token(
    token_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("tokens.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    item = db.get(ApiToken, token_id)
    if not item:
        raise HTTPException(404, "API 토큰을 찾을 수 없습니다")
    item.active = False
    audit(db, principal.username, "api_token.revoke", "api_token", item.id, {"name": item.name})
    db.commit()
    return {"id": item.id, "active": item.active}


@app.get("/api/v1/services")
def list_services(
    db: Session = Depends(get_db),
    _=Depends(require_permission("services.view")),
) -> list[dict]:
    return [{"id": item.id, "slug": item.slug, "name": item.name, "active": item.active} for item in db.scalars(select(Service).order_by(Service.name))]


@app.post("/api/v1/services", status_code=201)
def create_service(
    body: ServiceRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("catalog.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,126}[a-z0-9]", body.slug):
        raise HTTPException(422, "slug 형식이 올바르지 않습니다")
    item = Service(slug=body.slug, name=body.name)
    try:
        db.add(item)
        db.flush()
        audit(db, principal.username, "service.create", "service", item.id, {"name": body.name})
        db.commit()
    except IntegrityError as exc:
        raise HTTPException(409, "이미 존재하는 서비스입니다") from exc
    return {"id": item.id, "slug": item.slug, "name": item.name}


@app.patch("/api/v1/services/{service_id}")
def patch_service(
    service_id: str,
    body: ServicePatch,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("catalog.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    item = db.get(Service, service_id)
    if not item:
        raise HTTPException(404, "서비스를 찾을 수 없습니다")
    if body.name is not None:
        item.name = body.name.strip()
    if body.active is not None:
        item.active = body.active
    audit(db, principal.username, "service.update", "service", item.id, {"active": item.active})
    db.commit()
    return {"id": item.id, "slug": item.slug, "name": item.name, "active": item.active}


@app.get("/api/v1/environments")
def list_environments(
    db: Session = Depends(get_db),
    _=Depends(require_permission("services.view")),
) -> list[dict]:
    return [{"id": item.id, "slug": item.slug, "name": item.name, "sortOrder": item.sort_order} for item in db.scalars(select(Environment).order_by(Environment.sort_order))]


@app.post("/api/v1/environments", status_code=201)
def create_environment(
    body: EnvironmentRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("catalog.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    item = Environment(slug=body.slug, name=body.name, sort_order=body.sortOrder)
    db.add(item)
    db.flush()
    audit(db, principal.username, "environment.create", "environment", item.id)
    db.commit()
    return {"id": item.id, "slug": item.slug, "name": item.name}


@app.patch("/api/v1/environments/{environment_id}")
def patch_environment(
    environment_id: str,
    body: EnvironmentPatch,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("catalog.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    item = db.get(Environment, environment_id)
    if not item:
        raise HTTPException(404, "환경을 찾을 수 없습니다")
    if body.name is not None:
        item.name = body.name.strip()
    if body.sortOrder is not None:
        item.sort_order = body.sortOrder
    audit(db, principal.username, "environment.update", "environment", item.id, {"sortOrder": item.sort_order})
    db.commit()
    return {"id": item.id, "slug": item.slug, "name": item.name, "sortOrder": item.sort_order}


def _principal_actor(principal: User | ApiToken) -> str:
    return principal.username if isinstance(principal, User) else f"token:{principal.id}"


def _persist_run(
    db: Session,
    *,
    principal: User | ApiToken,
    actor: str,
    service: Service,
    environment: Environment,
    release_version: str,
    raw: bytes,
    payload: dict,
    media_type: str,
    filename: str,
    note: str,
    idempotency_key: str | None,
    raw_sha256: str,
) -> dict:
    if db.bind and db.bind.dialect.name == "postgresql":
        lock_material = f"{service.id}:{environment.id}:{release_version}".encode()
        advisory_key = int.from_bytes(hashlib.sha256(lock_material).digest()[:8], "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": advisory_key})
    if idempotency_key:
        existing = db.scalar(
            select(SbomRun).where(SbomRun.idempotency_actor == actor, SbomRun.idempotency_key == idempotency_key)
        )
        if existing:
            return {"runId": existing.id, "state": existing.state, "idempotentReplay": True}
    release = db.scalar(
        select(Release).where(
            Release.service_id == service.id,
            Release.environment_id == environment.id,
            Release.version == release_version,
        )
    )
    if not release:
        release = Release(service_id=service.id, environment_id=environment.id, version=release_version)
        db.add(release)
        db.flush()
    round_number = int(db.scalar(select(func.max(SbomRun.round_number)).where(SbomRun.release_id == release.id)) or 0) + 1
    sha256, path = store_artifact(get_settings().artifact_dir, raw, digest=raw_sha256)
    run = SbomRun(
        release_id=release.id,
        round_number=round_number,
        original_filename=Path(filename or "sbom").name[:255],
        media_type=media_type,
        spec_version=str(payload.get("specVersion")),
        serial_number=payload.get("serialNumber"),
        sha256=sha256,
        size_bytes=len(raw),
        artifact_path=str(path),
        normalized_bom=payload,
        uploaded_by=principal.id if isinstance(principal, User) else None,
        idempotency_actor=actor,
        idempotency_key=idempotency_key,
        note=note,
        source="api" if isinstance(principal, ApiToken) else "manual",
    )
    db.add(run)
    db.flush()
    create_components(db, run)
    job = enqueue(db, "process_run", run.id)
    audit(db, actor, "sbom.upload", "sbom_run", run.id, {"sha256": sha256, "round": round_number})
    try:
        db.commit()
    except IntegrityError as exc:
        raise HTTPException(409, "회차 또는 idempotency 키가 충돌했습니다. 요청을 재시도하세요") from exc
    return {"runId": run.id, "jobId": job.id, "state": run.state, "roundNumber": round_number, "sha256": sha256}


@app.post("/api/v1/sbom-runs", status_code=202)
async def upload_sbom(
    request: Request,
    service_id: str = Form(alias="serviceId"),
    environment_id: str = Form(alias="environmentId"),
    release_version: str = Form(alias="releaseVersion"),
    note: str = Form(default=""),
    sbom: UploadFile = File(),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal=Depends(require_permission("sbom.upload", allow_service_token=True)),
    _csrf=Depends(require_csrf),
) -> dict:
    if isinstance(principal, ApiToken) and principal.service_id and principal.service_id != service_id:
        raise HTTPException(403, "이 토큰에는 해당 서비스 업로드 권한이 없습니다")
    actor = _principal_actor(principal)
    if idempotency_key:
        existing = db.scalar(
            select(SbomRun).where(SbomRun.idempotency_actor == actor, SbomRun.idempotency_key == idempotency_key)
        )
        if existing:
            return {"runId": existing.id, "state": existing.state, "idempotentReplay": True}
    raw, raw_sha256 = await _read_upload_stream(sbom, get_settings().max_upload_bytes)
    try:
        payload, media_type = parse_sbom(raw)
        validate_with_cyclonedx_cli(raw, get_settings().cyclonedx_cli_binary)
    except SbomValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    service = db.get(Service, service_id)
    environment = db.get(Environment, environment_id)
    if not service or not environment:
        raise HTTPException(404, "서비스 또는 환경을 찾을 수 없습니다")
    if not service.active:
        raise HTTPException(409, "비활성 서비스에는 SBOM을 업로드할 수 없습니다")
    lock_key = f"{service.id}:{environment.id}:{release_version}"
    async with _round_locks[lock_key]:
        return _persist_run(
            db,
            principal=principal,
            actor=actor,
            service=service,
            environment=environment,
            release_version=release_version,
            raw=raw,
            payload=payload,
            media_type=media_type,
            filename=sbom.filename or "sbom",
            note=note,
            idempotency_key=idempotency_key,
            raw_sha256=raw_sha256,
        )


def _run_payload(item: SbomRun) -> dict:
    latest = max(item.analyses, key=lambda analysis: analysis.sequence, default=None)
    return {
        "id": item.id,
        "service": {"id": item.release.service.id, "name": item.release.service.name, "slug": item.release.service.slug},
        "environment": {"id": item.release.environment.id, "name": item.release.environment.name, "slug": item.release.environment.slug},
        "releaseVersion": item.release.version,
        "roundNumber": item.round_number,
        "state": item.state,
        "analysisState": item.analysis_state,
        "dependencyTrackState": item.dtrack_state,
        "sha256": item.sha256,
        "sizeBytes": item.size_bytes,
        "specVersion": item.spec_version,
        "filename": item.original_filename,
        "componentCount": len(item.components),
        "vulnerabilityCount": len(latest.findings) if latest else 0,
        "policyViolationCount": len(latest.policies) if latest else 0,
        "dataAsOf": latest.data_as_of if latest else None,
        "analysisDataSources": (latest.data_sources or {}) if latest else {},
        "createdAt": item.created_at.isoformat(),
        "dependencyTrackUrl": (
            f"{get_settings().dependency_track_ui_url}projects/{item.dtrack_project_uuid}"
            if item.dtrack_project_uuid
            else None
        ),
        "dependencyTrackError": item.dtrack_error,
        "dependencyTrackMetrics": item.dtrack_metrics,
        "dependencyTrackPolicies": item.dtrack_policies,
    }


@app.get("/api/v1/sbom-runs")
def list_runs(
    service_id: str | None = None,
    environment_id: str | None = None,
    state: ProcessingState | None = None,
    q: str | None = Query(default=None, min_length=1, max_length=200),
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    _=Depends(require_permission("runs.view")),
) -> dict:
    query = select(SbomRun).options(
        selectinload(SbomRun.release).selectinload(Release.service),
        selectinload(SbomRun.release).selectinload(Release.environment),
        selectinload(SbomRun.components),
        selectinload(SbomRun.analyses),
    )
    if service_id:
        query = query.join(Release).where(Release.service_id == service_id)
    if environment_id:
        query = query.join(Release).where(Release.environment_id == environment_id)
    if state:
        query = query.where(SbomRun.state == state)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(
            or_(
                SbomRun.id.ilike(pattern),
                SbomRun.original_filename.ilike(pattern),
                SbomRun.release.has(Release.version.ilike(pattern)),
                SbomRun.release.has(Release.service.has(Service.name.ilike(pattern))),
            )
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(SbomRun.created_at.desc()).offset((page - 1) * size).limit(min(size, 100))).unique()
    return {"items": [_run_payload(item) for item in items], "page": page, "size": size, "total": total}


def _load_run(db: Session, run_id: str) -> SbomRun:
    item = db.scalar(
        select(SbomRun)
        .where(SbomRun.id == run_id)
        .options(
            selectinload(SbomRun.release).selectinload(Release.service),
            selectinload(SbomRun.release).selectinload(Release.environment),
            selectinload(SbomRun.components),
            selectinload(SbomRun.analyses),
        )
    )
    if not item:
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    return item


@app.get("/api/v1/sbom-runs/{run_id}")
def get_run(
    run_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_permission("runs.view")),
) -> dict:
    item = _load_run(db, run_id)
    payload = _run_payload(item)
    payload["components"] = [
        {
            "identityKey": component.identity_key,
            "identityStatus": component.identity_status,
            "componentType": component.component_type,
            "group": component.group_name,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "bomRef": component.bom_ref,
            "sha256": component.sha256,
            "licenses": component.licenses,
            "properties": component.properties,
        }
        for component in item.components
    ]
    payload["analyses"] = [
        {
            "id": analysis.id,
            "sequence": analysis.sequence,
            "state": analysis.state,
            "dataAsOf": analysis.data_as_of,
            "toolVersion": analysis.tool_version,
            "dataSources": analysis.data_sources or {},
            "findings": analysis.findings,
            "policies": analysis.policies,
            "error": analysis.error,
        }
        for analysis in sorted(item.analyses, key=lambda value: value.sequence, reverse=True)
    ]
    return payload


@app.get("/api/v1/sbom-runs/{run_id}/artifact")
def download_artifact(
    run_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_permission("artifact.download")),
):
    item = _load_run(db, run_id)
    return FileResponse(item.artifact_path, media_type=item.media_type, filename=item.original_filename)


@app.post("/api/v1/sbom-runs/{run_id}/retry-dependency-track", status_code=202)
def retry_dependency_track(
    run_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("dtrack.retry")),
    _csrf=Depends(require_csrf),
) -> dict:
    run = _load_run(db, run_id)
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        raise HTTPException(409, "보관된 회차는 다시 처리할 수 없습니다")
    run.dtrack_state = JobState.QUEUED
    run.dtrack_error = None
    run.state = ProcessingState.PROCESSING
    job = enqueue(db, "sync_dependency_track", run.id)
    audit(db, _principal_actor(principal), "dtrack.retry", "sbom_run", run.id)
    db.commit()
    return {"jobId": job.id, "runId": run.id}


@app.post("/api/v1/sbom-runs/{run_id}/analyses", status_code=202)
def create_analysis(
    run_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("analysis.create")),
    _csrf=Depends(require_csrf),
) -> dict:
    run = _load_run(db, run_id)
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        raise HTTPException(409, "보관된 회차는 다시 분석할 수 없습니다")
    run.analysis_state = JobState.QUEUED
    run.state = ProcessingState.PROCESSING
    job = enqueue(db, "analyze", run.id)
    audit(db, _principal_actor(principal), "analysis.create", "sbom_run", run.id)
    db.commit()
    return {"jobId": job.id, "runId": run.id}


@app.post("/api/v1/sbom-runs/{run_id}/archive")
def archive_run(
    run_id: str,
    body: ArchiveRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("sbom.archive")),
    _csrf=Depends(require_csrf),
) -> dict:
    if not body.reason.strip():
        raise HTTPException(422, "보관 사유가 필요합니다")
    run = _load_run(db, run_id)
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        raise HTTPException(409, "이미 보관된 회차입니다")
    run.archived_at = datetime.now(UTC)
    run.archive_reason = body.reason.strip()
    run.state = ProcessingState.ARCHIVED
    audit(db, principal.username, "sbom.archive", "sbom_run", run.id, {"reason": run.archive_reason})
    db.commit()
    return {"runId": run.id, "state": run.state, "archivedAt": run.archived_at.isoformat()}


@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db), principal=Depends(require_permission("runs.view", "sbom.upload", allow_service_token=True))) -> dict:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "작업을 찾을 수 없습니다")
    if isinstance(principal, ApiToken):
        run = db.get(SbomRun, job.run_id) if job.run_id else None
        if not run or run.idempotency_actor != f"token:{principal.id}":
            raise HTTPException(403, "자신이 생성한 작업만 조회할 수 있습니다")
    else:
        policy = db.get(RolePolicy, principal.role)
        permissions = set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
        if "runs.view" not in permissions:
            run = db.get(SbomRun, job.run_id) if job.run_id else None
            if not run or run.uploaded_by != principal.id:
                raise HTTPException(403, "자신이 생성한 작업만 조회할 수 있습니다")
    return {"id": job.id, "kind": job.kind, "runId": job.run_id, "state": job.state, "attempts": job.attempts, "error": job.error}


@app.get("/api/v1/comparisons")
def compare_runs(
    base_run_id: str = Query(alias="baseRunId"),
    target_run_id: str = Query(alias="targetRunId"),
    base_analysis_id: str | None = Query(default=None, alias="baseAnalysisId"),
    target_analysis_id: str | None = Query(default=None, alias="targetAnalysisId"),
    db: Session = Depends(get_db),
    _=Depends(require_permission("compare.view")),
) -> dict:
    base = _load_run(db, base_run_id)
    target = _load_run(db, target_run_id)

    def analysis(run: SbomRun, requested: str | None):
        values = [item for item in run.analyses if not requested or item.id == requested]
        return max(values, key=lambda item: item.sequence, default=None)

    base_analysis = analysis(base, base_analysis_id)
    target_analysis = analysis(target, target_analysis_id)
    component_changes = compare_components(base.components, target.components)
    finding_changes = compare_records(
        base_analysis.findings if base_analysis else [],
        target_analysis.findings if target_analysis else [],
        keys=("canonicalId", "component"),
    )
    policy_changes = compare_records(
        base_analysis.policies if base_analysis else [],
        target_analysis.policies if target_analysis else [],
        keys=("rule", "component"),
    )
    return {
        "base": {"runId": base.id, "sha256": base.sha256, "dataAsOf": base_analysis.data_as_of if base_analysis else None, "artifactUrl": f"/api/v1/sbom-runs/{base.id}/artifact"},
        "target": {"runId": target.id, "sha256": target.sha256, "dataAsOf": target_analysis.data_as_of if target_analysis else None, "artifactUrl": f"/api/v1/sbom-runs/{target.id}/artifact"},
        "summary": {
            "componentsAdded": sum(item["change"] == "added" for item in component_changes),
            "componentsRemoved": sum(item["change"] == "removed" for item in component_changes),
            "componentsChanged": sum(item["change"] == "changed" for item in component_changes),
            "vulnerabilitiesAdded": sum(item["change"] == "added" for item in finding_changes),
            "vulnerabilitiesRemoved": sum(item["change"] == "removed" for item in finding_changes),
            "policiesChanged": len(policy_changes),
        },
        "components": component_changes,
        "vulnerabilities": finding_changes,
        "policies": policy_changes,
    }


@app.get("/api/v1/audit-events")
def audit_events(
    page: int = 1,
    size: int = 50,
    db: Session = Depends(get_db),
    _=Depends(require_permission("audit.view")),
) -> dict:
    total = db.scalar(select(func.count()).select_from(AuditEvent)) or 0
    items = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).offset((page - 1) * size).limit(size))
    return {
        "items": [
            {
                "id": item.id,
                "actor": item.actor,
                "action": item.action,
                "targetType": item.target_type,
                "targetId": item.target_id,
                "detail": item.detail,
                "createdAt": item.created_at.isoformat(),
            }
            for item in items
        ],
        "total": total,
    }


def _bundle_payload(item: VulnerabilityDataBundle) -> dict:
    manifest = item.manifest or {}
    metadata = manifest.get("metadata") or {}
    return {
        "id": item.id,
        "version": item.version,
        "dataAsOf": item.data_as_of,
        "grypeDbSchema": metadata.get("GRYPE_DB_SCHEMA", "unknown"),
        "nvdDataAsOf": metadata.get("NVD_DATASET_DATE", "unknown"),
        "kevDataAsOf": metadata.get("KEV_DATASET_DATE", "unknown"),
        "aliasCount": int(manifest.get("aliasCount", 0) or 0),
        "kevCount": int(manifest.get("kevCount", 0) or 0),
        "manifestSha256": item.sha256,
        "active": item.active,
        "importedAt": item.imported_at.isoformat(),
    }


def _sync_bundle_records(db: Session, *, actor: str | None = None) -> tuple[list[VulnerabilityDataBundle], bool]:
    releases = scan_bundle_releases(get_settings())
    existing = {item.version: item for item in db.scalars(select(VulnerabilityDataBundle))}
    changed = False
    active_version = next((item.version for item in releases if item.active), None)
    for release in releases:
        context_manifest = release.as_manifest()
        context_manifest["aliasCount"] = 0
        context_manifest["kevCount"] = 0
        if release.active:
            # The worker will parse these sidecar indexes; keeping the counts in
            # the DB makes the admin view useful without opening the large files.
            from .vulnerability import load_context

            context = load_context(get_settings())
            if context.bundle and context.bundle.version == release.version:
                context_manifest["aliasCount"] = len(context.aliases)
                context_manifest["kevCount"] = len(context.kev)
        item = existing.get(release.version)
        if item is None:
            item = VulnerabilityDataBundle(
                version=release.version,
                sha256=release.manifest_sha256,
                data_as_of=release.data_as_of,
                manifest=context_manifest,
                active=release.active,
            )
            db.add(item)
            changed = True
            if actor:
                audit(db, actor, "vuln_data.register", "vulnerability_data_bundle", release.version, {"dataAsOf": release.data_as_of})
        else:
            next_manifest = context_manifest
            if item.sha256 != release.manifest_sha256 or item.data_as_of != release.data_as_of or item.manifest != next_manifest or item.active != release.active:
                item.sha256 = release.manifest_sha256
                item.data_as_of = release.data_as_of
                item.manifest = next_manifest
                item.active = release.active
                changed = True
    release_versions = {release.version for release in releases}
    for item in existing.values():
        expected_active = active_version is not None and item.version == active_version
        if item.version in release_versions or active_version is None:
            if item.active != expected_active:
                item.active = expected_active
                changed = True
    if changed:
        db.flush()
    return list(db.scalars(select(VulnerabilityDataBundle).order_by(VulnerabilityDataBundle.imported_at.desc()))), changed


@app.get("/api/v1/vulnerability-data-bundles")
def vulnerability_data_bundles(
    db: Session = Depends(get_db),
    _=Depends(require_permission("vulnerability.view")),
) -> dict:
    # GET stays read-only. An administrator explicitly synchronizes the
    # filesystem release after an import or rollback.
    items = list(db.scalars(select(VulnerabilityDataBundle).order_by(VulnerabilityDataBundle.imported_at.desc())))
    return {"items": [_bundle_payload(item) for item in items]}


@app.post("/api/v1/vulnerability-data-bundles/sync")
def sync_vulnerability_data_bundles(
    db: Session = Depends(get_db),
    principal=Depends(require_permission("vulnerability.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    items, _ = _sync_bundle_records(db, actor=principal.username)
    audit(db, principal.username, "vuln_data.sync", "vulnerability_data_bundle", "runtime", {"count": len(items)})
    db.commit()
    return {"items": [_bundle_payload(item) for item in items]}


@app.post("/api/v1/vulnerability-data-bundles/{version}/activate")
def activate_vulnerability_data_bundle(
    version: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("vulnerability.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    items, _ = _sync_bundle_records(db, actor=principal.username)
    item = next((value for value in items if value.version == version), None)
    if item is None:
        raise HTTPException(404, "취약점 데이터 번들을 찾을 수 없습니다")
    active = active_bundle(get_settings())
    if active is None or active.version != version:
        raise HTTPException(409, "파일시스템의 current 번들을 먼저 반입하거나 롤백해야 합니다")
    for value in items:
        value.active = value.version == version
    audit(db, principal.username, "vuln_data.activate", "vulnerability_data_bundle", item.id, {"version": version})
    db.commit()
    return _bundle_payload(item)


def run() -> None:
    import uvicorn

    uvicorn.run("koda_tracker.main:app", host="0.0.0.0", port=8000)
