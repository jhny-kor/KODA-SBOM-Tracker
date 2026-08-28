from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import ApiToken, Role, RolePolicy, User, UserSession

ph = PasswordHasher()

PERMISSION_CATALOG = tuple(sorted({
    "dashboard.view", "services.view", "runs.view", "compare.view", "vulnerability.view", "audit.view", "settings.view",
    "sbom.upload", "artifact.download", "analysis.create", "dtrack.retry", "sbom.archive", "sbom.delete", "catalog.manage", "vulnerability.manage", "users.manage", "tokens.manage", "dtrack.settings", "roles.manage",
}))
DEFAULT_ROLE_PERMISSIONS = {
    Role.ADMIN: set(PERMISSION_CATALOG),
    Role.MANAGER: {"dashboard.view", "services.view", "runs.view", "compare.view", "settings.view", "sbom.upload", "artifact.download", "analysis.create", "dtrack.retry", "sbom.archive", "catalog.manage", "users.manage"},
    Role.ANALYST: {"dashboard.view", "services.view", "runs.view", "compare.view", "sbom.upload", "artifact.download", "analysis.create", "dtrack.retry"},
    Role.UPLOADER: {"dashboard.view", "services.view", "runs.view", "compare.view", "sbom.upload", "artifact.download"},
    Role.VIEWER: {"dashboard.view", "services.view", "runs.view", "compare.view", "artifact.download"},
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(value: str) -> str:
    return ph.hash(value)


def verify_password(encoded: str, value: str) -> bool:
    try:
        return ph.verify(encoded, value)
    except Exception:
        return False


def issue_session(db: Session, user: User) -> tuple[str, str]:
    raw = secrets.token_urlsafe(40)
    csrf = secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(seconds=get_settings().session_ttl_seconds)
    db.add(UserSession(id_hash=digest(raw), user_id=user.id, csrf_hash=digest(csrf), expires_at=expires))
    db.commit()
    return raw, csrf


def rotate_csrf(db: Session, session: UserSession) -> str:
    csrf = secrets.token_urlsafe(32)
    session.csrf_hash = digest(csrf)
    db.commit()
    return csrf


def current_principal(
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
) -> User | ApiToken:
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
        token = db.scalar(select(ApiToken).where(ApiToken.token_hash == digest(raw), ApiToken.active.is_(True)))
        if token:
            return token
        raise HTTPException(401, "API 토큰이 유효하지 않습니다")
    # New cookie wins.  An invalid new cookie must not fall back to a legacy
    # cookie, which prevents ambiguous browser identity during migration.
    cookie_name = "__Host-koda_session"
    session_id = request.cookies.get(cookie_name)
    if session_id is None:
        session_id = request.cookies.get("koda_session")
        cookie_name = "koda_session" if session_id is not None else cookie_name
    if session_id:
        session = db.get(UserSession, digest(session_id))
        expires = session.expires_at if session else None
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if session and expires and expires > datetime.now(UTC):
            user = db.get(User, session.user_id)
            if user and user.active:
                request.state.session = session
                request.state.session_cookie_name = cookie_name
                return user
    raise HTTPException(401, "인증이 필요합니다")


def require_permission(*permissions: str, allow_service_token: bool = False):
    def dependency(principal: User | ApiToken = Depends(current_principal), db: Session = Depends(get_db)):
        if isinstance(principal, ApiToken):
            if allow_service_token:
                return principal
            raise HTTPException(403, "권한이 없습니다")
        policy = db.get(RolePolicy, principal.role)
        granted = set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
        if granted.isdisjoint(permissions):
            raise HTTPException(403, "권한이 없습니다")
        return principal
    return dependency


def require_admin(principal: User | ApiToken = Depends(current_principal)) -> User:
    if isinstance(principal, ApiToken) or principal.role != Role.ADMIN:
        raise HTTPException(403, "관리자 권한이 필요합니다")
    return principal


def require_csrf(request: Request, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token")) -> None:
    session = getattr(request.state, "session", None)
    if session is not None and (not csrf_token or digest(csrf_token) != session.csrf_hash):
        raise HTTPException(403, "CSRF 토큰이 유효하지 않습니다")
