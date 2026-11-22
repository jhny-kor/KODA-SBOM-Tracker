from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import false, select, true
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .environment_admin_models import EnvironmentAdministrator
from .models import ApiToken, Release, Role, RolePolicy, SbomRun, User, UserSession

ph = PasswordHasher()

PERMISSION_CATALOG = tuple(sorted({
    "metadata.view", "metadata.manage", "ssvc.view", "ssvc.manage",
    "vex.view", "vex.manage", "vex.approve", "notifications.view", "notifications.manage", "reanalysis.view", "reanalysis.manage",
    "dashboard.view", "services.view", "runs.view", "compare.view", "vulnerability.view", "audit.view", "settings.view",
    "sbom.upload", "artifact.download", "analysis.create", "policies.view", "policies.manage", "sbom.archive", "sbom.delete", "catalog.manage", "vulnerability.manage", "users.manage", "tokens.manage", "roles.manage",
}))
DEFAULT_ROLE_PERMISSIONS = {
    Role.ADMIN: set(PERMISSION_CATALOG),
    Role.MANAGER: {"dashboard.view", "services.view", "runs.view", "compare.view", "settings.view", "policies.view", "policies.manage", "sbom.upload", "artifact.download", "analysis.create", "sbom.archive", "catalog.manage", "users.manage"},
    Role.ANALYST: {"dashboard.view", "services.view", "runs.view", "compare.view", "policies.view", "sbom.upload", "artifact.download", "analysis.create", },
    Role.UPLOADER: {"dashboard.view", "services.view", "runs.view", "compare.view", "policies.view", "sbom.upload", "artifact.download"},
    Role.VIEWER: {"dashboard.view", "services.view", "runs.view", "compare.view", "policies.view", "artifact.download"},
}
for _role, _grants in DEFAULT_ROLE_PERMISSIONS.items():
    _grants.update({'metadata.view', 'ssvc.view', 'vex.view', 'notifications.view', 'reanalysis.view'})
    if _role in {Role.ADMIN, Role.MANAGER, Role.ANALYST}:
        _grants.update({'vex.manage', 'ssvc.manage'})
    if _role in {Role.ADMIN, Role.MANAGER}:
        _grants.update({'metadata.manage', 'vex.approve', 'notifications.manage', 'reanalysis.manage'})



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


def has_any_permission(db: Session, user: User, *permissions: str) -> bool:
    policy = db.get(RolePolicy, user.role)
    granted = policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(user.role, ())
    return not set(granted).isdisjoint(permissions)


def environment_scope(principal, environment_column):
    """Apply assignments to interactive accounts; integrations use their own scopes."""
    if not isinstance(principal, User):
        return true()
    if not principal.active or principal.approval_state != "approved":
        return false()
    if principal.role == Role.ADMIN:
        return true()
    return select(EnvironmentAdministrator.environment_id).where(
        EnvironmentAdministrator.environment_id == environment_column,
        EnvironmentAdministrator.user_id == principal.id,
    ).exists()


def run_scope(principal):
    if not isinstance(principal, User) or (
        principal.role == Role.ADMIN and principal.active and principal.approval_state == "approved"
    ):
        return true()
    return SbomRun.release.has(environment_scope(principal, Release.environment_id))


def require_run_scope(db: Session, principal, run_id: str):
    if isinstance(principal, User) and principal.role == Role.ADMIN and principal.active and principal.approval_state == "approved":
        return
    if isinstance(principal, User) and not db.scalar(select(SbomRun.id).where(SbomRun.id == run_id, run_scope(principal))):
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")


def require_permission(*permissions: str, allow_service_token: bool = False):
    def dependency(request: Request, principal: User | ApiToken = Depends(current_principal), db: Session = Depends(get_db)):
        if isinstance(principal, ApiToken):
            if allow_service_token:
                return principal
            raise HTTPException(403, "권한이 없습니다")
        if not has_any_permission(db, principal, *permissions):
            raise HTTPException(403, "권한이 없습니다")
        # Run-addressed endpoints share the same access rule, including
        # auxiliary reads and mutations such as quality, VEX and exports.
        if run_id := request.path_params.get("run_id"):
            require_run_scope(db, principal, run_id)
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
