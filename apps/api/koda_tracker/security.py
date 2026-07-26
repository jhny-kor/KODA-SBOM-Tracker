from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import ApiToken, Role, User, UserSession

ph = PasswordHasher()


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
    session_id: str | None = Cookie(default=None, alias="koda_session"),
    authorization: str | None = Header(default=None),
) -> User | ApiToken:
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
        token = db.scalar(select(ApiToken).where(ApiToken.token_hash == digest(raw), ApiToken.active.is_(True)))
        if token:
            return token
    if session_id:
        session = db.get(UserSession, digest(session_id))
        expires = session.expires_at if session else None
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if session and expires and expires > datetime.now(UTC):
            user = db.get(User, session.user_id)
            if user and user.active:
                request.state.session = session
                return user
    raise HTTPException(401, "인증이 필요합니다")


def require_roles(*roles: Role):
    def dependency(principal: User | ApiToken = Depends(current_principal)):
        if isinstance(principal, ApiToken):
            if Role.UPLOADER in roles:
                return principal
            raise HTTPException(403, "권한이 없습니다")
        if principal.role not in roles:
            raise HTTPException(403, "권한이 없습니다")
        return principal

    return dependency


def require_user_roles(*roles: Role):
    """Require a browser session; service tokens are intentionally excluded."""
    def dependency(principal: User | ApiToken = Depends(current_principal)):
        if not isinstance(principal, User) or principal.role not in roles:
            raise HTTPException(403, "권한이 없습니다")
        return principal

    return dependency


def require_csrf(request: Request, csrf_token: str | None = Header(default=None, alias="X-CSRF-Token")) -> None:
    session = getattr(request.state, "session", None)
    if session is not None and (not csrf_token or digest(csrf_token) != session.csrf_hash):
        raise HTTPException(403, "CSRF 토큰이 유효하지 않습니다")
