from __future__ import annotations

import base64
import uuid

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError

from koda_tracker.config import get_settings
from koda_tracker.db import SessionLocal
from koda_tracker.main import RegistrationRequest, _client_address, _consume_rate_limit, app, register
from koda_tracker.models import AuthAttempt, Role, User


def _login(client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
    assert response.status_code == 200


def test_tracker_session_projection_is_cookie_only_and_non_mutating() -> None:
    with TestClient(app) as client:
        _login(client)
        assert client.cookies.get("koda_session")
        response = client.get("/api/v1/auth/session")
        assert response.status_code == 204
        assert response.headers["X-KODA-Identity-ID"]
        assert response.headers["X-KODA-Identity-Display"] == base64.urlsafe_b64encode(b"test-admin").rstrip(b"=").decode()
        assert response.headers["Cache-Control"] == "no-store, private"
        assert response.headers["Pragma"] == "no-cache"
        assert response.headers["Vary"] == "Cookie"
        assert "set-cookie" not in response.headers
        assert client.get("/api/v1/auth/session", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_invalid_new_cookie_never_falls_back_to_valid_legacy_cookie() -> None:
    with TestClient(app) as client:
        _login(client)
        client.cookies.set("__Host-koda_session", "invalid-new-session")
        assert client.get("/api/v1/auth/session").status_code == 401


def test_ldap_returns_explicit_not_configured_before_password_check() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json={"username": "missing", "password": "wrong", "useLdap": True})
        assert response.status_code == 501
        assert response.json() == {"code": "ldap_not_configured", "detail": "LDAP 로그인은 아직 지원되지 않습니다"}


def test_registration_requires_admin_approval_before_login() -> None:
    username = f"request-{uuid.uuid4().hex[:12]}"
    password = "registration-password-123"
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/register", json={"username": username, "password": password, "passwordConfirm": password})
        assert response.status_code == 202
        assert response.json()["status"] == "pending"
        duplicate = client.post("/api/v1/auth/register", json={"username": username.upper(), "password": "replacement-password-123", "passwordConfirm": "replacement-password-123"})
        assert duplicate.status_code == 202
        assert client.post("/api/v1/auth/login", json={"username": username, "password": "replacement-password-123"}).status_code == 401
        assert client.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 403

        admin = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        csrf = admin.json()["csrfToken"]
        pending = next(item for item in client.get("/api/v1/users").json() if item["username"] == username)
        assert pending["role"] == "viewer"
        assert pending["active"] is False
        assert pending["status"] == "pending"
        assert client.patch(f"/api/v1/users/{pending['id']}", json={"active": True}, headers={"X-CSRF-Token": csrf}).status_code == 422
        approved = client.post(f"/api/v1/users/{pending['id']}/approve", headers={"X-CSRF-Token": csrf})
        assert approved.status_code == 200
        assert approved.json()["status"] == "active"

        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        assert client.post("/api/v1/auth/login", json={"username": f"  {username.upper()}  ", "password": password}).status_code == 200

        admin = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "correct-horse-battery-staple"})
        csrf = admin.json()["csrfToken"]
        assert client.patch(f"/api/v1/users/{pending['id']}", json={"active": False}, headers={"X-CSRF-Token": csrf}).json()["status"] == "inactive"


def test_logout_current_requires_browser_headers_and_invalidates_session() -> None:
    with TestClient(app) as client:
        _login(client)
        denied = client.post("/api/v1/auth/logout-current", headers={"Origin": "http://testserver"})
        assert denied.status_code == 403
        response = client.post(
            "/api/v1/auth/logout-current",
            headers={
                "Origin": "http://testserver",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "X-KODA-Logout": "current-browser",
            },
        )
        assert response.status_code == 204
        assert client.get("/api/v1/auth/session").status_code == 401


def _request(peer: str, forwarded: str = "") -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": (peer, 1234),
        "server": ("testserver", 80),
    })


def test_forwarded_client_ip_is_used_only_for_trusted_proxy(monkeypatch) -> None:
    monkeypatch.setenv("TRACKER_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    get_settings.cache_clear()
    try:
        assert _client_address(_request("203.0.113.10", "198.51.100.7")) == "203.0.113.10"
        assert _client_address(_request("127.0.0.1", "198.51.100.7")) == "198.51.100.7"
    finally:
        get_settings.cache_clear()


def test_existing_usernames_are_normalized_on_startup() -> None:
    user_id = str(uuid.uuid4())
    with TestClient(app):
        pass
    with SessionLocal() as db:
        db.add(User(id=user_id, username="Legacy-User", password_hash="unused", role=Role.VIEWER))
        db.commit()
    try:
        with TestClient(app) as client:
            _login(client)
            assert any(item["username"] == "legacy-user" for item in client.get("/api/v1/users").json())
    finally:
        with SessionLocal() as db:
            db.execute(delete(User).where(User.id == user_id))
            db.commit()


def test_auth_rate_limit_is_shared_between_database_sessions() -> None:
    bucket = f"test-{uuid.uuid4()}"
    try:
        with SessionLocal() as first:
            _consume_rate_limit(first, "test", bucket, 2, 60)
        with SessionLocal() as second:
            _consume_rate_limit(second, "test", bucket, 2, 60)
        with SessionLocal() as third, pytest.raises(HTTPException) as blocked:
            _consume_rate_limit(third, "test", bucket, 2, 60)
        assert blocked.value.status_code == 429
    finally:
        with SessionLocal() as db:
            db.execute(delete(AuthAttempt).where(AuthAttempt.kind == "test"))
            db.commit()


def test_registration_does_not_hide_unrelated_integrity_errors(monkeypatch) -> None:
    class FailingSession:
        def scalar(self, _statement):
            return None

        def add(self, _item) -> None:
            pass

        def flush(self) -> None:
            raise IntegrityError("insert", {}, RuntimeError("storage failure"))

        def rollback(self) -> None:
            pass

    monkeypatch.setattr("koda_tracker.main._consume_rate_limit", lambda *_args: None)
    monkeypatch.setattr("koda_tracker.main.hash_password", lambda _password: "hash")
    body = RegistrationRequest(username="new-user", password="long-enough-password", passwordConfirm="long-enough-password")
    with pytest.raises(IntegrityError):
        register(body, _request("127.0.0.1"), FailingSession())
