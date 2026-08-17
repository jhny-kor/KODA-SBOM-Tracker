from __future__ import annotations

import base64
import uuid

from fastapi.testclient import TestClient

from koda_tracker.main import app


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
        assert client.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 200

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
