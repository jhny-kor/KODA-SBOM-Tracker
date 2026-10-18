from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from koda_tracker import ldap_auth
from koda_tracker.db import SessionLocal
from koda_tracker.ldap_auth import (
    LdapConfig,
    LdapIdentity,
    LdapInvalidCredentials,
    authenticate_user,
)
from koda_tracker.main import app
from koda_tracker.models import LdapSettings, SbomRun, User, UserSession
from sqlalchemy import delete


def _admin(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "test-admin", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrfToken"]}


def _ldap_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "enabled": True,
        "host": "ldap.example.test",
        "port": 389,
        "tlsMode": "starttls",
        "verifyCertificate": True,
        "caCertPath": "/run/secrets/ldap-ca.crt",
        "bindDn": "svc-koda@example.test",
        "bindPassword": "bind-secret",
        "baseDn": "DC=example,DC=test",
        "loginAttribute": "sAMAccountName",
        "usernameAttribute": "sAMAccountName",
        "subjectAttribute": "objectGUID",
        "userFilter": "(sAMAccountName={username})",
        "groupAttribute": "memberOf",
        "groupMappings": {"CN=KODA-Admins,DC=example,DC=test": "admin"},
        "autoProvision": True,
        "defaultRole": "viewer",
    }
    body.update(overrides)
    return body


def _cleanup(*usernames: str) -> None:
    with SessionLocal() as db:
        ids = [item.id for item in db.query(User).filter(User.username.in_(usernames)).all()]
        if ids:
            db.execute(delete(UserSession).where(UserSession.user_id.in_(ids)))
            db.execute(delete(User).where(User.id.in_(ids)))
        db.execute(delete(LdapSettings).where(LdapSettings.id == "default"))
        db.commit()


def test_ldap_settings_encrypt_bind_password_and_provision_session(monkeypatch: pytest.MonkeyPatch) -> None:
    username = "ldap-test-user"
    try:
        with TestClient(app) as client:
            headers = _admin(client)
            saved = client.put("/api/v1/settings/ldap", json=_ldap_body(), headers=headers)
            assert saved.status_code == 200
            assert saved.json()["hasBindPassword"] is True
            assert "bindPassword" not in saved.json()
            assert client.get("/api/v1/settings/ldap").json()["subjectAttribute"] == "objectGUID"

            monkeypatch.setattr(
                "koda_tracker.main.authenticate_user",
                lambda config, supplied_username, password: LdapIdentity(
                    username=username,
                    subject="directory-subject-1",
                    groups=("CN=KODA-Admins,DC=example,DC=test",),
                ),
            )
            login = client.post(
                "/api/v1/auth/login",
                json={"username": "directory-input", "password": "directory-password", "useLdap": True},
            )
            assert login.status_code == 403
            pending = next(item for item in client.get("/api/v1/users").json() if item["username"] == username)
            assert pending["status"] == "pending"
            approved = client.post(f"/api/v1/users/{pending['id']}/approve", headers=headers)
            assert approved.status_code == 200
            assert approved.json()["status"] == "active"
            login = client.post(
                "/api/v1/auth/login",
                json={"username": "directory-input", "password": "directory-password", "useLdap": True},
            )
            assert login.status_code == 200
            assert login.json()["user"]["username"] == username
            assert login.json()["user"]["role"] == "admin"
            assert login.json()["user"]["authSource"] == "ldap"
            assert client.get("/api/v1/auth/session").status_code == 204
    finally:
        _cleanup(username)


def test_ldap_settings_requires_csrf_and_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    try:
        with TestClient(app) as client:
            headers = _admin(client)
            body = _ldap_body()
            assert client.put("/api/v1/settings/ldap", json=body).status_code == 403
            monkeypatch.setattr("koda_tracker.main._ldap_fernet", lambda: None)
            response = client.put("/api/v1/settings/ldap", json=body, headers=headers)
            assert response.status_code == 503
            assert "암호화 키" in response.json()["detail"]
    finally:
        _cleanup()


def test_ldap_never_falls_back_to_local_password(monkeypatch: pytest.MonkeyPatch) -> None:
    username = "ldap-local-collision"
    password = "long-enough-password"
    try:
        with TestClient(app) as client:
            headers = _admin(client)
            created = client.post(
                "/api/v1/users",
                json={"username": username, "password": password, "role": "viewer"},
                headers=headers,
            )
            assert created.status_code == 201
            assert client.put("/api/v1/settings/ldap", json=_ldap_body(), headers=headers).status_code == 200

            def reject(config: LdapConfig, supplied_username: str, password: str) -> LdapIdentity:
                raise LdapInvalidCredentials

            monkeypatch.setattr("koda_tracker.main.authenticate_user", reject)
            response = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": password, "useLdap": True},
            )
            assert response.status_code == 401
    finally:
        _cleanup(username)


def test_ldap_enabled_requires_certificate_verification() -> None:
    try:
        with TestClient(app) as client:
            headers = _admin(client)
            response = client.put(
                "/api/v1/settings/ldap",
                json=_ldap_body(verifyCertificate=False),
                headers=headers,
            )
            assert response.status_code == 422
            assert "인증서 검증" in response.json()["detail"]
    finally:
        _cleanup()


def test_plain_ldap_mode_is_explicitly_supported_for_ai_compatibility() -> None:
    try:
        with TestClient(app) as client:
            headers = _admin(client)
            response = client.put(
                "/api/v1/settings/ldap",
                json=_ldap_body(tlsMode="plain", verifyCertificate=True, caCertPath=""),
                headers=headers,
            )
            assert response.status_code == 200
            assert response.json()["tlsMode"] == "plain"
            assert response.json()["verifyCertificate"] is False
    finally:
        _cleanup()


def test_plain_ldap_bind_does_not_create_tls_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    server_options: dict[str, object] = {}

    class FakeServer:
        def __init__(self, host: str, **kwargs: object) -> None:
            server_options.update(kwargs)

    class FakeConnection:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.result = {"result": 0}

        def open(self) -> None:
            return None

        def bind(self) -> bool:
            return True

        def unbind(self) -> None:
            return None

    monkeypatch.setattr(ldap_auth, "Server", FakeServer)
    monkeypatch.setattr(ldap_auth, "Connection", FakeConnection)
    ldap_auth._bind(
        LdapConfig(
            host="ldap.example.test",
            port=389,
            tls_mode="plain",
            verify_certificate=False,
            ca_cert_path="",
            bind_dn="svc@example.test",
            bind_password="secret",
            base_dn="DC=example,DC=test",
            login_attribute="sAMAccountName",
            username_attribute="sAMAccountName",
            subject_attribute="objectGUID",
            user_filter="(sAMAccountName={username})",
            group_attribute="memberOf",
        ),
        "svc@example.test",
        "secret",
    )
    assert server_options["use_ssl"] is False
    assert server_options["tls"] is None


def test_admin_can_hard_delete_user_and_reuse_username() -> None:
    username = "delete-me-user"
    password = "long-enough-password"
    try:
        with TestClient(app) as client, TestClient(app) as user_client:
            headers = _admin(client)
            created = client.post(
                "/api/v1/users",
                json={"username": username, "password": password, "role": "uploader"},
                headers=headers,
            )
            assert created.status_code == 201
            login = user_client.post("/api/v1/auth/login", json={"username": username, "password": password})
            assert login.status_code == 200
            user_headers = {"X-CSRF-Token": login.json()["csrfToken"]}
            service = client.post("/api/v1/services", json={"slug": "deleted-user", "name": "삭제 사용자 서비스"}, headers=headers)
            environment = client.post("/api/v1/environments", json={"slug": "deleted-user", "name": "삭제 사용자 환경", "sortOrder": 3000}, headers=headers)
            assert service.status_code in {201, 409}
            assert environment.status_code in {201, 409}
            service_id = next(item["id"] for item in user_client.get("/api/v1/services").json() if item["slug"] == "deleted-user")
            environment_id = next(item["id"] for item in user_client.get("/api/v1/environments").json() if item["slug"] == "deleted-user")
            upload = user_client.post(
                "/api/v1/sbom-runs",
                data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": f"deleted-user-{base64.urlsafe_b64encode(username.encode()).decode()}"},
                files={"sbom": ("deleted-user.cdx.json", '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', "application/json")},
                headers=user_headers,
            )
            assert upload.status_code == 202
            run_id = upload.json()["runId"]
            deleted = client.delete(f"/api/v1/users/{created.json()['id']}", headers=headers)
            assert deleted.status_code == 200
            assert deleted.json()["status"] == "deleted"
            assert user_client.get("/api/v1/auth/me").status_code == 401
            with SessionLocal() as db:
                assert db.get(SbomRun, run_id).uploaded_by is None
            assert client.post("/api/v1/auth/login", json={"username": username, "password": password}).status_code == 401
            assert all(item["username"] != username for item in client.get("/api/v1/users").json())
            recreated = client.post(
                "/api/v1/users",
                json={"username": username, "password": password, "role": "viewer"},
                headers=headers,
            )
            assert recreated.status_code == 201
            assert recreated.json()["id"] != created.json()["id"]
    finally:
        _cleanup(username)


@dataclass
class _Entry:
    entry_dn: str
    entry_attributes_as_dict: dict[str, object]


class _Connection:
    def __init__(self, entries: list[_Entry], filters: list[str]) -> None:
        self.entries = entries
        self.filters = filters
        self.result = {"result": 0}

    def search(self, base: str, search_filter: str, *, attributes: list[str], size_limit: int) -> bool:
        self.filters.append(search_filter)
        return True

    def unbind(self) -> None:
        return None


def test_ldap_filter_escapes_input_and_requires_one_directory_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    filters: list[str] = []
    entry = _Entry(
        entry_dn="CN=LDAP User,DC=example,DC=test",
        entry_attributes_as_dict={
            "sAMAccountName": ["ldap-user"],
            "objectGUID": [b"\x01\x02"],
            "memberOf": ["CN=Readers,DC=example,DC=test"],
        },
    )
    calls: list[str] = []

    def fake_bind(config: LdapConfig, user: str, password: str) -> _Connection:
        calls.append(user)
        return _Connection([entry], filters)

    monkeypatch.setattr(ldap_auth, "_bind", fake_bind)
    config = LdapConfig(
        host="ldap.example.test",
        port=389,
        tls_mode="starttls",
        verify_certificate=True,
        ca_cert_path="",
        bind_dn="svc@example.test",
        bind_password="secret",
        base_dn="DC=example,DC=test",
        login_attribute="sAMAccountName",
        username_attribute="sAMAccountName",
        subject_attribute="objectGUID",
        user_filter="(sAMAccountName={username})",
        group_attribute="memberOf",
    )
    identity = authenticate_user(config, "a*)(uid=*)", "password")
    assert identity.username == "ldap-user"
    assert identity.subject == base64.urlsafe_b64encode(b"\x01\x02").rstrip(b"=").decode()
    assert "\\2a" in filters[0] and "\\29" in filters[0]
    assert calls == ["svc@example.test", "CN=LDAP User,DC=example,DC=test"]

    monkeypatch.setattr(ldap_auth, "_bind", lambda config, user, password: _Connection([entry, entry], []))
    with pytest.raises(LdapInvalidCredentials):
        authenticate_user(config, "one", "password")
