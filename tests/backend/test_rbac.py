from __future__ import annotations

import itertools
import json
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect as inspect_database, text
from sqlalchemy.orm import Session

from koda_tracker.db import Base, SessionLocal, ensure_environment_active_column, ensure_postgres_manager_enum, ensure_user_approval_state_column, ensure_user_identity_columns
from koda_tracker.main import app
from koda_tracker.models import Job, Role, RolePolicy, User
from koda_tracker.security import DEFAULT_ROLE_PERMISSIONS, PERMISSION_CATALOG, hash_password


_names = itertools.count()


def _unique(prefix: str) -> str:
    return f"rbac-{prefix}-{next(_names)}"


def _login(client: TestClient, username: str = "test-admin") -> tuple[dict, dict]:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": "correct-horse-battery-staple" if username == "test-admin" else "long-enough-password",
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return payload["user"], {"X-CSRF-Token": payload["csrfToken"]}


def _create_user(client: TestClient, headers: dict, role: str, prefix: str) -> dict:
    response = client.post(
        "/api/v1/users",
        json={"username": _unique(prefix), "password": "long-enough-password", "role": role},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_permission_catalog_and_default_role_policies_are_exact() -> None:
    with TestClient(app) as client:
        _, headers = _login(client)
        response = client.get("/api/v1/role-policies", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["catalog"] == list(PERMISSION_CATALOG)
        assert {item["role"] for item in payload["roles"]} == {role.value for role in Role}
        actual = {item["role"]: set(item["permissions"]) for item in payload["roles"]}
        assert actual == {role.value: permissions for role, permissions in DEFAULT_ROLE_PERMISSIONS.items()}


def test_login_and_me_return_policy_permissions_for_each_default_role() -> None:
    with TestClient(app) as admin_client:
        _, admin_headers = _login(admin_client)
        created = {
            role.value: _create_user(admin_client, admin_headers, role.value, role.value)
            for role in (Role.MANAGER, Role.ANALYST, Role.UPLOADER, Role.VIEWER)
        }
        for role, user in created.items():
            with TestClient(app) as client:
                login_user, _ = _login(client, user["username"])
                assert set(login_user["permissions"]) == DEFAULT_ROLE_PERMISSIONS[Role(role)]
                me = client.get("/api/v1/auth/me")
                assert me.status_code == 200
                assert set(me.json()["user"]["permissions"]) == DEFAULT_ROLE_PERMISSIONS[Role(role)]


def test_default_roles_have_representative_successes_and_forbidden_hidden_functions() -> None:
    with TestClient(app) as admin_client:
        _, admin_headers = _login(admin_client)
        users = {role.value: _create_user(admin_client, admin_headers, role.value, role.value) for role in (Role.MANAGER, Role.ANALYST, Role.UPLOADER, Role.VIEWER)}
    checks = {
        "manager": (("/api/v1/users", 200), ("/api/v1/role-policies", 403), ("/api/v1/api-tokens", 403)),
        "analyst": (("/api/v1/services", 200), ("/api/v1/users", 403), ("/api/v1/role-policies", 403)),
        "uploader": (("/api/v1/sbom-runs", 200), ("/api/v1/users", 403), ("/api/v1/api-tokens", 403)),
        "viewer": (("/api/v1/services", 200), ("/api/v1/users", 403), ("/api/v1/sbom-runs", 200)),
    }
    for role, expected in checks.items():
        with TestClient(app) as client:
            _login(client, users[role]["username"])
            for path, status in expected:
                assert client.get(path).status_code == status, (role, path)


def test_vulnerability_data_and_audit_log_are_admin_only() -> None:
    with TestClient(app) as admin:
        _, admin_headers = _login(admin)
        manager = _create_user(admin, admin_headers, "manager", "security-data")
        assert admin.get("/api/v1/audit-events").status_code == 200
        assert admin.get("/api/v1/vulnerability-data-bundles").status_code == 200
    with TestClient(app) as client:
        _login(client, manager["username"])
        assert client.get("/api/v1/audit-events").status_code == 403
        assert client.get("/api/v1/vulnerability-data-bundles").status_code == 403
        assert client.post("/api/v1/vulnerability-data-bundles/sync").status_code == 403


def test_read_apis_require_their_exact_permissions() -> None:
    with SessionLocal() as db:
        policy = db.get(RolePolicy, Role.ANALYST)
        original = list(policy.permissions)
        policy.permissions = ["dashboard.view"]
        job = Job(kind="rbac-test")
        db.add(job)
        db.commit()
        job_id = job.id
    try:
        with TestClient(app) as admin:
            _, headers = _login(admin)
            user = _create_user(admin, headers, "analyst", "dashboard-only")
        with TestClient(app) as client:
            _login(client, user["username"])
            assert client.get("/api/v1/sbom-runs").status_code == 403
            assert client.get("/api/v1/services").status_code == 403
            assert client.get("/api/v1/environments").status_code == 403
            assert client.get(f"/api/v1/jobs/{job_id}").status_code == 403
        with SessionLocal() as db:
            db.get(RolePolicy, Role.ANALYST).permissions = ["services.view"]
            db.commit()
        with TestClient(app) as client:
            _login(client, user["username"])
            assert client.get("/api/v1/services").status_code == 200
            assert client.get("/api/v1/environments").status_code == 200
            assert client.get("/api/v1/sbom-runs").status_code == 403
        with SessionLocal() as db:
            db.get(RolePolicy, Role.ANALYST).permissions = ["runs.view"]
            db.commit()
        with TestClient(app) as client:
            _login(client, user["username"])
            assert client.get("/api/v1/sbom-runs").status_code == 200
            assert client.get(f"/api/v1/jobs/{job_id}").status_code == 200
            assert client.get("/api/v1/services").status_code == 403
    finally:
        with SessionLocal() as db:
            db.get(RolePolicy, Role.ANALYST).permissions = original
            db.commit()


def test_manager_with_users_manage_only_can_manage_non_privileged_roles_but_not_admin_or_manager() -> None:
    with SessionLocal() as db:
        policy = db.get(RolePolicy, Role.MANAGER)
        original = list(policy.permissions)
        policy.permissions = ["users.manage"]
        db.commit()
    try:
        with TestClient(app) as admin:
            _, admin_headers = _login(admin)
            manager = _create_user(admin, admin_headers, "manager", "manager-only")
            privileged = {role: _create_user(admin, admin_headers, role, f"target-{role}") for role in ("admin", "manager")}
            ordinary = {role: _create_user(admin, admin_headers, role, f"target-{role}") for role in ("analyst", "uploader", "viewer")}
        with TestClient(app) as client:
            _, headers = _login(client, manager["username"])
            listed = {item["username"] for item in client.get("/api/v1/users").json()}
            assert privileged["admin"]["username"] not in listed
            assert privileged["manager"]["username"] not in listed
            assert {item["username"] for item in ordinary.values()} <= listed
            for role in ("analyst", "uploader", "viewer"):
                assert client.patch(f"/api/v1/users/{ordinary[role]['id']}", json={"active": False}, headers=headers).status_code == 200
            for role in ("admin", "manager"):
                target = privileged[role]
                assert client.post("/api/v1/users", json={"username": _unique(f"new-{role}"), "password": "long-enough-password", "role": role}, headers=headers).status_code == 403
                assert client.patch(f"/api/v1/users/{target['id']}", json={"role": "viewer"}, headers=headers).status_code == 403
                assert client.patch(f"/api/v1/users/{target['id']}", json={"active": False}, headers=headers).status_code == 403
    finally:
        with SessionLocal() as db:
            db.get(RolePolicy, Role.MANAGER).permissions = original
            db.commit()


def test_users_manage_cannot_approve_privileged_pending_account() -> None:
    pending_ids: list[str] = []
    with SessionLocal() as db:
        policy = db.get(RolePolicy, Role.MANAGER)
        original = list(policy.permissions)
        policy.permissions = ["users.manage"]
        for role in (Role.ADMIN, Role.MANAGER, Role.VIEWER):
            user = User(
                username=_unique(f"pending-{role.value}"),
                password_hash=hash_password("long-enough-password"),
                role=role,
                active=False,
                approval_state="pending",
            )
            db.add(user)
            db.flush()
            pending_ids.append(user.id)
        db.commit()
    try:
        with TestClient(app) as admin:
            _, admin_headers = _login(admin)
            manager = _create_user(admin, admin_headers, "manager", "approval-manager")
        with TestClient(app) as client:
            _, headers = _login(client, manager["username"])
            assert client.post(f"/api/v1/users/{pending_ids[0]}/approve", headers=headers).status_code == 403
            assert client.post(f"/api/v1/users/{pending_ids[1]}/approve", headers=headers).status_code == 403
            assert client.post(f"/api/v1/users/{pending_ids[2]}/approve", headers=headers).status_code == 200
    finally:
        with SessionLocal() as db:
            db.get(RolePolicy, Role.MANAGER).permissions = original
            for user_id in pending_ids:
                user = db.get(User, user_id)
                if user is not None:
                    db.delete(user)
            db.commit()


def test_administrative_user_creation_enforces_shared_password_policy() -> None:
    with TestClient(app) as client:
        _, headers = _login(client)
        short = client.post(
            "/api/v1/users",
            json={"username": _unique("short-password"), "password": "tiny", "role": "viewer"},
            headers=headers,
        )
        assert short.status_code == 422
        accepted = client.post(
            "/api/v1/users",
            json={"username": _unique("valid-password"), "password": "twelve-chars", "role": "viewer"},
            headers=headers,
        )
        assert accepted.status_code == 201


def test_role_policy_put_requires_csrf_changes_next_request_and_audits_before_after_actor() -> None:
    with TestClient(app) as client:
        _, headers = _login(client)
        before = client.get("/api/v1/role-policies").json()
        admin_before = next(item for item in before["roles"] if item["role"] == "admin")["permissions"]
        changed = [permission for permission in admin_before if permission != "services.view"]
        try:
            assert client.put("/api/v1/role-policies/admin", json={"permissions": admin_before}).status_code == 403
            response = client.put("/api/v1/role-policies/admin", json={"permissions": changed}, headers=headers)
            assert response.status_code == 200
            assert client.get("/api/v1/services").status_code == 403
            audit = next(item for item in client.get("/api/v1/audit-events").json()["items"] if item["action"] == "role_policy.update")
            assert audit["actor"] == "test-admin"
            assert audit["targetId"] == "admin"
            assert audit["detail"]["before"] == admin_before
            assert audit["detail"]["after"] == changed
        finally:
            assert client.put("/api/v1/role-policies/admin", json={"permissions": admin_before}, headers=headers).status_code == 200


def test_bulk_role_policy_put_is_csrf_protected_and_atomic() -> None:
    with TestClient(app) as client:
        _, headers = _login(client)
        before = client.get("/api/v1/role-policies").json()["roles"]
        original = {item["role"]: item["permissions"] for item in before}
        body = {"roles": {"analyst": ["runs.view"], "viewer": ["unknown.permission"]}}
        assert client.put("/api/v1/role-policies", json=body).status_code == 403
        assert client.put("/api/v1/role-policies", json=body, headers=headers).status_code == 422
        assert client.put(
            "/api/v1/role-policies",
            json={"roles": {"viewer": ["runs.view", "sbom.delete"]}},
            headers=headers,
        ).status_code == 422
        after = client.get("/api/v1/role-policies").json()["roles"]
        assert {item["role"]: item["permissions"] for item in after} == original
        changed = {"roles": {"analyst": ["runs.view"], "viewer": ["runs.view"]}}
        try:
            response = client.put("/api/v1/role-policies", json=changed, headers=headers)
            assert response.status_code == 200
            assert {item["role"] for item in response.json()["roles"]} == {"analyst", "viewer"}
        finally:
            restore = {"roles": {role: original[role] for role in ("analyst", "viewer")}}
            assert client.put("/api/v1/role-policies", json=restore, headers=headers).status_code == 200


def test_invalid_bearer_does_not_fall_back_to_browser_session() -> None:
    with TestClient(app) as client:
        _login(client)
        assert client.get("/api/v1/services", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_upload_only_browser_user_can_read_only_its_own_job() -> None:
    with SessionLocal() as db:
        policy = db.get(RolePolicy, Role.ANALYST)
        original = list(policy.permissions)
        policy.permissions = ["sbom.upload"]
        db.commit()
    try:
        with TestClient(app) as client:
            _, admin_headers = _login(client)
            service_id = client.get("/api/v1/services").json()[0]["id"]
            environment_id = client.get("/api/v1/environments").json()[0]["id"]
            user = _create_user(client, admin_headers, "analyst", "upload-only")
            client.cookies.clear()
            _, headers = _login(client, user["username"])
            upload = client.post(
                "/api/v1/sbom-runs",
                data={"serviceId": service_id, "environmentId": environment_id, "releaseVersion": _unique("upload")},
                files={"sbom": ("empty.cdx.json", json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}), "application/json")},
                headers=headers,
            )
            assert upload.status_code == 202, upload.text
            assert client.get(f"/api/v1/jobs/{upload.json()['jobId']}").status_code == 200
            with SessionLocal() as db:
                foreign_job = Job(kind="foreign")
                db.add(foreign_job)
                db.commit()
                foreign_job_id = foreign_job.id
            assert client.get(f"/api/v1/jobs/{foreign_job_id}").status_code == 403
            assert client.get("/api/v1/services").status_code == 403
    finally:
        with SessionLocal() as db:
            db.get(RolePolicy, Role.ANALYST).permissions = original
            db.commit()


def test_policy_and_user_changes_cannot_remove_last_active_management_principal() -> None:
    with TestClient(app) as client:
        admin, headers = _login(client)
        policy = client.get("/api/v1/role-policies").json()
        admin_permissions = next(item["permissions"] for item in policy["roles"] if item["role"] == "admin")
        assert "roles.manage" in admin_permissions
        rejected = client.put("/api/v1/role-policies/admin", json={"permissions": ["roles.manage"]}, headers=headers)
        assert rejected.status_code == 422, rejected.text
        assert client.patch(f"/api/v1/users/{admin['id']}", json={"active": False}, headers=headers).status_code == 422
        assert client.put("/api/v1/role-policies/admin", json={"permissions": admin_permissions}, headers=headers).status_code == 200


def test_startup_seeds_only_missing_policies_and_preserves_custom_permissions() -> None:
    with SessionLocal() as db:
        db.delete(db.get(RolePolicy, Role.VIEWER))
        db.get(RolePolicy, Role.ANALYST).permissions = ["runs.view"]
        db.commit()
    try:
        with TestClient(app):
            pass
        with SessionLocal() as db:
            assert set(db.get(RolePolicy, Role.VIEWER).permissions) == DEFAULT_ROLE_PERMISSIONS[Role.VIEWER]
            assert db.get(RolePolicy, Role.ANALYST).permissions == ["runs.view"]
    finally:
        with SessionLocal() as db:
            db.get(RolePolicy, Role.ANALYST).permissions = sorted(DEFAULT_ROLE_PERMISSIONS[Role.ANALYST])
            db.commit()


def test_startup_backfills_admin_delete_permission_and_removes_it_from_other_roles() -> None:
    with SessionLocal() as db:
        admin = db.get(RolePolicy, Role.ADMIN)
        manager = db.get(RolePolicy, Role.MANAGER)
        admin_before = list(admin.permissions)
        manager_before = list(manager.permissions)
        admin.permissions = [permission for permission in admin.permissions if permission != "sbom.delete"]
        manager.permissions = sorted(set(manager.permissions) | {"sbom.delete"})
        db.commit()
    try:
        with TestClient(app):
            pass
        with SessionLocal() as db:
            assert "sbom.delete" in db.get(RolePolicy, Role.ADMIN).permissions
            assert "sbom.delete" not in db.get(RolePolicy, Role.MANAGER).permissions
    finally:
        with SessionLocal() as db:
            db.get(RolePolicy, Role.ADMIN).permissions = admin_before
            db.get(RolePolicy, Role.MANAGER).permissions = manager_before
            db.commit()


def test_sqlite_legacy_user_table_accepts_manager_without_rebuild() -> None:
    legacy = create_engine("sqlite://")
    with legacy.begin() as connection:
        connection.execute(text("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(128) UNIQUE, password_hash TEXT, role VARCHAR(8), active BOOLEAN, created_at DATETIME)"))
        connection.execute(text("INSERT INTO users VALUES ('legacy', 'legacy-admin', 'x', 'ADMIN', 1, CURRENT_TIMESTAMP)"))
    Base.metadata.create_all(legacy)
    ensure_user_approval_state_column(legacy)
    ensure_user_approval_state_column(legacy)
    ensure_user_identity_columns(legacy)
    ensure_user_identity_columns(legacy)
    with Session(legacy) as db:
        db.add(User(username="sqlite-manager", password_hash="not-used", role=Role.MANAGER))
        db.commit()
        assert db.scalar(text("SELECT role FROM users WHERE username = 'sqlite-manager'")) == "MANAGER"
        assert db.scalar(text("SELECT approval_state FROM users WHERE username = 'legacy-admin'")) == "approved"


def test_environment_active_migration_is_additive_and_idempotent() -> None:
    legacy = create_engine("sqlite://")
    with legacy.begin() as connection:
        connection.execute(text("CREATE TABLE environments (id VARCHAR(36) PRIMARY KEY, slug VARCHAR(64), name VARCHAR(128), sort_order INTEGER)"))
        connection.execute(text("INSERT INTO environments VALUES ('prod', 'prod', '운영', 1)"))

    ensure_environment_active_column(legacy)
    ensure_environment_active_column(legacy)

    assert "active" in {column["name"] for column in inspect_database(legacy).get_columns("environments")}
    with legacy.connect() as connection:
        assert bool(connection.scalar(text("SELECT active FROM environments WHERE id = 'prod'"))) is True


def test_postgres_manager_enum_migration_is_fresh_db_safe_and_idempotent() -> None:
    class Connection:
        def __init__(self, type_exists: bool = True) -> None:
            self.statements: list[str] = []
            self.type_exists = type_exists

        def execute(self, statement):
            self.statements.append(str(statement))

        def scalar(self, statement):
            return self.type_exists

    class Engine:
        class Dialect:
            name = "postgresql"

        dialect = Dialect()

        def __init__(self) -> None:
            self.connection = Connection()

        @contextmanager
        def begin(self):
            yield self.connection

    fake = Engine()
    ensure_postgres_manager_enum(fake)
    ensure_postgres_manager_enum(fake)
    assert fake.connection.statements == ["ALTER TYPE role ADD VALUE IF NOT EXISTS 'MANAGER'"] * 2

    fresh = Engine()
    fresh.connection = Connection(type_exists=False)
    ensure_postgres_manager_enum(fresh)
    assert fresh.connection.statements == []
