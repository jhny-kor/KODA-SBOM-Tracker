"""Regression: reopen a frozen pre-feature DB through the real application startup.

The SQL below is frozen from the core schema before library/CVE/environment-admin
features. It deliberately does not use current Base.metadata to create the old
installation, and does not include environment_administrators.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker

from koda_tracker import config, db as database, main, security
from koda_tracker.config import Settings
from koda_tracker.models import (AnalysisRevision, ApiToken, AuditEvent, Environment, FeatureUpgrade, LdapSettings,
    ProcessingState, JobState, Release, Role, RolePolicy, RunComponent, SbomPolicyRevision, SbomRun, Service, User, UserSession,
    VulnerabilityDataBundle)
from koda_tracker.reanalysis import ReanalysisSchedule

LEGACY_DDL = (
    'CREATE TABLE audit_events ( id VARCHAR(36) NOT NULL, actor VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, target_type VARCHAR(64) NOT NULL, target_id VARCHAR(128) NOT NULL, detail JSON NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (id) )',
    'CREATE TABLE environments ( id VARCHAR(36) NOT NULL, slug VARCHAR(64) NOT NULL, name VARCHAR(128) NOT NULL, sort_order INTEGER NOT NULL, active BOOLEAN NOT NULL, PRIMARY KEY (id), UNIQUE (slug) )',
    'CREATE TABLE feature_upgrades ( name VARCHAR(128) NOT NULL, applied_at DATETIME NOT NULL, PRIMARY KEY (name) )',
    'CREATE TABLE ldap_settings ( id VARCHAR(16) NOT NULL, enabled BOOLEAN NOT NULL, host VARCHAR(253) NOT NULL, port INTEGER NOT NULL, tls_mode VARCHAR(16) NOT NULL, verify_certificate BOOLEAN NOT NULL, ca_cert_path TEXT NOT NULL, bind_dn VARCHAR(512) NOT NULL, bind_password_ciphertext TEXT, base_dn VARCHAR(512) NOT NULL, login_attribute VARCHAR(128) NOT NULL, username_attribute VARCHAR(128) NOT NULL, subject_attribute VARCHAR(128) NOT NULL, user_filter VARCHAR(512) NOT NULL, group_attribute VARCHAR(128) NOT NULL, group_mappings JSON NOT NULL, auto_provision BOOLEAN NOT NULL, default_role VARCHAR(8) NOT NULL, updated_at DATETIME NOT NULL, PRIMARY KEY (id) )',
    'CREATE TABLE reanalysis_schedule ( id VARCHAR(16) NOT NULL, version INTEGER NOT NULL, enabled BOOLEAN NOT NULL, interval_minutes INTEGER NOT NULL, on_data_update BOOLEAN NOT NULL, latest_only BOOLEAN NOT NULL, service_ids JSON NOT NULL, environment_ids JSON NOT NULL, next_run_at DATETIME, last_run_at DATETIME, last_data_revision VARCHAR(255), rerun_requested BOOLEAN NOT NULL, PRIMARY KEY (id) )',
    'CREATE TABLE role_policies ( role VARCHAR(8) NOT NULL, permissions JSON NOT NULL, updated_at DATETIME NOT NULL, PRIMARY KEY (role) )',
    'CREATE TABLE sbom_policy_revisions ( version INTEGER NOT NULL, document JSON NOT NULL, created_by VARCHAR(128) NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (version) )',
    'CREATE TABLE services ( id VARCHAR(36) NOT NULL, slug VARCHAR(128) NOT NULL, name VARCHAR(255) NOT NULL, active BOOLEAN NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (id) )',
    'CREATE TABLE users ( id VARCHAR(36) NOT NULL, username VARCHAR(128) NOT NULL, password_hash TEXT NOT NULL, role VARCHAR(8) NOT NULL, active BOOLEAN NOT NULL, approval_state VARCHAR(16) NOT NULL, auth_source VARCHAR(16) NOT NULL, ldap_subject VARCHAR(512), created_at DATETIME NOT NULL, PRIMARY KEY (id), UNIQUE (ldap_subject) )',
    'CREATE TABLE vulnerability_data_bundles ( id VARCHAR(36) NOT NULL, version VARCHAR(128) NOT NULL, sha256 VARCHAR(64) NOT NULL, data_as_of VARCHAR(64) NOT NULL, manifest JSON NOT NULL, active BOOLEAN NOT NULL, imported_at DATETIME NOT NULL, PRIMARY KEY (id), UNIQUE (version) )',
    'CREATE TABLE api_tokens ( id VARCHAR(36) NOT NULL, name VARCHAR(128) NOT NULL, token_hash VARCHAR(64) NOT NULL, service_id VARCHAR(36), active BOOLEAN NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (id), UNIQUE (token_hash), FOREIGN KEY(service_id) REFERENCES services (id) )',
    'CREATE TABLE releases ( id VARCHAR(36) NOT NULL, service_id VARCHAR(36) NOT NULL, environment_id VARCHAR(36) NOT NULL, version VARCHAR(255) NOT NULL, PRIMARY KEY (id), UNIQUE (service_id, environment_id, version), FOREIGN KEY(service_id) REFERENCES services (id), FOREIGN KEY(environment_id) REFERENCES environments (id) )',
    'CREATE TABLE user_sessions ( id_hash VARCHAR(64) NOT NULL, user_id VARCHAR(36) NOT NULL, csrf_hash VARCHAR(64) NOT NULL, expires_at DATETIME NOT NULL, created_at DATETIME NOT NULL, PRIMARY KEY (id_hash), FOREIGN KEY(user_id) REFERENCES users (id) )',
    'CREATE TABLE sbom_runs ( id VARCHAR(36) NOT NULL, release_id VARCHAR(36) NOT NULL, round_number INTEGER NOT NULL, state VARCHAR(10) NOT NULL, analysis_state VARCHAR(9) NOT NULL, source VARCHAR(32) NOT NULL, original_filename VARCHAR(255) NOT NULL, media_type VARCHAR(64) NOT NULL, spec_version VARCHAR(16) NOT NULL, serial_number VARCHAR(255), sha256 VARCHAR(64) NOT NULL, size_bytes INTEGER NOT NULL, artifact_path TEXT NOT NULL, normalized_bom JSON NOT NULL, uploaded_by VARCHAR(36), idempotency_actor VARCHAR(128), idempotency_key VARCHAR(255), note TEXT NOT NULL, source_metadata JSON NOT NULL, archived_at DATETIME, archive_reason TEXT, created_at DATETIME NOT NULL, PRIMARY KEY (id), UNIQUE (release_id, round_number), UNIQUE (idempotency_actor, idempotency_key), FOREIGN KEY(release_id) REFERENCES releases (id), FOREIGN KEY(uploaded_by) REFERENCES users (id) )',
    'CREATE TABLE analysis_revisions ( id VARCHAR(36) NOT NULL, run_id VARCHAR(36) NOT NULL, sequence INTEGER NOT NULL, state VARCHAR(9) NOT NULL, data_as_of VARCHAR(64) NOT NULL, tool_version VARCHAR(64) NOT NULL, data_sources JSON NOT NULL, findings JSON NOT NULL, policies JSON NOT NULL, policy_state VARCHAR(32) NOT NULL, policy_version INTEGER, policy_snapshot JSON NOT NULL, policy_error TEXT, metrics JSON NOT NULL, error TEXT, created_at DATETIME NOT NULL, PRIMARY KEY (id), UNIQUE (run_id, sequence), FOREIGN KEY(run_id) REFERENCES sbom_runs (id) )',
    'CREATE TABLE run_components ( id VARCHAR(36) NOT NULL, run_id VARCHAR(36) NOT NULL, identity_key VARCHAR(1024) NOT NULL, identity_status VARCHAR(32) NOT NULL, component_type VARCHAR(64) NOT NULL, group_name VARCHAR(512) NOT NULL, name VARCHAR(512) NOT NULL, version VARCHAR(255) NOT NULL, purl TEXT NOT NULL, bom_ref TEXT NOT NULL, search_text TEXT NOT NULL, sha256 VARCHAR(64) NOT NULL, licenses JSON NOT NULL, properties JSON NOT NULL, PRIMARY KEY (id), FOREIGN KEY(run_id) REFERENCES sbom_runs (id) )',
)


def _legacy_installation(engine, artifact, ldap_key):
    stamp = datetime(2026, 10, 19, 10, 30, tzinfo=UTC)
    description = "기존에 보관한 긴 라이브러리 설명과 경로를 유지합니다. " * 180
    component = {"type": "library", "name": "upgrade-example", "version": "1.0.0", "purl": "pkg:pypi/upgrade-example@1.0.0",
                 "description": description, "licenses": [{"license": {"id": "MIT"}}]}
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [component]}
    original = json.dumps(bom, ensure_ascii=False, indent=2).encode()
    artifact.write_bytes(original)
    sha = hashlib.sha256(original).hexdigest()
    password = "upgrade-fixture-only-password-42"
    password_hash = security.hash_password(password)
    findings = [{"id": "CVE-2026-10001", "canonicalId": "CVE-2026-10001", "component": component["purl"],
                 "version": "1.0.0", "severity": "High", "description": description, "fixedIn": ["1.0.1"]}]
    with engine.begin() as connection:
        for statement in LEGACY_DDL:
            connection.execute(text(statement))
    runs = Table("sbom_runs", MetaData(), autoload_with=engine)
    with Session(engine) as session:
        session.add_all([
            User(id="old-admin", username="upgrade-admin", role=Role.ADMIN, password_hash=password_hash, active=True, approval_state="approved", auth_source="local", created_at=stamp),
            User(id="old-reader", username="upgrade-reader", role=Role.VIEWER, password_hash=password_hash, active=True, approval_state="approved", auth_source="local", created_at=stamp),
            Service(id="old-service", slug="upgrade-service", name="기존 결제 서비스", active=True, created_at=stamp),
            Environment(id="old-prod", slug="prod", name="기존 운영 환경", sort_order=40, active=True),
        ])
        session.flush()
        session.add(Release(id="old-release", service_id="old-service", environment_id="old-prod", version="2026.10.1"))
        session.flush()
        common = dict(release_id="old-release", analysis_state=JobState.COMPLETED.name, source="manual",
                      media_type="application/json", spec_version="1.6", sha256=sha, size_bytes=len(original),
                      artifact_path=str(artifact), normalized_bom=bom, uploaded_by="old-admin", note="",
                      serial_number=None, idempotency_actor=None, idempotency_key=None, archived_at=None, archive_reason=None)
        session.execute(runs.insert(), [
            dict(common, id="old-run", round_number=3, state=ProcessingState.COMPLETED.name,
                 source_metadata={"originalSource": "preserved"}, original_filename="기존-업로드-SBOM.json",
                 serial_number="urn:uuid:legacy-upgrade", idempotency_actor="user:old-admin", idempotency_key="legacy-upload",
                 note="기존 검토 메모", created_at=stamp),
            dict(common, id="old-archive", round_number=1, state=ProcessingState.ARCHIVED.name,
                 source_metadata={}, original_filename="기존-보관-SBOM.json",
                 archived_at=stamp, archive_reason="기존 보관 사유", created_at=stamp - timedelta(days=365)),
        ])
        session.flush()
        session.add_all([
            RunComponent(id="old-component", run_id="old-run", identity_key="purl:pkg:pypi/upgrade-example", identity_status="identified",
                         component_type="library", name="upgrade-example", group_name="", version="1.0.0", purl=component["purl"], bom_ref="old-ref",
                         search_text="upgrade-example 1.0.0 pkg:pypi/upgrade-example@1.0.0 old-ref", sha256="b" * 64,
                         licenses=[{"license": {"id": "MIT"}}], properties=[{"name": "old-description", "value": description}]),
            AnalysisRevision(id="old-analysis", run_id="old-run", sequence=4, state=JobState.COMPLETED, data_as_of="2026-10-19", tool_version="legacy-test",
                             data_sources={"nvd": {"dataAsOf": "2026-10-19"}}, findings=findings,
                             policies=[{"id": "old-rule", "status": "warn", "description": description}], policy_state="completed", policy_version=9,
                             policy_snapshot={"name": "기존 사용자 정책"}, metrics={"policyViolationCount": 1, "policyWarnCount": 1}, created_at=stamp),
            RolePolicy(role=Role.ADMIN, permissions=sorted(security.DEFAULT_ROLE_PERMISSIONS[Role.ADMIN]), updated_at=stamp),
            RolePolicy(role=Role.VIEWER, permissions=["artifact.download", "runs.view"], updated_at=stamp),
            UserSession(id_hash=security.digest("legacy-admin-session"), user_id="old-admin", csrf_hash=security.digest("legacy-admin-csrf"),
                        expires_at=datetime.now(UTC) + timedelta(hours=2), created_at=stamp),
            UserSession(id_hash=security.digest("legacy-reader-session"), user_id="old-reader", csrf_hash=security.digest("legacy-reader-csrf"),
                        expires_at=datetime.now(UTC) + timedelta(hours=2), created_at=stamp),
            ApiToken(id="old-token", name="기존 업로드 연동", token_hash=security.digest("legacy-integration-token"), service_id="old-service", active=True, created_at=stamp),
            LdapSettings(id="default", enabled=False, host="directory.example.invalid", port=636, tls_mode="ldaps", verify_certificate=True,
                         bind_dn="cn=reader,dc=example,dc=invalid", bind_password_ciphertext=Fernet(ldap_key).encrypt(b"fixture LDAP bind password").decode(), base_dn="dc=example,dc=invalid",
                         group_mappings={"existing-group": "viewer"}, subject_attribute="entryUUID", default_role=Role.VIEWER, updated_at=stamp),
            ReanalysisSchedule(id="default", version=7, enabled=False, interval_minutes=4320, on_data_update=False, latest_only=True,
                               service_ids=["old-service"], environment_ids=["old-prod"], next_run_at=None, last_data_revision="old-data", rerun_requested=False),
            SbomPolicyRevision(version=9, document={"name": "기존 사용자 정책", "rules": [], "exceptions": []}, created_by="old-admin", created_at=stamp),
            AuditEvent(id="old-audit", actor="upgrade-admin", action="sbom.upload", target_type="sbom_run", target_id="old-run",
                       detail={"sha256": sha, "historical": True}, created_at=stamp),
            VulnerabilityDataBundle(id="old-bundle", version="old-offline-release", sha256="c" * 64, data_as_of="2026-10-19",
                                    manifest={"originalApprovedRelease": True}, active=True, imported_at=stamp),
        ])
        for name in ("ssvc-deployer-v1", "metadata-migration-v1", "nuget-semver2-v1"):
            session.add(FeatureUpgrade(name=name, applied_at=stamp))
        session.commit()
    return original, password


def _snapshot(engine):
    reflected = MetaData()
    reflected.reflect(engine)
    with engine.connect() as connection:
        return {name: {tuple(row[column.name] for column in table.primary_key): dict(row)
                       for row in connection.execute(select(table)).mappings()}
                for name, table in reflected.tables.items()}


def _assert_existing_records_preserved(engine, before):
    after = _snapshot(engine)
    for table_name, rows in before.items():
        for identity, old_values in rows.items():
            assert identity in after[table_name], (table_name, "existing row removed")
            for column, value in old_values.items():
                assert after[table_name][identity][column] == value, (table_name, column, "existing value changed")


@pytest.mark.parametrize("older_columns", [False, True], ids=["pre-feature-schema", "older-additive-schema"])
def test_existing_database_survives_real_startup_restart_and_new_administration(tmp_path, monkeypatch, older_columns):
    database_path = tmp_path / "legacy-tracker.db"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    artifact = artifact_root / "original-sbom.json"
    old_engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    ldap_key = Fernet.generate_key()
    original, password = _legacy_installation(old_engine, artifact, ldap_key)
    assert "environment_administrators" not in inspect(old_engine).get_table_names()
    if older_columns:
        # These guarded migrations predate this feature. The application must
        # still add them without rewriting the findings or original upload.
        missing = {"users": ["approval_state", "auth_source"], "environments": ["active"],
                   "sbom_runs": ["source_metadata"], "run_components": ["search_text"], "ldap_settings": ["subject_attribute"],
                   "analysis_revisions": ["data_sources", "policy_state", "policy_version", "policy_snapshot", "policy_error", "metrics"]}
        with old_engine.begin() as connection:
            for table_name, columns in missing.items():
                for column in columns:
                    connection.execute(text(f'ALTER TABLE "{table_name}" DROP COLUMN "{column}"'))
    before = _snapshot(old_engine)
    old_engine.dispose()

    upgraded_engine = create_engine(f"sqlite:///{database_path}", connect_args={"check_same_thread": False})
    sessions = sessionmaker(bind=upgraded_engine, autoflush=False, expire_on_commit=False)
    settings = Settings(database_url=f"sqlite:///{database_path}", artifact_dir=artifact_root, environment="test", public_bind="127.0.0.1",
                        bootstrap_admin_username="upgrade-admin", bootstrap_admin_password="", secure_cookies=False,
                        ldap_encryption_key=ldap_key.decode(), offline_mode=True)
    monkeypatch.setattr(main, "engine", upgraded_engine)
    monkeypatch.setattr(main, "SessionLocal", sessions)
    monkeypatch.setattr(database, "SessionLocal", sessions)
    for module in (main, config, security):
        monkeypatch.setattr(module, "get_settings", lambda: settings)
    try:
        # A real TestClient starts and stops the application's lifespan, unlike
        # calling create_all in a unit test. Reopening proves idempotence too.
        for restart in range(2):
            with TestClient(main.app) as client:
                _assert_existing_records_preserved(upgraded_engine, before)
                assert "environment_administrators" in inspect(upgraded_engine).get_table_names()
                assert "run_component_corrections" in inspect(upgraded_engine).get_table_names()
                assert "sbom_document_records" in inspect(upgraded_engine).get_table_names()
                assert artifact.read_bytes() == original
                with sessions() as session:
                    assert session.get(SbomRun, "old-run").split_document is False
                    ldap = main._ldap_row_config(session.get(LdapSettings, "default"))
                    assert ldap.host == "directory.example.invalid" and ldap.bind_password == "fixture LDAP bind password"
                client.cookies.set("koda_session", "legacy-reader-session")
                if restart == 0:
                    assert client.get("/api/v1/sbom-runs/old-run").status_code == 404
                    assert client.get("/api/v1/libraries").json()["total"] == 0
                    client.cookies.set("koda_session", "legacy-admin-session")
                detail = client.get("/api/v1/sbom-runs/old-run")
                assert detail.status_code == 200
                assert detail.json()["filename"] == "기존-업로드-SBOM.json"
                assert detail.json()["releaseVersion"] == "2026.10.1"
                findings = client.get("/api/v1/sbom-runs/old-run/findings", params={"analysisId": "old-analysis"})
                assert findings.status_code == 200 and findings.json()["items"][0]["id"] == "CVE-2026-10001"
                assert detail.json()["policyState"] == ("not_evaluated" if older_columns else "completed")
                download = client.get("/api/v1/sbom-runs/old-run/artifact")
                assert download.status_code == 200 and download.content == original
                libraries = client.get("/api/v1/libraries", params={"q": "upgrade-example"})
                assert libraries.status_code == 200 and libraries.json()["total"] == 1
                assert libraries.json()["items"][0]["currentVersions"] == ["1.0.0"]
                client.cookies.clear()
                integration = client.get("/api/v1/integrations/koda/runs/old-run", headers={"Authorization": "Bearer legacy-integration-token"})
                assert integration.status_code == 200 and integration.json()["run"]["sha256"] == hashlib.sha256(original).hexdigest()
                if restart == 0:
                    client.cookies.set("koda_session", "legacy-admin-session")
                    result = client.put("/api/v1/environment-administrators/old-prod", json={"userIds": ["old-reader"]}, headers={"X-CSRF-Token": "legacy-admin-csrf"})
                    assert result.status_code == 200
                else:
                    client.cookies.set("koda_session", "legacy-admin-session")
                    assignments = client.get("/api/v1/environment-administrators")
                    assert assignments.status_code == 200
                    env = next(item for item in assignments.json()["environments"] if item["id"] == "old-prod")
                    assert [user["id"] for user in env["administrators"]] == ["old-reader"]
                    client.cookies.set("koda_session", "legacy-reader-session")
                    assert client.get("/api/v1/sbom-runs/old-run/edit-permission").json()["canEdit"] is True
                    assert client.get("/api/v1/environment-administrators").status_code == 403
        # Original passwords still authenticate after upgrade/restart; startup
        # must not silently rotate an already configured account.
        with TestClient(main.app) as client:
            result = client.post("/api/v1/auth/login", json={"username": "upgrade-admin", "password": password})
            assert result.status_code == 200 and result.json()["user"]["id"] == "old-admin"
            _assert_existing_records_preserved(upgraded_engine, before)
            assert artifact.read_bytes() == original
    finally:
        upgraded_engine.dispose()
