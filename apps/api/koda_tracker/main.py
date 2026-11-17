from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import ipaddress
import io
import json
import logging
import re
import secrets
import tempfile
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import Text, cast, delete, func, inspect, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from starlette.concurrency import run_in_threadpool

from .external_api import router as external_router
from .java_impact import router as java_impact_router
from .shared_ai import KodaFindingReviewRequest, KodaSummaryFacts, review_koda_finding, router as ai_router, summarize_koda_facts
from .upgrade_batches import router as upgrade_batches_router
from .compatibility_data import router as compatibility_data_router
from .compatibility_sources import MAX_ARCHIVE_BYTES as MAX_COMPATIBILITY_ARCHIVE_BYTES
from .config import get_settings, session_cookie_name
from .comparison import compare_components, compare_records
from .db import Base, SessionLocal, engine, ensure_component_search_support, ensure_environment_active_column, ensure_ldap_subject_attribute_column, ensure_native_policy_columns, ensure_postgres_manager_enum, ensure_sbom_media_type_column, ensure_sbom_size_bytes_column, ensure_sbom_source_metadata_column, ensure_user_approval_state_column, ensure_user_identity_columns, get_db
from .models import (
    AnalysisRevision,
    ApiToken,
    AuthAttempt,
    AuditEvent,
    Environment,
    FeatureUpgrade,
    Job,
    JobState,
    LdapSettings,
    ProcessingState,
    Release,
    Role,
    RolePolicy,
    RunComponent,
    SbomRun,
    SbomPolicyRevision,
    Service,
    User,
    UserSession,
    VulnerabilityDataBundle,
)
from .sbom_normalization import mark_current
from .sbom import (
    SbomValidationError,
    component_count,
    parse_sbom_upload_document,
    sbom_document_path,
    sbom_upload_media_type,
    store_artifact_file,
    validate_component_count,
    validate_file_with_cyclonedx_cli,
)
from .collection_coverage import coverage_for_bom
from .sbom_workbook import MAX_WORKBOOK_BYTES, METADATA_LABELS, WORKBOOK_MEDIA_TYPE
from .security import (
    current_principal,
    digest,
    hash_password,
    require_admin,
    issue_session,
    require_csrf,
    require_permission,
    rotate_csrf,
    verify_password,
    DEFAULT_ROLE_PERMISSIONS,
    PERMISSION_CATALOG,
)
from .services import audit, create_components, enqueue
from .policies import PolicyDocument, get_policy_document, validate_policy_expressions, validate_expression, preview_expression, policy_context_for_run, components_with_dependency_graph
from . import package_metadata_models, vulnerability_intelligence_models
from .vulnerability_intelligence_api import router as vulnerability_intelligence_router
from .private_vulnerability_api import router as private_vulnerability_router
from . import private_vulnerability_models
from .project_catalog_api import router as project_catalog_router
from .project_catalog_models import NativeReanalysisPending
from .package_metadata_api import router as package_metadata_router
from .package_metadata import enrich_components
from . import workflow_models
from .reanalysis import ReanalysisSchedule, get_schedule
from .reanalysis_api import router as reanalysis_router
from .workflow_api import router as workflow_router
from .ssvc_api import router as ssvc_router
from .offline_intelligence_api import router as offline_intelligence_router
from .quality_api import router as quality_router
from .ci_gate import router as ci_gate_router
from .environment_admin_api import router as environment_admin_router
from .library_api import router as library_router
from .cve_catalog_api import router as cve_catalog_router
from .vulnerability import active_bundle, cvss_score, project_cve_findings, scan_bundle_releases, vulnerable_component_count
from .ldap_auth import LdapConfig, LdapConfigurationError, LdapInvalidCredentials, LdapUnavailable, authenticate_user


logger = logging.getLogger(__name__)
KNOWN_PASSWORD_PLACEHOLDERS = {
    "change-me-admin-password",
    "change-me",
    "password",
    "admin",
}


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Reject oversized bodies before JSON or multipart parsing allocates them."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _limit(scope: dict) -> int:
        settings = get_settings()
        path = scope.get("path", "")
        method = scope.get("method", "GET")
        if method == "POST" and path == "/api/v1/compatibility-data/import":
            return MAX_COMPATIBILITY_ARCHIVE_BYTES + 64 * 1024
        if method == "POST" and path == "/api/v1/upgrade-batches/import":
            return 1024 * 1024
        if method == "POST" and path == "/api/v1/sbom-runs":
            return settings.max_upload_bytes + (2 * 1024 * 1024)
        if method == "POST" and path == "/api/v1/offline-intelligence/import":
            return 192 * 1024 * 1024
        if method == "POST" and path == "/api/v1/vulnerability-intelligence/import-csv":
            return (64 * 1024 * 1024) + (2 * 1024 * 1024)
        if method == "POST" and path == "/api/v1/vulnerability-data-bundles/upload":
            return (2 * 1024 * 1024 * 1024) + (2 * 1024 * 1024)
        if method == "POST" and path in {"/api/v1/package-metadata/import", "/api/v1/vulnerability-intelligence/import"}:
            return 64 * 1024 * 1024 + 1024
        if method == "PUT" and path == "/api/v1/sbom-policies":
            return 1024 * 1024
        return settings.max_request_body_bytes

    @staticmethod
    def _response(path: str) -> JSONResponse:
        return JSONResponse(
            status_code=413,
            content={
                "type": "about:blank",
                "title": "요청을 처리할 수 없습니다",
                "status": 413,
                "detail": "요청 본문이 허용된 크기를 초과했습니다",
                "instance": path,
            },
            media_type="application/problem+json",
        )

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit(scope)
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length", b"")
        if raw_length:
            try:
                if int(raw_length) > limit:
                    await self._response(scope.get("path", ""))(scope, receive, send)
                    return
            except ValueError:
                await self._response(scope.get("path", ""))(scope, receive, send)
                return

        # For small control-plane routes, pre-read at most 64 KiB so a client
        # cannot bypass the 413 response by omitting Content-Length. Large
        # upload routes keep streaming to disk and retain their own bounds.
        if (
            not raw_length
            and scope.get("method") in {"POST", "PUT", "PATCH", "DELETE"}
            and limit == get_settings().max_request_body_bytes
        ):
            buffered: list[dict] = []
            total = 0
            while True:
                message = await receive()
                buffered.append(message)
                if message.get("type") == "http.request":
                    total += len(message.get("body", b""))
                    if total > limit:
                        await self._response(scope.get("path", ""))(scope, receive, send)
                        return
                    if not message.get("more_body", False):
                        break
                elif message.get("type") == "http.disconnect":
                    break

            async def buffered_receive():
                if buffered:
                    return buffered.pop(0)
                return {"type": "http.disconnect"}

            await self.app(scope, buffered_receive, send)
            return

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise RequestBodyTooLarge
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except RequestBodyTooLarge:
            if not response_started:
                await self._response(scope.get("path", ""))(scope, receive, send)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)
    useLdap: bool = False


class LdapSettingsRequest(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = Field(default=389, ge=1, le=65535)
    tlsMode: Literal["ldaps", "starttls", "plain"] = "starttls"
    verifyCertificate: bool = True
    caCertPath: str = ""
    bindDn: str = ""
    bindPassword: str | None = None
    baseDn: str = ""
    loginAttribute: str = "sAMAccountName"
    usernameAttribute: str = "sAMAccountName"
    subjectAttribute: str = "objectGUID"
    userFilter: str = "(sAMAccountName={username})"
    groupAttribute: str = "memberOf"
    groupMappings: dict[str, Role] = Field(default_factory=dict)
    autoProvision: bool = False
    defaultRole: Role = Role.VIEWER


class RegistrationRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    passwordConfirm: str = Field(min_length=1, max_length=1024)


class ServiceRequest(BaseModel):
    slug: str
    name: str


class EnvironmentRequest(BaseModel):
    slug: str
    name: str
    sortOrder: int = 0


class UserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
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
    slug: str | None = None
    sortOrder: int | None = None
    active: bool | None = None


class KodaRepositoryRequest(BaseModel):
    gitlabUrl: str = Field(min_length=1, max_length=512)
    gitlabProjectId: int = Field(gt=0)
    pathWithNamespace: str = Field(min_length=1, max_length=255)


class ArchiveRequest(BaseModel):
    reason: str


class RolePolicyRequest(BaseModel):
    permissions: list[str]


class RolePoliciesRequest(BaseModel):
    roles: dict[Role, list[str]]


class SbomPolicyRequest(PolicyDocument):
    expectedVersion: int = Field(ge=1)


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
    if not _is_loopback_bind(settings.public_bind) and settings.environment.lower() != "production":
        raise RuntimeError("non-loopback Tracker exposure requires production mode")
    if settings.environment.lower() == "production" and (
        not settings.secure_cookies or not settings.public_origin.startswith("https://")
    ):
        raise RuntimeError("production Tracker requires HTTPS public_origin and secure cookies")
    from .db import remove_retired_connector_schema
    remove_retired_connector_schema(engine)
    ensure_postgres_manager_enum(engine)
    Base.metadata.create_all(engine)
    ensure_user_approval_state_column(engine)
    ensure_user_identity_columns(engine)
    ensure_ldap_subject_attribute_column(engine)
    ensure_component_search_support(engine)
    ensure_environment_active_column(engine)
    ensure_sbom_source_metadata_column(engine)
    ensure_sbom_media_type_column(engine)
    ensure_sbom_size_bytes_column(engine)
    ensure_native_policy_columns(engine)
    # v1 uses create_all for a fresh install, but keep the one additive field
    # introduced by the vulnerability-data lifecycle backward compatible with
    # an already initialized portal database.
    if "data_sources" not in {column["name"] for column in inspect(engine).get_columns("analysis_revisions")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE analysis_revisions ADD COLUMN data_sources JSON"))
    _prune_scheduled_runs()
    with SessionLocal() as db:
        first_ssvc = db.get(FeatureUpgrade, "ssvc-deployer-v1") is None
        if first_ssvc:
            db.add(FeatureUpgrade(name="ssvc-deployer-v1"))
        first_extensions = db.get(FeatureUpgrade, "metadata-migration-v1") is None
        if first_extensions:
            db.add(FeatureUpgrade(name="metadata-migration-v1"))
        first_workflows = db.get(ReanalysisSchedule, "default") is None
        get_schedule(db)
        first_native_policy = db.scalar(select(SbomPolicyRevision.version).limit(1)) is None
        get_policy_document(db)
        if db.get(FeatureUpgrade, "nuget-semver2-v1") is None:
            from .package_metadata import requeue_legacy_nuget_metadata
            requeue_legacy_nuget_metadata(db)
            db.add(FeatureUpgrade(name="nuget-semver2-v1"))
        db.execute(
            delete(AuthAttempt).where(
                AuthAttempt.created_at
                < datetime.now(UTC) - timedelta(seconds=settings.auth_attempt_retention_seconds)
            )
        )
        normalized_usernames: dict[str, str] = {}
        for user in db.scalars(select(User)):
            try:
                normalized = _normalize_username(user.username)
            except HTTPException as exc:
                raise RuntimeError(f"invalid existing username: {user.username}") from exc
            if normalized in normalized_usernames and normalized_usernames[normalized] != user.id:
                raise RuntimeError(f"case-insensitive username collision: {normalized}")
            normalized_usernames[normalized] = user.id
            user.username = normalized
        for slug, name, order in [
            ("dev", "개발", 10),
            ("qa", "검증", 20),
            ("stage", "스테이징", 30),
            ("prod", "운영", 40),
        ]:
            if not db.scalar(select(Environment).where(Environment.slug == slug)):
                db.add(Environment(slug=slug, name=name, sort_order=order, active=True))
        for role, permissions in DEFAULT_ROLE_PERMISSIONS.items():
            policy = db.get(RolePolicy, role)
            if policy is None:
                db.add(RolePolicy(role=role, permissions=sorted(permissions)))
                continue
            granted = set(policy.permissions or [])
            if first_extensions:
                if "runs.view" in granted:
                    granted.add("metadata.view")
                if "roles.manage" in granted:
                    granted.update({"metadata.view", "metadata.manage"})
            if first_workflows:
                if "runs.view" in granted:
                    granted.update({"vex.view", "notifications.view", "reanalysis.view"})
                if "roles.manage" in granted:
                    granted.update({"vex.manage", "vex.approve", "notifications.manage", "reanalysis.manage"})
            if first_native_policy:
                if "runs.view" in granted:
                    granted.add("policies.view")
                if "roles.manage" in granted:
                    granted.update({"policies.view", "policies.manage"})
            if first_ssvc:
                if "vex.view" in granted or "runs.view" in granted:
                    granted.add("ssvc.view")
                if "vex.manage" in granted or "roles.manage" in granted:
                    granted.update({"ssvc.view", "ssvc.manage"})
            if role == Role.ADMIN:
                granted.add("sbom.delete")
            else:
                granted.discard("sbom.delete")
            policy.permissions = sorted(granted)
        _ensure_bootstrap_admin(
            db,
            settings.bootstrap_admin_username,
            settings.bootstrap_admin_password,
        )
        db.commit()
    yield


app = FastAPI(title="KODA SBOM Tracker API", version="0.1.0", lifespan=lifespan)
app.include_router(reanalysis_router)
app.include_router(workflow_router)
app.include_router(ssvc_router)
app.include_router(offline_intelligence_router)
app.include_router(package_metadata_router)
app.include_router(vulnerability_intelligence_router)
app.include_router(project_catalog_router)
app.include_router(private_vulnerability_router)
app.include_router(quality_router)
app.include_router(ci_gate_router)
app.include_router(environment_admin_router)
app.include_router(library_router)
app.include_router(cve_catalog_router)
app.include_router(external_router)
app.include_router(java_impact_router)
app.include_router(upgrade_batches_router)
app.include_router(compatibility_data_router)
app.include_router(ai_router)
app.add_middleware(RequestBodyLimitMiddleware)
_upload_persist_lock = asyncio.Lock()


def _prune_scheduled_runs(days: int = 90) -> int:
    """Retain scheduled Tracker results for the same window as KODA."""
    cutoff = datetime.now(UTC) - timedelta(days=int(days))
    artifact_root = get_settings().artifact_dir.resolve()
    paths: list[Path] = []
    deleted = 0
    with SessionLocal() as db:
        runs = list(db.scalars(select(SbomRun).where(
            SbomRun.source == "scheduled",
            SbomRun.created_at < cutoff,
            SbomRun.state.in_((ProcessingState.COMPLETED, ProcessingState.PARTIAL, ProcessingState.FAILED, ProcessingState.ARCHIVED)),
        )))
        for run in runs:
            if db.scalar(select(Job.id).where(Job.run_id == run.id, Job.state.in_((JobState.QUEUED, JobState.RUNNING))).limit(1)):
                continue
            artifact = Path(run.artifact_path)
            shared = db.scalar(select(SbomRun.id).where(SbomRun.id != run.id, SbomRun.artifact_path == run.artifact_path).limit(1))
            if artifact.exists() and not shared:
                try:
                    artifact.resolve().relative_to(artifact_root)
                except ValueError:
                    logger.error("scheduled artifact outside artifact root; retaining run: %s", run.id)
                    continue
                if not artifact.is_file():
                    logger.error("scheduled artifact is not a regular file; retaining run: %s", run.id)
                    continue
                paths.append(artifact)
            db.execute(delete(RunComponent).where(RunComponent.run_id == run.id))
            db.execute(delete(AnalysisRevision).where(AnalysisRevision.run_id == run.id))
            db.execute(delete(Job).where(Job.run_id == run.id))
            db.delete(run)
            deleted += 1
        db.commit()
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.exception("scheduled artifact cleanup failed: %s", path)
    return deleted


def _user_status(user: User) -> str:
    if user.approval_state == "deleted":
        return "deleted"
    if user.approval_state == "pending":
        return "pending"
    return "active" if user.active else "inactive"


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "active": user.active,
        "status": _user_status(user),
        "authSource": user.auth_source,
    }


def _cve_data_as_of(analysis: AnalysisRevision | None) -> str | None:
    if analysis is None:
        return None
    sources = analysis.data_sources or {}
    nvd = sources.get("nvd") if isinstance(sources, dict) else None
    if isinstance(nvd, dict) and nvd.get("dataAsOf") not in (None, "", "unknown"):
        return str(nvd["dataAsOf"])
    return analysis.data_as_of


def _csv_safe(value: object) -> str:
    text_value = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":")) if value is not None else ""
    candidate = text_value.lstrip(" \t\r\n")
    return "'" + text_value if text_value[:1] in ("\t", "\r", "\n") or candidate[:1] in ("=", "+", "-", "@") else text_value


def _audit_csv_value(value: object) -> str:
    if isinstance(value, dict):
        value = {
            key: _audit_csv_value(nested)
            for key, nested in value.items()
            if not re.search(r"sha[-_]?256", key, re.IGNORECASE)
        }
    elif isinstance(value, list):
        value = [_audit_csv_value(item) for item in value]
    return _csv_safe(value)


def _seoul_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(ZoneInfo("Asia/Seoul")).strftime("%Y-%m-%d %H:%M:%S")


def _ldap_public(row: LdapSettings | None) -> dict:
    return {
        "enabled": bool(row and row.enabled),
        "host": row.host if row else "",
        "port": row.port if row else 389,
        "tlsMode": row.tls_mode if row else "starttls",
        "verifyCertificate": row.verify_certificate if row else True,
        "caCertPath": row.ca_cert_path if row else "",
        "bindDn": row.bind_dn if row else "",
        "baseDn": row.base_dn if row else "",
        "loginAttribute": row.login_attribute if row else "sAMAccountName",
        "usernameAttribute": row.username_attribute if row else "sAMAccountName",
        "subjectAttribute": row.subject_attribute if row else "objectGUID",
        "userFilter": row.user_filter if row else "(sAMAccountName={username})",
        "groupAttribute": row.group_attribute if row else "memberOf",
        "groupMappings": row.group_mappings if row else {},
        "autoProvision": bool(row and row.auto_provision),
        "defaultRole": (row.default_role.value if row else Role.VIEWER.value),
        "hasBindPassword": bool(row and row.bind_password_ciphertext),
        "encryptionReady": _ldap_fernet() is not None,
    }


def _ldap_fernet() -> Fernet | None:
    key = get_settings().ldap_encryption_key.strip()
    if not key:
        return None
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError):
        return None


def _ldap_row_config(row: LdapSettings) -> LdapConfig:
    fernet = _ldap_fernet()
    if fernet is None:
        raise LdapConfigurationError("TRACKER_LDAP_ENCRYPTION_KEY가 올바르게 설정되지 않았습니다")
    if not row.bind_password_ciphertext:
        raise LdapConfigurationError("LDAP bind 비밀번호가 설정되지 않았습니다")
    try:
        password = fernet.decrypt(row.bind_password_ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise LdapConfigurationError("LDAP bind 비밀번호를 복호화할 수 없습니다") from exc
    return LdapConfig(
        host=row.host,
        port=row.port,
        tls_mode=row.tls_mode,
        verify_certificate=row.verify_certificate,
        ca_cert_path=row.ca_cert_path,
        bind_dn=row.bind_dn,
        bind_password=password,
        base_dn=row.base_dn,
        login_attribute=row.login_attribute,
        username_attribute=row.username_attribute,
        subject_attribute=row.subject_attribute,
        user_filter=row.user_filter,
        group_attribute=row.group_attribute,
    )


def _ldap_role(groups: tuple[str, ...], mappings: dict, default_role: Role) -> Role:
    normalized = {str(group).strip().casefold(): value for group, value in (mappings or {}).items()}
    priority = [Role.ADMIN, Role.MANAGER, Role.ANALYST, Role.UPLOADER, Role.VIEWER]
    matched = {normalized[group.strip().casefold()] for group in groups if group.strip().casefold() in normalized}
    role_values = {item.value if isinstance(item, Role) else str(item).casefold() for item in matched}
    for role in priority:
        if role.value in role_values:
            return role
    return default_role


def _validate_ldap_attribute(name: str) -> None:
    if not re.fullmatch(r"(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*", name):
        raise HTTPException(422, "LDAP 속성 이름이 올바르지 않습니다")


def _validate_ldap_request(body: LdapSettingsRequest) -> None:
    if body.host and (len(body.host) > 253 or any(char.isspace() for char in body.host) or "://" in body.host or "/" in body.host):
        raise HTTPException(422, "LDAP 서버 호스트가 올바르지 않습니다")
    if not body.userFilter or body.userFilter.count("{username}") != 1:
        raise HTTPException(422, "LDAP 사용자 검색 필터에 {username}이 정확히 한 번 필요합니다")
    if body.enabled and (not body.host.strip() or not body.bindDn.strip() or not body.baseDn.strip()):
        raise HTTPException(422, "LDAP 서버, bind DN, 검색 기준 DN은 필수입니다")
    if len(body.bindDn) > 512 or len(body.baseDn) > 512 or len(body.caCertPath) > 4096:
        raise HTTPException(422, "LDAP DN 또는 인증서 경로가 너무 깁니다")
    if any(len(value) > 128 for value in (body.loginAttribute, body.usernameAttribute, body.subjectAttribute, body.groupAttribute)):
        raise HTTPException(422, "LDAP 속성 이름이 너무 깁니다")
    for attribute in (body.loginAttribute, body.usernameAttribute, body.subjectAttribute, body.groupAttribute):
        _validate_ldap_attribute(attribute.strip())
    if len(body.userFilter) > 512 or any(len(group) > 1024 for group in body.groupMappings):
        raise HTTPException(422, "LDAP 검색 또는 그룹 설정값이 너무 깁니다")
    if body.enabled and body.tlsMode != "plain" and not body.verifyCertificate:
        raise HTTPException(422, "LDAP 인증서 검증은 필수입니다")


def _ldap_error(code: str, detail: str, status: int = 503) -> JSONResponse:
    return JSONResponse(status_code=status, content={"code": code, "detail": detail})


def _normalize_username(value: str) -> str:
    username = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", username):
        raise HTTPException(422, "사용자 이름은 영문, 숫자, 점, 밑줄, 하이픈으로 3~64자여야 합니다")
    return username


def _validate_local_password(value: str) -> str:
    if len(value) < 12:
        raise HTTPException(422, "비밀번호는 12자 이상이어야 합니다")
    if len(value) > 1024:
        raise HTTPException(422, "비밀번호는 1024자 이하여야 합니다")
    if value.strip().casefold() in KNOWN_PASSWORD_PLACEHOLDERS:
        raise HTTPException(422, "알려진 기본 비밀번호는 사용할 수 없습니다")
    return value


def _is_loopback_bind(value: str) -> bool:
    candidate = value.strip().strip("[]")
    if candidate.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _ensure_bootstrap_admin(db: Session, username: str, password: str) -> None:
    bootstrap_username = _normalize_username(username)
    bootstrap_user = db.scalar(select(User).where(func.lower(User.username) == bootstrap_username))
    if bootstrap_user is None:
        if not password:
            raise RuntimeError("fresh Tracker database requires an explicit TRACKER_BOOTSTRAP_ADMIN_PASSWORD")
        try:
            _validate_local_password(password)
        except HTTPException as exc:
            raise RuntimeError(f"invalid bootstrap administrator password: {exc.detail}") from exc
        db.add(
            User(
                username=bootstrap_username,
                password_hash=hash_password(password),
                role=Role.ADMIN,
            )
        )
        return
    if not verify_password(bootstrap_user.password_hash, "change-me-admin-password"):
        return
    if not password:
        raise RuntimeError(
            "bootstrap administrator still uses the retired known password; set a strong "
            "TRACKER_BOOTSTRAP_ADMIN_PASSWORD once to rotate it"
        )
    try:
        _validate_local_password(password)
    except HTTPException as exc:
        raise RuntimeError(f"invalid bootstrap administrator replacement password: {exc.detail}") from exc
    bootstrap_user.password_hash = hash_password(password)
    audit(
        db,
        "system",
        "user.bootstrap_password.rotate",
        "user",
        bootstrap_user.id,
        {"username": bootstrap_user.username},
    )


def _client_address(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    trusted = []
    for raw in get_settings().trusted_proxy_cidrs.split(","):
        if raw.strip():
            try:
                trusted.append(ipaddress.ip_network(raw.strip(), strict=False))
            except ValueError:
                continue
    if any(peer_ip in network for network in trusted):
        forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    return str(peer_ip)


def _consume_rate_limit(db: Session, kind: str, bucket: str, limit: int, window_seconds: int) -> None:
    bucket_hash = digest(f"{kind}:{bucket}")
    if db.bind and db.bind.dialect.name == "postgresql":
        advisory_key = int.from_bytes(hashlib.sha256(bucket_hash.encode()).digest()[:8], "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": advisory_key})
    cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
    db.execute(
        delete(AuthAttempt).where(
            AuthAttempt.kind == kind,
            AuthAttempt.created_at < cutoff,
        )
    )
    count = db.scalar(
        select(func.count()).select_from(AuthAttempt).where(
            AuthAttempt.kind == kind,
            AuthAttempt.bucket_hash == bucket_hash,
            AuthAttempt.created_at >= cutoff,
        )
    ) or 0
    if count >= limit:
        db.rollback()
        raise HTTPException(429, "인증 시도가 너무 많습니다. 잠시 후 다시 시도하세요")
    db.add(AuthAttempt(kind=kind, bucket_hash=bucket_hash))
    db.commit()


def _consume_login_address_rate_limit(db: Session, address: str) -> None:
    settings = get_settings()
    _consume_rate_limit(
        db,
        "login-address",
        address,
        settings.login_address_limit,
        settings.login_window_seconds,
    )


def _consume_login_rate_limit(db: Session, address: str, username: str) -> None:
    _consume_login_address_rate_limit(db, address)
    settings = get_settings()
    _consume_rate_limit(
        db,
        "login-account",
        username.strip().casefold(),
        settings.login_account_limit,
        settings.login_window_seconds,
    )


def _consume_ldap_account_rate_limit(db: Session, subject: str) -> None:
    settings = get_settings()
    _consume_rate_limit(
        db, "login-ldap-subject", subject, settings.login_account_limit, settings.login_window_seconds
    )


def _clear_rate_limit(db: Session, kind: str, bucket: str) -> None:
    db.execute(
        delete(AuthAttempt).where(
            AuthAttempt.kind == kind,
            AuthAttempt.bucket_hash == digest(f"{kind}:{bucket}"),
        )
    )


async def _stage_upload(upload: UploadFile, max_bytes: int) -> tuple[Path, str, int]:
    """Bound and hash the upload while keeping the payload on disk."""
    total = 0
    hasher = hashlib.sha256()
    directory = get_settings().artifact_dir
    directory.mkdir(parents=True, exist_ok=True)
    staged = tempfile.NamedTemporaryFile(prefix=".koda-sbom-upload-", dir=directory, delete=False)
    path = Path(staged.name)
    try:
        while chunk := await upload.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise HTTPException(413, "SBOM 파일이 업로드 제한을 초과했습니다")
            hasher.update(chunk)
            staged.write(chunk)
        staged.flush()
        return path, hasher.hexdigest(), total
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        staged.close()


def _consume_upload_rate_limit(db: Session, principal: User | ApiToken, service_id: str) -> None:
    settings = get_settings()
    bucket = f"service:{service_id}" if isinstance(principal, ApiToken) else f"user:{principal.id}"
    _consume_rate_limit(
        db,
        "sbom-upload",
        bucket,
        settings.upload_rate_limit,
        settings.upload_rate_window_seconds,
    )


def _enforce_upload_capacity(
    db: Session,
    service_id: str,
    *,
    raw_sha256: str | None = None,
    size_bytes: int = 0,
    component_count: int = 0,
) -> None:
    settings = get_settings()
    queued = db.scalar(
        select(func.count()).select_from(Job).where(Job.state.in_((JobState.QUEUED, JobState.RUNNING)))
    ) or 0
    if queued >= settings.max_queued_jobs:
        raise HTTPException(429, "처리 대기열이 가득 찼습니다. 기존 작업 완료 후 다시 시도하세요")
    if component_count > settings.max_sbom_components:
        raise HTTPException(422, f"SBOM 구성요소 수가 제한({settings.max_sbom_components})을 초과했습니다")
    service_run_count = db.scalar(
        select(func.count())
        .select_from(SbomRun)
        .join(Release, SbomRun.release_id == Release.id)
        .where(Release.service_id == service_id)
    ) or 0
    if service_run_count >= settings.max_service_runs:
        raise HTTPException(507, "서비스별 SBOM 회차 보관 한도를 초과했습니다")
    service_component_count = db.scalar(
        select(func.count())
        .select_from(RunComponent)
        .join(SbomRun, RunComponent.run_id == SbomRun.id)
        .join(Release, SbomRun.release_id == Release.id)
        .where(Release.service_id == service_id)
    ) or 0
    if int(service_component_count) + component_count > settings.max_service_components:
        raise HTTPException(507, "서비스별 누적 구성요소 보관 한도를 초과했습니다")
    if not raw_sha256 or size_bytes <= 0:
        return
    ingested_bytes = db.scalar(
        select(func.coalesce(func.sum(SbomRun.size_bytes), 0))
        .select_from(SbomRun)
        .join(Release, SbomRun.release_id == Release.id)
        .where(Release.service_id == service_id)
    ) or 0
    if int(ingested_bytes) + size_bytes > settings.max_service_ingested_bytes:
        raise HTTPException(507, "서비스별 누적 SBOM 데이터 한도를 초과했습니다")
    already_stored = db.scalar(
        select(SbomRun.id)
        .join(Release, SbomRun.release_id == Release.id)
        .where(Release.service_id == service_id, SbomRun.sha256 == raw_sha256)
        .limit(1)
    )
    if already_stored:
        return
    unique_artifacts = (
        select(SbomRun.sha256.label("sha256"), func.max(SbomRun.size_bytes).label("size_bytes"))
        .join(Release, SbomRun.release_id == Release.id)
        .where(Release.service_id == service_id)
        .group_by(SbomRun.sha256)
        .subquery()
    )
    stored_bytes = db.scalar(select(func.coalesce(func.sum(unique_artifacts.c.size_bytes), 0))) or 0
    if int(stored_bytes) + size_bytes > settings.max_service_storage_bytes:
        raise HTTPException(507, "서비스별 SBOM 저장 한도를 초과했습니다")


@app.exception_handler(HTTPException)
async def http_problem(request: Request, exc: HTTPException):
    return problem(exc.status_code, "요청을 처리할 수 없습니다", str(exc.detail), request)


@app.exception_handler(RequestValidationError)
async def validation_problem(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/v1/integrations/koda/ai-finding-review":
        return problem(422, "입력값 검증 실패", "AI 검토 자료의 필드 형식과 길이를 확인하세요", request)
    if request.url.path == "/api/v1/upgrade-batches/import":
        errors = exc.errors()
        if errors:
            location = ".".join(str(part) for part in errors[0]["loc"][1:])
            detail = " · ".join(part for part in (location, errors[0]["msg"]) if part)
            return problem(422, "일괄 검토 JSON 입력값 검증 실패", detail, request)
    return problem(422, "입력값 검증 실패", str(exc.errors()), request)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}




@app.get("/api/v1/settings/ldap")
def get_ldap_settings(
    db: Session = Depends(get_db),
    _=Depends(require_admin),
) -> dict:
    return _ldap_public(db.get(LdapSettings, "default"))


@app.put("/api/v1/settings/ldap")
def update_ldap_settings(
    body: LdapSettingsRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_admin),
    _csrf=Depends(require_csrf),
) -> dict:
    _validate_ldap_request(body)
    row = db.get(LdapSettings, "default")
    if row is None:
        row = LdapSettings(id="default")
        db.add(row)
    password = body.bindPassword
    if password is not None and password != "":
        fernet = _ldap_fernet()
        if fernet is None:
            raise HTTPException(503, "LDAP 암호화 키가 서버에 설정되지 않았습니다")
        row.bind_password_ciphertext = fernet.encrypt(password.encode("utf-8")).decode("ascii")
    row.enabled = body.enabled
    row.host = body.host.strip()
    row.port = body.port
    row.tls_mode = body.tlsMode
    row.verify_certificate = body.verifyCertificate if body.tlsMode != "plain" else False
    row.ca_cert_path = body.caCertPath.strip()
    row.bind_dn = body.bindDn.strip()
    row.base_dn = body.baseDn.strip()
    row.login_attribute = body.loginAttribute.strip()
    row.username_attribute = body.usernameAttribute.strip()
    row.subject_attribute = body.subjectAttribute.strip()
    row.user_filter = body.userFilter.strip()
    row.group_attribute = body.groupAttribute.strip()
    row.group_mappings = {key.strip(): role.value for key, role in body.groupMappings.items() if key.strip()}
    row.auto_provision = body.autoProvision
    row.default_role = body.defaultRole
    if row.enabled and not row.bind_password_ciphertext:
        raise HTTPException(422, "LDAP bind 비밀번호를 입력하세요")
    try:
        db.flush()
        audit(
            db,
            principal.username,
            "ldap.settings.update",
            "ldap_settings",
            "default",
            {
                "enabled": row.enabled,
                "host": row.host,
                "port": row.port,
                "tlsMode": row.tls_mode,
                "verifyCertificate": row.verify_certificate,
                "baseDn": row.base_dn,
                "loginAttribute": row.login_attribute,
                "usernameAttribute": row.username_attribute,
                "subjectAttribute": row.subject_attribute,
                "groupAttribute": row.group_attribute,
                "autoProvision": row.auto_provision,
                "defaultRole": row.default_role.value,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return _ldap_public(row)


def _complete_login(db: Session, response: Response, user: User) -> dict:
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
    return {
        "user": {**_user_payload(user), "permissions": sorted(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(user.role, ()))},
        "csrfToken": csrf,
    }


@app.post("/api/v1/auth/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    if body.useLdap:
        username = body.username.strip()
        if not username or len(username) > 256:
            raise HTTPException(401, "사용자 이름 또는 비밀번호가 올바르지 않습니다")
        address = _client_address(request)
        _consume_login_address_rate_limit(db, address)
        row = db.get(LdapSettings, "default")
        if row is None or not row.enabled:
            return _ldap_error("ldap_not_configured", "LDAP 로그인이 구성되지 않았습니다")
        try:
            config = _ldap_row_config(row)
            identity = authenticate_user(
                config, username, body.password,
                before_bind=lambda subject: _consume_ldap_account_rate_limit(db, subject),
            )
        except LdapInvalidCredentials:
            raise HTTPException(401, "사용자 이름 또는 비밀번호가 올바르지 않습니다")
        except (LdapConfigurationError, LdapUnavailable) as exc:
            return _ldap_error("ldap_unavailable", str(exc))
        try:
            local_username = _normalize_username(identity.username)
        except HTTPException:
            return _ldap_error("ldap_identity_invalid", "LDAP 사용자 식별자를 Tracker 계정으로 사용할 수 없습니다", 422)
        user = db.scalar(select(User).where(User.auth_source == "ldap", User.ldap_subject == identity.subject))
        username_user = db.scalar(select(User).where(func.lower(User.username) == local_username))
        if username_user is not None and (user is None or user.id != username_user.id):
            raise HTTPException(403, "LDAP 사용자 이름이 기존 Tracker 계정과 충돌합니다")
        if user is None:
            if not row.auto_provision:
                raise HTTPException(403, "LDAP 인증은 성공했지만 Tracker 사용자 승인이 필요합니다")
            user = User(
                username=local_username,
                password_hash=hash_password(secrets.token_urlsafe(32)),
                role=_ldap_role(identity.groups, row.group_mappings, row.default_role),
                active=False,
                approval_state="pending",
                auth_source="ldap",
                ldap_subject=identity.subject,
            )
            db.add(user)
            try:
                db.flush()
            except IntegrityError as exc:
                db.rollback()
                raise HTTPException(409, "LDAP 사용자 계정을 생성하는 중 충돌이 발생했습니다") from exc
            audit(db, "ldap", "user.provision", "user", user.id, {"username": user.username, "role": user.role.value})
        _clear_rate_limit(db, "login-ldap-subject", identity.subject)
        if user.approval_state == "pending":
            db.commit()
            raise HTTPException(403, "계정이 관리자 승인 대기 중입니다")
        if not user.active or user.approval_state == "deleted":
            db.commit()
            raise HTTPException(403, "비활성화된 계정입니다")
        return _complete_login(db, response, user)
    try:
        username = _normalize_username(body.username)
    except HTTPException:
        username = body.username.strip().lower()
    address = _client_address(request)
    _consume_login_rate_limit(db, address, username)
    user = db.scalar(select(User).where(func.lower(User.username) == username))
    if not user or not verify_password(user.password_hash, body.password):
        raise HTTPException(401, "사용자 이름 또는 비밀번호가 올바르지 않습니다")
    _clear_rate_limit(db, "login-account", username.strip().casefold())
    if user.approval_state == "pending":
        db.commit()
        raise HTTPException(403, "계정이 관리자 승인 대기 중입니다")
    if not user.active:
        db.commit()
        raise HTTPException(403, "비활성화된 계정입니다")
    return _complete_login(db, response, user)


@app.post("/api/v1/auth/register", status_code=202)
def register(body: RegistrationRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    username = _normalize_username(body.username)
    _validate_local_password(body.password)
    if body.password != body.passwordConfirm:
        raise HTTPException(422, "비밀번호 확인이 일치하지 않습니다")

    _consume_rate_limit(db, "registration", _client_address(request), 5, 3600)

    detail = "가입 신청이 접수되었습니다. 관리자 승인 후 로그인할 수 있습니다."
    if db.scalar(select(User.id).where(func.lower(User.username) == username)):
        return {"status": "pending", "detail": detail}
    user = User(
        username=username,
        password_hash=hash_password(body.password),
        role=Role.VIEWER,
        active=False,
        approval_state="pending",
    )
    try:
        db.add(user)
        db.flush()
    except IntegrityError:
        db.rollback()
        if db.scalar(select(User.id).where(func.lower(User.username) == username)):
            return {"status": "pending", "detail": detail}
        raise
    audit(db, "self-service", "user.register", "user", user.id, {"username": username, "role": Role.VIEWER})
    db.commit()
    return {"status": "pending", "detail": detail}


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
    return {"user": {**_user_payload(principal), "permissions": sorted(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))}, "csrfToken": csrf}


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
    users = db.scalars(select(User).with_for_update())
    if not any(user.active and policies.get(user.role, set()) >= {"roles.manage", "users.manage"} for user in users):
        raise HTTPException(422, "roles.manage 및 users.manage 권한을 가진 활성 사용자가 최소 한 명 필요합니다")


def _validate_permissions(permissions: list[str], role: Role | None = None) -> list[str]:
    if len(permissions) != len(set(permissions)) or any(item not in PERMISSION_CATALOG for item in permissions):
        raise HTTPException(422, "알 수 없거나 중복된 권한입니다")
    if role != Role.ADMIN and "sbom.delete" in permissions:
        raise HTTPException(422, "sbom.delete 권한은 관리자 역할에만 부여할 수 있습니다")
    return sorted(permissions)

def _sbom_policy_payload(item: SbomPolicyRevision) -> dict:
    return {
        **item.document,
        "version": item.version,
        "createdAt": (item.created_at.replace(tzinfo=UTC) if item.created_at.tzinfo is None else item.created_at).isoformat(),
        "createdBy": item.created_by,
    }


@app.get("/api/v1/sbom-policies")
def get_sbom_policies(
    db: Session = Depends(get_db),
    _=Depends(require_permission("policies.view", "policies.manage")),
) -> dict:
    return _sbom_policy_payload(get_policy_document(db))


@app.get("/api/v1/sbom-policies/history")
def get_sbom_policy_history(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_permission("policies.view", "policies.manage")),
) -> dict:
    return {
        "items": [
            _sbom_policy_payload(item)
            for item in db.scalars(select(SbomPolicyRevision).order_by(SbomPolicyRevision.version.desc()).offset((page - 1) * size).limit(size))
        ],
        "total": db.scalar(select(func.count()).select_from(SbomPolicyRevision)) or 0,
        "page": page,
        "size": size,
    }


@app.put("/api/v1/sbom-policies")
def update_sbom_policies(
    body: SbomPolicyRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("policies.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    for rule in body.rules:
        for ids, model in ((rule.serviceIds, Service), (rule.environmentIds, Environment), (rule.runIds, SbomRun)):
            if ids and set(ids) != set(db.scalars(select(model.id).where(model.id.in_(ids)))):
                raise HTTPException(422, "정책 범위에 존재하지 않는 서비스 또는 환경이 있습니다")
    try:
        validate_policy_expressions(body)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    current = db.scalar(select(SbomPolicyRevision).order_by(SbomPolicyRevision.version.desc()).limit(1).with_for_update())
    if current is None or current.version != body.expectedVersion:
        raise HTTPException(409, "다른 사용자가 정책을 변경했습니다. 최신 정책을 다시 불러오세요")
    item = SbomPolicyRevision(
        version=current.version + 1,
        document=body.model_dump(mode="json", exclude={"expectedVersion"}),
        created_by=_principal_actor(principal),
    )
    db.add(item)
    audit(db, _principal_actor(principal), "sbom_policy.update", "sbom_policy", str(item.version), {"previousVersion": current.version, "version": item.version})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "정책이 동시에 변경됐습니다. 최신 정책을 다시 불러오세요") from exc
    return _sbom_policy_payload(item)


class CelValidationRequest(BaseModel):
    expression: str = Field(min_length=1, max_length=16384)
    target: Literal["component", "vulnerability", "project"] = "vulnerability"
    runId: str | None = None


@app.post("/api/v1/sbom-policies/validate")
def validate_cel_policy(body: CelValidationRequest, db: Session = Depends(get_db), _=Depends(require_permission("policies.manage")), _csrf=Depends(require_csrf)):
    try:
        result = validate_expression(body.expression, body.target)
        if body.runId:
            run = _load_run(db, body.runId, include_components=True, include_analyses=True)
            latest = max(run.analyses, key=lambda item: item.sequence, default=None)
            from .vulnerability_intelligence import enrich_findings
            result.update(preview_expression(body.expression, body.target, enrich_components(db, components_with_dependency_graph(run.normalized_bom)), enrich_findings(db, latest.findings if latest else []), policy_context_for_run(run, db)))
        return result
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/api/v1/role-policies")
def list_role_policies(db: Session = Depends(get_db), _=Depends(require_permission("roles.manage"))) -> dict:
    return {"catalog": list(PERMISSION_CATALOG), "roles": [{"role": role.value, "permissions": sorted((db.get(RolePolicy, role) or RolePolicy(role=role, permissions=[])).permissions or [])} for role in Role]}

@app.put("/api/v1/role-policies/{role}")
def update_role_policy(role: Role, body: RolePolicyRequest, db: Session = Depends(get_db), principal=Depends(require_permission("roles.manage")), _csrf=Depends(require_csrf)) -> dict:
    permissions = _validate_permissions(body.permissions, role)
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
    updates = {role: _validate_permissions(permissions, role) for role, permissions in body.roles.items()}
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
        _user_payload(item)
        for item in db.scalars(select(User).order_by(User.username))
        if can_roles or item.role not in {Role.ADMIN, Role.MANAGER}
    ]


def _require_privileged_role_management(db: Session, principal: User, *roles: Role | None) -> None:
    if not any(role in {Role.ADMIN, Role.MANAGER} for role in roles):
        return
    policy = db.get(RolePolicy, principal.role)
    granted = set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
    if "roles.manage" not in granted:
        raise HTTPException(403, "관리자 또는 매니저 계정 변경에는 roles.manage 권한이 필요합니다")


@app.post("/api/v1/users", status_code=201)
def create_user(
    body: UserRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("users.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    username = _normalize_username(body.username)
    _validate_local_password(body.password)
    _require_privileged_role_management(db, principal, body.role)
    user = User(username=username, password_hash=hash_password(body.password), role=body.role)
    try:
        db.add(user)
        db.flush()
        _policy_invariant(db)
        audit(db, principal.username, "user.create", "user", user.id, {"username": user.username, "role": user.role})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if db.scalar(select(User.id).where(func.lower(User.username) == username)):
            raise HTTPException(409, "이미 존재하는 사용자입니다") from exc
        raise
    return _user_payload(user)


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
    if user.approval_state == "deleted" and body.active is True:
        raise HTTPException(422, "삭제된 사용자 계정은 다시 활성화할 수 없습니다")
    _require_privileged_role_management(db, principal, user.role, body.role)
    if body.role is not None:
        user.role = body.role
    if body.active is not None:
        if body.active and user.approval_state == "pending":
            raise HTTPException(422, "가입 대기 계정은 승인 작업으로 활성화해야 합니다")
        user.active = body.active
    db.flush()
    _policy_invariant(db)
    audit(db, principal.username, "user.update", "user", user.id, {"role": user.role, "active": user.active, "status": _user_status(user)})
    db.commit()
    return _user_payload(user)


@app.delete("/api/v1/users/{user_id}")
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("users.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "사용자를 찾을 수 없습니다")
    if user.id == principal.id:
        raise HTTPException(422, "현재 로그인한 계정은 삭제할 수 없습니다")
    _require_privileged_role_management(db, principal, user.role)
    receipt = {"id": user.id, "username": user.username, "role": user.role.value, "status": "deleted"}
    try:
        db.execute(delete(UserSession).where(UserSession.user_id == user.id))
        db.execute(SbomRun.__table__.update().where(SbomRun.uploaded_by == user.id).values(uploaded_by=None))
        db.delete(user)
        db.flush()
        _policy_invariant(db)
        audit(db, principal.username, "user.delete", "user", receipt["id"], receipt | {"hardDelete": True})
        db.commit()
    except Exception:
        db.rollback()
        raise
    return receipt


@app.post("/api/v1/users/{user_id}/approve")
def approve_user(
    user_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("users.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "사용자를 찾을 수 없습니다")
    if user.approval_state != "pending":
        raise HTTPException(409, "가입 승인 대기 계정이 아닙니다")
    _require_privileged_role_management(db, principal, user.role)
    user.approval_state = "approved"
    user.active = True
    db.flush()
    _policy_invariant(db)
    audit(db, principal.username, "user.approve", "user", user.id, {"role": user.role, "status": "active"})
    db.commit()
    return _user_payload(user)


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
    include_inactive: bool = Query(default=False, alias="includeInactive"),
    db: Session = Depends(get_db),
    principal=Depends(require_permission("services.view")),
) -> list[dict]:
    if include_inactive:
        policy = db.get(RolePolicy, principal.role)
        permissions = set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
        if "catalog.manage" not in permissions and "*" not in permissions:
            raise HTTPException(403, "비활성 서비스 조회에는 catalog.manage 권한이 필요합니다")
        query = select(Service).order_by(Service.name)
    else:
        query = select(Service).where(Service.active.is_(True)).order_by(Service.name)
    return [{"id": item.id, "slug": item.slug, "name": item.name, "active": item.active} for item in db.scalars(query)]


@app.post("/api/v1/services", status_code=201)
def create_service(
    body: ServiceRequest,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("catalog.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,126}[a-z0-9]", body.slug):
        raise HTTPException(422, "식별자 형식이 올바르지 않습니다")
    item = Service(slug=body.slug, name=body.name)
    try:
        db.add(item)
        db.flush()
        audit(db, principal.username, "service.create", "service", item.id, {"name": body.name})
        db.commit()
    except IntegrityError as exc:
        raise HTTPException(409, "이미 존재하는 서비스입니다") from exc
    return {"id": item.id, "slug": item.slug, "name": item.name, "active": item.active}


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
    include_inactive: bool = Query(default=False, alias="includeInactive"),
    db: Session = Depends(get_db),
    principal=Depends(require_permission("services.view")),
) -> list[dict]:
    if include_inactive:
        policy = db.get(RolePolicy, principal.role)
        permissions = set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
        if "catalog.manage" not in permissions and "*" not in permissions:
            raise HTTPException(403, "비활성 환경 조회에는 catalog.manage 권한이 필요합니다")
        query = select(Environment).order_by(Environment.sort_order)
    else:
        query = select(Environment).where(Environment.active.is_(True)).order_by(Environment.sort_order)
    return [{"id": item.id, "slug": item.slug, "name": item.name, "sortOrder": item.sort_order, "active": item.active} for item in db.scalars(query)]


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
    return {"id": item.id, "slug": item.slug, "name": item.name, "sortOrder": item.sort_order, "active": item.active}


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
    if body.slug is not None:
        next_slug = body.slug.strip()
        if not next_slug or len(next_slug) > 64:
            raise HTTPException(422, "환경 식별자는 비어 있지 않은 64자 이하여야 합니다")
        duplicate = db.scalar(select(Environment).where(Environment.slug == next_slug, Environment.id != item.id))
        if duplicate:
            raise HTTPException(409, "이미 존재하는 환경 식별자입니다")
        item.slug = next_slug
    if body.sortOrder is not None:
        item.sort_order = body.sortOrder
    if body.active is not None:
        item.active = body.active
    audit(db, principal.username, "environment.update", "environment", item.id, {"name": item.name, "slug": item.slug, "sortOrder": item.sort_order, "active": item.active})
    db.commit()
    return {"id": item.id, "slug": item.slug, "name": item.name, "sortOrder": item.sort_order, "active": item.active}


def _principal_actor(principal: User | ApiToken) -> str:
    return principal.username if isinstance(principal, User) else f"token:{principal.id}"


_SCHEDULE_SOURCE_METADATA_KEYS = frozenset({
    "targetId", "scheduleRunId", "server", "directory", "mode", "changedFiles", "changedFilesTruncated",
    "kodaRunId", "rulePolicyVersion",
})
_MAX_SCHEDULE_CHANGED_FILES = 20_000


def _validated_source_metadata(
    principal: User | ApiToken, source: str, source_metadata: dict | None,
) -> tuple[str, dict]:
    source_value = str(source or "").strip().lower()
    if source_value not in {"", "manual", "api", "scheduled"}:
        raise HTTPException(422, "SBOM 출처가 올바르지 않습니다")
    metadata = source_metadata if isinstance(source_metadata, dict) else {}
    if source_value != "scheduled":
        return source_value, {}
    if not isinstance(principal, ApiToken) or not principal.name.startswith("koda-gitlab:"):
        raise HTTPException(403, "예약 점검 출처는 KODA 연동 토큰만 지정할 수 있습니다")
    metadata = {key: value for key, value in metadata.items() if key in _SCHEDULE_SOURCE_METADATA_KEYS}
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", str(metadata.get("targetId") or "")):
        raise HTTPException(422, "예약 점검 대상 ID가 올바르지 않습니다")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", str(metadata.get("scheduleRunId") or "")):
        raise HTTPException(422, "예약 점검 실행 ID가 올바르지 않습니다")
    for key, limit in (("server", 1024), ("directory", 1024), ("kodaRunId", 128)):
        value = metadata.get(key)
        if not isinstance(value, str) or not value or len(value) > limit or any(ord(char) < 32 for char in value):
            raise HTTPException(422, f"예약 점검 {key} 메타데이터가 올바르지 않습니다")
    if not str(metadata["directory"]).startswith("/"):
        raise HTTPException(422, "예약 점검 디렉토리는 절대 경로여야 합니다")
    if metadata.get("mode") not in {"full", "changed"}:
        raise HTTPException(422, "예약 점검 방식이 올바르지 않습니다")
    changed_files = metadata.get("changedFiles", [])
    if (
        not isinstance(changed_files, list)
        or len(changed_files) > _MAX_SCHEDULE_CHANGED_FILES
        or any(
            not isinstance(item, str) or not item or len(item) > 2048 or any(ord(char) < 32 for char in item)
            for item in changed_files
        )
    ):
        raise HTTPException(422, "예약 점검 변경 파일 목록이 올바르지 않습니다")
    if "changedFilesTruncated" in metadata and not isinstance(metadata["changedFilesTruncated"], bool):
        raise HTTPException(422, "예약 점검 변경 파일 목록 상태가 올바르지 않습니다")
    if "rulePolicyVersion" in metadata and (
        isinstance(metadata["rulePolicyVersion"], bool)
        or not isinstance(metadata["rulePolicyVersion"], int)
        or metadata["rulePolicyVersion"] < 0
    ):
        raise HTTPException(422, "예약 점검 규칙 버전이 올바르지 않습니다")
    return source_value, metadata


def _scheduled_environment(db: Session, *, service: Service, requested: Environment, metadata: dict) -> Environment:
    """Keep each target's full and changed SBOM history in separate catalogs."""
    target = str(metadata["targetId"])
    mode = str(metadata["mode"])
    slug = f"scheduled-{service.id[:12]}-{target}-{mode}"
    if len(slug) > 128:
        slug = f"scheduled-{hashlib.sha256(f'{service.id}:{target}'.encode()).hexdigest()[:32]}-{mode}"
    environment = db.scalar(select(Environment).where(Environment.slug == slug))
    if environment is None:
        environment = Environment(
            slug=slug,
            name=f"예약 {target} · {'전체' if mode == 'full' else '변경분'}",
            sort_order=requested.sort_order + 1000,
            active=True,
        )
        db.add(environment)
        db.flush()
    elif not environment.active:
        environment.active = True
    return environment


def _find_idempotent_run(
    db: Session,
    *,
    principal: User | ApiToken,
    idempotency_key: str,
    service_id: str | None = None,
) -> SbomRun | None:
    """Find a replay without coupling service-scoped tokens to token IDs."""
    query = select(SbomRun).join(Release, SbomRun.release_id == Release.id).where(
        SbomRun.idempotency_key == idempotency_key,
    )
    if isinstance(principal, ApiToken) and principal.service_id:
        scoped_service_id = service_id or principal.service_id
        if scoped_service_id != principal.service_id:
            return None
        query = query.where(Release.service_id == scoped_service_id)
    else:
        query = query.where(SbomRun.idempotency_actor == _principal_actor(principal))
    return db.scalar(query)


def _require_koda_provisioning(
    authorization: str | None = Header(default=None),
) -> str:
    token_file = get_settings().koda_provisioning_token_file
    if token_file is None:
        raise HTTPException(503, "KODA 자동 연동이 설정되지 않았습니다")
    try:
        if not token_file.is_file() or token_file.stat().st_size > 16 * 1024:
            raise OSError
        expected = token_file.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise HTTPException(503, "KODA 자동 연동 비밀값을 읽을 수 없습니다") from exc
    supplied = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else ""
    if not expected or not secrets.compare_digest(supplied, expected):
        raise HTTPException(401, "KODA 자동 연동 인증이 필요합니다")
    return "integration:koda"


@app.post("/api/v1/integrations/koda/ai-summary", dependencies=[Depends(_require_koda_provisioning)])
def koda_ai_summary(body: KodaSummaryFacts, db: Session = Depends(get_db)):
    return summarize_koda_facts(db, body)


@app.post("/api/v1/integrations/koda/ai-finding-review", dependencies=[Depends(_require_koda_provisioning)])
def koda_ai_finding_review(body: KodaFindingReviewRequest, response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return review_koda_finding(db, body)


@app.get("/api/v1/integrations/koda/users")
def list_koda_users(
    db: Session = Depends(get_db),
    _actor: str = Depends(_require_koda_provisioning),
) -> dict:
    """Return a complete, password-free identity snapshot for KODA sync."""
    users = []
    for user in db.scalars(select(User).where(User.approval_state != "deleted").order_by(User.id)):
        users.append({
            "id": user.id,
            "username": user.username,
            "status": "approved" if user.approval_state == "approved" and user.active else "revoked",
        })
    return {"users": users, "snapshotAt": datetime.now(UTC).isoformat()}


@app.post("/api/v1/integrations/koda/repositories", status_code=201)
def provision_koda_repository(
    body: KodaRepositoryRequest,
    db: Session = Depends(get_db),
    actor: str = Depends(_require_koda_provisioning),
) -> dict:
    gitlab_url = body.gitlabUrl.strip().rstrip("/")
    parsed = urlparse(gitlab_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(422, "GitLab URL은 인증정보가 없는 HTTPS URL이어야 합니다")
    path = body.pathWithNamespace.strip().strip("/")
    if not re.fullmatch(r"[^/\s]+(?:/[^/\s]+)+", path):
        raise HTTPException(422, "GitLab 저장소 경로가 올바르지 않습니다")
    repository_key = hashlib.sha256(f"{gitlab_url.lower()}:{body.gitlabProjectId}".encode()).hexdigest()
    slug = f"gitlab-{body.gitlabProjectId}-{repository_key[:12]}"
    service = db.scalar(select(Service).where(Service.slug == slug))
    service_created = service is None
    if service_created:
        service = Service(slug=slug, name=path, active=True)
        db.add(service)
        db.flush()
    else:
        service.name = path
        service.active = True
    environment = db.scalar(select(Environment).where(Environment.slug == "gitlab-source"))
    if environment is None:
        environment = Environment(slug="gitlab-source", name="GitLab 소스", sort_order=50, active=True)
        db.add(environment)
        db.flush()
    else:
        environment.active = True
    token_name = f"koda-gitlab:{repository_key[:24]}"
    for token in db.scalars(select(ApiToken).where(ApiToken.name == token_name, ApiToken.active.is_(True))):
        token.active = False
    raw = f"koda_{secrets.token_urlsafe(36)}"
    db.add(ApiToken(name=token_name, token_hash=digest(raw), service_id=service.id))
    audit(db, actor, "koda.repository.provision", "service", service.id, {
        "gitlabUrl": gitlab_url, "gitlabProjectId": body.gitlabProjectId,
        "pathWithNamespace": path, "environmentId": environment.id,
    })
    db.commit()
    return {
        "serviceId": service.id, "environmentId": environment.id,
        "uploadToken": raw, "serviceCreated": service_created,
    }


def _persist_run(
    db: Session,
    *,
    principal: User | ApiToken,
    actor: str,
    service: Service,
    environment: Environment,
    release_version: str,
    staged_path: Path,
    size_bytes: int,
    payload: dict,
    media_type: str,
    filename: str,
    note: str,
    idempotency_key: str | None,
    raw_sha256: str,
    source: str = "",
    source_metadata: dict | None = None,
) -> dict:
    source_value, metadata = _validated_source_metadata(principal, source, source_metadata)
    if len(json.dumps(metadata, ensure_ascii=False).encode("utf-8")) > 64 * 1024:
        raise HTTPException(422, "예약 점검 메타데이터가 너무 큽니다")
    if db.bind and db.bind.dialect.name == "postgresql":
        lock_material = b"sbom-upload-admission"
        advisory_key = int.from_bytes(hashlib.sha256(lock_material).digest()[:8], "big", signed=True)
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": advisory_key})
    if idempotency_key:
        existing = _find_idempotent_run(
            db, principal=principal, idempotency_key=idempotency_key, service_id=service.id
        )
        if existing:
            return {"runId": existing.id, "state": existing.state, "idempotentReplay": True}
    _enforce_upload_capacity(
        db,
        service.id,
        raw_sha256=raw_sha256,
        size_bytes=size_bytes,
        component_count=component_count(payload),
    )
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
    sha256, path = store_artifact_file(get_settings().artifact_dir, staged_path, digest=raw_sha256)
    run = SbomRun(
        release_id=release.id,
        round_number=round_number,
        original_filename=Path(filename or "sbom").name[:255],
        media_type=media_type,
        spec_version=str(payload.get("specVersion")),
        serial_number=payload.get("serialNumber"),
        sha256=sha256,
        size_bytes=size_bytes,
        artifact_path=str(path),
        normalized_bom=payload,
        uploaded_by=principal.id if isinstance(principal, User) else None,
        idempotency_actor=actor,
        idempotency_key=idempotency_key,
        note=note,
        source=source_value or ("api" if isinstance(principal, ApiToken) else "manual"),
        source_metadata=metadata,
    )
    db.add(run)
    db.flush()
    create_components(db, run)
    mark_current(db, run)
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
    source: str = Form(default=""),
    source_metadata: str = Form(default="", alias="sourceMetadata"),
    sbom: UploadFile = File(),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    principal=Depends(require_permission("sbom.upload", allow_service_token=True)),
    _csrf=Depends(require_csrf),
) -> dict:
    if isinstance(principal, ApiToken) and principal.service_id and principal.service_id != service_id:
        raise HTTPException(403, "이 토큰에는 해당 서비스 업로드 권한이 없습니다")
    if not service_id or len(service_id) > 64 or not environment_id or len(environment_id) > 64:
        raise HTTPException(422, "서비스 또는 환경 식별자가 올바르지 않습니다")
    if not release_version.strip() or len(release_version) > 255:
        raise HTTPException(422, "릴리스 버전은 1~255자여야 합니다")
    if len(note) > 4096:
        raise HTTPException(422, "업로드 메모가 너무 깁니다")
    if idempotency_key is not None and len(idempotency_key) > 255:
        raise HTTPException(422, "Idempotency-Key가 너무 깁니다")
    source_value = str(source or "").strip().lower()
    if source_value not in {"", "manual", "api", "scheduled"}:
        raise HTTPException(422, "SBOM 출처가 올바르지 않습니다")
    actor = _principal_actor(principal)
    if idempotency_key:
        existing = _find_idempotent_run(
            db, principal=principal, idempotency_key=idempotency_key, service_id=service_id
        )
        if existing:
            return {"runId": existing.id, "state": existing.state, "idempotentReplay": True}
    service = db.get(Service, service_id)
    environment = db.get(Environment, environment_id)
    if not service or not environment:
        raise HTTPException(404, "서비스 또는 환경을 찾을 수 없습니다")
    if not service.active:
        raise HTTPException(409, "비활성 서비스에는 SBOM을 업로드할 수 없습니다")
    if not environment.active:
        raise HTTPException(409, "비활성 환경에는 SBOM을 업로드할 수 없습니다")
    _consume_upload_rate_limit(db, principal, service_id)
    _enforce_upload_capacity(db, service_id)
    parsed_source_metadata: dict = {}
    if source_metadata:
        try:
            parsed_source_metadata = json.loads(source_metadata)
        except (TypeError, json.JSONDecodeError) as exc:
            raise HTTPException(422, "예약 점검 메타데이터 JSON이 올바르지 않습니다") from exc
        if not isinstance(parsed_source_metadata, dict):
            raise HTTPException(422, "예약 점검 메타데이터는 객체여야 합니다")
    source_value, parsed_source_metadata = _validated_source_metadata(principal, source_value, parsed_source_metadata)
    workbook = Path(sbom.filename or "").suffix.lower() == ".xlsx"
    max_bytes = get_settings().max_upload_bytes
    staged_path, raw_sha256, size_bytes = await _stage_upload(
        sbom, min(max_bytes, MAX_WORKBOOK_BYTES) if workbook else max_bytes
    )

    def validate_and_persist():
        settings = get_settings()
        with sbom_document_path(staged_path, max_bytes=max_bytes, workbook=workbook) as document:
            payload, document_media_type = parse_sbom_upload_document(document)
            validate_component_count(payload, settings.max_sbom_components)
            input_format = "json" if document_media_type.endswith("+json") else "xml"
            validate_file_with_cyclonedx_cli(
                document,
                settings.cyclonedx_cli_binary,
                input_format=input_format,
                parsed_document=(payload, document_media_type),
            )
            media_type = WORKBOOK_MEDIA_TYPE if workbook else sbom_upload_media_type(staged_path, document_media_type)
        selected_environment = environment
        if source_value == "scheduled":
            selected_environment = _scheduled_environment(
                db, service=service, requested=environment, metadata=parsed_source_metadata
            )
        return _persist_run(
            db,
            principal=principal,
            actor=actor,
            service=service,
            environment=selected_environment,
            release_version=release_version,
            staged_path=staged_path,
            size_bytes=size_bytes,
            payload=payload,
            media_type=media_type,
            filename=sbom.filename or "sbom",
            note=note,
            idempotency_key=idempotency_key,
            raw_sha256=raw_sha256,
            source=source_value,
            source_metadata=parsed_source_metadata,
        )

    try:
        await sbom.close()
        async with _upload_persist_lock:
            return await run_in_threadpool(validate_and_persist)
    except SbomValidationError as exc:
        raise HTTPException(422, str(exc)) from exc
    finally:
        staged_path.unlink(missing_ok=True)


def _native_policy_result(analysis: AnalysisRevision | None, *, include_evidence: bool = False) -> dict:
    state = analysis.policy_state if analysis else "not_evaluated"
    status = state
    if state == "completed":
        status = (analysis.metrics or {}).get("policyStatus")
        if status not in {"pass", "warn", "fail", "info"}:
            active = [record for record in analysis.policies or [] if not record.get("suppressed", False)]
            status = "fail" if any(record.get("action") == "fail" for record in active) else "warn" if any(record.get("action") == "warn" for record in active) else "info" if active else "pass"
    payload = {
        "analysisId": analysis.id if analysis else None,
        "policyState": state,
        "policyStatus": status,
        "policyVersion": analysis.policy_version if analysis else None,
        "policyError": analysis.policy_error if analysis else None,
        "analysisMetrics": (analysis.metrics or {}) if analysis else {},
    }
    if include_evidence:
        payload["policySnapshot"] = (analysis.policy_snapshot or {}) if analysis else {}
    return payload


def _policy_count(analysis: AnalysisRevision | None) -> int:
    if analysis is None:
        return 0
    if analysis.policy_state == "completed" and "policyViolationCount" in (analysis.metrics or {}):
        return int(analysis.metrics["policyViolationCount"])
    return sum(not row.get("suppressed", False) for row in analysis.policies or [])


def _run_payload(
    item: SbomRun,
    *,
    component_count: int | None = None,
    component_type_counts: dict[str, int] | None = None,
    native_reanalysis_pending: bool = False,
) -> dict:
    latest = max(item.analyses, key=lambda analysis: analysis.sequence, default=None)
    findings = project_cve_findings(latest.findings if latest else [])
    severity_counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        severity_counts[severity if severity in {"critical", "high", "medium", "low", "info"} else "unknown"] += 1
    return {
        "id": item.id,
        "runUrl": (
            f"{get_settings().public_origin.rstrip('/')}/?page=runs&runId={quote(item.id, safe='')}"
            if get_settings().public_origin.strip()
            else None
        ),
        "service": {"id": item.release.service.id, "name": item.release.service.name, "slug": item.release.service.slug},
        "environment": {"id": item.release.environment.id, "name": item.release.environment.name, "slug": item.release.environment.slug},
        "releaseVersion": item.release.version,
        "roundNumber": item.round_number,
        "state": (ProcessingState.PROCESSING if item.analysis_state == JobState.RUNNING else ProcessingState.QUEUED) if native_reanalysis_pending else item.state,
        "source": item.source or "manual",
        "sourceMetadata": item.source_metadata or {},
        "analysisState": (JobState.RUNNING if item.analysis_state == JobState.RUNNING else JobState.QUEUED) if native_reanalysis_pending else item.analysis_state,
        "nativeReanalysisPending": native_reanalysis_pending,
        "analysisAvailable": bool(latest and latest.state == JobState.COMPLETED and item.analysis_state == JobState.COMPLETED and not native_reanalysis_pending),
        "analysisUnavailableReason": ((latest.error or "현재 분석이 완료되지 않았습니다") if latest else "분석 결과가 없습니다") if not latest or latest.state != JobState.COMPLETED or item.analysis_state != JobState.COMPLETED or native_reanalysis_pending else None,
        **_native_policy_result(latest),
        "sha256": item.sha256,
        "sizeBytes": item.size_bytes,
        "specVersion": item.spec_version,
        "filename": item.original_filename,
        "note": item.note,
        "componentCount": component_count if component_count is not None else len(item.components),
        "componentTypeCounts": component_type_counts or {},
        "vulnerabilityCount": len(findings),
        "vulnerableComponentCount": vulnerable_component_count(item.normalized_bom, findings),
        "severityCounts": dict(severity_counts),
        "kevCount": sum(1 for finding in findings if finding.get("kev") is True),
        "policyViolationCount": _policy_count(latest),
        "dataAsOf": latest.data_as_of if latest else None,
        "cveDataAsOf": _cve_data_as_of(latest),
        "analysisDataSources": (latest.data_sources or {}) if latest else {},
        "createdAt": item.created_at.isoformat(),
    }


@app.get("/api/v1/integrations/koda/runs/{run_id}")
def koda_run_result(
    run_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("runs.view", allow_service_token=True)),
) -> dict:
    item = db.scalar(
        select(SbomRun)
        .where(SbomRun.id == run_id)
        .options(
            selectinload(SbomRun.release).selectinload(Release.service),
            selectinload(SbomRun.release).selectinload(Release.environment),
            selectinload(SbomRun.analyses),
            selectinload(SbomRun.components),
        )
    )
    if item is None:
        raise HTTPException(404, "회차를 찾을 수 없습니다")
    if isinstance(principal, ApiToken) and principal.service_id != item.release.service_id:
        raise HTTPException(404, "회차를 찾을 수 없습니다")
    latest = max(item.analyses, key=lambda analysis: analysis.sequence, default=None)
    return {
        "run": _run_payload(item, native_reanalysis_pending=bool(db.scalar(select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id == run_id).limit(1)))),
        "analysis": None if latest is None else {
            "sequence": latest.sequence,
            "state": latest.state,
            "dataAsOf": latest.data_as_of,
            "cveDataAsOf": _cve_data_as_of(latest),
            "findings": project_cve_findings(latest.findings or []),
            "policyViolations": latest.policies or [],
            **_native_policy_result(latest),
            "error": latest.error,
        },
    }


@app.get("/api/v1/sbom-runs")
def list_runs(
    service_id: str | None = None,
    environment_id: str | None = None,
    state: ProcessingState | None = None,
    source: str | None = Query(default=None, pattern="^(manual|api|scheduled)$"),
    q: str | None = Query(default=None, min_length=1, max_length=200),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_permission("runs.view")),
) -> dict:
    query = select(SbomRun).options(
        selectinload(SbomRun.release).selectinload(Release.service),
        selectinload(SbomRun.release).selectinload(Release.environment),
        selectinload(SbomRun.analyses).defer(AnalysisRevision.policies).defer(AnalysisRevision.policy_snapshot),
    )
    if service_id:
        query = query.join(Release).where(Release.service_id == service_id)
    if environment_id:
        query = query.join(Release).where(Release.environment_id == environment_id)
    if state:
        query = query.where(SbomRun.state == state)
    if source:
        query = query.where(
            SbomRun.source.in_(("", "manual", "api")) if source == "manual" else SbomRun.source == source
        )
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(
            or_(
                SbomRun.id.ilike(pattern),
                SbomRun.original_filename.ilike(pattern),
                SbomRun.release.has(Release.version.ilike(pattern)),
                SbomRun.release.has(Release.service.has(Service.name.ilike(pattern))),
                SbomRun.components.any(RunComponent.search_text.ilike(pattern.lower())),
            )
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = list(db.scalars(query.order_by(SbomRun.created_at.desc()).offset((page - 1) * size).limit(size)).unique())
    run_ids = [item.id for item in items]
    native_pending_ids = set(db.scalars(select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id.in_(run_ids)))) if run_ids else set()
    component_counts = dict(
        db.execute(
            select(RunComponent.run_id, func.count()).where(RunComponent.run_id.in_(run_ids)).group_by(RunComponent.run_id)
        ).all()
    ) if run_ids else {}
    component_type_counts: dict[str, dict[str, int]] = defaultdict(dict)
    if run_ids:
        for run_id, component_type, count in db.execute(
            select(RunComponent.run_id, RunComponent.component_type, func.count())
            .where(RunComponent.run_id.in_(run_ids))
            .group_by(RunComponent.run_id, RunComponent.component_type)
        ):
            component_type_counts[run_id][component_type or "library"] = count
    return {
        "items": [
            _run_payload(
                item,
                component_count=component_counts.get(item.id, 0),
                component_type_counts=component_type_counts.get(item.id, {}),
                native_reanalysis_pending=item.id in native_pending_ids,
            )
            for item in items
        ],
        "page": page,
        "size": size,
        "total": total,
    }


def _load_run(
    db: Session,
    run_id: str,
    *,
    include_components: bool = False,
    include_analyses: bool = False,
    include_policy_records: bool = True,
    for_update: bool = False,
) -> SbomRun:
    options = [
        selectinload(SbomRun.release).selectinload(Release.service),
        selectinload(SbomRun.release).selectinload(Release.environment),
    ]
    if include_components:
        options.append(selectinload(SbomRun.components))
    if include_analyses:
        analyses = selectinload(SbomRun.analyses)
        if not include_policy_records:
            analyses = analyses.defer(AnalysisRevision.policies)
        options.append(analyses)
    query = select(SbomRun)
    if for_update:
        query = query.with_for_update()
    item = db.scalar(
        query
        .where(SbomRun.id == run_id)
        .options(*options)
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
    item = _load_run(db, run_id, include_analyses=True, include_policy_records=False)
    component_count = db.scalar(
        select(func.count()).select_from(RunComponent).where(RunComponent.run_id == run_id)
    ) or 0
    payload = {**_run_payload(item, component_count=component_count, native_reanalysis_pending=bool(db.scalar(select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id == run_id).limit(1)))), **_native_policy_result(max(item.analyses, key=lambda value: value.sequence, default=None), include_evidence=True)}
    coverage, _ = coverage_for_bom(item.normalized_bom or {})
    payload.update(coverage)
    payload["components"] = []
    if item.media_type == WORKBOOK_MEDIA_TYPE:
        properties = item.normalized_bom["metadata"]["properties"]
        values = {prop["name"]: prop["value"] for prop in properties}
        payload["workbookMetadata"] = {label: values.get(f"koda:xlsx:{label}", "") for label in METADATA_LABELS}
    analyses = []
    latest_id = payload["analysisId"]
    for analysis in sorted(item.analyses, key=lambda value: value.sequence, reverse=True):
        findings = project_cve_findings(analysis.findings)
        affected_count = None
        if analysis.state == JobState.COMPLETED:
            affected_count = (
                payload["vulnerableComponentCount"] if analysis.id == latest_id
                else vulnerable_component_count(item.normalized_bom, findings)
            )
        analyses.append({
            "id": analysis.id,
            "sequence": analysis.sequence,
            "state": analysis.state,
            "dataAsOf": analysis.data_as_of,
            "cveDataAsOf": _cve_data_as_of(analysis),
            "toolVersion": analysis.tool_version,
            "dataSources": analysis.data_sources or {},
            "findingCount": len(findings),
            "vulnerableComponentCount": affected_count,
            "policyCount": _policy_count(analysis),
            **_native_policy_result(analysis, include_evidence=True),
            "error": analysis.error,
        })
    payload["analyses"] = analyses
    return payload


@app.get("/api/v1/sbom-runs/{run_id}/components")
def get_run_components(
    run_id: str,
    q: str | None = Query(default=None, min_length=1, max_length=200),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_permission("runs.view")),
) -> dict:
    if db.get(SbomRun, run_id) is None:
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    query = select(RunComponent).where(RunComponent.run_id == run_id)
    if q:
        query = query.where(RunComponent.search_text.ilike(f"%{q.strip().lower()}%"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    components = db.scalars(
        query.order_by(RunComponent.name, RunComponent.version).offset((page - 1) * size).limit(size)
    )
    return {
        "items": [
            {
                "identityKey": component.identity_key,
                "identityStatus": component.identity_status,
                "componentType": component.component_type,
                "group": component.group_name,
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "bomRef": component.bom_ref,
                "licenses": component.licenses,
                "properties": component.properties,
            }
            for component in components
        ],
        "page": page,
        "size": size,
        "total": total,
    }


def _finding_sort_key(finding: dict) -> tuple:
    """Stable server-side order, applied before slicing pages."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    raw_score = cvss_score(finding)
    try:
        score = float(raw_score) if raw_score is not None else -1.0
    except (TypeError, ValueError):
        score = -1.0
    if not 0 <= score <= 10:
        score = -1.0
    component = str(finding.get("component") or "").casefold()
    canonical = str(finding.get("canonicalId") or finding.get("id") or "").casefold()
    return (0 if finding.get("kev") is True else 1, -score, -severity_rank.get(str(finding.get("severity") or "unknown").casefold(), 0), component, canonical)


@app.get("/api/v1/sbom-runs/{run_id}/findings")
def get_run_findings(
    run_id: str,
    analysis_id: str | None = Query(default=None, alias="analysisId"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_permission("runs.view")),
) -> dict:
    if db.get(SbomRun, run_id) is None:
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    query = select(AnalysisRevision).where(AnalysisRevision.run_id == run_id)
    if analysis_id:
        query = query.where(AnalysisRevision.id == analysis_id)
    analysis = db.scalar(query.order_by(AnalysisRevision.sequence.desc()).limit(1))
    findings = sorted(project_cve_findings(analysis.findings if analysis else []), key=_finding_sort_key)
    start = (page - 1) * size
    return {
        "analysisId": analysis.id if analysis else None,
        "items": findings[start:start + size],
        "page": page,
        "size": size,
        "total": len(findings),
    }


@app.get("/api/v1/sbom-runs/{run_id}/policy-violations")
def get_run_policy_violations(
    run_id: str,
    analysis_id: str | None = Query(default=None, alias="analysisId"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_permission("runs.view")),
) -> dict:
    if db.get(SbomRun, run_id) is None:
        raise HTTPException(404, "SBOM 회차를 찾을 수 없습니다")
    query = select(AnalysisRevision).where(AnalysisRevision.run_id == run_id)
    if analysis_id:
        query = query.where(AnalysisRevision.id == analysis_id)
    analysis = db.scalar(query.order_by(AnalysisRevision.sequence.desc()).limit(1))
    if analysis_id and analysis is None:
        raise HTTPException(404, "이 회차의 분석 리비전을 찾을 수 없습니다")
    records = (analysis.policies or []) if analysis else []
    start = (page - 1) * size
    return {"analysisId": analysis.id if analysis else None, "items": records[start:start + size], "page": page, "size": size, "total": len(records)}


@app.get("/api/v1/sbom-runs/{run_id}/artifact")
def download_artifact(
    run_id: str,
    db: Session = Depends(get_db),
    _=Depends(require_permission("artifact.download")),
):
    item = _load_run(db, run_id)
    return FileResponse(item.artifact_path, media_type=item.media_type, filename=item.original_filename)




@app.post("/api/v1/sbom-runs/{run_id}/analyses", status_code=202)
def create_analysis(
    run_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_permission("analysis.create")),
    _csrf=Depends(require_csrf),
) -> dict:
    from .data_updates import reference_import_allowed
    try: reference_import_allowed(get_settings())
    except ValueError as exc: raise HTTPException(409, str(exc)) from exc
    run = _load_run(db, run_id, for_update=True)
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        raise HTTPException(409, "보관된 회차는 다시 분석할 수 없습니다")
    existing = db.scalar(select(Job).where(Job.run_id == run.id, Job.kind.in_(["analyze", "process_run"]), Job.state.in_([JobState.QUEUED, JobState.RUNNING])).order_by(Job.created_at).limit(1))
    if existing:
        return {"jobId": existing.id, "runId": run.id}
    if (db.scalar(select(func.count()).select_from(Job).where(Job.state.in_([JobState.QUEUED, JobState.RUNNING]))) or 0) >= get_settings().max_queued_jobs:
        raise HTTPException(429, "처리 대기열이 가득 찼습니다. 기존 작업 완료 후 다시 시도하세요")
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
    run = _load_run(db, run_id, for_update=True)
    if run.archived_at is not None or run.state == ProcessingState.ARCHIVED:
        raise HTTPException(409, "이미 보관된 회차입니다")
    run.archived_at = datetime.now(UTC)
    run.archive_reason = body.reason.strip()
    run.state = ProcessingState.ARCHIVED
    audit(db, principal.username, "sbom.archive", "sbom_run", run.id, {"reason": run.archive_reason})
    db.commit()
    return {"runId": run.id, "state": run.state, "archivedAt": run.archived_at.isoformat()}


@app.delete("/api/v1/sbom-runs/{run_id}")
def delete_run(
    run_id: str,
    db: Session = Depends(get_db),
    principal=Depends(require_admin),
    _=Depends(require_permission("sbom.delete")),
    _csrf=Depends(require_csrf),
) -> dict:
    run = _load_run(db, run_id, for_update=True)
    jobs = list(db.scalars(select(Job).where(Job.run_id == run.id)))
    if run.state not in {ProcessingState.COMPLETED, ProcessingState.FAILED, ProcessingState.ARCHIVED} or any(job.state in {JobState.QUEUED, JobState.RUNNING} for job in jobs):
        raise HTTPException(409, "완료·실패·보관 상태의 회차만 삭제할 수 있습니다")

    root = get_settings().artifact_dir.resolve()
    artifact = Path(run.artifact_path)
    resolved = artifact.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HTTPException(422, "회차 원본 경로가 artifact 루트 밖에 있습니다") from exc
    shared_artifact = db.scalar(
        select(SbomRun.id).where(
            SbomRun.id != run.id,
            SbomRun.artifact_path == run.artifact_path,
        ).limit(1)
    )
    quarantine: Path | None = None
    if artifact.exists() and not artifact.is_file():
        raise HTTPException(422, "회차 원본은 일반 파일이어야 합니다")
    if artifact.exists() and shared_artifact is None:
        quarantine = root / ".delete-quarantine" / f"{run.id}-{uuid.uuid4().hex}"
        quarantine.parent.mkdir(parents=True, exist_ok=True)
        artifact.rename(quarantine)
    receipt = {
        "runId": run.id,
        "deleted": True,
    }
    try:
        db.execute(delete(RunComponent).where(RunComponent.run_id == run.id))
        db.execute(delete(AnalysisRevision).where(AnalysisRevision.run_id == run.id))
        db.execute(delete(Job).where(Job.run_id == run.id))
        db.delete(run)
        db.flush()
        audit(db, principal.username, "sbom.delete", "sbom_run", run_id, {})
        db.commit()
    except Exception:
        db.rollback()
        if quarantine is not None and quarantine.exists() and not artifact.exists():
            quarantine.rename(artifact)
        raise
    if quarantine is not None:
        try:
            quarantine.unlink(missing_ok=True)
            quarantine.parent.rmdir()
        except OSError:
            receipt["artifactCleanupPending"] = True
            logger.exception("SBOM artifact cleanup failed after committed deletion: run_id=%s path=%s", run_id, quarantine)
        else:
            receipt["artifactCleanupPending"] = False
    else:
        receipt["artifactCleanupPending"] = False
    return receipt


@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db), principal=Depends(require_permission("runs.view", "sbom.upload", allow_service_token=True))) -> dict:
    job = db.get(Job, job_id)
    if not job:
        raise HTTPException(404, "작업을 찾을 수 없습니다")
    if isinstance(principal, ApiToken):
        run = db.get(SbomRun, job.run_id) if job.run_id else None
        if not run or (
            principal.service_id
            and run.release.service_id != principal.service_id
        ) or (
            principal.service_id is None
            and run.idempotency_actor != f"token:{principal.id}"
        ):
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
    base = _load_run(db, base_run_id, include_components=True, include_analyses=True)
    target = _load_run(db, target_run_id, include_components=True, include_analyses=True)

    def analysis(run: SbomRun, requested: str | None):
        values = [item for item in run.analyses if not requested or item.id == requested]
        return max(values, key=lambda item: item.sequence, default=None)

    base_analysis = analysis(base, base_analysis_id)
    target_analysis = analysis(target, target_analysis_id)
    if any(value is None or value.state != JobState.COMPLETED for value in (base_analysis, target_analysis)):
        raise HTTPException(409, "완료된 분석 리비전만 비교할 수 있습니다. 보존된 완료 리비전을 선택하십시오")
    if any(((value.data_sources or {}).get("vulnerabilityDataStatus") or {}).get("status") == "unavailable" for value in (base_analysis, target_analysis)):
        raise HTTPException(409, "취약점 데이터가 없어 실패한 분석은 취약점 제거로 비교할 수 없습니다. 보존된 완료 리비전을 선택하십시오")
    component_changes = compare_components(base.components, target.components)
    finding_changes = compare_records(
        project_cve_findings(base_analysis.findings if base_analysis else []),
        project_cve_findings(target_analysis.findings if target_analysis else []),
        keys=("canonicalId", "component"),
    )
    policy_changes = compare_records(
        base_analysis.policies if base_analysis else [],
        target_analysis.policies if target_analysis else [],
        keys=("policyId", "rule", "name", "component", "componentVersion", "vulnerabilityId"),
    )
    return {
        "base": {"runId": base.id, "sha256": base.sha256, "dataAsOf": base_analysis.data_as_of if base_analysis else None, "cveDataAsOf": _cve_data_as_of(base_analysis), "policyState": base_analysis.policy_state if base_analysis else "not_evaluated", "policyVersion": base_analysis.policy_version if base_analysis else None, "artifactUrl": f"/api/v1/sbom-runs/{base.id}/artifact"},
        "target": {"runId": target.id, "sha256": target.sha256, "dataAsOf": target_analysis.data_as_of if target_analysis else None, "cveDataAsOf": _cve_data_as_of(target_analysis), "policyState": target_analysis.policy_state if target_analysis else "not_evaluated", "policyVersion": target_analysis.policy_version if target_analysis else None, "artifactUrl": f"/api/v1/sbom-runs/{target.id}/artifact"},
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
    q: str | None = Query(default=None, min_length=1, max_length=200),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=10, ge=1, le=100),
    format: Literal["json", "csv"] = Query(default="json"),
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
    _=Depends(require_permission("audit.view")),
) -> dict:
    query = select(AuditEvent)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(
            or_(
                AuditEvent.actor.ilike(pattern),
                AuditEvent.action.ilike(pattern),
                AuditEvent.target_type.ilike(pattern),
                AuditEvent.target_id.ilike(pattern),
                cast(AuditEvent.detail, Text).ilike(pattern),
            )
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    if format == "csv":
        def rows():
            output = io.StringIO(newline="")
            writer = csv.writer(output, lineterminator="\r\n")
            yield "\ufeff"
            writer.writerow(["시각", "행위자", "작업", "대상 유형", "대상 ID", "상세"])
            yield output.getvalue()
            with SessionLocal() as stream_db:
                result = stream_db.scalars(query.order_by(AuditEvent.created_at.desc())).yield_per(100)
                for item in result:
                    output.seek(0)
                    output.truncate(0)
                    writer.writerow([
                        _seoul_datetime(item.created_at),
                        _csv_safe(item.actor),
                        _csv_safe(item.action),
                        _csv_safe(item.target_type),
                        _csv_safe(item.target_id),
                        _audit_csv_value(item.detail),
                    ])
                    yield output.getvalue()

        return StreamingResponse(
            rows(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="koda-audit-events.csv"'},
        )
    items = db.scalars(query.order_by(AuditEvent.created_at.desc()).offset((page - 1) * size).limit(size))
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
        "page": page,
        "size": size,
        "total": total,
    }


def _bundle_payload(item: VulnerabilityDataBundle) -> dict:
    manifest = item.manifest or {}
    metadata = manifest.get("metadata") or {}
    return {
        "id": item.id,
        "version": item.version,
        "dataAsOf": metadata.get("GRYPE_DATASET_DATE", item.data_as_of),
        "grypeDbSchema": metadata.get("GRYPE_DB_SCHEMA", "unknown"),
        "grypeDbVersion": metadata.get("GRYPE_DB_VERSION", item.version if item.active else None),
        "vulnDataVersion": metadata.get("VULN_DATA_VERSION", item.version if item.active else None),
        "nvdDataAsOf": metadata.get("NVD_DATASET_DATE", "unknown"),
        "kevDataAsOf": metadata.get("KEV_DATASET_DATE", "unknown"),
        "aliasCount": int(manifest.get("aliasCount", 0) or 0),
        "kevCount": int(manifest.get("kevCount", 0) or 0),
        "manifestSha256": item.sha256,
        "active": item.active,
        "importedAt": item.imported_at.isoformat(),
    }


_DATA_UPDATE_MAX_BYTES = 2 * 1024 * 1024 * 1024


async def _stage_data_update_request(request: Request, *, kind: str) -> tuple[Path, str, int]:
    if kind not in {"grype-db", "vuln-data", "unified"}:
        raise HTTPException(422, "데이터 종류는 unified, grype-db 또는 vuln-data여야 합니다")
    spool = get_settings().data_update_spool_dir
    spool.mkdir(parents=True, exist_ok=True)
    # The data worker detects the actual archive format from its contents.
    path = spool / f"upload-{uuid.uuid4().hex}.archive"
    digest_value = hashlib.sha256()
    total = 0
    try:
        with path.open("wb") as handle:
            async for chunk in request.stream():
                total += len(chunk)
                if total > _DATA_UPDATE_MAX_BYTES:
                    raise HTTPException(413, "취약점 데이터 파일이 업로드 제한을 초과했습니다")
                digest_value.update(chunk)
                handle.write(chunk)
        if total == 0:
            raise HTTPException(422, "빈 데이터 파일은 업로드할 수 없습니다")
        return path, digest_value.hexdigest(), total
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _data_job_payload(job: Job) -> dict:
    payload = job.payload or {}
    return {
        "id": job.id,
        "kind": payload.get("kind"),
        "action": payload.get("action", "validate"),
        "state": job.state,
        "attempts": job.attempts,
        "error": job.error,
        "version": payload.get("version"),
        "dataAsOf": payload.get("dataAsOf"),
        "manifestSha256": payload.get("manifestSha256"),
        "fileSha256": payload.get("fileSha256"),
        "bytes": payload.get("bytes"),
        "expectedBaseVersion": payload.get("expectedBaseVersion"),
        "createdAt": job.created_at.isoformat(),
        "updatedAt": job.updated_at.isoformat(),
    }


def _current_update_version() -> str | None:
    root = get_settings().grype_db_dir.parent.parent / "current"
    try:
        return root.resolve().name if root.is_symlink() and root.resolve().is_dir() else None
    except OSError:
        return None


def _running_data_readers(db):
    return bool(db.scalar(select(Job.id).where(Job.kind.in_(["analyze", "process_run"]), Job.state == JobState.RUNNING).limit(1)))


@app.get("/api/v1/vulnerability-data-bundles/active-baseline")
def active_cve_baseline(response: Response, _=Depends(require_permission("dashboard.view", "runs.view", "vulnerability.view", "metadata.view"))) -> dict:
    from .data_updates import DataUpdateEngine, _metadata, assert_approved_release, managed_state, release_read_lease

    response.headers["Cache-Control"] = "no-store"
    settings = get_settings()
    try:
        with release_read_lease(settings):
            current = DataUpdateEngine(settings, read_only=True).current()
            if current and (managed_state(settings) or {}).get("state") == "active":
                assert_approved_release(settings, current.path)
                date = _metadata(current.path / "metadata.env").get("NVD_DATASET_DATE")
                if date and date != "unknown":
                    return {"cveDataAsOf": date}
    except (OSError, ValueError):
        pass
    return {"cveDataAsOf": None}


@app.get("/api/v1/vulnerability-data-bundles/unified/status")
def unified_vulnerability_status(db: Session = Depends(get_db), _admin=Depends(require_admin), _permission=Depends(require_permission("vulnerability.manage"))):
    from .data_updates import DataUpdateEngine, managed_state, assert_approved_release, release_busy, release_read_lease, verification_status
    from .offline_intelligence_store import active_reference_document, reference_manifest
    settings = get_settings(); engine = DataUpdateEngine(settings, read_only=True); marker = managed_state(settings)
    current = engine.current(); error = None
    available = False
    sources = []; metadata = {}
    try:
        with release_read_lease(settings):
            current = engine.current()
            if current is not None:
                assert_approved_release(settings, current.path)
                available = marker is not None and marker.get("state") == "active"
            if available:
                sources = reference_manifest(active_reference_document(db))["sources"]
                from .data_updates import _metadata as update_metadata
                metadata = update_metadata(current.path / "metadata.env")
    except (ValueError, OSError) as exc: error = str(exc)
    pending = list(db.scalars(select(Job).where(Job.kind.in_(["data_update","vulnerability_data_update"]),Job.state.in_([JobState.QUEUED,JobState.RUNNING])).order_by(Job.created_at)))
    state = (marker or {}).get("state", "empty")
    if not available and state == "active": state = "unavailable"
    dates = {"grype-db":metadata.get("GRYPE_DATASET_DATE",metadata.get("DATASET_DATE")), "nvd":metadata.get("NVD_DATASET_DATE"),"kev":metadata.get("KEV_DATASET_DATE"),"epss":metadata.get("EPSS_DATASET_DATE")}
    busy = _running_data_readers(db) or bool(pending) or release_busy(settings)
    return {"state":state,"available":available,"currentVersion":current.version if available else None,"expectedBaseVersion":current.version if current else None,"managed":marker is not None,"signatureRequired":True,"verification":verification_status(settings),"referenceSources":sources,"datasets":[{"kind":kind,"dataDate":value,"status":"available" if value and available else "missing"} for kind,value in dates.items()],"pendingJobs":[_data_job_payload(job) for job in pending],"canPurge":not busy,"blockedReason":("분석 또는 데이터 작업이 진행 중입니다. 완료 후 재시도하십시오" if busy else error)}


class PurgeVulnerabilityBody(BaseModel):
    confirm: str
    expectedBaseVersion: str | None = None


@app.post("/api/v1/vulnerability-data-bundles/unified/purge", status_code=202)
def purge_unified_vulnerability_data(body: PurgeVulnerabilityBody, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("vulnerability.manage")), _csrf=Depends(require_csrf)):
    from .data_updates import DataUpdateEngine, release_busy
    if body.confirm != "DELETE VULNERABILITY DATA": raise HTTPException(422,"확인 문구가 일치하지 않습니다")
    if body.expectedBaseVersion is not None and body.expectedBaseVersion != _current_update_version(): raise HTTPException(409,"현재 데이터가 변경되었습니다. 상태를 새로 조회하십시오")
    if _running_data_readers(db) or release_busy(get_settings()) or db.scalar(select(Job.id).where(Job.kind.in_(["data_update","vulnerability_data_update"]), Job.state.in_([JobState.QUEUED,JobState.RUNNING])).limit(1)):
        raise HTTPException(409,"분석 또는 데이터 작업이 진행 중입니다. 완료 후 삭제를 다시 요청하십시오")
    job = Job(kind="vulnerability_data_update", payload={"action":"purge","kind":"unified","expectedBaseVersion":body.expectedBaseVersion})
    db.add(job); db.flush(); audit(db,principal.username,"vuln_data.purge.request","vulnerability_data_job",job.id,{"preserved":["users","projects","sbom","results","ssvc","responses","vex","private_vulnerabilities"]});db.commit()
    return _data_job_payload(job)


@app.post("/api/v1/vulnerability-data-bundles/upload", status_code=202)
async def upload_vulnerability_data_bundle(
    request: Request,
    kind: str = Query(...),
    db: Session = Depends(get_db),
    principal=Depends(require_admin),
    _permission=Depends(require_permission("vulnerability.manage")),
    _csrf=Depends(require_csrf),
) -> dict:
    archive, file_sha256, size = await _stage_data_update_request(request, kind=kind)
    payload = {"action": "validate", "kind": kind, "archive": str(archive), "fileSha256": file_sha256, "bytes": size, "expectedBaseVersion": _current_update_version()}
    job = Job(kind="vulnerability_data_update", run_id=None, payload=payload)
    db.add(job)
    db.flush()
    audit(db, principal.username, "vuln_data.upload", "vulnerability_data_job", job.id, {"kind": kind, "bytes": size, "sha256": file_sha256})
    db.commit()
    return _data_job_payload(job)


@app.get("/api/v1/vulnerability-data-bundles/jobs/{job_id}")
def vulnerability_data_job(job_id: str, db: Session = Depends(get_db), _admin=Depends(require_admin), _=Depends(require_permission("vulnerability.manage"))) -> dict:
    job = db.get(Job, job_id)
    if job is None or job.kind != "vulnerability_data_update":
        raise HTTPException(404, "취약점 데이터 작업을 찾을 수 없습니다")
    return _data_job_payload(job)


@app.post("/api/v1/vulnerability-data-bundles/jobs/{job_id}/apply", status_code=202)
def apply_vulnerability_data_job(job_id: str, db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("vulnerability.manage")), _csrf=Depends(require_csrf)) -> dict:
    source = db.get(Job, job_id)
    if source is None or source.kind != "vulnerability_data_update":
        raise HTTPException(404, "취약점 데이터 작업을 찾을 수 없습니다")
    if source.state != JobState.COMPLETED or (source.payload or {}).get("action") != "validate" or (source.payload or {}).get("phase") != "validated":
        raise HTTPException(409, "검증 완료된 작업만 적용할 수 있습니다")
    payload = dict(source.payload or {})
    payload["action"] = "apply"
    payload["sourceJobId"] = source.id
    job = Job(kind="vulnerability_data_update", run_id=None, payload=payload)
    db.add(job)
    db.flush()
    audit(db, principal.username, "vuln_data.apply", "vulnerability_data_job", source.id, {"kind": payload.get("kind")})
    db.commit()
    return _data_job_payload(job)


@app.post("/api/v1/vulnerability-data-bundles/{kind}/rollback", status_code=202)
def rollback_vulnerability_data_bundle(kind: str, version: str | None = Query(default=None), db: Session = Depends(get_db), principal=Depends(require_admin), _permission=Depends(require_permission("vulnerability.manage")), _csrf=Depends(require_csrf)) -> dict:
    if kind not in {"grype-db", "vuln-data", "unified"}:
        raise HTTPException(422, "데이터 종류는 unified, grype-db 또는 vuln-data여야 합니다")
    job = Job(kind="vulnerability_data_update", run_id=None, payload={"action": "rollback", "kind": kind, "version": version})
    db.add(job)
    db.flush()
    audit(db, principal.username, "vuln_data.rollback", "vulnerability_data_job", job.id, {"kind": kind, "version": version})
    db.commit()
    return _data_job_payload(job)


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
    _admin=Depends(require_admin),
    _=Depends(require_permission("vulnerability.view")),
) -> dict:
    # GET stays read-only. An administrator explicitly synchronizes the
    # filesystem release after an import or rollback.
    items = list(db.scalars(select(VulnerabilityDataBundle).order_by(VulnerabilityDataBundle.imported_at.desc())))
    return {"items": [_bundle_payload(item) for item in items]}


@app.post("/api/v1/vulnerability-data-bundles/sync")
def sync_vulnerability_data_bundles(
    db: Session = Depends(get_db),
    principal=Depends(require_admin),
    _permission=Depends(require_permission("vulnerability.manage")),
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
    principal=Depends(require_admin),
    _permission=Depends(require_permission("vulnerability.manage")),
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
