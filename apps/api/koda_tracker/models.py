from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def new_id() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(UTC)


class Role(str, enum.Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    ANALYST = "analyst"
    UPLOADER = "uploader"
    VIEWER = "viewer"


class JobState(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ProcessingState(str, enum.Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    ARCHIVED = "archived"


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.VIEWER)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    approval_state: Mapped[str] = mapped_column(String(16), default="approved")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class RolePolicy(Base):
    __tablename__ = "role_policies"
    role: Mapped[Role] = mapped_column(Enum(Role), primary_key=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    user: Mapped[User] = relationship()


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    dtrack_collection_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Environment(Base):
    __tablename__ = "environments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    sort_order: Mapped[int] = mapped_column(Integer, default=0)


class Release(Base):
    __tablename__ = "releases"
    __table_args__ = (UniqueConstraint("service_id", "environment_id", "version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"), index=True)
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id"), index=True)
    version: Mapped[str] = mapped_column(String(255))
    service: Mapped[Service] = relationship()
    environment: Mapped[Environment] = relationship()


class SbomRun(Base):
    __tablename__ = "sbom_runs"
    __table_args__ = (
        UniqueConstraint("release_id", "round_number"),
        UniqueConstraint("idempotency_actor", "idempotency_key"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    release_id: Mapped[str] = mapped_column(ForeignKey("releases.id"), index=True)
    round_number: Mapped[int] = mapped_column(Integer)
    state: Mapped[ProcessingState] = mapped_column(Enum(ProcessingState), default=ProcessingState.QUEUED)
    analysis_state: Mapped[JobState] = mapped_column(Enum(JobState), default=JobState.QUEUED)
    dtrack_state: Mapped[JobState] = mapped_column(Enum(JobState), default=JobState.QUEUED)
    source: Mapped[str] = mapped_column(String(32), default="manual")
    original_filename: Mapped[str] = mapped_column(String(255))
    media_type: Mapped[str] = mapped_column(String(64))
    spec_version: Mapped[str] = mapped_column(String(16))
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    artifact_path: Mapped[str] = mapped_column(Text)
    normalized_bom: Mapped[dict] = mapped_column(JSON)
    uploaded_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    idempotency_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    dtrack_project_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)
    dtrack_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dtrack_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    dtrack_metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    dtrack_policies: Mapped[list] = mapped_column(JSON, default=list)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    release: Mapped[Release] = relationship()
    components: Mapped[list["RunComponent"]] = relationship(cascade="all, delete-orphan")
    analyses: Mapped[list["AnalysisRevision"]] = relationship(cascade="all, delete-orphan")


class RunComponent(Base):
    __tablename__ = "run_components"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("sbom_runs.id"), index=True)
    identity_key: Mapped[str] = mapped_column(String(1024), index=True)
    identity_status: Mapped[str] = mapped_column(String(32), default="identified")
    component_type: Mapped[str] = mapped_column(String(64), default="library")
    group_name: Mapped[str] = mapped_column(String(512), default="")
    name: Mapped[str] = mapped_column(String(512))
    version: Mapped[str] = mapped_column(String(255), default="")
    purl: Mapped[str] = mapped_column(Text, default="")
    bom_ref: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    licenses: Mapped[list] = mapped_column(JSON, default=list)
    properties: Mapped[list] = mapped_column(JSON, default=list)


class AnalysisRevision(Base):
    __tablename__ = "analysis_revisions"
    __table_args__ = (UniqueConstraint("run_id", "sequence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("sbom_runs.id"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    state: Mapped[JobState] = mapped_column(Enum(JobState), default=JobState.QUEUED)
    data_as_of: Mapped[str] = mapped_column(String(64), default="unknown")
    tool_version: Mapped[str] = mapped_column(String(64), default="unknown")
    data_sources: Mapped[dict] = mapped_column(JSON, default=dict)
    findings: Mapped[list] = mapped_column(JSON, default=list)
    policies: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[str | None] = mapped_column(ForeignKey("sbom_runs.id"), nullable=True, index=True)
    state: Mapped[JobState] = mapped_column(Enum(JobState), default=JobState.QUEUED, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(128))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class VulnerabilityDataBundle(Base):
    __tablename__ = "vulnerability_data_bundles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    version: Mapped[str] = mapped_column(String(128), unique=True)
    sha256: Mapped[str] = mapped_column(String(64))
    data_as_of: Mapped[str] = mapped_column(String(64))
    manifest: Mapped[dict] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
