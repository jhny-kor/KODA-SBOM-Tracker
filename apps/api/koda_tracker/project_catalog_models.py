"""Mutable project catalog, immutable run links and durable source-sync records."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base
from .models import new_id, now


class NativeProject(Base):
    __tablename__ = "native_projects"
    __table_args__ = (UniqueConstraint("source_id", "source_project_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(128), index=True)
    source_project_id: Mapped[str] = mapped_column(String(128), index=True)
    service_id: Mapped[str] = mapped_column(String(36), index=True)
    environment_id: Mapped[str] = mapped_column(String(36), index=True)
    release_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    current_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(255), default="")
    parent_project_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    is_latest: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class ProjectRunLink(Base):
    __tablename__ = "project_run_links"
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ProjectSyncSource(Base):
    __tablename__ = "project_sync_sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    base_url: Mapped[str] = mapped_column(String(2048))
    allowed_origins: Mapped[list] = mapped_column(JSON)
    project_uuids: Mapped[list] = mapped_column(JSON, default=list)
    source_timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    key_ciphertext: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    version: Mapped[int] = mapped_column(Integer, default=1)
    state: Mapped[str] = mapped_column(String(16), default="idle")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_migration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(36))
    actor_name: Mapped[str] = mapped_column(String(128))


class ProjectSyncEvent(Base):
    __tablename__ = "project_sync_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    attempt: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    migration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class NativeReanalysisPending(Base):
    __tablename__ = "native_reanalysis_pending"
    source_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    reason: Mapped[str] = mapped_column(String(128), default="source_sync")
