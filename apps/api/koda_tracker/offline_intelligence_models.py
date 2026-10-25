"""Immutable imported reference datasets and append-only operational responses."""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base
from .models import new_id, now


class OfflineReferenceSnapshot(Base):
    __tablename__ = "offline_reference_snapshots"
    __table_args__ = (UniqueConstraint("kind", "source_id", "sha256"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    source_version: Mapped[str] = mapped_column(String(128))
    data_as_of: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    record_count: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict] = mapped_column(JSON)
    imported_by: Mapped[str] = mapped_column(String(128))
    origin: Mapped[str] = mapped_column(String(32), default="manual")
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class OfflineReferenceCurrent(Base):
    __tablename__ = "offline_reference_current"
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class OfflineResponseEvent(Base):
    __tablename__ = "offline_response_events"
    __table_args__ = (Index("ix_offline_response_target", "run_id", "target_key", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    revision_id: Mapped[str] = mapped_column(String(36))
    service_id: Mapped[str] = mapped_column(String(36), index=True)
    environment_id: Mapped[str] = mapped_column(String(36), index=True)
    component: Mapped[str] = mapped_column(Text)
    component_version: Mapped[str] = mapped_column(String(255))
    vulnerability_id: Mapped[str] = mapped_column(String(255))
    target_key: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str] = mapped_column(String(255))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rationale: Mapped[str] = mapped_column(Text)
    ticket: Mapped[str] = mapped_column(String(2048), default="")
    author: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
