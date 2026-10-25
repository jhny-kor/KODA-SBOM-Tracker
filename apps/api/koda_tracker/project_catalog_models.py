"""Mutable project catalog, immutable run links and durable source-sync records."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
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

    collection_config: Mapped["NativeCollectionConfig | None"] = relationship(cascade="all, delete-orphan", uselist=False, lazy="selectin")


class NativeCollectionConfig(Base):
    __tablename__ = "native_collection_configs"
    project_id: Mapped[str] = mapped_column(ForeignKey("native_projects.id", ondelete="CASCADE"), primary_key=True)
    logic: Mapped[str] = mapped_column(String(64), default="NONE")
    tag: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ProjectRunLink(Base):
    __tablename__ = "project_run_links"
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), index=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)






class NativeReanalysisPending(Base):
    __tablename__ = "native_reanalysis_pending"
    source_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    reason: Mapped[str] = mapped_column(String(128), default="source_sync")
