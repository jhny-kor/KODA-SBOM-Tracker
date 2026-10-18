"""Registry metadata is an optional cache, separate from SBOM/Grype evidence."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base
from .models import now


class PackageMetadataCache(Base):
    __tablename__ = "package_metadata_cache"
    __table_args__ = (UniqueConstraint("package_key", "current_version"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    package_key: Mapped[str] = mapped_column(String(1024), index=True)
    current_version: Mapped[str] = mapped_column(String(255))
    purl: Mapped[str] = mapped_column(Text)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)
    state: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    document: Mapped[dict] = mapped_column(JSON, default=dict)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=now, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PackageMetadataCursor(Base):
    __tablename__ = "package_metadata_cursor"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="backfill")
    last_component_id: Mapped[str] = mapped_column(String(36), default="")
