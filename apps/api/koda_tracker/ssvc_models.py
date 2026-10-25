"""Append-only, revision-scoped SSVC decisions; historical identifiers survive deletion."""
from __future__ import annotations

from datetime import datetime
from sqlalchemy import JSON, DateTime, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base
from .models import new_id, now


class SsvcAssessment(Base):
    __tablename__ = "ssvc_assessments"
    __table_args__ = (Index("ix_ssvc_assessment_target", "run_id", "target_key", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    revision_id: Mapped[str] = mapped_column(String(36))
    service_id: Mapped[str] = mapped_column(String(36), index=True)
    environment_id: Mapped[str] = mapped_column(String(36), index=True)
    release_id: Mapped[str] = mapped_column(String(36))
    target_key: Mapped[str] = mapped_column(String(64))
    component: Mapped[str] = mapped_column(Text)
    component_version: Mapped[str] = mapped_column(String(255))
    vulnerability_id: Mapped[str] = mapped_column(String(255))
    model: Mapped[str] = mapped_column(String(64))
    table_sha256: Mapped[str] = mapped_column(String(64))
    inputs: Mapped[dict] = mapped_column(JSON)
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON)
    evidence_sha256: Mapped[str] = mapped_column(String(64))
    rationale: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON, default=list)
    author: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
