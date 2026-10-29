"""Explicit environment administration grants, separate from global roles."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base
from .models import now


class EnvironmentAdministrator(Base):
    __tablename__ = "environment_administrators"

    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    assigned_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
