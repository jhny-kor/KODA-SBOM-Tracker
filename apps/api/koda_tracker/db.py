from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def _engine():
    url = get_settings().database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, pool_pre_ping=True, connect_args=connect_args)


engine = _engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def ensure_postgres_manager_enum(bind=engine) -> None:
    """Additive migration for installations created before manager existed."""
    if bind.dialect.name != "postgresql":
        return
    with bind.begin() as connection:
        if connection.scalar(text("SELECT to_regtype('role') IS NOT NULL")):
            connection.execute(text("ALTER TYPE role ADD VALUE IF NOT EXISTS 'MANAGER'"))


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
