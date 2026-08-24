from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
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


def ensure_user_approval_state_column(bind=engine) -> None:
    """Add the explicit signup approval state to an existing users table."""
    if "users" not in inspect(bind).get_table_names():
        return
    if "approval_state" in {column["name"] for column in inspect(bind).get_columns("users")}:
        return
    with bind.begin() as connection:
        connection.execute(
            text("ALTER TABLE users ADD COLUMN approval_state VARCHAR(16) NOT NULL DEFAULT 'approved'")
        )


def ensure_user_identity_columns(bind=engine) -> None:
    """Add the auth-source boundary used to prevent local/LDAP identity collisions."""
    if "users" not in inspect(bind).get_table_names():
        return
    columns = {column["name"] for column in inspect(bind).get_columns("users")}
    with bind.begin() as connection:
        if "auth_source" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN auth_source VARCHAR(16) NOT NULL DEFAULT 'local'"))
        if "ldap_subject" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN ldap_subject VARCHAR(512)"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_ldap_subject ON users (ldap_subject)"))


def ensure_ldap_subject_attribute_column(bind=engine) -> None:
    """Keep the LDAP identity selector additive for databases created mid-release."""
    if "ldap_settings" not in inspect(bind).get_table_names():
        return
    if "subject_attribute" in {column["name"] for column in inspect(bind).get_columns("ldap_settings")}:
        return
    with bind.begin() as connection:
        connection.execute(text("ALTER TABLE ldap_settings ADD COLUMN subject_attribute VARCHAR(128) NOT NULL DEFAULT 'objectGUID'"))


def ensure_component_search_support(bind=engine) -> None:
    """Backfill the component search field and enable trigram indexes."""
    if "run_components" not in inspect(bind).get_table_names():
        return
    columns = {column["name"] for column in inspect(bind).get_columns("run_components")}
    with bind.begin() as connection:
        if "search_text" not in columns:
            connection.execute(text("ALTER TABLE run_components ADD COLUMN search_text TEXT NOT NULL DEFAULT ''"))
        connection.execute(
            text(
                "UPDATE run_components SET search_text = lower("
                "coalesce(group_name, '') || ' ' || coalesce(name, '') || ' ' || "
                "coalesce(version, '') || ' ' || coalesce(purl, '') || ' ' || coalesce(bom_ref, '')"
                ") WHERE search_text = ''"
            )
        )
        if bind.dialect.name == "postgresql":
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
            for statement in (
                "CREATE INDEX IF NOT EXISTS ix_run_components_search_trgm ON run_components USING gin (search_text gin_trgm_ops)",
                "CREATE INDEX IF NOT EXISTS ix_services_name_trgm ON services USING gin (name gin_trgm_ops)",
                "CREATE INDEX IF NOT EXISTS ix_releases_version_trgm ON releases USING gin (version gin_trgm_ops)",
                "CREATE INDEX IF NOT EXISTS ix_sbom_runs_filename_trgm ON sbom_runs USING gin (original_filename gin_trgm_ops)",
            ):
                connection.execute(text(statement))


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
