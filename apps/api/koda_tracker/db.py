from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import BigInteger, create_engine, inspect, text
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


def ensure_environment_active_column(bind=engine) -> None:
    """Add the catalog tombstone flag without changing historical releases."""
    if "environments" not in inspect(bind).get_table_names():
        return
    if "active" not in {column["name"] for column in inspect(bind).get_columns("environments")}:
        with bind.begin() as connection:
            connection.execute(text("ALTER TABLE environments ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE"))


def ensure_sbom_source_metadata_column(bind=engine) -> None:
    """Add scheduled-run provenance without changing existing SBOM rows."""
    if "sbom_runs" not in inspect(bind).get_table_names():
        return
    if "source_metadata" not in {column["name"] for column in inspect(bind).get_columns("sbom_runs")}:
        with bind.begin() as connection:
            connection.execute(text("ALTER TABLE sbom_runs ADD COLUMN source_metadata JSON"))


def ensure_sbom_media_type_column(bind=engine) -> None:
    """Widen existing PostgreSQL columns to fit the standard Excel media type."""
    if bind.dialect.name != "postgresql":
        return
    for column in inspect(bind).get_columns("sbom_runs"):
        if column["name"] == "media_type":
            length = getattr(column["type"], "length", None)
            if length is not None and length < 128:
                with bind.begin() as connection:
                    connection.execute(text("ALTER TABLE sbom_runs ALTER COLUMN media_type TYPE VARCHAR(128)"))
            return


def ensure_sbom_size_bytes_column(bind=engine) -> None:
    """Preserve old size values while allowing artifacts larger than 2 GiB."""
    if bind.dialect.name != "postgresql":
        return
    for column in inspect(bind).get_columns("sbom_runs"):
        if column["name"] == "size_bytes" and not isinstance(column["type"], BigInteger):
            with bind.begin() as connection:
                connection.execute(text("ALTER TABLE sbom_runs ALTER COLUMN size_bytes TYPE BIGINT"))
            return


def ensure_native_policy_columns(bind=engine) -> None:
    """Preserve historical findings; old revisions remain explicitly unevaluated."""
    if "analysis_revisions" not in inspect(bind).get_table_names():
        return
    columns = {column["name"] for column in inspect(bind).get_columns("analysis_revisions")}
    definitions = {
        "policy_state": "VARCHAR(32) NOT NULL DEFAULT 'not_evaluated'",
        "policy_version": "INTEGER",
        "policy_snapshot": "JSON",
        "policy_error": "TEXT",
        "metrics": "JSON",
    }
    with bind.begin() as connection:
        for name, definition in definitions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE analysis_revisions ADD COLUMN {name} {definition}"))


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session


def remove_retired_connector_schema(bind=engine) -> None:
    """Remove retired connector-only state while preserving all SBOM/project rows.

    Native policy expressions and historical scanner evidence are deliberately
    retained. This idempotent upgrade contains only fixed schema identifiers.
    """
    retired_columns = {"services": ("dtrack_collection_uuid",), "sbom_runs": ("dtrack_state", "dtrack_project_uuid", "dtrack_token", "dtrack_error", "dtrack_metrics", "dtrack_policies")}
    with bind.begin() as connection:
        tables = set(inspect(connection).get_table_names())
        for table in ("project_sync_events", "project_sync_sources", "legacy_object_maps", "legacy_migrations"):
            if table in tables:
                connection.execute(text(f'DROP TABLE "{table}"'))
        if "jobs" in tables:
            connection.execute(text("DELETE FROM jobs WHERE kind = :kind"), {"kind": "sync_dependency_track"})
        for table, columns in retired_columns.items():
            if table not in tables: continue
            existing = {column["name"] for column in inspect(connection).get_columns(table)}
            for column in columns:
                if column in existing:
                    connection.execute(text(f'ALTER TABLE "{table}" DROP COLUMN "{column}"'))
        if "role_policies" in tables:
            import json
            rows = connection.execute(text("SELECT role, permissions FROM role_policies")).all()
            for role, raw in rows:
                values = json.loads(raw) if isinstance(raw, str) else raw
                cleaned = [value for value in (values or []) if value not in {"dtrack.retry", "dtrack.settings", "migrations.manage"}]
                if cleaned != values:
                    # JSON binding differs between SQLite and PostgreSQL; the
                    # typed table update preserves the database JSON adapter.
                    from .models import RolePolicy
                    connection.execute(RolePolicy.__table__.update().where(RolePolicy.__table__.c.role == role).values(permissions=cleaned))
