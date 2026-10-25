from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACKER_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./tracker.db"
    artifact_dir: Path = Path("./data/artifacts")
    max_upload_bytes: int = 500 * 1024 * 1024
    max_request_body_bytes: int = 64 * 1024
    max_sbom_components: int = 50_000
    max_service_runs: int = 10_000
    max_service_components: int = 2_000_000
    max_queued_jobs: int = 100
    max_service_storage_bytes: int = 10 * 1024 * 1024 * 1024
    max_service_ingested_bytes: int = 20 * 1024 * 1024 * 1024
    upload_rate_limit: int = 60
    upload_rate_window_seconds: int = 60 * 60
    login_address_limit: int = 100
    login_account_limit: int = 10
    login_window_seconds: int = 5 * 60
    auth_attempt_retention_seconds: int = 24 * 60 * 60
    session_ttl_seconds: int = 8 * 60 * 60
    secure_cookies: bool = False
    environment: str = "development"
    public_bind: str = "127.0.0.1"
    public_origin: str = ""
    trusted_proxy_cidrs: str = ""
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
    ldap_encryption_key: str = ""
    # Closed-network installations use imported data. Enabling an older online
    # feature flag cannot override this boundary.
    offline_mode: bool = True
    epss_policy_max_age_days: int = Field(default=7, ge=0, le=365)
    package_metadata_enabled: bool = True
    package_metadata_ttl_seconds: int = 86400
    package_metadata_request_timeout_seconds: int = 10
    package_metadata_min_interval_seconds: int = 1
    package_metadata_max_attempts: int = 3
    package_metadata_retry_seconds: int = 60
    notification_webhook_enabled: bool = False
    notification_webhook_url: str = ""
    notification_webhook_secret: str = ""
    notification_allowed_hosts: str = ""
    cyclonedx_cli_binary: str = ""
    grype_binary: str = "grype"
    grype_db_dir: Path = Path("./data/vuln-data/current/grype-db")
    # Optional second pinned binary used to prove KODA/Tracker DB compatibility
    # during an offline update.  Empty keeps standalone Tracker installs valid.
    data_update_koda_grype_binary: str = ""
    data_update_verify_key: Path | None = None
    data_update_spool_dir: Path = Path("./data/vuln-data/staging")
    koda_provisioning_token_file: Path | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()


def session_cookie_name() -> str:
    """Use the host-only production name; keep local HTTP installs usable."""
    return "__Host-koda_session" if get_settings().secure_cookies else "koda_session"
