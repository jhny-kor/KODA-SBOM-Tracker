from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRACKER_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./tracker.db"
    artifact_dir: Path = Path("./data/artifacts")
    max_upload_bytes: int = 25 * 1024 * 1024
    session_ttl_seconds: int = 8 * 60 * 60
    secure_cookies: bool = False
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
    dependency_track_url: str = ""
    dependency_track_api_key: str = ""
    dependency_track_ui_url: str = "/dependency-track/"
    cyclonedx_cli_binary: str = ""
    grype_binary: str = "grype"
    grype_db_dir: Path = Path("./data/vuln-data/current/grype-db")


@lru_cache
def get_settings() -> Settings:
    return Settings()
