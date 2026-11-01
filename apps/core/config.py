from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", extra="ignore")

    database_url: str = "sqlite:///./.runtime/hardened.db"
    origin: str = "http://127.0.0.1:18081"
    secure_cookie: bool = False  # Loopback HTTP lab only. Enable behind local TLS.
    session_seconds: int = Field(default=1800, ge=30, le=86400)
    upload_limit: int = Field(default=65536, ge=1024, le=65536)
    progress_path: Path = Path(".runtime/progress.sqlite3")

    @field_validator("origin")
    @classmethod
    def local_origin(cls, value: str) -> str:
        if value not in {
            "http://127.0.0.1:18080",
            "http://127.0.0.1:18081",
            "http://127.0.0.1:18082",
            "https://127.0.0.1:18081",
        }:
            raise ValueError("Only documented loopback origins are supported")
        return value
