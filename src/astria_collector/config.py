"""Configuration contains public material only; HMAC lives in Credential Manager."""

import ipaddress
import os
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import Digest, Identifier


def local_root() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local/share"))) / "AstriaCollector"


def application_root() -> Path:
    return Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="forbid", env_prefix="ASTRIA_", case_sensitive=False)
    ingest_base_url: str = "http://127.0.0.1:8081"
    collector_key_id: Identifier
    androidqf_path: Path = Path("tools/androidqf.exe")
    androidqf_sha256: Digest
    adb_path: Path
    adb_sha256: Digest
    work_dir: Path = Field(default_factory=lambda: local_root() / "work")
    log_dir: Path = Field(default_factory=lambda: local_root() / "logs")
    poll_interval_s: int = Field(default=10, ge=1, le=3600)
    device_wait_min: float = Field(default=10, gt=0, le=120)
    task_timeout_min: float = Field(default=60, gt=0, le=240)
    upload_retries: int = Field(default=5, ge=1, le=8)
    request_timeout_s: float = Field(default=60, gt=0, le=600)
    upload_timeout_s: float = Field(default=600, gt=0, le=7200)
    max_archive_bytes: int = Field(default=20 * 1024**3, gt=0, le=1024**4)

    @field_validator("ingest_base_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        url = urlsplit(value)
        if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("INGEST_BASE_URL must be an origin without credentials")
        if not url.hostname or url.scheme not in {"http", "https"}:
            raise ValueError("invalid Ingest origin")
        if url.scheme == "http":
            try:
                loopback = ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                loopback = url.hostname == "localhost"
            if not loopback:
                raise ValueError("HTTPS required outside loopback")
        _ = url.port
        return value.rstrip("/")

    @field_validator("work_dir", "log_dir", "androidqf_path", "adb_path")
    @classmethod
    def local_path(cls, value: Path) -> Path:
        if str(value).startswith(("\\\\", "//")) or "\x00" in str(value):
            raise ValueError("local path required")
        return value


def load_settings(path: Path) -> Settings:
    with path.open("rb") as stream:
        config = tomllib.load(stream)
    # Documented uppercase keys and Python lowercase spellings both work, without a secret field.
    settings = Settings(**{key.lower(): value for key, value in config.items()})
    return settings.model_copy(
        update={
            "androidqf_path": (application_root() / settings.androidqf_path).absolute(),
            "adb_path": (application_root() / settings.adb_path).absolute(),
            "work_dir": settings.work_dir.absolute(),
            "log_dir": settings.log_dir.absolute(),
        }
    )
