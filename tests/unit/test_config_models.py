"""Configuration and wire-model validation, including the contract Ingest actually issues."""

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import NOW, SERIAL, job_document
from pydantic import ValidationError

from astria_collector.config import Settings, load_settings
from astria_collector.models import Job, Scope
from astria_collector.tasks import unsupported_scope


def base(tmp_path: Path, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "collector_key_id": "collector-1",
        "androidqf_sha256": "a" * 64,
        "adb_path": tmp_path / "adb.exe",
        "adb_sha256": "b" * 64,
    }
    values.update(overrides)
    return values


def test_safe_defaults(tmp_path: Path) -> None:
    settings = Settings(**base(tmp_path))
    assert settings.ingest_base_url == "http://127.0.0.1:8081"
    assert (settings.poll_interval_s, settings.device_wait_min, settings.task_timeout_min) == (10, 10, 60)
    assert settings.upload_retries == 5
    assert "AstriaCollector" in str(settings.work_dir)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8081", "http://localhost:8081", "https://ingest.example.internal"])
def test_accepted_origins(tmp_path: Path, url: str) -> None:
    assert Settings(**base(tmp_path, ingest_base_url=url)).ingest_base_url == url


@pytest.mark.parametrize(
    "url",
    [
        "http://ingest.example.internal",  # plain HTTP is loopback only
        "http://10.0.0.5:8081",
        "https://user:pass@ingest.example.internal",
        "https://ingest.example.internal/api",
        "https://ingest.example.internal?x=1",
        "ftp://ingest.example.internal",
        "https://",
    ],
)
def test_rejected_origins(tmp_path: Path, url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**base(tmp_path, ingest_base_url=url))


@pytest.mark.parametrize("field", ["collector_hmac_secret", "hmac_secret", "password", "unknown"])
def test_secret_and_unknown_keys_are_not_configuration(tmp_path: Path, field: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**base(tmp_path, **{field: "x" * 64}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"androidqf_sha256": "A" * 64},
        {"androidqf_sha256": "a" * 63},
        {"collector_key_id": "../escape"},
        {"upload_retries": 0},
        {"upload_retries": 99},
        {"task_timeout_min": 0},
        {"device_wait_min": 1000},
        {"poll_interval_s": 0},
        {"work_dir": "\\\\server\\share\\work"},
    ],
)
def test_invalid_values_rejected(tmp_path: Path, overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Settings(**base(tmp_path, **overrides))


def test_toml_uses_documented_uppercase_keys_and_resolves_paths(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        'INGEST_BASE_URL = "http://127.0.0.1:8081"\nCOLLECTOR_KEY_ID = "collector-1"\n'
        f'ANDROIDQF_SHA256 = "{"a" * 64}"\nADB_PATH = "platform-tools/adb.exe"\nADB_SHA256 = "{"b" * 64}"\n'
        "POLL_INTERVAL_S = 15\n",
        encoding="utf-8",
    )
    settings = load_settings(config)
    assert settings.poll_interval_s == 15
    assert settings.adb_path.is_absolute()
    assert settings.androidqf_path.is_absolute()


def test_toml_with_secret_field_is_refused(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        f'COLLECTOR_KEY_ID = "k"\nANDROIDQF_SHA256 = "{"a" * 64}"\nADB_PATH = "adb.exe"\n'
        f'ADB_SHA256 = "{"b" * 64}"\nCOLLECTOR_HMAC_SECRET = "{"0" * 64}"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_settings(config)


def test_job_from_design_example_parses(job: Job) -> None:
    assert job.device.serial_sha256 == hashlib.sha256(SERIAL.encode()).hexdigest()
    assert job.limitations.startswith("Tidak membaca")


def test_job_accepts_every_scope_ingest_may_issue() -> None:
    # Ingest's wire contract allows these values; Collector must parse them and refuse them explicitly.
    wide = dict(job_document()["scope_flags"], backup="all", intrusion_logs="yes")  # type: ignore[call-overload]
    parsed = Job.model_validate(job_document(scope_flags=wide))
    assert unsupported_scope(parsed) in {"backup", "intrusion_logs"}


def test_supported_scope_is_accepted(job: Job) -> None:
    assert unsupported_scope(job) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"job_id": "../etc"},
        {"job_id": "a" * 65},
        {"trace_id": "xyz"},
        {"expires_at": "2026-11-15T12:00:00"},  # naive datetime
        {"limitations": ""},
        {"limitations": "line\nbreak"},
        {"extra_field": 1},
        {"scope_flags": {"backup": "none"}},
    ],
)
def test_job_rejects_malformed(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Job.model_validate(job_document(**overrides))


def test_job_expiry(job: Job) -> None:
    job.check_expiry(NOW)
    with pytest.raises(ValueError, match="JOB_EXPIRED"):
        job.check_expiry(job.expires_at)
    with pytest.raises(ValueError, match="JOB_EXPIRED"):
        job.check_expiry(job.expires_at + timedelta(seconds=1))
    assert job.expires_at.tzinfo is not None


def test_scope_model_has_no_defaults() -> None:
    with pytest.raises(ValidationError):
        Scope.model_validate({})
