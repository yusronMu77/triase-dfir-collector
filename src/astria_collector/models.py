"""Strict Collector wire models; server owns consent and final metadata verification."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeText = Annotated[str, Field(min_length=1, max_length=500, pattern=r"^[^\x00-\x1f\x7f]*$")]
# Ingest allows 512 characters of free text; Collector must accept every job Ingest may issue.
LongText = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f]+$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Scope(StrictModel):
    # Wire contract owned by Ingest. Whether Collector may execute a value is decided by
    # androidqf.SCOPE_VALUES, so an unsupported scope is refused before the operator confirms.
    backup: Literal["none", "all"]
    download: Literal["none", "non-system", "all"]
    remove_trusted: Literal["yes", "no"]
    intrusion_logs: Literal["yes", "no"]
    hash_files: Literal["yes", "no"]
    browser_history: Literal["yes", "no"]
    magisk_modules: Literal["yes", "no"]


class DeviceIdentity(StrictModel):
    label: SafeText
    serial_tail: Annotated[str, Field(min_length=1, max_length=4, pattern=r"^[A-Za-z0-9_-]+$")]
    serial_sha256: Digest


class Job(StrictModel):
    job_id: Identifier
    consent_id: Identifier
    device: DeviceIdentity
    scope_flags: Scope
    expires_at: datetime
    trace_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    owner_ref: SafeText
    purpose: SafeText
    limitations: LongText

    @field_validator("expires_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("UTC offset required")
        return value

    def check_expiry(self, now: datetime | None = None) -> None:
        if self.expires_at <= (now or datetime.now(UTC)):
            raise ValueError("JOB_EXPIRED")


class ServerConfig(StrictModel):
    age_recipient: Annotated[str, Field(pattern=r"^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$")]
    age_recipient_sha256: Digest
    androidqf_version: Literal["1.8.3"]


class Receipt(StrictModel):
    acquisition_id: Identifier
    job_id: Identifier
    status: Literal["received"]
    archive_sha256: Digest
    archive_size: Annotated[int, Field(gt=0)]
    metadata_status: Literal["pending_verification"]


class Manifest(StrictModel):
    schema_version: Literal[1] = 1
    job: Job
    archive_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,100}\.zip\.age$")]
    archive_sha256: Digest
    archive_size: Annotated[int, Field(gt=0)]
    androidqf_version: Literal["1.8.3"] = "1.8.3"
    androidqf_sha256: Digest
    adb_version: SafeText
    started_at: datetime
    ended_at: datetime
    # Metadata stays inside the encrypted archive. Exit code is not module success.
    status: Literal["pending_verification"] = "pending_verification"
    process_exit_code: int
