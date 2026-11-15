"""Shared synthetic fixtures. Nothing here touches an Android device or the real AndroidQF."""

import hashlib
import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from astria_collector import pack
from astria_collector.client import IngestClient
from astria_collector.config import Settings
from astria_collector.device import Device, DeviceError, serial_sha256
from astria_collector.models import Job, Manifest, Receipt
from astria_collector.processes import ProcessResult
from astria_collector.tasks import AcquireRequest, Runner

SERIAL = "SYNTHETIC0017K2A"
KEY_ID = "collector-1"
SECRET = bytes(range(32))
AGE = pack.AGE_HEADER + b"synthetic ciphertext, not real age encryption" * 8
JOB_ID = "SJ-2026-0001"
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
SCOPE = {
    "backup": "none",
    "download": "non-system",
    "remove_trusted": "yes",
    "intrusion_logs": "no",
    "hash_files": "no",
    "browser_history": "no",
    "magisk_modules": "no",
}


def job_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "job_id": JOB_ID,
        "consent_id": "CS-2026-0001",
        "device": {"label": "HP-STF-017", "serial_tail": SERIAL[-4:], "serial_sha256": serial_sha256(SERIAL)},
        "scope_flags": dict(SCOPE),
        "expires_at": (NOW + timedelta(hours=2)).isoformat(),
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "owner_ref": "Rujukan-STF-017",
        "purpose": "Pemeriksaan HP milik tim sendiri",
        "limitations": "Tidak membaca pesan, kontak, atau aplikasi pribadi",
    }
    document.update(overrides)
    return document


@pytest.fixture
def job() -> Job:
    return Job.model_validate(job_document())


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    tools = tmp_path / "tools"
    tools.mkdir()
    androidqf = tools / "androidqf.exe"
    adb = tools / "adb.exe"
    androidqf.write_bytes(b"synthetic androidqf stand-in")
    adb.write_bytes(b"synthetic adb stand-in")
    return Settings(
        collector_key_id=KEY_ID,
        androidqf_path=androidqf,
        androidqf_sha256=hashlib.sha256(androidqf.read_bytes()).hexdigest(),
        adb_path=adb,
        adb_sha256=hashlib.sha256(adb.read_bytes()).hexdigest(),
        work_dir=tmp_path / "work",
        log_dir=tmp_path / "logs",
        upload_retries=3,
    )


class FakeUplink:
    """In-memory Ingest double with scripted upload behaviour."""

    def __init__(self, uploads: list[Exception | None] | None = None) -> None:
        self.script = list(uploads or [None])
        self.progress_calls: list[tuple[str, str | None]] = []
        self.uploaded: list[Manifest] = []
        self.progress_error: Exception | None = None

    def progress(self, job: Job, stage: str, code: str | None = None) -> None:
        if self.progress_error:
            raise self.progress_error
        self.progress_calls.append((stage, code))

    def upload(self, archive: Path, manifest: Manifest) -> Receipt:
        action = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if action is not None:
            raise action
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest.archive_sha256
        self.uploaded.append(manifest)
        return Receipt(
            acquisition_id="AQ-synthetic",
            job_id=manifest.job.job_id,
            status="received",
            archive_sha256=manifest.archive_sha256,
            archive_size=manifest.archive_size,
            metadata_status="pending_verification",
        )

    @property
    def stages(self) -> list[str]:
        return [stage for stage, _ in self.progress_calls]


def good_acquirer(data: bytes = AGE, name: str = "ACQ-0001.zip.age") -> Callable[[AcquireRequest], ProcessResult]:
    def acquire(request: AcquireRequest) -> ProcessResult:
        (request.output_dir / name).write_bytes(data)
        return ProcessResult(0, "", "")

    return acquire


def device_waiter(serial: str = SERIAL, error: str | None = None):
    def wait(job: Job, cancel: threading.Event, on_status: Callable[[str], None]) -> Device:
        if error:
            raise DeviceError(error)
        return Device(serial, "device", "Pixel_7")

    return wait


def make_runner(settings: Settings, uplink: FakeUplink, **overrides) -> Runner:
    options = {
        "acquire": good_acquirer(),
        "wait": device_waiter(),
        "now": lambda: NOW,
        "adb_version_reader": lambda _path: "1.0.41 (fixture)",
    }
    options.update(overrides)
    return Runner(settings, uplink, **options)


def transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.fixture
def client_factory(settings: Settings):
    created: list[IngestClient] = []

    def build(handler: Callable[[httpx.Request], httpx.Response]) -> IngestClient:
        client = IngestClient(settings, SECRET, transport=transport(handler), sleep=lambda _seconds: None)
        created.append(client)
        return client

    yield build
    for client in created:
        client.close()


def job_json(**overrides: object) -> bytes:
    return json.dumps(job_document(**overrides)).encode()


def receipt_for(manifest: Manifest) -> Receipt:
    return Receipt(
        acquisition_id="AQ-synthetic",
        job_id=manifest.job.job_id,
        status="received",
        archive_sha256=manifest.archive_sha256,
        archive_size=manifest.archive_size,
        metadata_status="pending_verification",
    )


def scripted(*answers: str) -> Callable[[str], str]:
    """An operator who types the given answers in order."""
    remaining = iter(answers)
    return lambda _prompt: next(remaining)
