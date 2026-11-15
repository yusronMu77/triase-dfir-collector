"""Synthetic end to end: real Collector code against the real Ingest app and a real PostgreSQL.

Fake AndroidQF and a synthetic device stand in for the phone, so this is NOT physical-device validation.
Enable with both variables (PostgreSQL must be disposable):

    ASTRIA_TEST_DATABASE_URL=postgresql+psycopg://user:pass@127.0.0.1:5432/db
    ASTRIA_E2E_INGEST_PROJECT=..\\ingest
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import AGE, SCOPE, FakeUplink, device_waiter, good_acquirer

from astria_collector import pack
from astria_collector.client import ClientError, IngestClient
from astria_collector.config import Settings
from astria_collector.models import Job
from astria_collector.tasks import Runner, State, confirm_job

DB = os.environ.get("ASTRIA_TEST_DATABASE_URL")
PROJECT = os.environ.get("ASTRIA_E2E_INGEST_PROJECT")
pytestmark = pytest.mark.skipif(
    not (DB and PROJECT), reason="ASTRIA_TEST_DATABASE_URL and ASTRIA_E2E_INGEST_PROJECT are required"
)
HARNESS = Path(__file__).with_name("ingest_harness.py")


@pytest.fixture(scope="module")
def ingest(tmp_path_factory: pytest.TempPathFactory):
    folder = tmp_path_factory.mktemp("harness")
    ready = folder / "ready.json"
    env = {**os.environ, "PYTHONUTF8": "1", "ASTRIA_HARNESS_READY": str(ready)}
    with (folder / "ingest.log").open("wb") as log:
        process = subprocess.Popen(  # noqa: S603 -- fixed argv, test harness only
            ["uv", "run", "--no-active", "--project", str(PROJECT), "python", str(HARNESS)],
            stdin=subprocess.PIPE,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        deadline = time.monotonic() + 90
        while not ready.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                process.kill()
                pytest.fail("harness failed:\n" + (folder / "ingest.log").read_text(errors="replace")[-3000:])
            time.sleep(0.25)
        info = json.loads(ready.read_text(encoding="utf-8"))
        yield info
        assert process.stdin is not None
        process.stdin.close()
        process.wait(timeout=60)


def provision(ingest: dict, job_id: str, trace: str) -> dict:
    expires = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    job = {
        "job_id": job_id,
        "consent_id": "CS-" + job_id,
        "device": {
            "label": "HP-STF-017",
            "serial_tail": ingest["serial"][-4:],
            "serial_sha256": ingest["serial_sha256"],
        },
        "scope_flags": dict(SCOPE),
        "expires_at": expires,
        "trace_id": trace,
        "owner_ref": "Rujukan-STF-017",
        "purpose": "Uji sintetis tanpa HP nyata",
        "limitations": "Tidak membaca pesan, kontak, atau aplikasi pribadi",
    }
    consent = {
        "owner_ref": job["owner_ref"],
        "purpose": job["purpose"],
        "basis": "explicit_owner_consent",
        "given_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
        "record_ref": "synthetic-record",
        "record_sha256": hashlib.sha256(b"synthetic consent").hexdigest(),
        "scope_flags": dict(SCOPE),
        "device_serial_sha256": ingest["serial_sha256"],
        "expires_at": expires,
        "explicit": True,
    }
    response = httpx.post(
        ingest["url"] + "/svc/v1/device-scans",
        json={"collector_key_id": ingest["key_id"], "job": job, "consent": consent},
        headers={"Authorization": "Bearer " + ingest["manager_token"]},
        timeout=15,
    )
    assert response.status_code == 201, response.text
    return job


def collector_settings(ingest: dict, tmp: Path) -> Settings:
    tools = tmp / "tools"
    tools.mkdir(exist_ok=True)
    (tools / "androidqf.exe").write_bytes(b"synthetic androidqf stand-in")
    (tools / "adb.exe").write_bytes(b"synthetic adb stand-in")
    return Settings(
        ingest_base_url=ingest["url"],
        collector_key_id=ingest["key_id"],
        androidqf_path=tools / "androidqf.exe",
        androidqf_sha256=hashlib.sha256(b"synthetic androidqf stand-in").hexdigest(),
        adb_path=tools / "adb.exe",
        adb_sha256=hashlib.sha256(b"synthetic adb stand-in").hexdigest(),
        work_dir=tmp / "work",
        log_dir=tmp / "logs",
        upload_retries=2,
    )


def runner_for(settings: Settings, client: IngestClient, job: Job) -> Runner:
    return Runner(
        settings,
        client,
        acquire=good_acquirer(),
        wait=device_waiter(),
        adb_version_reader=lambda _p: "1.0.41 (synthetic)",
    )


def test_hmac_accepted_and_config_matches_pinned_recipient(ingest: dict, tmp_path: Path) -> None:
    client = IngestClient(collector_settings(ingest, tmp_path), bytes.fromhex(ingest["key_hex"]))
    try:
        config = client.config()
        assert config.age_recipient == ingest["recipient"]
        assert client.next_job() is None  # nothing authorised yet
    finally:
        client.close()


def test_wrong_key_and_skewed_clock_are_rejected_by_the_real_server(
    ingest: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = collector_settings(ingest, tmp_path)
    bad = IngestClient(settings, bytes(range(1, 33)))
    try:
        with pytest.raises(ClientError, match="AUTH_OR_CLOCK_INVALID"):
            bad.next_job()
    finally:
        bad.close()
    good = IngestClient(settings, bytes.fromhex(ingest["key_hex"]))
    try:
        real = time.time
        monkeypatch.setattr("astria_collector.client.time.time", lambda: real() - 3600)
        with pytest.raises(ClientError, match="AUTH_OR_CLOCK_INVALID"):
            good.next_job()
    finally:
        good.close()


def test_full_workflow_against_real_ingest(ingest: dict, tmp_path: Path) -> None:
    settings = collector_settings(ingest, tmp_path)
    provision(ingest, "SJ-live-1", "a" * 32)
    client = IngestClient(settings, bytes.fromhex(ingest["key_hex"]))
    try:
        job = client.next_job()
        assert job is not None
        assert job.job_id == "SJ-live-1"  # the real wire contract parses in Collector's strict model
        assert job.device.serial_sha256 == ingest["serial_sha256"]
        confirmation = confirm_job(job, job.job_id)
        assert confirmation is not None
        outcome = runner_for(settings, client, job).execute(job, confirmation)
        assert outcome.ok, outcome
        assert outcome.receipt is not None
        assert outcome.receipt.archive_sha256 == hashlib.sha256(AGE).hexdigest()
        assert outcome.receipt.metadata_status == "pending_verification"

        stored = Path(ingest["archive_root"]) / f"{outcome.receipt.acquisition_id}.zip.age"
        assert stored.read_bytes() == AGE  # byte-identical custody on the server
        assert not (settings.work_dir / job.job_id).exists()  # local copy removed only after the 201
        assert client.next_job() is None  # the job is no longer offered

        # An exact repeat (for example a lost response) returns the same acknowledgement.
        again = tmp_path / "again"
        again.mkdir()
        archive = again / "ACQ-0001.zip.age"
        archive.write_bytes(AGE)
        manifest = pack.build_manifest(
            job,
            archive,
            androidqf_sha256="a" * 64,
            adb_version="1",
            started_at=job.expires_at,
            ended_at=job.expires_at,
            exit_code=0,
        )
        assert client.upload(archive, manifest).acquisition_id == outcome.receipt.acquisition_id

        # Different bytes for the same job can never replace received evidence.
        archive.write_bytes(AGE + b"different")
        other = manifest.model_copy(
            update={
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "archive_size": archive.stat().st_size,
            }
        )
        with pytest.raises(ClientError, match="JOB_CONFLICT"):
            client.upload(archive, other)
    finally:
        client.close()


def test_revoked_consent_blocks_upload_and_keeps_the_archive(ingest: dict, tmp_path: Path) -> None:
    settings = collector_settings(ingest, tmp_path)
    provision(ingest, "SJ-live-2", "b" * 32)
    client = IngestClient(settings, bytes.fromhex(ingest["key_hex"]))
    try:
        job = client.next_job()
        assert job is not None
        revoke = httpx.post(
            f"{ingest['url']}/svc/v1/device-scans/{job.job_id}/revoke",
            headers={"Authorization": "Bearer " + ingest["manager_token"]},
            timeout=15,
        )
        assert revoke.status_code == 204
        assert client.next_job() is None
        confirmation = confirm_job(job, job.job_id)
        assert confirmation is not None
        outcome = runner_for(settings, client, job).execute(job, confirmation)
        assert (outcome.state, outcome.code, outcome.retained) == (State.GAGAL, "CONSENT_DENIED", True)
        directory = settings.work_dir / job.job_id
        assert pack.classify(directory, settings.max_archive_bytes)[0] == "siap_unggah"  # ciphertext preserved
    finally:
        client.close()


def test_unencrypted_upload_is_refused_by_the_server_too(ingest: dict, tmp_path: Path) -> None:
    """Defence in depth: even if Collector were bypassed, Ingest refuses a non-age body."""
    settings = collector_settings(ingest, tmp_path)
    provision(ingest, "SJ-live-3", "c" * 32)
    client = IngestClient(settings, bytes.fromhex(ingest["key_hex"]))
    try:
        job = client.next_job()
        assert job is not None
        archive = tmp_path / "plain.zip.age"
        archive.write_bytes(b"PK\x03\x04 plaintext zip, not age" * 10)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest = pack.Manifest.model_construct(  # bypasses Collector's own age check on purpose
            job=job,
            archive_name=archive.name,
            archive_sha256=digest,
            archive_size=archive.stat().st_size,
        )
        with pytest.raises(ClientError, match="SERVER_REJECTED"):
            client.upload(archive, manifest)
    finally:
        client.close()


def test_progress_conflicts_are_ignored_not_fatal(ingest: dict, tmp_path: Path) -> None:
    settings = collector_settings(ingest, tmp_path)
    provision(ingest, "SJ-live-4", "d" * 32)
    client = IngestClient(settings, bytes.fromhex(ingest["key_hex"]))
    try:
        job = client.next_job()
        assert job is not None
        client.progress(job, "mengunggah")
        with pytest.raises(ClientError, match="JOB_CONFLICT"):
            client.progress(job, "perangkat_terdeteksi")  # backwards: the server refuses it
        # Runner treats advisory progress failures as non-fatal, so evidence delivery still succeeds.
        confirmation = confirm_job(job, job.job_id)
        assert confirmation is not None
        assert runner_for(settings, client, job).execute(job, confirmation).ok
    finally:
        client.close()


def test_fake_uplink_double_matches_the_real_surface() -> None:
    # Guards the test double: it must expose exactly the methods Runner calls on the real client.
    for name in ("progress", "upload"):
        assert callable(getattr(FakeUplink, name))
        assert callable(getattr(IngestClient, name))
    assert sys.version_info >= (3, 14)
