"""Whole-job behaviour with deterministic doubles: confirmation to acknowledgement, failure and recovery."""

import hashlib
import threading
from pathlib import Path

import httpx
import pytest
from conftest import (
    AGE,
    NOW,
    SERIAL,
    FakeUplink,
    device_waiter,
    good_acquirer,
    job_document,
    make_runner,
    receipt_for,
)

from astria_collector import pack
from astria_collector.client import ClientError
from astria_collector.config import Settings
from astria_collector.models import Job
from astria_collector.processes import ProcessError, ProcessResult
from astria_collector.tasks import AcquireRequest, State, confirm_job


def confirmed(job: Job):
    confirmation = confirm_job(job, job.job_id)
    assert confirmation is not None
    return confirmation


def job_dir(settings: Settings, job: Job) -> Path:
    return settings.work_dir / job.job_id


def test_happy_path_uploads_acknowledges_and_removes_work(settings: Settings, job: Job) -> None:
    uplink = FakeUplink()
    outcome = make_runner(settings, uplink).execute(job, confirmed(job))
    assert outcome.ok
    assert outcome.code == "ACKNOWLEDGED"
    assert outcome.receipt is not None
    assert outcome.receipt.archive_sha256 == hashlib.sha256(AGE).hexdigest()
    assert uplink.stages == ["perangkat_terdeteksi", "mengambil", "mengemas", "mengunggah", "selesai"]
    assert not job_dir(settings, job).exists()  # deleted only after the acknowledgement
    manifest = uplink.uploaded[0]
    assert manifest.androidqf_sha256 == settings.androidqf_sha256
    assert manifest.adb_version == "1.0.41 (fixture)"
    assert manifest.status == "pending_verification"
    assert manifest.process_exit_code == 0


def test_acquirer_receives_serial_only_in_memory_and_stays_in_work_dir(settings: Settings, job: Job) -> None:
    seen: list[AcquireRequest] = []

    def acquire(request: AcquireRequest) -> ProcessResult:
        seen.append(request)
        return good_acquirer()(request)

    make_runner(settings, FakeUplink(), acquire=acquire).execute(job, confirmed(job))
    request = seen[0]
    assert request.serial == SERIAL
    assert request.output_dir.parent == settings.work_dir / job.job_id
    assert request.timeout_s == settings.task_timeout_min * 60
    assert SERIAL not in repr(request)


def test_sleep_is_inhibited_only_during_acquisition_and_upload(settings: Settings, job: Job) -> None:
    events: list[str] = []

    class Power:
        def __enter__(self) -> None:
            events.append("on")

        def __exit__(self, *_exc: object) -> None:
            events.append("off")

    uplink = FakeUplink()
    original = uplink.upload

    def upload(archive, manifest):
        events.append("upload")
        return original(archive, manifest)

    uplink.upload = upload  # type: ignore[method-assign]

    def acquire(request: AcquireRequest) -> ProcessResult:
        events.append("acquire")
        return good_acquirer()(request)

    make_runner(settings, uplink, power=Power, acquire=acquire).execute(job, confirmed(job))
    assert events == ["on", "acquire", "upload", "off"]


def test_power_request_refused_means_nothing_is_acquired(settings: Settings, job: Job) -> None:
    from astria_collector.power import PowerError

    def refuse():
        raise PowerError("POWER_REQUEST_FAILED")

    def acquire(_request):
        raise AssertionError("must not run")

    outcome = make_runner(settings, FakeUplink(), power=refuse, acquire=acquire).execute(job, confirmed(job))
    assert (outcome.state, outcome.code) == (State.GAGAL, "POWER_REQUEST_FAILED")


def test_power_restore_failure_does_not_hide_the_delivered_result(settings: Settings, job: Job) -> None:
    from astria_collector.power import PowerError

    class Power:
        def __enter__(self) -> None:
            return None

        def __exit__(self, *_exc: object) -> None:
            raise PowerError("POWER_RESTORE_FAILED")

    outcome = make_runner(settings, FakeUplink(), power=Power).execute(job, confirmed(job))
    assert outcome.ok


def test_expired_job_is_never_started(settings: Settings, job: Job) -> None:
    runner = make_runner(settings, FakeUplink(), now=lambda: job.expires_at)
    outcome = runner.execute(job, confirmed(job))
    assert (outcome.state, outcome.code) == (State.KEDALUWARSA, "JOB_EXPIRED")
    assert not settings.work_dir.exists() or not list(settings.work_dir.iterdir())


def test_unsupported_scope_never_starts(settings: Settings) -> None:
    wide = dict(job_document()["scope_flags"], intrusion_logs="yes")  # type: ignore[call-overload]
    job = Job.model_validate(job_document(scope_flags=wide))
    outcome = make_runner(settings, FakeUplink(), acquire=lambda _r: pytest.fail("ran")).execute(job, confirmed(job))
    assert outcome.code == "SCOPE_UNSUPPORTED"


@pytest.mark.parametrize(
    ("code", "state"),
    [
        ("SERIAL_MISMATCH", State.GAGAL),
        ("DEVICE_NOT_FOUND", State.GAGAL),
        ("MULTIPLE_DEVICES", State.GAGAL),
        ("USB_DEVICE_REQUIRED", State.GAGAL),
        ("DEVICE_TIMEOUT", State.KEDALUWARSA),
        ("CANCELLED", State.DIBATALKAN),
    ],
)
def test_device_failures_stop_before_acquisition_and_leave_nothing(settings: Settings, job: Job, code, state) -> None:
    uplink = FakeUplink()
    runner = make_runner(settings, uplink, wait=device_waiter(error=code), acquire=lambda _r: pytest.fail("ran"))
    outcome = runner.execute(job, confirmed(job))
    assert (outcome.state, outcome.code) == (state, code)
    assert uplink.progress_calls[-1] == ("gagal", code)
    assert not job_dir(settings, job).exists()
    assert "mengambil" not in uplink.stages


def test_waiter_returning_a_different_device_is_still_refused(settings: Settings, job: Job) -> None:
    runner = make_runner(
        settings, FakeUplink(), wait=device_waiter(serial="OTHERPHONE0000"), acquire=lambda _r: pytest.fail("ran")
    )
    assert runner.execute(job, confirmed(job)).code == "SERIAL_MISMATCH"


def test_tampered_tool_checksum_blocks_everything(settings: Settings, job: Job) -> None:
    settings.androidqf_path.write_bytes(b"replaced binary")
    waited: list[int] = []

    def wait(*_a):
        waited.append(1)
        raise AssertionError

    outcome = make_runner(settings, FakeUplink(), wait=wait, acquire=lambda _r: pytest.fail("ran")).execute(
        job, confirmed(job)
    )
    assert outcome.code == "TOOL_CHECKSUM_MISMATCH"
    assert waited == []
    settings.adb_path.write_bytes(b"replaced adb")
    settings.androidqf_path.write_bytes(b"synthetic androidqf stand-in")
    assert make_runner(settings, FakeUplink()).execute(job, confirmed(job)).code == "TOOL_CHECKSUM_MISMATCH"


@pytest.mark.parametrize(
    ("result", "code", "state"),
    [
        (ProcessResult(1, "", ""), "ACQUISITION_FAILED", State.GAGAL),
        (ProcessResult(-1, "", "", timed_out=True), "TASK_TIMEOUT", State.GAGAL),
        (ProcessResult(-1, "", "", cancelled=True), "CANCELLED", State.DIBATALKAN),
    ],
)
def test_acquisition_failures_report_gagal_and_never_upload(settings: Settings, job: Job, result, code, state) -> None:
    uplink = FakeUplink()
    outcome = make_runner(settings, uplink, acquire=lambda _r: result).execute(job, confirmed(job))
    assert (outcome.state, outcome.code) == (state, code)
    assert uplink.uploaded == []
    assert "mengunggah" not in uplink.stages
    assert uplink.progress_calls[-1] == ("gagal", code)


def test_partial_output_after_a_crash_is_retained_not_deleted(settings: Settings, job: Job) -> None:
    def crash(request: AcquireRequest) -> ProcessResult:
        (request.output_dir / "ACQ-partial.zip.age").write_bytes(AGE)
        return ProcessResult(3, "", "")

    outcome = make_runner(settings, FakeUplink(), acquire=crash).execute(job, confirmed(job))
    assert (outcome.state, outcome.retained) == (State.GAGAL, True)
    assert (job_dir(settings, job) / "output" / "ACQ-partial.zip.age").exists()


def test_controlled_cancellation_event_is_honoured(settings: Settings, job: Job) -> None:
    cancel = threading.Event()

    def slow(request: AcquireRequest) -> ProcessResult:
        cancel.set()  # operator presses Ctrl+C while AndroidQF runs
        return ProcessResult(-1, "", "", cancelled=request.cancel.is_set())

    outcome = make_runner(settings, FakeUplink(), acquire=slow).execute(job, confirmed(job), cancel)
    assert (outcome.state, outcome.code) == (State.DIBATALKAN, "CANCELLED")


def test_gate_rejection_leaves_no_work_and_reports_gagal(settings: Settings, job: Job) -> None:
    from astria_collector.androidqf import AndroidQFError

    def blocked(_request):
        raise AndroidQFError("TOOL_INCOMPATIBLE")

    uplink = FakeUplink()
    outcome = make_runner(settings, uplink, acquire=blocked).execute(job, confirmed(job))
    assert outcome.code == "TOOL_INCOMPATIBLE"
    assert not job_dir(settings, job).exists()
    assert uplink.progress_calls[-1] == ("gagal", "TOOL_INCOMPATIBLE")


def test_process_error_is_reported_as_code_only(settings: Settings, job: Job) -> None:
    def broken(_request):
        raise ProcessError("PROCESS_START_FAILED")

    assert (
        make_runner(settings, FakeUplink(), acquire=broken).execute(job, confirmed(job)).code == "PROCESS_START_FAILED"
    )


@pytest.mark.parametrize(
    ("name", "data", "code"),
    [
        ("ACQ.zip", b"PK plaintext" * 20, "UNEXPECTED_ARTIFACT"),
        ("ACQ.zip.age", b"PK plaintext" * 20, "ARCHIVE_NOT_AGE"),
        ("ACQ.zip.age", AGE[:5], "ARCHIVE_SIZE_INVALID"),
    ],
)
def test_unencrypted_or_unexpected_output_is_refused_and_kept(settings: Settings, job: Job, name, data, code) -> None:
    uplink = FakeUplink()
    outcome = make_runner(settings, uplink, acquire=good_acquirer(data, name)).execute(job, confirmed(job))
    assert (outcome.state, outcome.code, outcome.retained) == (State.GAGAL, code, True)
    assert uplink.uploaded == []
    assert (job_dir(settings, job) / "output" / name).exists()


def test_no_archive_at_all_is_a_failure(settings: Settings, job: Job) -> None:
    outcome = make_runner(settings, FakeUplink(), acquire=lambda _r: ProcessResult(0, "", "")).execute(
        job, confirmed(job)
    )
    assert outcome.code == "ARCHIVE_COUNT_INVALID"


@pytest.mark.parametrize(
    "error",
    [
        ClientError("NETWORK_UNAVAILABLE"),
        ClientError("SERVER_UNAVAILABLE"),
        ClientError("CONSENT_DENIED"),
        ClientError("JOB_EXPIRED"),
        ClientError("ACK_MISMATCH"),
    ],
)
def test_failed_upload_preserves_the_encrypted_archive(settings: Settings, job: Job, error: ClientError) -> None:
    uplink = FakeUplink([error])
    outcome = make_runner(settings, uplink).execute(job, confirmed(job))
    assert (outcome.state, outcome.code, outcome.retained) == (State.GAGAL, error.code, True)
    directory = job_dir(settings, job)
    assert (directory / "ACQ-0001.zip.age").read_bytes() == AGE
    assert pack.classify(directory, settings.max_archive_bytes)[0] == "siap_unggah"


def test_os_error_during_upload_also_preserves(settings: Settings, job: Job) -> None:
    outcome = make_runner(settings, FakeUplink([OSError("disk")])).execute(job, confirmed(job))
    assert (outcome.code, outcome.retained) == ("NETWORK_UNAVAILABLE", True)
    assert (job_dir(settings, job) / "ACQ-0001.zip.age").exists()


def test_progress_failures_never_change_the_evidence_outcome(settings: Settings, job: Job) -> None:
    uplink = FakeUplink()
    uplink.progress_error = ClientError("NETWORK_UNAVAILABLE")
    assert make_runner(settings, uplink).execute(job, confirmed(job)).ok
    assert len(uplink.uploaded) == 1


def test_existing_work_folder_blocks_a_second_run_and_is_preserved(settings: Settings, job: Job) -> None:
    uplink = FakeUplink([ClientError("NETWORK_UNAVAILABLE")])
    runner = make_runner(settings, uplink)
    runner.execute(job, confirmed(job))
    outcome = runner.execute(job, confirmed(job))  # would overwrite retained evidence otherwise
    assert outcome.code == "WORK_EXISTS"
    assert (job_dir(settings, job) / "ACQ-0001.zip.age").read_bytes() == AGE


def test_explicit_retry_uploads_the_retained_archive_then_cleans_up(settings: Settings, job: Job) -> None:
    uplink = FakeUplink([ClientError("NETWORK_UNAVAILABLE"), None])
    runner = make_runner(settings, uplink)
    assert not runner.execute(job, confirmed(job)).ok
    assert runner.retained() == [(job.job_id, "siap_unggah")]
    outcome = runner.retry_upload(job.job_id)
    assert outcome.ok
    assert len(uplink.uploaded) == 1
    assert uplink.uploaded[0].archive_sha256 == hashlib.sha256(AGE).hexdigest()
    assert not job_dir(settings, job).exists()
    assert runner.retained() == []


def test_retry_refuses_a_modified_archive(settings: Settings, job: Job) -> None:
    uplink = FakeUplink([ClientError("NETWORK_UNAVAILABLE")])
    runner = make_runner(settings, uplink)
    runner.execute(job, confirmed(job))
    archive = job_dir(settings, job) / "ACQ-0001.zip.age"
    archive.write_bytes(AGE[:-1] + b"X")
    outcome = runner.retry_upload(job.job_id)
    assert (outcome.state, outcome.code, outcome.retained) == (State.GAGAL, "NOT_RETRYABLE", True)
    assert archive.exists()
    assert uplink.uploaded == []


def test_restart_after_acknowledgement_finishes_cleanup_without_reuploading(settings: Settings, job: Job) -> None:
    uplink = FakeUplink()
    runner = make_runner(settings, uplink)
    runner.execute(job, confirmed(job))
    # Simulate a crash between "receipt written" and "cleanup": rebuild the folder with a receipt present.
    directory = pack.job_directory(settings.work_dir, job.job_id, create=True)
    archive = directory / "ACQ-0001.zip.age"
    archive.write_bytes(AGE)
    manifest = pack.build_manifest(
        job,
        archive,
        androidqf_sha256=settings.androidqf_sha256,
        adb_version="1.0",
        started_at=NOW,
        ended_at=NOW,
        exit_code=0,
    )
    pack.write_manifest(directory, manifest)
    pack.write_receipt(directory, receipt_for(manifest))
    uploads_before = len(uplink.uploaded)
    assert runner.retained() == [(job.job_id, "diakui")]
    outcome = runner.retry_upload(job.job_id)
    assert outcome.ok
    assert len(uplink.uploaded) == uploads_before  # no second upload
    assert not directory.exists()


def test_restart_with_interrupted_acquisition_is_not_retryable_and_discardable(settings: Settings, job: Job) -> None:
    directory = pack.job_directory(settings.work_dir, job.job_id, create=True)
    (directory / "output").mkdir()
    (directory / "output" / "partial.zip.age").write_bytes(AGE)
    pack.write_job(directory, job)
    runner = make_runner(settings, FakeUplink())
    assert runner.retained() == [(job.job_id, "tidak_lengkap")]
    assert runner.retry_upload(job.job_id).code == "NOT_RETRYABLE"
    runner.discard(job.job_id)
    assert runner.retained() == []


def test_cleanup_incomplete_is_reported_but_receipt_is_kept(settings: Settings, job: Job) -> None:
    uplink = FakeUplink()
    runner = make_runner(settings, uplink)
    original = pack.cleanup_acknowledged

    def blocked(directory, manifest):
        raise pack.ArtifactError("UNSAFE_CLEANUP")

    pack.cleanup_acknowledged = blocked  # type: ignore[assignment]
    try:
        outcome = runner.execute(job, confirmed(job))
    finally:
        pack.cleanup_acknowledged = original  # type: ignore[assignment]
    assert (outcome.state, outcome.code, outcome.retained) == (State.SELESAI, "CLEANUP_INCOMPLETE", True)
    assert (job_dir(settings, job) / "receipt.json").exists()


def test_end_to_end_over_http_transport_with_signed_requests(settings: Settings, job: Job, client_factory) -> None:
    """Runner plus the real IngestClient against a scripted Ingest (httpx.MockTransport)."""
    calls: list[tuple[str, str]] = []
    body: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "PUT":
            body["archive"] = request.read()
            digest = request.headers["x-archive-sha256"]
            assert hashlib.sha256(body["archive"]).hexdigest() == digest
            return httpx.Response(
                201,
                json={
                    "acquisition_id": "AQ-1",
                    "job_id": job.job_id,
                    "status": "received",
                    "archive_sha256": digest,
                    "archive_size": len(body["archive"]),
                    "metadata_status": "pending_verification",
                },
            )
        return httpx.Response(204)

    outcome = make_runner(settings, client_factory(handler)).execute(job, confirmed(job))
    assert outcome.ok
    assert body["archive"] == AGE
    assert [m for m, _ in calls] == ["POST", "POST", "POST", "POST", "PUT", "POST"]
    assert calls[-2] == ("PUT", f"/svc/v1/collector/acquisitions/{job.job_id}")


def test_preflight_refusal_stops_before_device_wait_and_does_not_burn_the_job(settings: Settings, job: Job) -> None:
    from astria_collector.androidqf import AndroidQFError

    def refuse() -> None:
        raise AndroidQFError("TOOL_INCOMPATIBLE")

    def wait(*_a):
        raise AssertionError("must not wait for a phone when the tool is refused")

    uplink = FakeUplink()
    runner = make_runner(settings, uplink, preflight=refuse, wait=wait, acquire=lambda _r: pytest.fail("ran"))
    assert runner.preflight_error() == "TOOL_INCOMPATIBLE"
    outcome = runner.execute(job, confirmed(job))
    assert (outcome.state, outcome.code) == (State.GAGAL, "TOOL_INCOMPATIBLE")
    assert uplink.progress_calls == []  # the server is not told, so the consent is not consumed
    assert not job_dir(settings, job).exists()


def test_console_refuses_before_asking_for_confirmation_or_showing_usb_steps(settings: Settings, job: Job) -> None:
    from astria_collector import menu
    from astria_collector.androidqf import AndroidQFError

    def refuse() -> None:
        raise AndroidQFError("TOOL_INCOMPATIBLE")

    asked: list[str] = []
    said: list[str] = []
    runner = make_runner(settings, FakeUplink(), preflight=refuse)
    result = menu.run_job(runner, job, lambda p: asked.append(p) or job.job_id, said.append, threading.Event())
    assert result is None
    assert asked == []
    text = "\n".join(said)
    assert "tidak punya mode tanpa interaksi" in text
    assert "USB debugging" not in text


def test_long_console_output_does_not_fail_a_clean_acquisition(settings: Settings, job: Job) -> None:
    """A real phone makes AndroidQF print more than the capture limit; only the exit code decides (2026-11-15)."""

    def acquire(request: AcquireRequest) -> ProcessResult:
        good_acquirer()(request)
        return ProcessResult(0, "progress " * 10, "", False, False, True)

    uplink = FakeUplink()
    outcome = make_runner(settings, uplink, acquire=acquire).execute(job, confirmed(job))
    assert outcome.ok
    assert outcome.code == "ACKNOWLEDGED"


def test_nonzero_exit_still_fails_and_keeps_the_partial_output(settings: Settings, job: Job) -> None:
    def acquire(request: AcquireRequest) -> ProcessResult:
        good_acquirer()(request)
        return ProcessResult(1, "", "boom", False, False, True)

    outcome = make_runner(settings, FakeUplink(), acquire=acquire).execute(job, confirmed(job))
    assert not outcome.ok
    assert outcome.code == "ACQUISITION_FAILED"
    assert job_dir(settings, job).exists()  # partial output kept until the operator discards it


INCOMPLETE_TAIL = (
    "INFO Finalizing acquisition archive...\n"
    "\x1b[31mFATAL\x1b[0m Acquisition finalized with 2 incomplete module(s). "
    "Review acquisition.json and command.log for details.\n"
)


def test_finalized_archive_with_incomplete_modules_is_uploaded_with_its_exit_code(settings: Settings, job: Job) -> None:
    """Real phone, 2026-11-15: AndroidQF exits 1 after finalizing when some modules fail; the archive is complete."""

    def acquire(request: AcquireRequest) -> ProcessResult:
        good_acquirer()(request)
        return ProcessResult(1, "progress " * 10, "", False, False, True, INCOMPLETE_TAIL)

    uplink = FakeUplink()
    outcome = make_runner(settings, uplink, acquire=acquire).execute(job, confirmed(job))
    assert outcome.ok
    assert uplink.uploaded[0].process_exit_code == 1


def test_other_exit_one_still_fails_even_if_the_message_is_not_last(settings: Settings, job: Job) -> None:
    def acquire(request: AcquireRequest) -> ProcessResult:
        good_acquirer()(request)
        tail = INCOMPLETE_TAIL + "FATAL Failed to finalize acquisition archive\n" + "x\n" * 6
        return ProcessResult(1, "", "", False, False, False, tail)

    outcome = make_runner(settings, FakeUplink(), acquire=acquire).execute(job, confirmed(job))
    assert not outcome.ok
    assert outcome.code == "ACQUISITION_FAILED"
