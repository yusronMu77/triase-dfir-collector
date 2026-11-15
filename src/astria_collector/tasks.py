"""Job state machine and the single path that may start an acquisition.

An acquisition can only start through `Runner.execute`, which requires a `Confirmation`. A
`Confirmation` can only be produced by `confirm_job`, which requires the operator to type the exact
job ID. Evidence that fails to upload is retained; nothing is deleted before the server acknowledges it.
"""

from __future__ import annotations

import enum
import re
import threading
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import structlog

from . import androidqf, pack
from .androidqf import AndroidQFError
from .client import ClientError
from .config import Settings
from .device import Device, DeviceError, adb_version, serial_sha256, wait_for_device
from .models import Job, Manifest, Receipt
from .pack import ArtifactError
from .power import PowerError, prevent_sleep
from .processes import ProcessError, ProcessResult, secure_directory

log = structlog.get_logger("collector")


class State(enum.StrEnum):
    MENUNGGU = "menunggu"
    DIKONFIRMASI = "dikonfirmasi"
    MENUNGGU_PERANGKAT = "menunggu_perangkat"
    PERANGKAT_COCOK = "perangkat_cocok"
    MENGAMBIL = "mengambil"
    MENGEMAS = "mengemas"
    MENGUNGGAH = "mengunggah"
    SELESAI = "selesai"
    GAGAL = "gagal"
    KEDALUWARSA = "kedaluwarsa"
    DIBATALKAN = "dibatalkan"


TERMINAL = frozenset({State.SELESAI, State.GAGAL, State.KEDALUWARSA, State.DIBATALKAN})
_ACTIVE = (State.DIKONFIRMASI, State.MENUNGGU_PERANGKAT, State.PERANGKAT_COCOK, State.MENGAMBIL, State.MENGEMAS)
TRANSITIONS: dict[State, frozenset[State]] = {
    State.MENUNGGU: frozenset({State.DIKONFIRMASI, State.DIBATALKAN, State.KEDALUWARSA}),
    State.DIKONFIRMASI: frozenset({State.MENUNGGU_PERANGKAT, State.GAGAL, State.KEDALUWARSA, State.DIBATALKAN}),
    State.MENUNGGU_PERANGKAT: frozenset({State.PERANGKAT_COCOK, State.GAGAL, State.KEDALUWARSA, State.DIBATALKAN}),
    State.PERANGKAT_COCOK: frozenset({State.MENGAMBIL, State.GAGAL, State.DIBATALKAN}),
    State.MENGAMBIL: frozenset({State.MENGEMAS, State.GAGAL, State.DIBATALKAN}),
    State.MENGEMAS: frozenset({State.MENGUNGGAH, State.GAGAL}),
    State.MENGUNGGAH: frozenset({State.SELESAI, State.GAGAL}),
    State.SELESAI: frozenset(),
    State.GAGAL: frozenset(),
    State.KEDALUWARSA: frozenset(),
    State.DIBATALKAN: frozenset(),
}
assert all(TRANSITIONS[state] for state in State if state not in TERMINAL)
assert all(not TRANSITIONS[state] for state in TERMINAL)
assert all(State.GAGAL in TRANSITIONS[state] for state in _ACTIVE)


class InvalidTransition(RuntimeError):
    pass


class JobRun:
    """The only holder of job state; every change is checked against `TRANSITIONS`."""

    def __init__(self) -> None:
        self.state = State.MENUNGGU
        self.code: str | None = None

    def to(self, new: State, code: str | None = None) -> None:
        if new not in TRANSITIONS[self.state]:
            raise InvalidTransition(f"{self.state} -> {new}")
        self.state, self.code = new, code


# --- operator confirmation --------------------------------------------------------------------

_SEAL = object()


class UnconfirmedJob(RuntimeError):
    pass


@dataclass(frozen=True)
class Confirmation:
    """Proof that the operator typed the exact job ID. Not constructible by accident."""

    job_id: str
    _seal: object = field(repr=False, compare=False)


def confirm_job(job: Job, typed: str) -> Confirmation | None:
    """Exact match only: no case folding and no trimming beyond the line terminator."""
    return Confirmation(job.job_id, _SEAL) if typed.rstrip("\r\n") == job.job_id else None


def unsupported_scope(job: Job) -> str | None:
    """Scope values Collector will not run. Checked before the operator is asked to confirm."""
    scope = job.scope_flags.model_dump()
    for key, allowed in androidqf.SCOPE_VALUES.items():
        if scope.get(key) not in allowed:
            return key
    return None


# --- collaborators ----------------------------------------------------------------------------


class Uplink(Protocol):
    def progress(self, job: Job, stage: str, code: str | None = None) -> None: ...
    def upload(self, archive: Path, manifest: Manifest) -> Receipt: ...


@dataclass(frozen=True)
class AcquireRequest:
    serial: str = field(repr=False)
    job: Job
    output_dir: Path
    timeout_s: float
    cancel: threading.Event


Acquirer = Callable[[AcquireRequest], ProcessResult]
Waiter = Callable[[Job, threading.Event, Callable[[str], None]], Device]


@dataclass(frozen=True)
class Outcome:
    state: State
    code: str | None = None
    receipt: Receipt | None = None
    retained: bool = False

    @property
    def ok(self) -> bool:
        return self.state is State.SELESAI


def production_acquirer(settings: Settings, recipient: Callable[[], str]) -> Acquirer:
    """AndroidQF through the gate: the official v1.8.3 is rejected (TOOL_INCOMPATIBLE); only the
    digest-pinned build runs. ``recipient`` returns the age recipient Ingest publishes, already checked
    against its published SHA-256 by the client."""

    def acquire(request: AcquireRequest) -> ProcessResult:
        try:
            age_recipient = recipient()
        except (ClientError, OSError, ValueError) as error:
            raise AndroidQFError("RECIPIENT_UNAVAILABLE") from error
        return androidqf.run_acquisition(
            settings.androidqf_path,
            settings.androidqf_sha256,
            request.serial,
            request.output_dir.parent,
            request.job.scope_flags.model_dump(),
            age_recipient,
            timeout_s=request.timeout_s,
            cancel=request.cancel,
        )

    return acquire


def production_preflight(settings: Settings) -> Callable[[], None]:
    """Reject an unapproved AndroidQF before the operator is told to connect a phone."""

    def preflight() -> None:
        secure_directory(settings.work_dir)
        info = androidqf.inspect_tool(settings.androidqf_path, settings.androidqf_sha256, settings.work_dir)
        androidqf.require_compatible(info)

    return preflight


def production_waiter(settings: Settings) -> Waiter:
    def wait(job: Job, cancel: threading.Event, on_status: Callable[[str], None]) -> Device:
        return wait_for_device(
            settings.adb_path,
            job.device.serial_sha256,
            settings.device_wait_min * 60,
            cancel=cancel,
            on_status=on_status,
        )

    return wait


_SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def _code(error: Exception, default: str) -> str:
    """A machine code from our own errors; free text from a subprocess or server never passes."""
    candidate = getattr(error, "code", None)
    if not isinstance(candidate, str) and error.args:
        candidate = error.args[0]
    if isinstance(candidate, str) and _SAFE_CODE.fullmatch(candidate):
        return candidate
    return default


class Runner:
    def __init__(
        self,
        settings: Settings,
        uplink: Uplink,
        *,
        acquire: Acquirer,
        wait: Waiter,
        power: Callable[[], AbstractContextManager[None]] = prevent_sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        on_status: Callable[[str], None] = lambda _code: None,
        adb_version_reader: Callable[[Path], str] = adb_version,
        preflight: Callable[[], None] = lambda: None,
    ) -> None:
        self.settings = settings
        self.uplink = uplink
        self._acquire = acquire
        self._wait = wait
        self._power = power
        self._now = now
        self._on_status = on_status
        self._adb_version = adb_version_reader
        self._preflight = preflight

    def preflight_error(self) -> str | None:
        """A safe code when acquisition cannot be allowed at all, else None. Touches no phone."""
        try:
            self._preflight()
        except (AndroidQFError, ProcessError, ArtifactError, OSError) as error:
            return _code(error, "TOOL_CHECK_FAILED")
        return None

    # progress is advisory; losing it never changes the evidence outcome
    def _report(self, job: Job, stage: str, code: str | None = None) -> None:
        try:
            self.uplink.progress(job, stage, code)
        except (ClientError, OSError) as error:
            log.warning(
                "progress_failed",
                job_id=job.job_id,
                trace_id=job.trace_id,
                stage=stage,
                code=getattr(error, "code", "NETWORK_UNAVAILABLE"),
            )

    def _finish(self, run: JobRun, job: Job, state: State, code: str, *, retained: bool = False) -> Outcome:
        run.to(state, code)
        stage = "gagal" if state in {State.GAGAL, State.KEDALUWARSA, State.DIBATALKAN} else state.value
        self._report(job, stage, code)
        log.info("job_finished", job_id=job.job_id, trace_id=job.trace_id, stage=state.value, code=code)
        return Outcome(state, code, retained=retained)

    def execute(self, job: Job, confirmation: Confirmation, cancel: threading.Event | None = None) -> Outcome:
        if confirmation._seal is not _SEAL or confirmation.job_id != job.job_id:
            raise UnconfirmedJob(job.job_id)
        cancel = cancel or threading.Event()
        run = JobRun()
        run.to(State.DIKONFIRMASI)
        bound = log.bind(job_id=job.job_id, trace_id=job.trace_id)
        try:
            job.check_expiry(self._now())
        except ValueError:
            return self._finish(run, job, State.KEDALUWARSA, "JOB_EXPIRED")
        if unsupported_scope(job) is not None:
            bound.warning("scope_unsupported", code="SCOPE_UNSUPPORTED")
            return self._finish(run, job, State.GAGAL, "SCOPE_UNSUPPORTED")
        if (blocked := self.preflight_error()) is not None:
            # A local tool problem must not burn the consent: the server is not told, so the job stays
            # available once the operator fixes the installation.
            bound.warning("preflight_refused", code=blocked)
            run.to(State.GAGAL, blocked)
            return Outcome(State.GAGAL, blocked)

        try:
            work_root = self.settings.work_dir
            secure_directory(work_root)
            directory = pack.job_directory(work_root, job.job_id, create=True)
        except FileExistsError:
            # An earlier run left a folder (possibly evidence). Retry or discard it explicitly first.
            return self._finish(run, job, State.GAGAL, "WORK_EXISTS")
        except (OSError, ProcessError, ArtifactError) as error:
            return self._finish(run, job, State.GAGAL, _code(error, "WORK_DIR_FAILED"))

        try:
            pack.write_job(directory, job)
            # Tool integrity is checked before any process runs and before the phone is touched.
            androidqf.verify_checksum(self.settings.androidqf_path, self.settings.androidqf_sha256)
            androidqf.verify_checksum(self.settings.adb_path, self.settings.adb_sha256)
            adb_text = self._adb_version(self.settings.adb_path)
        except (AndroidQFError, DeviceError, ArtifactError, OSError) as error:
            return self._cleanup_failed(run, job, directory, _code(error, "TOOL_CHECK_FAILED"))

        run.to(State.MENUNGGU_PERANGKAT)
        try:
            device = self._wait(job, cancel, self._on_status)
        except DeviceError as error:
            if error.code == "DEVICE_TIMEOUT":
                return self._cleanup_failed(run, job, directory, "DEVICE_TIMEOUT", State.KEDALUWARSA)
            if error.code == "CANCELLED":
                return self._cleanup_failed(run, job, directory, "CANCELLED", State.DIBATALKAN)
            return self._cleanup_failed(run, job, directory, error.code)
        # Defence in depth: the waiter already matched, but this gate is what the policy states.
        if serial_sha256(device.serial) != job.device.serial_sha256:
            return self._cleanup_failed(run, job, directory, "SERIAL_MISMATCH")
        run.to(State.PERANGKAT_COCOK)
        self._report(job, "perangkat_terdeteksi")

        outcome: Outcome | None = None
        try:
            with self._power():
                outcome = self._acquire_and_upload(run, job, directory, device, adb_text, cancel)
        except PowerError as error:
            bound.error("power_state_error", code=_code(error, "POWER_ERROR"))
            if outcome is None:
                # The sleep inhibitor was refused, so no acquisition started.
                return self._cleanup_failed(run, job, directory, "POWER_REQUEST_FAILED")
            # Restoring the previous state failed after the work finished: never hide the real result.
        assert outcome is not None
        return outcome

    def _cleanup_failed(self, run: JobRun, job: Job, directory: Path, code: str, state: State = State.GAGAL) -> Outcome:
        """Nothing was acquired yet, so the empty job folder (job.json only) may go."""
        try:
            pack.discard_directory(directory)
        except OSError, ArtifactError:
            log.warning("cleanup_skipped", job_id=job.job_id, trace_id=job.trace_id, code="CLEANUP_SKIPPED")
        return self._finish(run, job, state, code)

    def _acquire_and_upload(
        self, run: JobRun, job: Job, directory: Path, device: Device, adb_text: str, cancel: threading.Event
    ) -> Outcome:
        run.to(State.MENGAMBIL)
        self._report(job, "mengambil")
        output = directory / "output"
        output.mkdir()
        started = self._now()
        try:
            result = self._acquire(
                AcquireRequest(device.serial, job, output, self.settings.task_timeout_min * 60, cancel)
            )
        except (AndroidQFError, ProcessError) as error:
            return self._after_failed_acquisition(
                run,
                job,
                directory,
                _code(error, "ACQUIRE_FAILED"),
                rejected_before_start=isinstance(error, AndroidQFError),
            )
        ended = self._now()
        if result.cancelled or cancel.is_set():
            return self._after_failed_acquisition(run, job, directory, "CANCELLED", state=State.DIBATALKAN)
        if result.timed_out:
            return self._after_failed_acquisition(run, job, directory, "TASK_TIMEOUT")
        if result.exit_code != 0:
            incomplete = androidqf.incomplete_modules(result)
            if incomplete is None:
                log.warning("acquisition_exit", job_id=job.job_id, trace_id=job.trace_id, exit_code=result.exit_code)
                return self._after_failed_acquisition(run, job, directory, "ACQUISITION_FAILED")
            # Finalized archive with some modules incomplete: upload it; the exit code goes into the manifest.
            log.warning("acquisition_incomplete_modules", job_id=job.job_id, trace_id=job.trace_id, modules=incomplete)
        if result.output_truncated:
            # AndroidQF prints progress for every module; on a real phone this passes the console capture limit.
            # The console text is not evidence (the encrypted archive is), so only the exit code decides.
            log.warning("acquisition_output_truncated", job_id=job.job_id, trace_id=job.trace_id)

        run.to(State.MENGEMAS)
        self._report(job, "mengemas")
        try:
            archive = pack.adopt_archive(output, directory, self.settings.max_archive_bytes)
            manifest = pack.build_manifest(
                job,
                archive,
                androidqf_sha256=self.settings.androidqf_sha256,
                adb_version=adb_text,
                started_at=started,
                ended_at=ended,
                exit_code=result.exit_code,
            )
            pack.write_manifest(directory, manifest)
        except (ArtifactError, OSError, ValueError) as error:
            # Whatever AndroidQF produced stays on disk for the operator to inspect or discard explicitly.
            return self._finish(run, job, State.GAGAL, _code(error, "PACK_FAILED"), retained=True)
        return self._upload(run, job, directory, archive, manifest)

    def _after_failed_acquisition(
        self,
        run: JobRun,
        job: Job,
        directory: Path,
        code: str,
        *,
        state: State = State.GAGAL,
        rejected_before_start: bool = False,
    ) -> Outcome:
        output = directory / "output"
        produced = output.is_dir() and any(output.iterdir())
        if produced and not rejected_before_start:
            # Partial output may be sensitive. Keep it until the operator discards it explicitly.
            return self._finish(run, job, state, code, retained=True)
        try:
            pack.discard_directory(directory)
        except OSError, ArtifactError:
            return self._finish(run, job, state, code, retained=True)
        return self._finish(run, job, state, code)

    def _upload(self, run: JobRun, job: Job, directory: Path, archive: Path, manifest: Manifest) -> Outcome:
        run.to(State.MENGUNGGAH)
        self._report(job, "mengunggah")
        try:
            receipt = self.uplink.upload(archive, manifest)
        except ClientError as error:
            return self._finish(run, job, State.GAGAL, error.code, retained=True)
        except OSError:
            return self._finish(run, job, State.GAGAL, "NETWORK_UNAVAILABLE", retained=True)
        return self._acknowledged(run, job, directory, manifest, receipt)

    def _acknowledged(self, run: JobRun, job: Job, directory: Path, manifest: Manifest, receipt: Receipt) -> Outcome:
        # Persist the acknowledgement first: a crash before cleanup is recovered without re-uploading.
        pack.write_receipt(directory, receipt)
        try:
            pack.cleanup_acknowledged(directory, manifest)
        except ArtifactError, OSError:
            run.to(State.SELESAI, "ACKNOWLEDGED")
            self._report(job, "selesai")
            return Outcome(State.SELESAI, "CLEANUP_INCOMPLETE", receipt, retained=True)
        run.to(State.SELESAI, "ACKNOWLEDGED")
        self._report(job, "selesai")
        log.info("job_finished", job_id=job.job_id, trace_id=job.trace_id, stage="selesai", code="ACKNOWLEDGED")
        return Outcome(State.SELESAI, "ACKNOWLEDGED", receipt)

    # --- recovery -----------------------------------------------------------------------------

    def retained(self) -> list[tuple[str, pack.WorkState]]:
        found: list[tuple[str, pack.WorkState]] = []
        for name in pack.list_work(self.settings.work_dir):
            directory = pack.job_directory(self.settings.work_dir, name)
            found.append((name, pack.classify(directory, self.settings.max_archive_bytes)[0]))
        return found

    def retry_upload(self, job_id: str) -> Outcome:
        """Explicit operator retry of a retained encrypted archive. Never re-acquires."""
        directory = pack.job_directory(self.settings.work_dir, job_id)
        work_state, manifest = pack.classify(directory, self.settings.max_archive_bytes)
        if manifest is None or work_state == "tidak_lengkap":
            return Outcome(State.GAGAL, "NOT_RETRYABLE", retained=True)
        run = JobRun()
        run.to(State.DIKONFIRMASI)
        run.to(State.MENUNGGU_PERANGKAT)
        run.to(State.PERANGKAT_COCOK)
        run.to(State.MENGAMBIL)
        run.to(State.MENGEMAS)
        archive = directory / manifest.archive_name
        if work_state == "diakui":
            receipt = pack.read_receipt(directory)
            run.to(State.MENGUNGGAH)
            return self._acknowledged(run, manifest.job, directory, manifest, receipt)
        return self._upload(run, manifest.job, directory, archive, manifest)

    def discard(self, job_id: str) -> None:
        """Deletes a job folder. The caller must have obtained explicit operator confirmation."""
        pack.discard_directory(pack.job_directory(self.settings.work_dir, job_id))
