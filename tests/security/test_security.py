"""Security controls: injection, environment, secrets in logs, and refusal to act without authority."""

import hashlib
import json
import logging
import os
import sys
from pathlib import Path

import httpx
import pytest
import structlog
from conftest import AGE, KEY_ID, SECRET, SERIAL, FakeUplink, job_document, make_runner

from astria_collector import androidqf, logs, pack
from astria_collector.androidqf import AndroidQFError, build_args
from astria_collector.client import ClientError
from astria_collector.config import Settings
from astria_collector.device import Device, DeviceError, match_device, serial_sha256
from astria_collector.models import Job
from astria_collector.processes import ProcessError, restricted_environment, run_process
from astria_collector.tasks import State, confirm_job

SCOPE = job_document()["scope_flags"]


@pytest.mark.parametrize(
    "serial",
    [
        "A; calc.exe",
        "A && whoami",
        "A|B",
        "$(whoami)",
        "`id`",
        "A B",
        "A\nB",
        "A\x00B",
        '"A"',
        "-serial",
        "../../x",
        "A" * 300,
        "",
    ],
)
def test_command_injection_through_serial_is_refused(serial: str) -> None:
    with pytest.raises(AndroidQFError, match="DEVICE_SERIAL_INVALID"):
        build_args(Path("C:/tools/androidqf.exe"), serial, Path("C:/work/out"), dict(SCOPE))  # type: ignore[call-overload]


def test_scope_values_cannot_inject_extra_flags() -> None:
    for value in ["none -backup all", "--output C:\\x", "yes;no", "ALL", ""]:
        scope = dict(SCOPE, download=value)  # type: ignore[call-overload]
        with pytest.raises(AndroidQFError, match="SCOPE_INVALID"):
            build_args(Path("C:/t/androidqf.exe"), "ABC123", Path("C:/w"), scope)
    with pytest.raises(AndroidQFError, match="SCOPE_INVALID"):
        build_args(Path("C:/t/androidqf.exe"), "ABC123", Path("C:/w"), dict(SCOPE, extra="x"))  # type: ignore[call-overload]


def test_argument_list_is_flat_and_scope_cannot_be_widened_by_operator_input() -> None:
    args = build_args(Path("C:/t/androidqf.exe"), "ABC123", Path("C:/w"), dict(SCOPE))  # type: ignore[call-overload]
    assert all(isinstance(a, str) for a in args)
    assert args.count("-serial") == 1
    assert "-key" not in args  # upstream has no such flag; never send an invented one


@pytest.mark.skipif(sys.platform != "win32", reason="Windows executable policy")
def test_process_runner_requires_absolute_exe_and_rejects_shell_forms(tmp_path: Path) -> None:
    script = tmp_path / "tool.bat"
    script.write_text("@echo off\r\ncalc.exe\r\n")
    for args in (["cmd", "/c", "echo", "x"], [str(script)], [str(tmp_path / "missing.exe")], [], ["tool.exe"]):
        with pytest.raises(ProcessError):
            run_process(args, cwd=tmp_path, timeout_s=5)
    with pytest.raises(ProcessError):
        run_process(
            [str(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe"), "a\0b"], cwd=tmp_path, timeout_s=5
        )


def test_child_environment_does_not_inherit_secrets_or_proxies(tmp_path: Path, monkeypatch) -> None:
    for name in ("ASTRIA_HMAC", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PYTHONPATH", "PYTHONSTARTUP"):
        monkeypatch.setenv(name, "leak-me")
    environment = restricted_environment(tmp_path)
    assert "leak-me" not in " ".join(environment.values())
    assert set(environment).isdisjoint({"ASTRIA_HMAC", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"})
    assert set(environment).isdisjoint({"PYTHONPATH", "PYTHONSTARTUP"})
    assert environment["TEMP"] == str(tmp_path)


def test_wrong_checksum_never_reaches_a_subprocess(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "androidqf.exe"
    binary.write_bytes(b"tampered")
    calls: list[object] = []
    monkeypatch.setattr(androidqf, "run_process", lambda *a, **k: calls.append(a))
    for bad in ("0" * 64, "short", "A" * 64, hashlib.sha256(b"other").hexdigest()):
        with pytest.raises(AndroidQFError):
            androidqf.inspect_tool(binary, bad, tmp_path)
    assert calls == []


def test_official_release_is_never_approved_for_acquisition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with a perfect checksum and advertised flags there is no configuration that enables it."""
    info = androidqf.ToolInfo(androidqf.RELEASE_VERSION, androidqf.WINDOWS_RELEASE_SHA256, androidqf.REQUIRED_FLAGS)
    with pytest.raises(AndroidQFError, match="TOOL_PROFILE_UNAPPROVED"):
        androidqf.require_compatible(info)
    official = androidqf.ToolInfo(
        androidqf.RELEASE_VERSION, androidqf.WINDOWS_RELEASE_SHA256, frozenset({"-serial", "-output"})
    )
    with pytest.raises(AndroidQFError, match="TOOL_INCOMPATIBLE"):
        androidqf.require_compatible(official)


def test_unauthorised_acquisition_is_impossible_without_a_confirmation_object(settings: Settings, job: Job) -> None:
    runner = make_runner(settings, FakeUplink(), acquire=lambda _r: pytest.fail("acquired"))
    with pytest.raises(TypeError):
        runner.execute(job)  # type: ignore[call-arg]
    with pytest.raises(AttributeError):
        runner.execute(job, "SJ-2026-0001")  # type: ignore[arg-type]
    assert confirm_job(job, "") is None


def test_device_mismatch_is_rejected_and_never_logged_in_full(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with pytest.raises(DeviceError) as raised:
        match_device([Device("ATTACKERPHONE1234", "device")], serial_sha256(SERIAL))
    assert raised.value.code == "SERIAL_MISMATCH"
    assert "ATTACKERPHONE1234" not in str(raised.value) + repr(raised.value)


def configured_log(tmp_path: Path) -> Path:
    logs.configure(tmp_path / "logs")
    return tmp_path / "logs" / "collector.jsonl"


def test_logs_are_allowlisted_json_without_serials_secrets_or_content(tmp_path: Path) -> None:
    path = configured_log(tmp_path)
    log = structlog.get_logger("collector")
    log.info(
        "job_finished",
        job_id="SJ-2026-0001",
        trace_id="a" * 32,
        stage="selesai",
        code="OK",
        serial=SERIAL,
        hmac_secret=SECRET.hex(),
        archive_path="C:\\Users\\op\\work\\x.zip.age",
        owner="Budi",
        stdout="evidence text",
        password="hunter2",  # noqa: S106 -- a canary the redaction test must never find in the log
        authorization="Bearer abc",
    )
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = path.read_text(encoding="utf-8")
    record = json.loads(text.splitlines()[-1])
    assert set(record) <= {"event", "job_id", "trace_id", "stage", "code", "level", "timestamp"}
    for forbidden in (SERIAL, SECRET.hex(), "x.zip.age", "Budi", "evidence text", "hunter2", "Bearer"):
        assert forbidden not in text


def test_runner_logs_carry_no_device_identifier(settings: Settings, job: Job, tmp_path: Path) -> None:
    path = configured_log(tmp_path)
    make_runner(settings, FakeUplink()).execute(job, confirm_job(job, job.job_id))  # type: ignore[arg-type]
    for handler in logging.getLogger().handlers:
        handler.flush()
    text = path.read_text(encoding="utf-8")
    assert "job_finished" in text
    assert SERIAL not in text
    assert job.owner_ref not in text
    assert job.device.label not in text


def test_error_messages_never_contain_server_text_or_secrets(client_factory) -> None:
    leaked = f"signature {SECRET.hex()} for {KEY_ID}"
    with pytest.raises(ClientError) as raised:
        client_factory(lambda _r: httpx.Response(500, text=leaked)).next_job()
    assert SECRET.hex() not in str(raised.value) + repr(raised.value)
    with pytest.raises(ClientError) as raised:
        client_factory(lambda _r: httpx.Response(418, text=leaked)).next_job()
    assert leaked not in str(raised.value)


def test_secret_never_appears_in_settings_repr_or_dump(settings: Settings) -> None:
    assert SECRET.hex() not in repr(settings) + settings.model_dump_json()
    assert "hmac" not in settings.model_dump_json().lower()


def test_failed_upload_keeps_ciphertext_and_blocks_cleanup_of_foreign_files(settings: Settings, job: Job) -> None:
    uplink = FakeUplink([ClientError("NETWORK_UNAVAILABLE")])
    outcome = make_runner(settings, uplink).execute(job, confirm_job(job, job.job_id))  # type: ignore[arg-type]
    assert outcome.retained
    directory = settings.work_dir / job.job_id
    assert (directory / "ACQ-0001.zip.age").read_bytes() == AGE
    assert sorted(p.name for p in directory.iterdir()) == ["ACQ-0001.zip.age", "job.json", "manifest.json"]
    assert SERIAL not in "".join(p.read_text(errors="ignore") for p in directory.iterdir() if p.suffix == ".json")


def test_no_plaintext_evidence_artifact_names_are_ever_produced(settings: Settings, job: Job) -> None:
    uplink = FakeUplink([ClientError("NETWORK_UNAVAILABLE")])
    make_runner(settings, uplink).execute(job, confirm_job(job, job.job_id))  # type: ignore[arg-type]
    names = {p.name for p in (settings.work_dir / job.job_id).rglob("*")}
    assert not any(n.endswith((".zip", ".json.bak", ".csv", ".log")) for n in names)


def test_path_traversal_in_job_or_archive_names_cannot_escape(settings: Settings, tmp_path: Path) -> None:
    for job_id in ("..", "..\\..\\Windows", "../../x", "C:\\Windows", "SJ/../../x"):
        with pytest.raises(pack.ArtifactError):
            pack.job_directory(settings.work_dir, job_id, create=True)
    assert not (tmp_path / "x").exists()


def test_http_is_refused_outside_loopback() -> None:
    with pytest.raises(ValueError):
        Settings(
            collector_key_id=KEY_ID,
            androidqf_sha256="a" * 64,
            adb_path=Path("adb.exe"),
            adb_sha256="b" * 64,
            ingest_base_url="http://ingest.example.internal",
        )


def test_mismatched_server_acknowledgement_is_not_treated_as_success(
    settings: Settings, job: Job, client_factory
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            request.read()
            return httpx.Response(
                201,
                json={
                    "acquisition_id": "AQ-1",
                    "job_id": job.job_id,
                    "status": "received",
                    "archive_sha256": "0" * 64,
                    "archive_size": 1,
                    "metadata_status": "pending_verification",
                },
            )
        return httpx.Response(204)

    outcome = make_runner(settings, client_factory(handler)).execute(job, confirm_job(job, job.job_id))  # type: ignore[arg-type]
    assert (outcome.state, outcome.code, outcome.retained) == (State.GAGAL, "ACK_MISMATCH", True)
    assert (settings.work_dir / job.job_id / "ACQ-0001.zip.age").exists()
