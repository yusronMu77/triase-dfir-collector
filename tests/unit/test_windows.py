import ctypes
import os
import sys
import threading
from pathlib import Path
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from astria_collector import secrets
from astria_collector.device import Device, DeviceError, match_device, parse_devices, serial_sha256, wait_for_device
from astria_collector.power import ES_CONTINUOUS, ES_SYSTEM_REQUIRED, PowerError, prevent_sleep
from astria_collector.processes import ProcessError, restricted_environment, run_process, secure_directory


def test_device_parser_and_minimization():
    devices = parse_devices("List of devices attached\nTEST1234\tdevice product:test model:Pixel_7 device:panther\n")
    assert devices == [Device("TEST1234", "device", "Pixel_7")]
    assert "TEST1234" not in repr(devices)
    assert devices[0].serial_tail == "1234"
    assert match_device(devices, serial_sha256("TEST1234")) == devices[0]


@pytest.mark.parametrize("state,code", [("offline", "DEVICE_OFFLINE"), ("unauthorized", "DEVICE_UNAUTHORIZED")])
def test_unavailable_devices(state, code):
    with pytest.raises(DeviceError, match=code):
        match_device(parse_devices(f"TEST {state}"), serial_sha256("TEST"))


@pytest.mark.parametrize(
    "devices,code",
    [
        ([], "DEVICE_NOT_FOUND"),
        ([Device("TEST", "device"), Device("OTHER", "device")], "MULTIPLE_DEVICES"),
        ([Device("OTHER", "device")], "SERIAL_MISMATCH"),
    ],
)
def test_wrong_device_rejected(devices, code):
    with pytest.raises(DeviceError, match=code):
        match_device(devices, serial_sha256("TEST"))


@pytest.mark.parametrize("serial", ["192.168.1.1:5555", "emulator-5554"])
def test_usb_only(serial):
    with pytest.raises(DeviceError, match="USB_DEVICE_REQUIRED"):
        match_device([Device(serial, "device")], serial_sha256(serial))


@given(st.text(max_size=1024))
def test_adb_malformed_property(output):
    try:
        devices = parse_devices(output)
    except DeviceError as error:
        assert str(error) in {"ADB_OUTPUT_INVALID", "ADB_OUTPUT_TOO_LARGE"}
    else:
        assert len({d.serial for d in devices}) == len(devices)
        assert all(len(d.serial) <= 256 for d in devices)


def test_confirmation_hash_is_exact():
    assert serial_sha256("TEST") != serial_sha256("test")
    with pytest.raises(DeviceError, match="SERIAL_HASH_INVALID"):
        match_device([Device("TEST", "device")], "not-a-hash")


def test_wait_cancel_and_timeout(tmp_path):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(DeviceError, match="CANCELLED"):
        wait_for_device(tmp_path / "adb.exe", serial_sha256("TEST"), 1, cancel=cancel, discover=lambda: [])
    statuses = []
    with pytest.raises(DeviceError, match="DEVICE_TIMEOUT"):
        wait_for_device(
            tmp_path / "adb.exe", serial_sha256("TEST"), 0.01, discover=lambda: [], on_status=statuses.append
        )
    assert statuses == ["DEVICE_NOT_FOUND"]


def test_wait_mismatch_does_not_retry(tmp_path):
    with pytest.raises(DeviceError, match="SERIAL_MISMATCH"):
        wait_for_device(tmp_path / "adb.exe", serial_sha256("TEST"), 1, discover=lambda: [Device("OTHER", "device")])


def test_power_restored_after_exception():
    calls = []

    def setter(flags):
        calls.append(flags)
        return ES_CONTINUOUS | 2

    with pytest.raises(ValueError), prevent_sleep(setter=setter):
        raise ValueError("interruption")
    assert calls == [ES_CONTINUOUS | ES_SYSTEM_REQUIRED, ES_CONTINUOUS | 2]


def test_power_failure_blocks_work():
    with pytest.raises(PowerError, match="POWER_REQUEST_FAILED"), prevent_sleep(setter=lambda _: 0):
        pytest.fail("must not enter")


def test_restricted_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("COLLECTOR_HMAC_SECRET", "test-value-not-a-credential")
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    env = restricted_environment(tmp_path)
    assert "COLLECTOR_HMAC_SECRET" not in env
    assert "HTTP_PROXY" not in env
    assert "PYTHONPATH" not in env
    assert env["TEMP"] == str(tmp_path)


def test_process_output_bounded_and_private(tmp_path):
    result = run_process([sys.executable, "-c", "print('x'*20000)"], cwd=tmp_path, timeout_s=10, output_limit=128)
    assert result.exit_code == 0
    assert result.output_truncated
    assert len(result.stdout) == 128
    assert result.stdout not in repr(result)


def test_process_tail_survives_truncation(tmp_path):
    code = "print('x'*20000); print('LAST LINE')"
    result = run_process([sys.executable, "-c", code], cwd=tmp_path, timeout_s=10, output_limit=128)
    assert result.output_truncated
    assert "LAST LINE" not in result.stdout
    assert "LAST LINE" in result.tail
    assert len(result.tail) <= 2 * 8192 + 1
    assert result.tail not in repr(result)


def test_process_timeout(tmp_path):
    result = run_process([sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout_s=0.15)
    assert result.timed_out
    assert result.exit_code != 0


def test_process_cancellation(tmp_path):
    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.start()
    try:
        result = run_process(
            [sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout_s=10, cancel=cancel
        )
    finally:
        timer.cancel()
    assert result.cancelled
    assert not result.timed_out


def test_process_shell_metacharacters_are_literal(tmp_path):
    literal = "& echo FORBIDDEN > injected.txt"
    result = run_process([sys.executable, "-c", "import sys; print(sys.argv[1])", literal], cwd=tmp_path, timeout_s=10)
    assert result.exit_code == 0
    assert result.stdout.strip() == literal
    assert not (tmp_path / "injected.txt").exists()


def test_process_rejects_relative_or_script(tmp_path):
    with pytest.raises(ProcessError, match="PROCESS_ARGUMENT_INVALID"):
        run_process(["python", "-V"], cwd=tmp_path, timeout_s=1)
    if sys.platform == "win32":
        batch = tmp_path / "tool.cmd"
        batch.write_text("exit /b 0")
        with pytest.raises(ProcessError, match="PROCESS_EXECUTABLE_INVALID"):
            run_process([str(batch)], cwd=tmp_path, timeout_s=1)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native API")
def test_process_descendants_reaped_when_parent_exits(tmp_path):
    # Child inherits pipes: the runner would hang without killing descendants.
    code = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); print('parent')"
    )
    result = run_process([sys.executable, "-c", code], cwd=tmp_path, timeout_s=10)
    assert result.exit_code == 0
    assert result.stdout.strip() == "parent"
    assert not result.timed_out


@pytest.mark.parametrize("key_id", ["", "../escape", "x\nname", "x" * 65])
def test_credential_target_validation(key_id):
    with pytest.raises(secrets.CredentialError, match="KEY_ID_INVALID"):
        secrets.read_secret(key_id)


def test_credential_length_before_native_call():
    with pytest.raises(secrets.CredentialError, match="SECRET_LENGTH_INVALID"):
        secrets.store_secret("test", b"short")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native API")
def test_native_credential_roundtrip():
    key = "test-" + uuid4().hex
    value = os.urandom(32)
    secrets.store_secret(key, value)
    try:
        assert secrets.read_secret(key) == value
    finally:
        secrets.delete_secret(key)
    with pytest.raises(secrets.CredentialError, match="CREDENTIAL_UNAVAILABLE"):
        secrets.read_secret(key)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native API")
def test_native_power_request():
    with prevent_sleep():
        pass


def test_secure_directory(tmp_path):
    path = tmp_path / "work"
    secure_directory(path)
    assert path.is_dir()
    (path / "write-test").write_text("test")
    if sys.platform == "win32":
        # Protected DACL and two explicit ACEs, including SYSTEM.
        result = run_process(
            [str(Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"), str(path)],
            cwd=path,
            timeout_s=10,
        )
        assert result.exit_code == 0
        assert "(I)" not in result.stdout


def test_credential_native_structure_size():
    if sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(secrets._Credential) == 80
