"""ADB discovery only: device identifiers never enter exception messages."""

import hashlib
import hmac
import re
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .processes import run_process


class DeviceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Device:
    serial: str = field(repr=False)
    state: str
    model: str = "tidak diketahui"

    @property
    def serial_tail(self) -> str:
        return self.serial[-4:]


def serial_sha256(serial: str) -> str:
    return hashlib.sha256(serial.encode("utf-8")).hexdigest()


def parse_devices(output: str) -> list[Device]:
    if len(output) > 262144:
        raise DeviceError("ADB_OUTPUT_TOO_LARGE")
    devices: list[Device] = []
    seen: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line or line == "List of devices attached" or line.startswith("* daemon"):
            continue
        parts = line.split()
        if len(parts) < 2 or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", parts[0]):
            raise DeviceError("ADB_OUTPUT_INVALID")
        serial, state = parts[:2]
        if serial in seen or state not in {
            "device",
            "offline",
            "unauthorized",
            "recovery",
            "sideload",
            "bootloader",
            "no",
        }:
            raise DeviceError("ADB_OUTPUT_INVALID")
        if state == "no":
            if len(parts) < 3 or parts[2] != "permissions":
                raise DeviceError("ADB_OUTPUT_INVALID")
            state = "no_permissions"
        model = next((part[6:] for part in parts[2:] if part.startswith("model:")), "tidak diketahui")
        if not re.fullmatch(r"[A-Za-z0-9_. -]{1,128}", model):
            raise DeviceError("ADB_OUTPUT_INVALID")
        devices.append(Device(serial, state, model))
        seen.add(serial)
    return devices


def match_device(devices: Sequence[Device], expected_sha256: str) -> Device:
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise DeviceError("SERIAL_HASH_INVALID")
    if not devices:
        raise DeviceError("DEVICE_NOT_FOUND")
    if len(devices) != 1:
        raise DeviceError("MULTIPLE_DEVICES")
    device = devices[0]
    if not hmac.compare_digest(serial_sha256(device.serial), expected_sha256):
        raise DeviceError("SERIAL_MISMATCH")
    if device.state != "device":
        raise DeviceError(f"DEVICE_{device.state.upper()}")
    # TCP/IP and emulator targets are outside the USB-only authorization boundary.
    if ":" in device.serial or device.serial.startswith("emulator-"):
        raise DeviceError("USB_DEVICE_REQUIRED")
    return device


def discover_devices(adb_path: Path, *, cwd: Path | None = None) -> list[Device]:
    adb_path = adb_path.resolve(strict=True)
    result = run_process([str(adb_path), "devices", "-l"], cwd=cwd or adb_path.parent, timeout_s=15)
    if result.exit_code or result.timed_out or result.output_truncated:
        raise DeviceError("ADB_DISCOVERY_FAILED")
    return parse_devices(result.stdout)


def parse_adb_version(output: str) -> str:
    """Real adb prints CRLF on Windows; match line by line so a trailing carriage return cannot break it."""
    lines = output.splitlines()
    match = next((m for line in lines if (m := re.fullmatch(r"Android Debug Bridge version ([0-9.]+)\s*", line))), None)
    if match is None:
        raise DeviceError("ADB_VERSION_INVALID")
    build = next((m for line in lines if (m := re.fullmatch(r"Version ([A-Za-z0-9_.-]+)\s*", line))), None)
    return match[1] + (f" ({build[1]})" if build else "")


def adb_version(adb_path: Path, *, cwd: Path | None = None) -> str:
    adb_path = adb_path.resolve(strict=True)
    result = run_process([str(adb_path), "version"], cwd=cwd or adb_path.parent, timeout_s=15)
    if result.exit_code or result.output_truncated:
        raise DeviceError("ADB_VERSION_FAILED")
    return parse_adb_version(result.stdout)


def wait_for_device(
    adb_path: Path,
    expected_sha256: str,
    timeout_s: float,
    *,
    cancel: threading.Event | None = None,
    on_status: Callable[[str], None] | None = None,
    cwd: Path | None = None,
    discover: Callable[[], list[Device]] | None = None,
) -> Device:
    if timeout_s <= 0:
        raise DeviceError("DEVICE_TIMEOUT")
    deadline = time.monotonic() + timeout_s
    cancellation = cancel or threading.Event()
    while time.monotonic() < deadline:
        if cancellation.is_set():
            raise DeviceError("CANCELLED")
        devices = discover() if discover else discover_devices(adb_path, cwd=cwd)
        try:
            device = match_device(devices, expected_sha256)
        except DeviceError as error:
            if error.code not in {"DEVICE_NOT_FOUND", "DEVICE_OFFLINE", "DEVICE_UNAUTHORIZED", "DEVICE_NO_PERMISSIONS"}:
                raise
            if on_status:
                on_status(error.code)
        else:
            return device
        cancellation.wait(min(2.0, max(0, deadline - time.monotonic())))
    raise DeviceError("DEVICE_TIMEOUT")
