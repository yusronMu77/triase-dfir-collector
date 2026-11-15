"""adb output as the real Windows binary prints it (CRLF), captured from platform-tools 37.0.1."""

import pytest

from astria_collector.device import DeviceError, parse_adb_version

REAL = (
    "Android Debug Bridge version 1.0.41\r\nVersion 37.0.1-15733141\r\n"
    "Installed as C:\apps\android-sdk\\platform-tools\adb.exe\r\nRunning on Windows 10.0.26200\r\n"
)


def test_real_crlf_output_is_parsed() -> None:
    assert parse_adb_version(REAL) == "1.0.41 (37.0.1-15733141)"


def test_lf_output_and_missing_build_line() -> None:
    assert parse_adb_version("Android Debug Bridge version 1.0.39\n") == "1.0.39"


@pytest.mark.parametrize("output", ["", "adb: not found", "Android Debug Bridge version\r\n", "version 1.0.41"])
def test_unrecognised_output_is_refused(output: str) -> None:
    with pytest.raises(DeviceError, match="ADB_VERSION_INVALID"):
        parse_adb_version(output)
