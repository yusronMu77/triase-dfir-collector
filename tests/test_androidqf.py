"""Compatibility and scope tests. No test accesses an Android device."""

import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from astria_collector import androidqf
from astria_collector.processes import ProcessResult


def scope() -> dict[str, str]:
    return {
        "backup": "none",
        "download": "non-system",
        "remove_trusted": "yes",
        "intrusion_logs": "no",
        "hash_files": "no",
        "browser_history": "no",
        "magisk_modules": "no",
    }


def result(stdout: str = "", stderr: str = "", exit_code: int = 0) -> ProcessResult:
    return ProcessResult(exit_code, stdout, stderr, False, False, False)


def test_checksum_mismatch_never_executes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "androidqf.exe"
    binary.write_bytes(b"test fixture only")
    runner = Mock()
    monkeypatch.setattr(androidqf, "run_process", runner)
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_CHECKSUM_MISMATCH"):
        androidqf.inspect_tool(binary, "0" * 64, tmp_path)
    runner.assert_not_called()


@pytest.mark.parametrize("digest", ["", "A" * 64, "../file", "0" * 63, "0" * 65])
def test_checksum_format(tmp_path: Path, digest: str) -> None:
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_CHECKSUM_INVALID"):
        androidqf.verify_checksum(tmp_path / "absent", digest)


def test_actual_release_capability_shape_is_rejected() -> None:
    # Independently authored minimal fixture representing verified -h definitions.
    info = androidqf.parse_probe(
        "AndroidQF version: 1.8.3\n",
        "  -serial string\n  -output string\n  -fast\n  -module string\n  -version\n",
        androidqf.WINDOWS_RELEASE_SHA256,
    )
    assert info.version == "1.8.3"
    assert "-serial" in info.flags
    assert "-non-interactive" not in info.flags
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_INCOMPATIBLE"):
        androidqf.require_compatible(info)


def test_forged_help_does_not_approve_a_binary() -> None:
    info = androidqf.ToolInfo("1.8.3", "0" * 64, androidqf.REQUIRED_FLAGS)
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_PROFILE_UNAPPROVED"):
        androidqf.require_compatible(info)


@pytest.mark.parametrize("version", ["1.8.2", "1.8.30", "1.8.3-dev", "2.0.0", "", "1.8.3\nAndroidQF version: 1.8.3"])
def test_version_must_be_exact(version: str) -> None:
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_VERSION_UNSUPPORTED"):
        androidqf.parse_probe(f"AndroidQF version: {version}\n", "", "0" * 64)


def test_help_prose_cannot_impersonate_defined_flags() -> None:
    info = androidqf.parse_probe(
        "AndroidQF version: 1.8.3\n", "Supported someday: -non-interactive -backup\n", "0" * 64
    )
    assert not info.flags


def test_inspection_executes_only_help_and_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "androidqf.exe"
    binary.write_bytes(b"probe fixture")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    runner = Mock(side_effect=[result("AndroidQF version: 1.8.3\n"), result(stderr="  -output string\n")])
    monkeypatch.setattr(androidqf, "run_process", runner)
    info = androidqf.inspect_tool(binary, digest, tmp_path)
    assert info.sha256 == digest
    assert [call.args[0][1:] for call in runner.call_args_list] == [["-version"], ["-h"]]
    assert all(call.kwargs["cwd"] == tmp_path for call in runner.call_args_list)


def test_failed_probe_never_exposes_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "androidqf.exe"
    binary.write_bytes(b"probe fixture")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    monkeypatch.setattr(androidqf, "run_process", Mock(return_value=result("private-device-serial", exit_code=1)))
    with pytest.raises(androidqf.AndroidQFError) as raised:
        androidqf.inspect_tool(binary, digest, tmp_path)
    assert str(raised.value) == "TOOL_PROBE_FAILED"


def test_probe_detects_binary_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "androidqf.exe"
    binary.write_bytes(b"probe fixture")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()

    def runner(*args: object, **kwargs: object) -> ProcessResult:
        binary.write_bytes(b"changed")
        return result("AndroidQF version: 1.8.3\n")

    monkeypatch.setattr(androidqf, "run_process", runner)
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_CHECKSUM_MISMATCH"):
        androidqf.inspect_tool(binary, digest, tmp_path)


def test_scope_is_exact_and_never_uses_fictional_key_flag(tmp_path: Path) -> None:
    flags = scope()
    args = androidqf.build_args(tmp_path / "tool.exe", "USB_123-456", tmp_path / "output", flags)
    assert args[1:4] == ["-non-interactive", "-serial", "USB_123-456"]
    assert "-key" not in args
    for name, value in flags.items():
        assert args[args.index(androidqf.SCOPE_FLAGS[name]) + 1] == value


@pytest.mark.parametrize("key", list(androidqf.SCOPE_FLAGS))
def test_missing_scope_flag_is_rejected(tmp_path: Path, key: str) -> None:
    flags = scope()
    del flags[key]
    with pytest.raises(androidqf.AndroidQFError, match="SCOPE_INVALID"):
        androidqf.build_args(tmp_path / "tool.exe", "USB123", tmp_path / "output", flags)


@pytest.mark.parametrize(
    "key,value", [("backup", "all"), ("intrusion_logs", "yes"), ("download", ";whoami"), ("extra", "no")]
)
def test_unsupported_scope_is_rejected(tmp_path: Path, key: str, value: str) -> None:
    flags = scope()
    flags[key] = value
    with pytest.raises(androidqf.AndroidQFError, match="SCOPE_INVALID"):
        androidqf.build_args(tmp_path / "tool.exe", "USB123", tmp_path / "output", flags)


@pytest.mark.parametrize("serial", ["", "-serial", "A B", "ABC;whoami", "ABC\n123", "127.0.0.1:5555", "A" * 257])
def test_serial_cannot_add_flags_or_target_network_device(tmp_path: Path, serial: str) -> None:
    with pytest.raises(androidqf.AndroidQFError, match="DEVICE_SERIAL_INVALID"):
        androidqf.build_args(tmp_path / "tool.exe", serial, tmp_path / "output", scope())


@given(st.text())
def test_arbitrary_help_cannot_enable_production_acquisition(help_text: str) -> None:
    info = androidqf.parse_probe("AndroidQF version: 1.8.3", help_text, "0" * 64)
    with pytest.raises(androidqf.AndroidQFError):
        androidqf.require_compatible(info)


def test_acquisition_gate_runs_no_device_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        androidqf,
        "inspect_tool",
        Mock(return_value=androidqf.ToolInfo("1.8.3", androidqf.WINDOWS_RELEASE_SHA256, frozenset({"-serial"}))),
    )
    runner = Mock()
    monkeypatch.setattr(androidqf, "run_process", runner)
    with pytest.raises(androidqf.AndroidQFError, match="TOOL_INCOMPATIBLE"):
        androidqf.run_acquisition(
            tmp_path / "tool.exe", "0" * 64, "USB123", tmp_path, scope(), "age1" + "q" * 58, timeout_s=1
        )
    runner.assert_not_called()
