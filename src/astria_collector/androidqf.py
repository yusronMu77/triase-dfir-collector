"""Probe AndroidQF safely and refuse unreviewed acquisition implementations.

The official 1.8.3 release cannot enforce Astria's unattended scope or encrypted
workspace requirements. There is deliberately no runtime compatibility override.
The argument mapping is a candidate interface, exercised only by test doubles
until a compatible upstream release has been reviewed.
"""

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from astria_collector.processes import ProcessResult, run_process

RELEASE_VERSION = "1.8.3"
WINDOWS_RELEASE_SHA256 = "2a5aa89b8aa2145d1246372ef3310ffd1e6d8a457c59b0a232c3de79892d4650"
SCOPE_FLAGS = {
    "backup": "-backup",
    "download": "-download",
    "remove_trusted": "-remove-trusted",
    "intrusion_logs": "-intrusion-logs",
    "hash_files": "-hash-files",
    "browser_history": "-browser-history",
    "magisk_modules": "-magisk-modules",
}
SCOPE_VALUES = {
    "backup": frozenset({"none"}),
    "download": frozenset({"none", "non-system", "all"}),
    "remove_trusted": frozenset({"yes", "no"}),
    "intrusion_logs": frozenset({"no"}),
    "hash_files": frozenset({"yes", "no"}),
    "browser_history": frozenset({"yes", "no"}),
    "magisk_modules": frozenset({"yes", "no"}),
}
REQUIRED_FLAGS = frozenset({"-non-interactive", "-serial", "-output", *SCOPE_FLAGS.values()})
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class AndroidQFError(ValueError):
    """A safe error code; no subprocess output or device identifier is exposed."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ToolInfo:
    version: str
    sha256: str
    flags: frozenset[str]


def _regular_path(path: Path, *, directory: bool = False) -> Path:
    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink() or component.is_junction():
            raise AndroidQFError("TOOL_PATH_UNSAFE")
    if not (absolute.is_dir() if directory else absolute.is_file()):
        raise AndroidQFError("TOOL_PATH_INVALID")
    return absolute.resolve(strict=True)


def verify_checksum(executable: Path, expected_sha256: str) -> str:
    """Verify an operator-installed binary before executing even its help command."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise AndroidQFError("TOOL_CHECKSUM_INVALID")
    path = _regular_path(executable)
    try:
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise AndroidQFError("TOOL_UNREADABLE") from exc
    if not hmac.compare_digest(actual, expected_sha256):
        raise AndroidQFError("TOOL_CHECKSUM_MISMATCH")
    return actual


def parse_probe(version_output: str, help_output: str, sha256: str) -> ToolInfo:
    """Parse bounded help/version output, accepting only explicit flag definitions."""
    version_text = _ANSI.sub("", version_output)
    versions = re.findall(r"^AndroidQF version: ([0-9]+\.[0-9]+\.[0-9]+)\s*$", version_text, re.MULTILINE)
    if len(versions) != 1 or versions[0] != RELEASE_VERSION:
        raise AndroidQFError("TOOL_VERSION_UNSUPPORTED")
    flags = frozenset(re.findall(r"^\s{1,4}(-[a-zA-Z][a-zA-Z-]*)(?=\s|$)", _ANSI.sub("", help_output), re.MULTILINE))
    return ToolInfo(versions[0], sha256, flags)


def inspect_tool(executable: Path, expected_sha256: str, probe_dir: Path, *, timeout_s: float = 10) -> ToolInfo:
    """Run only -version and -h; neither initializes ADB in the reviewed release."""
    path = _regular_path(executable)
    cwd = _regular_path(probe_dir, directory=True)
    digest = verify_checksum(path, expected_sha256)
    outputs: list[str] = []
    for argument in ("-version", "-h"):
        result = run_process([str(path), argument], cwd=cwd, timeout_s=timeout_s, output_limit=32768)
        if result.timed_out or result.cancelled or result.output_truncated or result.exit_code != 0:
            raise AndroidQFError("TOOL_PROBE_FAILED")
        outputs.append(result.stdout + "\n" + result.stderr)
    verify_checksum(path, digest)
    return parse_probe(outputs[0], outputs[1], digest)


def require_compatible(info: ToolInfo) -> None:
    """Fail closed: no release is approved for acquisition at this revision.

    Help flags alone cannot prove encrypted-only output or workspace containment.
    A future code review must add an audited implementation and regression tests;
    changing a config checksum or forging help cannot enable acquisition.
    """
    if info.version != RELEASE_VERSION:
        raise AndroidQFError("TOOL_VERSION_UNSUPPORTED")
    if not REQUIRED_FLAGS.issubset(info.flags):
        raise AndroidQFError("TOOL_INCOMPATIBLE")
    raise AndroidQFError("TOOL_PROFILE_UNAPPROVED")


def build_args(executable: Path, serial: str, output_dir: Path, scope: Mapping[str, str]) -> list[str]:
    """Candidate mapping for synthetic verification, never a compatibility grant.

    No -key flag exists upstream. A reviewed adapter must resolve the actual key
    and encrypted-output paths before this mapping can be used in production.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", serial):
        raise AndroidQFError("DEVICE_SERIAL_INVALID")
    if set(scope) != set(SCOPE_FLAGS) or any(value not in SCOPE_VALUES[key] for key, value in scope.items()):
        raise AndroidQFError("SCOPE_INVALID")
    args = [str(executable.absolute()), "-non-interactive", "-serial", serial, "-output", str(output_dir.absolute())]
    for key, flag in SCOPE_FLAGS.items():
        args.extend((flag, scope[key]))
    return args


def run_acquisition(
    executable: Path,
    expected_sha256: str,
    serial: str,
    work_dir: Path,
    scope: Mapping[str, str],
    *,
    timeout_s: float,
    cancel: Event | None = None,
) -> ProcessResult:
    """Production gate. The reviewed release is rejected before acquisition starts."""
    info = inspect_tool(executable, expected_sha256, work_dir)
    require_compatible(info)
    # Unreachable until a reviewed profile replaces the fail-closed policy above.
    args = build_args(executable, serial, work_dir / "output", scope)
    return run_process(args, cwd=work_dir, timeout_s=timeout_s, cancel=cancel)
