"""Probe AndroidQF safely and run only a reviewed, digest-pinned build.

The official 1.8.3 release cannot enforce Astria's unattended scope or encrypted
workspace requirements and stays rejected. The only approved build is compiled
from a reviewed upstream commit (owner decision 2026-11-15, collector#2): it has
``-non-interactive`` and all scope flags, honours ``-output``, and reads the age
recipient ``key.txt`` from its working directory before its own folder. Approval
is keyed by the binary's SHA-256, never by help text, and there is no runtime
override. See docs/androidqf-compatibility.md.
"""

import hashlib
import hmac
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from astria_collector.processes import ProcessResult, run_process

RELEASE_VERSION = "1.8.3"
WINDOWS_RELEASE_SHA256 = "2a5aa89b8aa2145d1246372ef3310ffd1e6d8a457c59b0a232c3de79892d4650"


@dataclass(frozen=True)
class ApprovedBuild:
    """A reviewed AndroidQF binary: exact version string and the upstream commit it was built from."""

    version: str
    source_commit: str


# Built on Windows from https://github.com/mvt-project/androidqf at the commit below with
# docs/androidqf-compatibility.md "Reproducible build"; the digest is of that exact executable.
APPROVED_BUILDS: Mapping[str, ApprovedBuild] = {
    "260d65c69cc7101ea04ab8005d00928dd7f042f43999066e694eb77c6e4b8acd": ApprovedBuild(
        version="v1.8.3-95-g05811f3", source_commit="05811f3c6f1df58ad633f2f6c47598cab994dd57"
    ),
}
_SUPPORTED_VERSIONS = frozenset({RELEASE_VERSION, *(build.version for build in APPROVED_BUILDS.values())})
RECIPIENT_FILE = "key.txt"
_RECIPIENT = re.compile(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}")
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
    versions = re.findall(
        r"^AndroidQF version: (v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9]+-g[0-9a-f]{7,40})?)\s*$", version_text, re.MULTILINE
    )
    if len(versions) != 1 or versions[0] not in _SUPPORTED_VERSIONS:
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


def require_compatible(info: ToolInfo) -> ApprovedBuild:
    """Fail closed unless the binary digest is a reviewed build and its probe matches that build.

    Help flags alone cannot prove encrypted-only output or workspace containment, so a binary
    advertising every flag is still unapproved unless its SHA-256 is in APPROVED_BUILDS. Changing the
    configured checksum cannot enable another binary: the digest list lives in reviewed code.
    """
    if info.version not in _SUPPORTED_VERSIONS:
        raise AndroidQFError("TOOL_VERSION_UNSUPPORTED")
    if not REQUIRED_FLAGS.issubset(info.flags):
        raise AndroidQFError("TOOL_INCOMPATIBLE")
    approved = next(
        (build for digest, build in APPROVED_BUILDS.items() if hmac.compare_digest(digest, info.sha256)), None
    )
    if approved is None or approved.version != info.version:
        raise AndroidQFError("TOOL_PROFILE_UNAPPROVED")
    return approved


def write_recipient(work_dir: Path, recipient: str) -> Path:
    """Write the public age recipient where the approved build looks first (its working directory).

    The file is created exclusively in the job folder; an existing file is refused rather than
    trusted, so the archive is always encrypted to the recipient Ingest published for this run.
    """
    if not _RECIPIENT.fullmatch(recipient):
        raise AndroidQFError("RECIPIENT_INVALID")
    directory = _regular_path(work_dir, directory=True)
    path = directory / RECIPIENT_FILE
    try:
        with path.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(recipient + "\n")
    except FileExistsError as exc:
        raise AndroidQFError("RECIPIENT_FILE_EXISTS") from exc
    except OSError as exc:
        raise AndroidQFError("RECIPIENT_FILE_UNWRITABLE") from exc
    return path


def _reject_recipient_next_to_tool(executable: Path) -> None:
    """The build falls back to key.txt beside the exe; a stray file there must not exist at all."""
    if os.path.lexists(executable.absolute().parent / RECIPIENT_FILE):
        raise AndroidQFError("TOOL_DIRECTORY_HAS_KEY")


_INCOMPLETE = re.compile(r"Acquisition finalized with (\d{1,3}) incomplete module")


def incomplete_modules(result: ProcessResult) -> int | None:
    """Number of incomplete modules when AndroidQF finalized the archive but exited 1 for that reason only.

    The pinned build exits 1 after ``acq.Complete()`` when any module failed (common on a real phone:
    Android refuses some dumps). The archive is complete and encrypted; module status is inside it and
    is judged by the server after decryption. Any other non-zero exit returns None.
    """
    if result.exit_code != 1 or result.timed_out or result.cancelled:
        return None
    lines = [line for line in _ANSI.sub("", result.tail).splitlines() if line.strip()]
    for line in reversed(lines[-5:]):
        if match := _INCOMPLETE.search(line):
            return int(match.group(1))
    return None


def build_args(executable: Path, serial: str, output_dir: Path, scope: Mapping[str, str]) -> list[str]:
    """Argument list for the approved build. Not a compatibility grant on its own.

    There is no -key flag: the recipient is supplied through key.txt in the working
    directory (write_recipient), and run_acquisition sets that directory as cwd.
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
    recipient: str,
    *,
    timeout_s: float,
    cancel: Event | None = None,
) -> ProcessResult:
    """Production gate: only an approved build runs, with cwd = the job folder holding key.txt.

    Every check happens before the phone is touched. Whatever the tool writes is judged afterwards by
    pack.adopt_archive, which accepts exactly one age-encrypted archive and refuses plaintext.
    """
    info = inspect_tool(executable, expected_sha256, work_dir)
    require_compatible(info)
    _reject_recipient_next_to_tool(executable)
    args = build_args(executable, serial, work_dir / "output", scope)
    write_recipient(work_dir, recipient)
    verify_checksum(executable, info.sha256)
    return run_process(args, cwd=work_dir, timeout_s=timeout_s, cancel=cancel)
