"""Bounded, noninteractive subprocess execution without command or output logging."""

import ctypes
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO


class ProcessError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)
    timed_out: bool = False
    cancelled: bool = False
    output_truncated: bool = False


def restricted_environment(cwd: Path, tool_dirs: Sequence[Path] = ()) -> dict[str, str]:
    """Do not inherit secrets, proxies, Python hooks, or arbitrary PATH entries."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    dirs = [str(path.resolve(strict=True)) for path in tool_dirs]
    environment = {"TEMP": str(cwd), "TMP": str(cwd), "TMPDIR": str(cwd)}
    if sys.platform == "win32":
        system32 = str(Path(system_root) / "System32")
        environment.update(SystemRoot=system_root, WINDIR=system_root, PATH=os.pathsep.join([*dirs, system32]))
    else:
        environment.update(PATH=os.pathsep.join([*dirs, "/usr/bin", "/bin"]), LANG="C.UTF-8")
    return environment


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IOCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits),
        ("IoInfo", _IOCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _ThreadEntry(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


def _kernel() -> Any:
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
        "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
        "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        "CreateToolhelp32Snapshot": ([wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE),
        "Thread32First": ([wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)], wintypes.BOOL),
        "Thread32Next": ([wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)], wintypes.BOOL),
        "OpenThread": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
        "ResumeThread": ([wintypes.HANDLE], wintypes.DWORD),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(api, name)
        function.argtypes = arguments
        function.restype = result
    return api


class _WindowsJob:
    """Assign before resuming the process, closing the child-creation race."""

    def __init__(self) -> None:
        self.api = _kernel()
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ProcessError("PROCESS_JOB_FAILED")
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ProcessError("PROCESS_JOB_FAILED")

    def attach_and_resume(self, pid: int) -> None:
        process = self.api.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
        if not process:
            raise ProcessError("PROCESS_JOB_FAILED")
        try:
            if not self.api.AssignProcessToJobObject(self.handle, process):
                raise ProcessError("PROCESS_JOB_FAILED")
        finally:
            self.api.CloseHandle(process)
        snapshot = self.api.CreateToolhelp32Snapshot(0x00000004, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ProcessError("PROCESS_RESUME_FAILED")
        try:
            entry = _ThreadEntry()
            entry.dwSize = ctypes.sizeof(entry)
            found = self.api.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.th32OwnerProcessID == pid:
                    thread = self.api.OpenThread(0x0002, False, entry.th32ThreadID)
                    if not thread:
                        raise ProcessError("PROCESS_RESUME_FAILED")
                    try:
                        if self.api.ResumeThread(thread) == 0xFFFFFFFF:
                            raise ProcessError("PROCESS_RESUME_FAILED")
                        return
                    finally:
                        self.api.CloseHandle(thread)
                found = self.api.Thread32Next(snapshot, ctypes.byref(entry))
            raise ProcessError("PROCESS_RESUME_FAILED")
        finally:
            self.api.CloseHandle(snapshot)

    def close(self) -> None:
        if self.handle:
            if not self.api.CloseHandle(self.handle):
                raise ProcessError("PROCESS_JOB_CLOSE_FAILED")
            self.handle = None

    def terminate(self) -> None:
        if self.handle and not self.api.TerminateJobObject(self.handle, 1):
            raise ProcessError("PROCESS_JOB_TERMINATE_FAILED")


class _Capture:
    def __init__(self, limit: int) -> None:
        self.data = bytearray()
        self.limit = limit
        self.truncated = False

    def read(self, pipe: BinaryIO) -> None:
        try:
            while chunk := pipe.read(8192):
                remaining = self.limit - len(self.data)
                self.data.extend(chunk[:remaining])
                self.truncated |= len(chunk) > remaining
        finally:
            pipe.close()


def run_process(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout_s: float,
    cancel: threading.Event | None = None,
    output_limit: int = 262144,
    tool_dirs: Sequence[Path] = (),
) -> ProcessResult:
    """Run an absolute executable, bound output, and reap its entire process tree."""
    if not args or timeout_s <= 0 or output_limit < 0:
        raise ProcessError("PROCESS_ARGUMENT_INVALID")
    executable = Path(args[0])
    if not executable.is_absolute() or not executable.is_file() or any("\0" in arg for arg in args):
        raise ProcessError("PROCESS_ARGUMENT_INVALID")
    if sys.platform == "win32" and executable.suffix.lower() != ".exe":
        raise ProcessError("PROCESS_EXECUTABLE_INVALID")
    cwd = cwd.resolve(strict=True)
    if not cwd.is_dir():
        raise ProcessError("PROCESS_DIRECTORY_INVALID")
    if cancel is not None and cancel.is_set():
        return ProcessResult(-1, "", "", cancelled=True)
    job = _WindowsJob() if sys.platform == "win32" else None
    process: subprocess.Popen[bytes] | None = None
    captures = [_Capture(output_limit), _Capture(output_limit)]
    readers: list[threading.Thread] = []
    timed_out = cancelled = False
    try:
        process = subprocess.Popen(  # noqa: S603 -- fixed executable and argv, never a shell
            list(args),
            cwd=cwd,
            env=restricted_environment(cwd, tool_dirs),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=0x08000004 if job else 0,  # CREATE_NO_WINDOW | CREATE_SUSPENDED
            start_new_session=job is None,
        )
        if job:
            job.attach_and_resume(process.pid)
        for capture, pipe in zip(captures, (process.stdout, process.stderr), strict=True):
            assert pipe is not None
            reader = threading.Thread(target=capture.read, args=(pipe,), daemon=True)
            reader.start()
            readers.append(reader)
        deadline = time.monotonic() + timeout_s
        while process.poll() is None:
            cancelled = cancel is not None and cancel.is_set()
            timed_out = time.monotonic() >= deadline
            if cancelled or timed_out:
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    except OSError:
        raise ProcessError("PROCESS_START_FAILED") from None
    finally:
        if job:
            try:
                if process and process.poll() is None:
                    job.terminate()
            finally:
                job.close()
        elif process and sys.platform != "win32":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise ProcessError("PROCESS_OUTPUT_NOT_CLOSED")
    assert process is not None
    return ProcessResult(
        process.returncode,
        captures[0].data.decode("utf-8", errors="replace"),
        captures[1].data.decode("utf-8", errors="replace"),
        timed_out,
        cancelled,
        any(capture.truncated for capture in captures),
    )


def secure_directory(path: Path) -> None:
    """Restrict an owned directory to its current Windows user and SYSTEM."""
    if sys.platform != "win32":
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.chmod(0o700)
        return
    if not path.is_absolute() or str(path).startswith("\\\\"):
        raise ProcessError("DIRECTORY_NOT_LOCAL")
    path.mkdir(parents=True, exist_ok=True)
    for component in (path, *path.parents):
        if component.is_symlink() or component.is_junction():
            raise ProcessError("DIRECTORY_LINK_REJECTED")
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    result = run_process([str(system32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"], cwd=path, timeout_s=10)
    match = re.search(r'"(S-1-5-[0-9-]+)"', result.stdout)
    if result.exit_code or match is None:
        raise ProcessError("DIRECTORY_IDENTITY_FAILED")
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    api.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    api.SetFileSecurityW.restype = wintypes.BOOL
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;OICI;FA;;;{match[1]})(A;OICI;FA;;;SY)"
    if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ProcessError("DIRECTORY_ACL_FAILED")
    try:
        if not api.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ProcessError("DIRECTORY_ACL_FAILED")
    finally:
        kernel.LocalFree(descriptor)
