"""Generic credentials in the current Windows user's Credential Manager.

Only byte secrets are supported. No file or environment fallback is permitted.
"""

import ctypes
import re
import sys
from ctypes import wintypes
from typing import Any

CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
MAX_SECRET_BYTES = 2560


class CredentialError(RuntimeError):
    pass


class _Credential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def _target(key_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", key_id):
        raise CredentialError("KEY_ID_INVALID")
    return f"AstriaCollector/HMAC/{key_id}"


def _api() -> Any:
    if sys.platform != "win32":
        raise CredentialError("WINDOWS_REQUIRED")
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_Credential)),
    ]
    api.CredReadW.restype = wintypes.BOOL
    api.CredWriteW.argtypes = [ctypes.POINTER(_Credential), wintypes.DWORD]
    api.CredWriteW.restype = wintypes.BOOL
    api.CredFree.argtypes = [ctypes.c_void_p]
    api.CredFree.restype = None
    api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    api.CredDeleteW.restype = wintypes.BOOL
    return api


def read_secret(key_id: str) -> bytes:
    target = _target(key_id)
    api = _api()
    pointer = ctypes.POINTER(_Credential)()
    if not api.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
        raise CredentialError("CREDENTIAL_UNAVAILABLE")
    try:
        credential = pointer.contents
        size = credential.CredentialBlobSize
        if not 32 <= size <= MAX_SECRET_BYTES:
            raise CredentialError("CREDENTIAL_INVALID")
        return ctypes.string_at(credential.CredentialBlob, size)
    finally:
        api.CredFree(pointer)


def store_secret(key_id: str, secret: bytes) -> None:
    """Provision/rotate an explicitly supplied secret without serializing it."""
    target = _target(key_id)
    if not 32 <= len(secret) <= MAX_SECRET_BYTES:
        raise CredentialError("SECRET_LENGTH_INVALID")
    api = _api()
    buffer = (ctypes.c_ubyte * len(secret)).from_buffer_copy(secret)
    credential = _Credential()
    credential.Type = CRED_TYPE_GENERIC
    credential.TargetName = target
    credential.CredentialBlobSize = len(secret)
    credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE
    credential.UserName = "AstriaCollector"
    try:
        if not api.CredWriteW(ctypes.byref(credential), 0):
            raise CredentialError("CREDENTIAL_WRITE_FAILED")
    finally:
        ctypes.memset(buffer, 0, len(buffer))


def delete_secret(key_id: str) -> None:
    """Delete only the explicitly identified Collector credential."""
    target = _target(key_id)
    api = _api()
    if not api.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        raise CredentialError("CREDENTIAL_DELETE_FAILED")
