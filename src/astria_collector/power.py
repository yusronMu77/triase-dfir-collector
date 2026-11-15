"""Thread-scoped Windows sleep inhibition; never changes the user's power plan."""

import ctypes
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


class PowerError(RuntimeError):
    pass


def _set_execution_state(flags: int) -> int:
    if sys.platform != "win32":
        raise PowerError("WINDOWS_REQUIRED")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.SetThreadExecutionState
    function.argtypes = [ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    return int(function(flags))


@contextmanager
def prevent_sleep(*, setter: Callable[[int], int] | None = None) -> Iterator[None]:
    """Restore this thread's previous execution requirements, including on failure."""
    set_state = setter or _set_execution_state
    previous = set_state(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    if not previous:
        raise PowerError("POWER_REQUEST_FAILED")
    try:
        yield
    finally:
        if not set_state(previous | ES_CONTINUOUS):
            raise PowerError("POWER_RESTORE_FAILED")
