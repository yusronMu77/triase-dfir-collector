"""AndroidQF exit 1 is accepted only for 'finalized with N incomplete module(s)' (collector#2, 2026-11-15)."""

import pytest

from astria_collector.androidqf import incomplete_modules
from astria_collector.processes import ProcessResult

LINE = "Acquisition finalized with 3 incomplete module(s). Review acquisition.json and command.log for details."


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ProcessResult(1, "", "", tail="INFO x\n" + LINE + "\n"), 3),
        (ProcessResult(1, "", "", tail="\x1b[31m" + LINE + "\x1b[0m"), 3),
        (ProcessResult(2, "", "", tail=LINE), None),  # only exit code 1
        (ProcessResult(1, "", "", timed_out=True, tail=LINE), None),
        (ProcessResult(1, "", "", cancelled=True, tail=LINE), None),
        (ProcessResult(1, "", "", tail="Impossible to initialize ADB: x"), None),
        (ProcessResult(1, LINE, "", tail="FATAL Failed to finalize acquisition archive"), None),  # head is not trusted
        (ProcessResult(1, "", "", tail=LINE + "\n" + "later\n" * 5), None),  # must be among the last lines
    ],
)
def test_incomplete_modules(result: ProcessResult, expected: int | None) -> None:
    assert incomplete_modules(result) == expected
