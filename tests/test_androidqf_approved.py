"""The digest-pinned AndroidQF build (collector#2): approval, recipient file, and the acquisition call.

No test touches an Android device or the real binary; run_process and inspect_tool are replaced.
"""

from pathlib import Path

import pytest

from astria_collector import androidqf, tasks
from astria_collector.androidqf import AndroidQFError
from astria_collector.client import ClientError
from astria_collector.processes import ProcessResult

APPROVED_SHA, APPROVED = next(iter(androidqf.APPROVED_BUILDS.items()))
RECIPIENT = "age1" + "q" * 58
SCOPE = {
    "backup": "none",
    "download": "non-system",
    "remove_trusted": "yes",
    "intrusion_logs": "no",
    "hash_files": "no",
    "browser_history": "no",
    "magisk_modules": "no",
}


def approved_info(**overrides: object) -> androidqf.ToolInfo:
    values = {"version": APPROVED.version, "sha256": APPROVED_SHA, "flags": androidqf.REQUIRED_FLAGS} | overrides
    return androidqf.ToolInfo(**values)  # type: ignore[arg-type]


def test_pinned_build_is_well_formed() -> None:
    assert len(androidqf.APPROVED_BUILDS) == 1
    assert len(APPROVED_SHA) == 64 and APPROVED_SHA == APPROVED_SHA.lower()
    assert APPROVED_SHA != androidqf.WINDOWS_RELEASE_SHA256
    assert len(APPROVED.source_commit) == 40


def test_approved_build_passes_the_gate() -> None:
    assert androidqf.require_compatible(approved_info()) == APPROVED


def test_approved_version_string_is_parsed() -> None:
    info = androidqf.parse_probe(f"AndroidQF version: {APPROVED.version}\n", "", APPROVED_SHA)
    assert info.version == APPROVED.version


@pytest.mark.parametrize(
    "overrides,code",
    [
        ({"sha256": "0" * 64}, "TOOL_PROFILE_UNAPPROVED"),  # same version and flags, other binary
        ({"version": androidqf.RELEASE_VERSION}, "TOOL_PROFILE_UNAPPROVED"),  # digest/version pair must match
        ({"flags": frozenset({"-serial", "-output"})}, "TOOL_INCOMPATIBLE"),
        ({"version": "v1.8.3-96-gdeadbee"}, "TOOL_VERSION_UNSUPPORTED"),
    ],
)
def test_gate_rejects_anything_but_the_exact_build(overrides: dict[str, object], code: str) -> None:
    with pytest.raises(AndroidQFError, match=code):
        androidqf.require_compatible(approved_info(**overrides))


def test_recipient_is_written_exclusively(tmp_path: Path) -> None:
    path = androidqf.write_recipient(tmp_path, RECIPIENT)
    assert path == tmp_path.resolve() / "key.txt"
    assert path.read_text(encoding="ascii") == RECIPIENT + "\n"
    with pytest.raises(AndroidQFError, match="RECIPIENT_FILE_EXISTS"):
        androidqf.write_recipient(tmp_path, RECIPIENT)


@pytest.mark.parametrize(
    "bad", ["", "age1short", "AGE1" + "q" * 58, RECIPIENT + "\nage1" + "q" * 58, "AGE-SECRET-KEY-1X"]
)
def test_invalid_recipient_never_reaches_disk(tmp_path: Path, bad: str) -> None:
    with pytest.raises(AndroidQFError, match="RECIPIENT_INVALID"):
        androidqf.write_recipient(tmp_path, bad)
    assert not (tmp_path / "key.txt").exists()


def _fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, list[tuple[list[str], Path]]]:
    tools = tmp_path / "tools"
    tools.mkdir()
    exe = tools / "androidqf.exe"
    exe.write_bytes(b"fixture")
    work = tmp_path / "work" / "JOB1"
    (work / "output").mkdir(parents=True)
    calls: list[tuple[list[str], Path]] = []
    monkeypatch.setattr(androidqf, "inspect_tool", lambda *_a, **_k: approved_info())
    monkeypatch.setattr(androidqf, "verify_checksum", lambda *_a, **_k: APPROVED_SHA)

    def run(args: list[str], *, cwd: Path, **_kwargs: object) -> ProcessResult:
        calls.append((args, cwd))
        assert (cwd / "key.txt").read_text(encoding="ascii") == RECIPIENT + "\n"
        return ProcessResult(0, "", "", False, False, False)

    monkeypatch.setattr(androidqf, "run_process", run)
    return exe, work, calls


def test_acquisition_runs_in_the_job_folder_with_its_recipient(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, work, calls = _fake_tool(tmp_path, monkeypatch)
    result = androidqf.run_acquisition(exe, APPROVED_SHA, "USB123", work, SCOPE, RECIPIENT, timeout_s=5)
    assert result.exit_code == 0
    [(args, cwd)] = calls
    assert cwd == work
    assert args[1] == "-non-interactive"
    assert args[args.index("-output") + 1] == str((work / "output").absolute())
    assert "-key" not in args


def test_key_beside_the_tool_blocks_acquisition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, work, calls = _fake_tool(tmp_path, monkeypatch)
    (exe.parent / "key.txt").write_text(RECIPIENT + "\n", encoding="ascii")
    with pytest.raises(AndroidQFError, match="TOOL_DIRECTORY_HAS_KEY"):
        androidqf.run_acquisition(exe, APPROVED_SHA, "USB123", work, SCOPE, RECIPIENT, timeout_s=5)
    assert calls == []
    assert not (work / "key.txt").exists()


def test_unapproved_tool_writes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, work, calls = _fake_tool(tmp_path, monkeypatch)
    monkeypatch.setattr(androidqf, "inspect_tool", lambda *_a, **_k: approved_info(sha256="0" * 64))
    with pytest.raises(AndroidQFError, match="TOOL_PROFILE_UNAPPROVED"):
        androidqf.run_acquisition(exe, "0" * 64, "USB123", work, SCOPE, RECIPIENT, timeout_s=5)
    assert calls == []
    assert not (work / "key.txt").exists()


@pytest.mark.parametrize("error", [ClientError("NETWORK_UNAVAILABLE"), OSError("down"), ValueError("bad")])
def test_recipient_failure_stops_before_the_tool(error: Exception, monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[object] = []
    monkeypatch.setattr(androidqf, "run_acquisition", lambda *a, **k: called.append(a))

    def boom() -> str:
        raise error

    acquire = tasks.production_acquirer(object(), boom)  # type: ignore[arg-type]
    with pytest.raises(AndroidQFError, match="RECIPIENT_UNAVAILABLE"):
        acquire(object())  # type: ignore[arg-type]
    assert called == []
