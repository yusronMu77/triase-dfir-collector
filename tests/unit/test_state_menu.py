"""State machine invariants, operator confirmation and the Indonesian console screens."""

import threading
from datetime import timedelta

import pytest
from conftest import NOW, FakeUplink, job_document, make_runner, scripted
from hypothesis import given
from hypothesis import strategies as st

from astria_collector import menu
from astria_collector.client import ClientError
from astria_collector.models import Job
from astria_collector.tasks import (
    TERMINAL,
    TRANSITIONS,
    Confirmation,
    InvalidTransition,
    JobRun,
    Outcome,
    State,
    UnconfirmedJob,
    confirm_job,
)


def test_every_state_has_a_defined_row_and_terminals_are_final() -> None:
    assert set(TRANSITIONS) == set(State)
    for state in TERMINAL:
        assert TRANSITIONS[state] == frozenset()


def test_upload_is_unreachable_without_acquisition_and_packaging() -> None:
    reachable = {State.MENUNGGU}
    frontier = [State.MENUNGGU]
    while frontier:
        for nxt in TRANSITIONS[frontier.pop()]:
            if nxt not in reachable:
                reachable.add(nxt)
                frontier.append(nxt)
    # Only MENGEMAS leads to MENGUNGGAH, and only MENGAMBIL leads to MENGEMAS.
    assert [s for s, to in TRANSITIONS.items() if State.MENGUNGGAH in to] == [State.MENGEMAS]
    assert [s for s, to in TRANSITIONS.items() if State.MENGEMAS in to] == [State.MENGAMBIL]
    assert [s for s, to in TRANSITIONS.items() if State.MENGAMBIL in to] == [State.PERANGKAT_COCOK]
    assert [s for s, to in TRANSITIONS.items() if State.PERANGKAT_COCOK in to] == [State.MENUNGGU_PERANGKAT]
    assert reachable == set(State)


def test_forbidden_transition_raises() -> None:
    run = JobRun()
    with pytest.raises(InvalidTransition):
        run.to(State.MENGAMBIL)
    run.to(State.DIBATALKAN)
    with pytest.raises(InvalidTransition):
        run.to(State.DIKONFIRMASI)


@given(st.lists(st.sampled_from(list(State)), max_size=30))
def test_random_walks_never_break_invariants(moves: list[State]) -> None:
    run = JobRun()
    visited = [run.state]
    for move in moves:
        try:
            run.to(move)
        except InvalidTransition:
            assert move not in TRANSITIONS[run.state]
        else:
            visited.append(move)
    if State.MENGUNGGAH in visited:
        order = [
            visited.index(s)
            for s in (
                State.DIKONFIRMASI,
                State.MENUNGGU_PERANGKAT,
                State.PERANGKAT_COCOK,
                State.MENGAMBIL,
                State.MENGEMAS,
                State.MENGUNGGAH,
            )
        ]
        assert order == sorted(order)
    terminal_positions = [i for i, s in enumerate(visited) if s in TERMINAL]
    assert len(terminal_positions) <= 1
    if terminal_positions:
        assert terminal_positions[0] == len(visited) - 1


def test_confirmation_requires_exact_job_id(job: Job) -> None:
    assert isinstance(confirm_job(job, job.job_id), Confirmation)
    assert confirm_job(job, job.job_id + "\r\n") is not None  # only the line terminator is ignored
    for typed in [
        "",
        " ",
        job.job_id.lower(),
        job.job_id.upper() + "x",
        f" {job.job_id}",
        f"{job.job_id} ",
        job.job_id[:-1],
        "SJ-2026-0002",
        "yes",
        "y",
    ]:
        assert confirm_job(job, typed) is None, typed


@given(st.text(max_size=80))
def test_confirmation_property_only_exact_match(job_id_attempt: str) -> None:
    job = Job.model_validate(job_document())
    assert (confirm_job(job, job_id_attempt) is not None) == (job_id_attempt.rstrip("\r\n") == job.job_id)


def test_forged_or_foreign_confirmation_is_refused(settings, job: Job) -> None:
    runner = make_runner(settings, FakeUplink())
    forged = Confirmation(job.job_id, object())
    with pytest.raises(UnconfirmedJob):
        runner.execute(job, forged)
    other = Job.model_validate(job_document(job_id="SJ-2026-0002"))
    real = confirm_job(other, other.job_id)
    assert real is not None
    with pytest.raises(UnconfirmedJob):
        runner.execute(job, real)  # confirmation for a different job cannot start this one
    assert not settings.work_dir.exists() or not list(settings.work_dir.iterdir())


def lines_of(job: Job) -> str:
    return "\n".join(menu.render_job(job, NOW))


def test_job_screen_shows_identity_consent_scope_limits_expiry(job: Job) -> None:
    text = lines_of(job)
    for needle in [
        job.job_id,
        job.consent_id,
        job.owner_ref,
        job.purpose,
        job.device.label,
        "7K2A",
        job.limitations,
        "Cakupan",
        "Kedaluwarsa",
        "sisa 120 menit",
    ]:
        assert needle in text
    assert "SYNTHETIC0017K2A" not in text  # only the serial tail is shown


def test_wrong_confirmation_cancels_without_running(settings, job: Job) -> None:
    runner = make_runner(settings, FakeUplink())
    said: list[str] = []
    outcome = menu.run_job(runner, job, lambda _p: "sj-2026-0001", said.append, threading.Event())
    assert outcome is None
    assert any("ID tidak cocok" in line for line in said)
    assert not any("USB debugging" in line for line in said)  # never reaches the phone instructions


def test_usb_instructions_appear_only_after_confirmation(settings, job: Job) -> None:
    uplink = FakeUplink()
    runner = make_runner(settings, uplink)
    said: list[str] = []
    menu.run_job(runner, job, lambda _p: job.job_id, said.append, threading.Event())
    text = "\n".join(said)
    assert "USB debugging" in text
    assert "Opsi pengembang" in text


def test_unsupported_scope_is_refused_before_asking_for_confirmation(settings) -> None:
    wide = dict(job_document()["scope_flags"], backup="all")  # type: ignore[call-overload]
    job = Job.model_validate(job_document(scope_flags=wide))
    asked: list[str] = []

    def ask(prompt: str) -> str:
        asked.append(prompt)
        return job.job_id

    said: list[str] = []
    assert menu.run_job(make_runner(settings, FakeUplink()), job, ask, said.append, threading.Event()) is None
    assert asked == []
    assert any("belum didukung" in line for line in said)


@pytest.mark.parametrize(
    ("outcome", "needle"),
    [
        (Outcome(State.SELESAI, "ACKNOWLEDGED"), "SELESAI"),
        (Outcome(State.GAGAL, "TOOL_INCOMPATIBLE"), "tidak punya mode tanpa interaksi"),
        (Outcome(State.GAGAL, "SERIAL_MISMATCH", retained=False), "bukan HP yang disetujui"),
        (Outcome(State.KEDALUWARSA, "DEVICE_TIMEOUT"), "KEDALUWARSA"),
        (Outcome(State.DIBATALKAN, "CANCELLED"), "DIBATALKAN"),
        (Outcome(State.GAGAL, "NETWORK_UNAVAILABLE", retained=True), "Berkas terenkripsi disimpan"),
    ],
)
def test_result_screens(outcome: Outcome, needle: str) -> None:
    assert needle in "\n".join(menu.describe(outcome))


def test_success_screen_does_not_claim_module_completeness() -> None:
    text = "\n".join(menu.describe(Outcome(State.SELESAI, "ACKNOWLEDGED")))
    assert "ditentukan server" in text
    assert "tidak membaca isi arsip" in text


def test_unknown_codes_are_shown_as_codes_not_free_text() -> None:
    assert menu.reason("WEIRD_CODE") == "Kode galat: WEIRD_CODE"


def test_main_menu_flow(settings, job: Job) -> None:
    runner = make_runner(settings, FakeUplink())

    said: list[str] = []
    menu.main_menu(runner, lambda: job, scripted("1", job.job_id, "0"), said.append, threading.Event())
    assert any("SELESAI" in line for line in said)


def test_main_menu_handles_server_errors_and_no_job(settings, job: Job) -> None:
    runner = make_runner(settings, FakeUplink())
    said: list[str] = []

    def failing() -> Job | None:
        raise ClientError("AUTH_OR_CLOCK_INVALID")

    menu.main_menu(runner, failing, scripted("1", "0"), said.append, threading.Event())
    assert any("jam komputer" in line for line in said)
    said.clear()
    menu.main_menu(runner, lambda: None, scripted("1", "9", "0"), said.append, threading.Event())
    assert "Tidak ada tugas." in said
    assert "Pilihan tidak dikenal." in said


def test_main_menu_ignores_invalid_jobs(settings) -> None:
    runner = make_runner(settings, FakeUplink())
    said: list[str] = []

    def invalid() -> Job | None:
        raise ValueError("JOB_EXPIRED")

    menu.main_menu(runner, invalid, scripted("1", "0"), said.append, threading.Event())
    assert any("tidak sah" in line for line in said)


def test_expired_job_is_remaining_time_zero(job: Job) -> None:
    text = "\n".join(menu.render_job(job, job.expires_at + timedelta(hours=1)))
    assert "sisa 0 menit" in text
