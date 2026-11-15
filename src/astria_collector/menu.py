"""Operator console in Indonesian. Input and output are injected so every screen is testable.

Nothing here starts an acquisition except through `confirm_job`, which needs the exact job ID.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime

from .client import ClientError
from .models import Job
from .tasks import Confirmation, Outcome, Runner, State, confirm_job, unsupported_scope

Ask = Callable[[str], str]
Say = Callable[[str], None]

SCOPE_LABELS = {
    "backup": "Cadangan (backup) aplikasi",
    "download": "Unduh APK",
    "remove_trusted": "Hapus sertifikat tepercaya dari daftar",
    "intrusion_logs": "Log intrusi",
    "hash_files": "Hash berkas",
    "browser_history": "Riwayat peramban",
    "magisk_modules": "Modul Magisk",
}
VALUE_LABELS = {"none": "tidak", "no": "tidak", "yes": "ya", "all": "semua", "non-system": "bukan aplikasi sistem"}

USB_STEPS = (
    "Aktifkan USB debugging di HP:",
    "  1. Pengaturan > Tentang ponsel > ketuk 'Nomor versi' 7 kali untuk membuka Opsi pengembang.",
    "  2. Pengaturan > Opsi pengembang > aktifkan 'USB debugging'.",
    "  3. Sambungkan HP ke komputer dengan kabel USB (bukan nirkabel).",
    "  4. Di HP, setujui 'Izinkan debugging USB dari komputer ini'.",
    "  5. Biarkan layar HP menyala dan terbuka sampai pemindaian selesai.",
)

DEVICE_STATUS = {
    "DEVICE_NOT_FOUND": "Belum ada HP terdeteksi. Periksa kabel dan USB debugging.",
    "DEVICE_OFFLINE": "HP terdeteksi tetapi offline. Cabut dan sambungkan ulang kabel.",
    "DEVICE_UNAUTHORIZED": "HP belum menyetujui komputer ini. Setujui dialog di layar HP.",
    "DEVICE_NO_PERMISSIONS": "Windows belum punya izin ke HP. Pasang driver USB dari pabrikan HP.",
}

# Fixed messages keyed by machine code. Text from subprocesses or servers is never displayed.
REASONS = {
    "JOB_EXPIRED": "Tugas sudah kedaluwarsa. Minta tugas baru dari pengelola.",
    "SCOPE_UNSUPPORTED": "Cakupan tugas ini belum didukung Collector. Tidak ada yang dijalankan.",
    "DEVICE_TIMEOUT": "Batas waktu menunggu HP habis. Tugas boleh dijalankan ulang selama belum kedaluwarsa.",
    "SERIAL_MISMATCH": "HP yang tersambung bukan HP yang disetujui untuk tugas ini. Pemindaian ditolak.",
    "MULTIPLE_DEVICES": "Lebih dari satu perangkat tersambung. Cabut yang lain.",
    "USB_DEVICE_REQUIRED": "Hanya HP yang tersambung lewat kabel USB yang diizinkan.",
    "CANCELLED": "Dihentikan oleh operator.",
    "TASK_TIMEOUT": "Batas waktu tugas habis; AndroidQF dihentikan.",
    "ACQUISITION_FAILED": "AndroidQF berakhir dengan galat.",
    "TOOL_INCOMPATIBLE": (
        "AndroidQF yang terpasang (v1.8.3) tidak punya mode tanpa interaksi dan kontrol cakupan yang "
        "disyaratkan. Pemindaian ditolak demi keamanan. Lihat docs/androidqf-compatibility.md."
    ),
    "TOOL_PROFILE_UNAPPROVED": "Versi AndroidQF ini belum disetujui untuk pengambilan data.",
    "TOOL_CHECKSUM_MISMATCH": "SHA-256 alat tidak cocok dengan konfigurasi. Alat tidak dijalankan.",
    "TOOL_VERSION_UNSUPPORTED": "Versi AndroidQF tidak didukung.",
    "NETWORK_UNAVAILABLE": "Ingest tidak terjangkau. Arsip terenkripsi disimpan; unggah ulang dari menu.",
    "SERVER_UNAVAILABLE": "Ingest sedang tidak tersedia. Arsip terenkripsi disimpan; unggah ulang dari menu.",
    "AUTH_OR_CLOCK_INVALID": "Tanda tangan ditolak. Periksa kunci dan jam komputer (selisih maksimal 5 menit).",
    "CONSENT_DENIED": "Server menolak: persetujuan tidak berlaku.",
    "JOB_CONFLICT": "Server menolak: arsip lain sudah tercatat untuk tugas ini.",
    "WORK_EXISTS": "Folder kerja tugas ini sudah ada. Coba unggah ulang atau buang lewat menu arsip tertahan.",
    "NOT_RETRYABLE": "Folder ini tidak memuat arsip yang utuh. Buang secara eksplisit bila tidak diperlukan.",
}


def reason(code: str | None) -> str:
    return REASONS.get(code or "", f"Kode galat: {code}" if code else "Tidak diketahui.")


def _scope_lines(job: Job) -> list[str]:
    values = job.scope_flags.model_dump()
    return [f"  - {SCOPE_LABELS[key]}: {VALUE_LABELS.get(value, value)}" for key, value in values.items()]


def render_job(job: Job, now: datetime | None = None) -> list[str]:
    remaining = job.expires_at - (now or datetime.now(UTC))
    minutes = max(0, int(remaining.total_seconds() // 60))
    return [
        "=" * 60,
        f"ID tugas        : {job.job_id}",
        f"Rujukan setuju  : {job.consent_id}",
        f"Pemilik (rujuk) : {job.owner_ref}",
        f"Tujuan          : {job.purpose}",
        f"HP              : {job.device.label} (serial berakhiran {job.device.serial_tail})",
        "Cakupan:",
        *_scope_lines(job),
        f"Batas (tidak diambil): {job.limitations}",
        f"Kedaluwarsa     : {job.expires_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC (sisa {minutes} menit)",
        "=" * 60,
    ]


def ask_confirmation(job: Job, ask: Ask, say: Say) -> Confirmation | None:
    """The operator must type the exact job ID. Anything else cancels; there is no default."""
    typed = ask(f"Ketik ID tugas persis ({job.job_id}) untuk melanjutkan, atau kosongkan untuk batal: ")
    confirmation = confirm_job(job, typed)
    if confirmation is None:
        say("ID tidak cocok. Tugas dibatalkan; tidak ada yang dijalankan.")
    return confirmation


def describe(outcome: Outcome) -> list[str]:
    if outcome.state is State.SELESAI:
        lines = [
            "SELESAI: arsip terenkripsi sudah diterima Ingest.",
            "Status modul (lengkap/sebagian) ditentukan server setelah arsip didekripsi; "
            "Collector tidak membaca isi arsip.",
        ]
        if outcome.code == "CLEANUP_INCOMPLETE":
            lines.append("Peringatan: sebagian berkas lokal belum terhapus; periksa menu arsip tertahan.")
        return lines
    title = {State.KEDALUWARSA: "KEDALUWARSA", State.DIBATALKAN: "DIBATALKAN"}.get(outcome.state, "GAGAL")
    lines = [f"{title}: {reason(outcome.code)}"]
    if outcome.retained:
        lines.append(
            "Berkas terenkripsi disimpan di folder kerja. Pilih 'Arsip tertahan' untuk unggah ulang atau buang."
        )
    return lines


def run_job(
    runner: Runner,
    job: Job,
    ask: Ask,
    say: Say,
    cancel: threading.Event,
    busy: threading.Event | None = None,
) -> Outcome | None:
    for line in render_job(job):
        say(line)
    if unsupported_scope(job) is not None:
        say(f"GAGAL: {reason('SCOPE_UNSUPPORTED')}")
        return None
    if (blocked := runner.preflight_error()) is not None:
        # Do not ask the operator to plug in a phone when the tool will refuse to run anyway.
        say(f"GAGAL: {reason(blocked)}")
        say("Tugas tidak dilaporkan gagal ke server; tetap tersedia setelah alat diperbaiki.")
        return None
    confirmation = ask_confirmation(job, ask, say)
    if confirmation is None:
        return None
    for line in USB_STEPS:
        say(line)
    say("Tekan Ctrl+C sekali untuk menghentikan dengan aman (AndroidQF dihentikan dan dilaporkan gagal).")
    if busy is not None:
        busy.set()  # Ctrl+C now cancels the running job instead of leaving the program
    try:
        outcome = runner.execute(job, confirmation, cancel)
    finally:
        if busy is not None:
            busy.clear()
    for line in describe(outcome):
        say(line)
    return outcome


def retained_menu(runner: Runner, ask: Ask, say: Say) -> None:
    items = runner.retained()
    if not items:
        say("Tidak ada arsip tertahan.")
        return
    labels = {
        "siap_unggah": "arsip utuh, belum diakui server",
        "diakui": "sudah diakui server, tinggal bersihkan",
        "tidak_lengkap": "tidak lengkap",
    }
    for index, (name, work_state) in enumerate(items, 1):
        say(f"{index}. {name}: {labels[work_state]}")
    choice = ask("Nomor yang diproses (kosong untuk kembali): ").strip()
    if not choice.isdecimal() or not 1 <= int(choice) <= len(items):
        return
    name, work_state = items[int(choice) - 1]
    action = ask("[u] unggah ulang, [b] buang permanen, kosong = kembali: ").strip().lower()
    if action == "u":
        for line in describe(runner.retry_upload(name)):
            say(line)
    elif action == "b":
        if ask(f"Buang permanen {name}? Ketik ID tugas persis untuk menghapus: ") == name:
            runner.discard(name)
            say("Folder dibuang.")
        else:
            say("ID tidak cocok. Tidak ada yang dihapus.")


def main_menu(
    runner: Runner,
    fetch_job: Callable[[], Job | None],
    ask: Ask,
    say: Say,
    cancel: threading.Event,
    *,
    check_tools: Callable[[], list[str]] | None = None,
    busy: threading.Event | None = None,
) -> None:
    say("Astria Collector. Tidak ada pemindaian tanpa tugas berpersetujuan dan konfirmasi Anda.")
    while True:
        say("")
        say("1. Ambil tugas berikutnya")
        say("2. Arsip tertahan (unggah ulang atau buang)")
        say("3. Periksa alat (AndroidQF dan adb)")
        say("0. Keluar")
        choice = ask("Pilih: ").strip()
        if choice == "0":
            return
        if choice == "1":
            try:
                job = fetch_job()
            except ClientError as error:
                say(f"Gagal mengambil tugas: {reason(error.code)}")
                continue
            except ValueError:
                say("Tugas dari server tidak sah (format atau kedaluwarsa); diabaikan.")
                continue
            if job is None:
                say("Tidak ada tugas.")
                continue
            run_job(runner, job, ask, say, cancel, busy)
            cancel.clear()
        elif choice == "2":
            retained_menu(runner, ask, say)
        elif choice == "3" and check_tools is not None:
            for line in check_tools():
                say(line)
        else:
            say("Pilihan tidak dikenal.")
