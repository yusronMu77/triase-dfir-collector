"""Entry point: operator menu plus explicit maintenance commands. No listener, no unattended mode."""

from __future__ import annotations

import argparse
import getpass
import signal
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from types import FrameType

import structlog
from pydantic import ValidationError

from . import __version__, androidqf, logs, menu
from .client import ClientError, IngestClient
from .config import Settings, load_settings, local_root
from .device import DeviceError, adb_version
from .secrets import CredentialError, read_secret, store_secret
from .tasks import Runner, production_acquirer, production_preflight, production_waiter

EXIT_OK, EXIT_FAILED, EXIT_CONFIG = 0, 1, 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="astria-collector", description="Astria Collector (A11)")
    root.add_argument("--version", action="version", version=f"astria-collector {__version__}")
    root.add_argument("--config", type=Path, default=local_root() / "config.toml", help="path ke config.toml")
    commands = root.add_subparsers(dest="command")
    commands.add_parser("menu", help="konsol operator (bawaan)")
    commands.add_parser("check", help="periksa konfigurasi, alat, dan kunci tanpa menyentuh HP")
    commands.add_parser("list", help="daftar folder kerja yang tertahan")
    retry = commands.add_parser("retry", help="unggah ulang arsip terenkripsi yang tertahan")
    retry.add_argument("job_id")
    discard = commands.add_parser("discard", help="buang folder kerja secara eksplisit")
    discard.add_argument("job_id")
    secret = commands.add_parser("secret-set", help="simpan kunci HMAC ke Windows Credential Manager")
    secret.add_argument("--key-id", required=True)
    return root


def startup_error(error: Exception) -> int:
    """Field names only: configuration values and secrets are never echoed."""
    if isinstance(error, ValidationError):
        names = ", ".join(sorted({".".join(str(part) for part in item["loc"]).upper() for item in error.errors()}))
        print(f"Konfigurasi tidak sah. Periksa kunci berikut di config.toml: {names}", file=sys.stderr)
    elif isinstance(error, FileNotFoundError):
        print("Berkas konfigurasi tidak ditemukan. Salin config.example.toml ke path yang dipakai.", file=sys.stderr)
    else:
        print(f"Konfigurasi tidak dapat dibaca ({type(error).__name__}).", file=sys.stderr)
    return EXIT_CONFIG


def check_report(settings: Settings) -> tuple[list[str], bool]:
    """Human lines plus an overall verdict. Any failed or refused check makes the verdict False."""
    lines: list[str] = []
    ok = True
    try:
        info = androidqf.inspect_tool(settings.androidqf_path, settings.androidqf_sha256, settings.work_dir.parent)
        lines.append(f"AndroidQF: v{info.version}, SHA-256 cocok ({info.sha256[:12]}...)")
        try:
            androidqf.require_compatible(info)
        except androidqf.AndroidQFError as error:
            ok = False
            lines.append(f"AndroidQF belum boleh dipakai mengambil data: {menu.reason(error.code)}")
    except androidqf.AndroidQFError as error:
        ok = False
        lines.append(f"AndroidQF GAGAL diperiksa: {menu.reason(error.code)} ({error.code})")
    except OSError, ValueError:
        ok = False
        lines.append("AndroidQF GAGAL diperiksa: berkas tidak ditemukan atau tidak dapat dibaca.")
    try:
        androidqf.verify_checksum(settings.adb_path, settings.adb_sha256)
        lines.append(f"adb: {adb_version(settings.adb_path)}, SHA-256 cocok")
    except (androidqf.AndroidQFError, DeviceError) as error:
        ok = False
        lines.append(f"adb GAGAL diperiksa: {error.code}")
    except OSError, ValueError:
        ok = False
        lines.append("adb GAGAL diperiksa: berkas tidak ditemukan atau tidak dapat dibaca.")
    try:
        read_secret(settings.collector_key_id)
        lines.append("Kunci HMAC: ada di Credential Manager")
    except CredentialError as error:
        ok = False
        lines.append(f"Kunci HMAC: {error} (jalankan 'astria-collector secret-set --key-id <ID>')")
    return lines, ok


def check_tools(settings: Settings) -> list[str]:
    return check_report(settings)[0]


def build_runner(settings: Settings, client: IngestClient, say) -> Runner:
    return Runner(
        settings,
        client,
        acquire=production_acquirer(settings),
        wait=production_waiter(settings),
        preflight=production_preflight(settings),
        on_status=lambda code: say(menu.DEVICE_STATUS.get(code, code)),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    command = args.command or "menu"

    if command == "secret-set":
        # Hex on input matches how Ingest mounts the same key; the raw bytes are stored once.
        try:
            raw = bytes.fromhex(getpass.getpass("Kunci HMAC (hex, minimal 64 karakter, tidak ditampilkan): ").strip())
            store_secret(args.key_id, raw)
        except (ValueError, CredentialError) as error:
            print(
                f"Gagal menyimpan kunci: {error if isinstance(error, CredentialError) else 'format hex tidak sah'}",
                file=sys.stderr,
            )
            return EXIT_FAILED
        print("Kunci tersimpan di Credential Manager.")
        return EXIT_OK

    try:
        settings = load_settings(args.config)
    except (ValidationError, OSError, ValueError) as error:
        return startup_error(error)
    logs.configure(settings.log_dir)
    structlog.get_logger("collector").info("startup", stage="start", code="OK")

    if command == "check":
        lines, ok = check_report(settings)
        for line in lines:
            print(line)
        return EXIT_OK if ok else EXIT_FAILED

    try:
        secret = read_secret(settings.collector_key_id)
    except CredentialError as error:
        print(
            f"Kunci HMAC tidak tersedia ({error}). Jalankan: astria-collector secret-set --key-id "
            f"{settings.collector_key_id}",
            file=sys.stderr,
        )
        return EXIT_CONFIG
    client = IngestClient(settings, secret)
    runner = build_runner(settings, client, print)
    cancel, busy = threading.Event(), threading.Event()

    def on_interrupt(_signum: int, _frame: FrameType | None) -> None:
        if busy.is_set():
            cancel.set()  # controlled: stops AndroidQF, reports gagal
            print("\nMenghentikan dengan aman...")
        else:
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_interrupt)
    try:
        if command == "list":
            items = runner.retained()
            for name, state in items:
                print(f"{name}\t{state}")
            if not items:
                print("Tidak ada arsip tertahan.")
            return EXIT_OK
        if command == "retry":
            outcome = runner.retry_upload(args.job_id)
            for line in menu.describe(outcome):
                print(line)
            return EXIT_OK if outcome.ok else EXIT_FAILED
        if command == "discard":
            if input(f"Ketik ID tugas persis untuk membuang {args.job_id} secara permanen: ") != args.job_id:
                print("ID tidak cocok. Tidak ada yang dihapus.")
                return EXIT_FAILED
            runner.discard(args.job_id)
            print("Folder dibuang.")
            return EXIT_OK

        menu.main_menu(
            runner, client.next_job, input, print, cancel, check_tools=lambda: check_tools(settings), busy=busy
        )
        return EXIT_OK
    except KeyboardInterrupt:
        print("\nKeluar.")
        return EXIT_FAILED
    except (ClientError, ValueError) as error:
        print(f"Galat: {getattr(error, 'code', type(error).__name__)}", file=sys.stderr)
        return EXIT_FAILED
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
