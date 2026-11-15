"""Handle ciphertext only. Never extract or infer module success from an exit code."""

import hashlib
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Literal

from .models import Job, Manifest, Receipt

AGE_HEADER = b"age-encryption.org/v1\n"


class ArtifactError(ValueError):
    pass


def reject_links(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink() or component.is_junction():
            raise ArtifactError("UNSAFE_PATH")


def job_directory(root: Path, job_id: str, *, create: bool = False) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", job_id):
        raise ArtifactError("INVALID_JOB_ID")
    if job_id.upper().split(".")[0] in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(10)),
        *(f"LPT{i}" for i in range(10)),
    }:
        raise ArtifactError("INVALID_JOB_ID")
    path = root.absolute() / job_id
    reject_links(path)
    if create:
        path.mkdir(parents=True, exist_ok=False)
    elif not path.is_dir():
        raise ArtifactError("WORK_NOT_FOUND")
    return path


def sha256_file(path: Path) -> str:
    reject_links(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ArtifactError("NOT_REGULAR_FILE")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def find_archive(directory: Path, max_bytes: int) -> Path:
    reject_links(directory)
    archives: list[Path] = []
    for path in directory.iterdir():
        reject_links(path)
        if path.name in {"key.txt", "manifest.json", "receipt.json", "job.json"}:
            if not path.is_file():
                raise ArtifactError("UNEXPECTED_ARTIFACT")
            continue
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}\.zip\.age", path.name) or not path.is_file():
            raise ArtifactError("UNEXPECTED_ARTIFACT")
        archives.append(path)
    if len(archives) != 1:
        raise ArtifactError("ARCHIVE_COUNT_INVALID")
    path = archives[0]
    if not len(AGE_HEADER) < path.stat().st_size <= max_bytes:
        raise ArtifactError("ARCHIVE_SIZE_INVALID")
    with path.open("rb") as stream:
        if stream.read(len(AGE_HEADER)) != AGE_HEADER:
            raise ArtifactError("ARCHIVE_NOT_AGE")
    # A header only identifies the container; Ingest must authenticate/decrypt it.
    return path


def atomic_text(path: Path, text: str) -> None:
    reject_links(path)
    temporary = path.with_name(path.name + ".tmp")
    reject_links(temporary)
    temporary.unlink(missing_ok=True)  # a stale temporary is our own interrupted write
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def read_manifest(directory: Path) -> Manifest:
    path = directory / "manifest.json"
    reject_links(path)
    if path.stat().st_size > 64 * 1024:
        raise ArtifactError("MANIFEST_TOO_LARGE")
    return Manifest.model_validate_json(path.read_bytes())


def verify_archive(directory: Path, manifest: Manifest, max_bytes: int) -> Path:
    path = find_archive(directory, max_bytes)
    if path.name != manifest.archive_name or path.stat().st_size != manifest.archive_size:
        raise ArtifactError("ARCHIVE_CHANGED")
    if sha256_file(path) != manifest.archive_sha256:
        raise ArtifactError("ARCHIVE_CHANGED")
    return path


def cleanup_acknowledged(directory: Path, manifest: Manifest) -> None:
    # Never recurse. Unexpected files and reparse points stop cleanup, preserving evidence.
    verify_archive(directory, manifest, manifest.archive_size)
    paths = list(directory.iterdir())
    for path in paths:
        reject_links(path)
        if not path.is_file():
            raise ArtifactError("UNSAFE_CLEANUP")
    for path in paths:
        path.unlink()
    directory.rmdir()


ARCHIVE_NAME = re.compile(r"[A-Za-z0-9_-]{1,100}\.zip\.age")
WorkState = Literal["siap_unggah", "diakui", "tidak_lengkap"]


def _check_age_file(path: Path, max_bytes: int) -> None:
    if not path.is_file() or not len(AGE_HEADER) < path.stat().st_size <= max_bytes:
        raise ArtifactError("ARCHIVE_SIZE_INVALID")
    with path.open("rb") as stream:
        if stream.read(len(AGE_HEADER)) != AGE_HEADER:
            raise ArtifactError("ARCHIVE_NOT_AGE")


def adopt_archive(output_dir: Path, job_dir: Path, max_bytes: int) -> Path:
    """Move the single encrypted archive from the tool's output folder into the job folder.

    Anything else in the output folder (a plaintext archive, a stray file, a link) fails the job and is
    left in place: evidence is never deleted silently, and the operator must discard it explicitly.
    """
    reject_links(output_dir)
    reject_links(job_dir)
    entries = list(output_dir.iterdir())
    if not entries:
        raise ArtifactError("ARCHIVE_COUNT_INVALID")
    for entry in entries:
        reject_links(entry)
        if not entry.is_file() or not ARCHIVE_NAME.fullmatch(entry.name):
            raise ArtifactError("UNEXPECTED_ARTIFACT")
    if len(entries) != 1:
        raise ArtifactError("ARCHIVE_COUNT_INVALID")
    source = entries[0]
    _check_age_file(source, max_bytes)
    target = job_dir / source.name
    if target.exists():
        raise ArtifactError("ARCHIVE_EXISTS")
    source.replace(target)
    output_dir.rmdir()
    return target


def build_manifest(
    job: Job,
    archive: Path,
    *,
    androidqf_sha256: str,
    adb_version: str,
    started_at: datetime,
    ended_at: datetime,
    exit_code: int,
) -> Manifest:
    """Hash the ciphertext in a stream. Module status is unknown until the server decrypts it."""
    return Manifest(
        job=job,
        archive_name=archive.name,
        archive_sha256=sha256_file(archive),
        archive_size=archive.stat().st_size,
        androidqf_sha256=androidqf_sha256,
        adb_version=adb_version,
        started_at=started_at,
        ended_at=ended_at,
        process_exit_code=exit_code,
    )


def write_manifest(directory: Path, manifest: Manifest) -> None:
    atomic_text(directory / "manifest.json", manifest.model_dump_json(indent=2) + "\n")


def write_receipt(directory: Path, receipt: Receipt) -> None:
    atomic_text(directory / "receipt.json", receipt.model_dump_json(indent=2) + "\n")


def read_receipt(directory: Path) -> Receipt:
    path = directory / "receipt.json"
    reject_links(path)
    if path.stat().st_size > 64 * 1024:
        raise ArtifactError("RECEIPT_TOO_LARGE")
    return Receipt.model_validate_json(path.read_bytes())


def write_job(directory: Path, job: Job) -> None:
    atomic_text(directory / "job.json", job.model_dump_json(indent=2) + "\n")


def classify(directory: Path, max_bytes: int) -> tuple[WorkState, Manifest | None]:
    """Decide what a job folder left by an earlier run may safely become."""
    try:
        manifest = read_manifest(directory)
        verify_archive(directory, manifest, max_bytes)
    except OSError, ValueError:
        return "tidak_lengkap", None
    try:
        receipt = read_receipt(directory)
    except OSError, ValueError:
        return "siap_unggah", manifest
    # A receipt that does not match the manifest is not an acknowledgement of this archive.
    if (
        receipt.job_id == manifest.job.job_id
        and receipt.archive_sha256 == manifest.archive_sha256
        and receipt.archive_size == manifest.archive_size
    ):
        return "diakui", manifest
    return "siap_unggah", manifest


def list_work(root: Path) -> list[str]:
    """Job folder names under the work root; unsafe names are ignored, never followed."""
    if not root.is_dir():
        return []
    names: list[str] = []
    for entry in sorted(root.iterdir()):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", entry.name) and entry.is_dir() and not entry.is_junction():
            names.append(entry.name)
    return names


def discard_directory(directory: Path) -> None:
    """Explicit operator discard. Files only, one level of `output`, no links, no recursion."""
    reject_links(directory)
    for entry in list(directory.iterdir()):
        reject_links(entry)
        if entry.is_dir():
            if entry.name != "output":
                raise ArtifactError("UNSAFE_CLEANUP")
            for inner in list(entry.iterdir()):
                reject_links(inner)
                if not inner.is_file():
                    raise ArtifactError("UNSAFE_CLEANUP")
                inner.unlink()
            entry.rmdir()
        elif entry.is_file():
            entry.unlink()
        else:
            raise ArtifactError("UNSAFE_CLEANUP")
    directory.rmdir()
