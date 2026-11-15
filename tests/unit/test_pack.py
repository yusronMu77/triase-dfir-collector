"""Ciphertext-only artifact handling: adoption, hashing, manifest, links, cleanup, classification."""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import AGE, NOW, job_document

from astria_collector import pack
from astria_collector.models import Job, Manifest, Receipt
from astria_collector.pack import ArtifactError

MAX = 1024 * 1024


@pytest.fixture
def folders(tmp_path: Path) -> tuple[Path, Path]:
    job_dir = tmp_path / "work" / "SJ-2026-0001"
    job_dir.mkdir(parents=True)
    output = job_dir / "output"
    output.mkdir()
    return job_dir, output


def adopt(folders: tuple[Path, Path], name: str = "ACQ-1.zip.age", data: bytes = AGE) -> Path:
    job_dir, output = folders
    (output / name).write_bytes(data)
    return pack.adopt_archive(output, job_dir, MAX)


def manifest_of(job: Job, archive: Path) -> Manifest:
    return pack.build_manifest(
        job, archive, androidqf_sha256="a" * 64, adb_version="1.0.41", started_at=NOW, ended_at=NOW, exit_code=0
    )


def test_streaming_sha256_matches_hashlib(tmp_path: Path) -> None:
    big = tmp_path / "big.zip.age"
    payload = pack.AGE_HEADER + b"x" * (3 * 1024 * 1024 + 17)  # spans several 1 MiB blocks
    big.write_bytes(payload)
    assert pack.sha256_file(big) == hashlib.sha256(payload).hexdigest()


def test_adopt_moves_single_encrypted_archive(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    archive = adopt(folders)
    assert archive == job_dir / "ACQ-1.zip.age"
    assert archive.read_bytes() == AGE
    assert not output.exists()


@pytest.mark.parametrize("name", ["evil.zip", "notes.txt", "..zip.age", "a b.zip.age", "ACQ.ZIP.AGE", "x.zip.age.bak"])
def test_adopt_rejects_unexpected_names_and_leaves_them(folders: tuple[Path, Path], name: str) -> None:
    job_dir, output = folders
    (output / name).write_bytes(AGE)
    with pytest.raises(ArtifactError, match="UNEXPECTED_ARTIFACT"):
        pack.adopt_archive(output, job_dir, MAX)
    assert (output / name).exists()  # evidence is never silently deleted


def test_adopt_rejects_plaintext_pretending_to_be_age(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    (output / "ACQ.zip.age").write_bytes(b"PK\x03\x04 plaintext zip" * 20)
    with pytest.raises(ArtifactError, match="ARCHIVE_NOT_AGE"):
        pack.adopt_archive(output, job_dir, MAX)
    assert (output / "ACQ.zip.age").exists()
    assert not (job_dir / "ACQ.zip.age").exists()


def test_adopt_rejects_extra_plaintext_next_to_ciphertext(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    (output / "ACQ.zip.age").write_bytes(AGE)
    (output / "acquisition.json").write_text("{}")
    with pytest.raises(ArtifactError, match="UNEXPECTED_ARTIFACT"):
        pack.adopt_archive(output, job_dir, MAX)


def test_adopt_requires_exactly_one(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    with pytest.raises(ArtifactError, match="ARCHIVE_COUNT_INVALID"):
        pack.adopt_archive(output, job_dir, MAX)
    (output / "A.zip.age").write_bytes(AGE)
    (output / "B.zip.age").write_bytes(AGE)
    with pytest.raises(ArtifactError, match="ARCHIVE_COUNT_INVALID"):
        pack.adopt_archive(output, job_dir, MAX)


def test_adopt_enforces_size_bounds(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    (output / "A.zip.age").write_bytes(pack.AGE_HEADER)  # header only, no payload
    with pytest.raises(ArtifactError, match="ARCHIVE_SIZE_INVALID"):
        pack.adopt_archive(output, job_dir, MAX)
    (output / "A.zip.age").write_bytes(AGE)
    with pytest.raises(ArtifactError, match="ARCHIVE_SIZE_INVALID"):
        pack.adopt_archive(output, job_dir, len(AGE) - 1)


def test_adopt_rejects_subdirectory(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    (output / "nested.zip.age").mkdir()
    with pytest.raises(ArtifactError, match="UNEXPECTED_ARTIFACT"):
        pack.adopt_archive(output, job_dir, MAX)


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions")
def test_junction_in_output_is_rejected_and_target_untouched(folders: tuple[Path, Path], tmp_path: Path) -> None:
    job_dir, output = folders
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("sensitive")
    link = output / "ACQ.zip.age"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], check=True, capture_output=True)  # noqa: S603, S607
    with pytest.raises(ArtifactError, match="UNSAFE_PATH"):
        pack.adopt_archive(output, job_dir, MAX)
    assert (outside / "keep.txt").read_text() == "sensitive"


@pytest.mark.parametrize(
    "job_id",
    ["", ".", "..", "../x", "a/b", "a\\b", "C:evil", "a" * 65, "CON", "nul", "COM1", "LPT3", "a b", "a\x00b", "é"],
)
def test_job_directory_rejects_unsafe_ids(tmp_path: Path, job_id: str) -> None:
    with pytest.raises(ArtifactError, match="INVALID_JOB_ID"):
        pack.job_directory(tmp_path, job_id, create=True)
    assert list(tmp_path.iterdir()) == []


def test_job_directory_does_not_follow_a_replaced_root(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    pack.job_directory(root, "SJ-1", create=True)
    with pytest.raises(FileExistsError):
        pack.job_directory(root, "SJ-1", create=True)


def test_manifest_records_hash_size_and_unknown_status(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    job = Job.model_validate(job_document())
    archive = adopt(folders)
    manifest = manifest_of(job, archive)
    pack.write_manifest(job_dir, manifest)
    assert manifest.archive_sha256 == hashlib.sha256(AGE).hexdigest()
    assert manifest.archive_size == len(AGE)
    assert manifest.status == "pending_verification"  # module status is inside the ciphertext
    assert pack.read_manifest(job_dir) == manifest
    text = (job_dir / "manifest.json").read_text(encoding="utf-8")
    assert "serial_sha256" in text
    assert "SYNTHETIC0017K2A" not in text  # the full serial never reaches disk


def test_manifest_write_is_atomic_and_survives_stale_temp(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    job = Job.model_validate(job_document())
    manifest = manifest_of(job, adopt(folders))
    (job_dir / "manifest.json.tmp").write_text("garbage from an interrupted write")
    pack.write_manifest(job_dir, manifest)
    assert not (job_dir / "manifest.json.tmp").exists()
    assert pack.read_manifest(job_dir) == manifest


def test_verify_detects_modification_and_replacement(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    job = Job.model_validate(job_document())
    archive = adopt(folders)
    manifest = manifest_of(job, archive)
    assert pack.verify_archive(job_dir, manifest, MAX) == archive
    archive.write_bytes(AGE[:-1] + b"X")  # same size, different content
    with pytest.raises(ArtifactError, match="ARCHIVE_CHANGED"):
        pack.verify_archive(job_dir, manifest, MAX)


def test_classify_states(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    job = Job.model_validate(job_document())
    assert pack.classify(job_dir, MAX)[0] == "tidak_lengkap"  # nothing but an empty output folder
    archive = adopt(folders)
    assert pack.classify(job_dir, MAX)[0] == "tidak_lengkap"  # no manifest yet
    manifest = manifest_of(job, archive)
    pack.write_manifest(job_dir, manifest)
    assert pack.classify(job_dir, MAX)[0] == "siap_unggah"
    receipt = Receipt(
        acquisition_id="AQ-1",
        job_id=job.job_id,
        status="received",
        archive_sha256=manifest.archive_sha256,
        archive_size=manifest.archive_size,
        metadata_status="pending_verification",
    )
    pack.write_receipt(job_dir, receipt)
    assert pack.classify(job_dir, MAX)[0] == "diakui"
    # A receipt for another archive does not acknowledge this one.
    pack.write_receipt(job_dir, receipt.model_copy(update={"archive_sha256": "0" * 64}))
    assert pack.classify(job_dir, MAX)[0] == "siap_unggah"


def test_cleanup_only_after_verification_and_never_recurses(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    job = Job.model_validate(job_document())
    archive = adopt(folders)
    manifest = manifest_of(job, archive)
    pack.write_manifest(job_dir, manifest)
    (job_dir / "stray.bin").write_bytes(b"unexpected")
    with pytest.raises(ArtifactError, match="UNEXPECTED_ARTIFACT"):
        pack.cleanup_acknowledged(job_dir, manifest)
    assert archive.exists()  # an unexpected file stops cleanup and preserves evidence
    (job_dir / "stray.bin").unlink()
    pack.cleanup_acknowledged(job_dir, manifest)
    assert not job_dir.exists()


def test_cleanup_refuses_if_archive_no_longer_matches(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    job = Job.model_validate(job_document())
    archive = adopt(folders)
    manifest = manifest_of(job, archive)
    pack.write_manifest(job_dir, manifest)
    archive.write_bytes(AGE[:-1] + b"X")
    with pytest.raises(ArtifactError, match="ARCHIVE_CHANGED"):
        pack.cleanup_acknowledged(job_dir, manifest)
    assert archive.exists()


def test_discard_is_explicit_non_recursive(folders: tuple[Path, Path]) -> None:
    job_dir, output = folders
    (output / "partial.zip.age").write_bytes(AGE)
    (job_dir / "job.json").write_text("{}")
    pack.discard_directory(job_dir)
    assert not job_dir.exists()


def test_discard_refuses_unknown_nested_directories(folders: tuple[Path, Path]) -> None:
    job_dir, _ = folders
    nested = job_dir / "other"
    nested.mkdir()
    (nested / "x").write_text("x")
    with pytest.raises(ArtifactError, match="UNSAFE_CLEANUP"):
        pack.discard_directory(job_dir)
    assert (nested / "x").exists()


def test_list_work_ignores_unsafe_names(tmp_path: Path) -> None:
    root = tmp_path / "work"
    (root / "SJ-1").mkdir(parents=True)
    (root / "not valid!").mkdir()
    (root / "file.txt").write_text("x")
    assert pack.list_work(root) == ["SJ-1"]
    assert pack.list_work(tmp_path / "missing") == []
