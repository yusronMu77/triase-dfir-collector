"""Hypothesis properties: hostile input fails with a safe code, never escapes, never crashes."""

import json
import tempfile
from pathlib import Path

import pytest
from conftest import AGE, job_document
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from astria_collector import androidqf, pack
from astria_collector.androidqf import AndroidQFError, build_args, parse_probe
from astria_collector.device import DeviceError, match_device, parse_devices, serial_sha256
from astria_collector.models import Job, Manifest, Receipt, ServerConfig

SLOW = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=12), inner, max_size=5),
    max_leaves=15,
)


@given(json_values)
def test_malformed_wire_documents_only_raise_validation_errors(document) -> None:
    for model in (Job, Manifest, Receipt, ServerConfig):
        with pytest.raises(ValidationError):
            model.model_validate(document)


@given(st.binary(max_size=2048))
def test_arbitrary_bytes_never_crash_the_parsers(raw: bytes) -> None:
    for model in (Job, Receipt, ServerConfig):
        try:
            model.model_validate_json(raw)
        except ValidationError:
            pass


@given(st.dictionaries(st.sampled_from(sorted(job_document())), json_values, max_size=6))
def test_mutated_jobs_are_rejected_unless_they_stay_valid(overrides: dict) -> None:
    candidate = {**job_document(), **overrides}
    try:
        job = Job.model_validate(candidate)
    except ValidationError:
        return
    # If accepted, every identifier is a safe path component and time carries an offset.
    assert job.job_id.isascii()
    assert "/" not in job.job_id
    assert "\\" not in job.job_id
    assert ".." not in job.job_id
    assert job.expires_at.tzinfo is not None
    assert len(job.trace_id) == 32


@given(st.text(max_size=300))
def test_job_ids_only_accepted_when_safe_for_a_single_path_component(job_id: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        try:
            created = pack.job_directory(root, job_id, create=True)
        except pack.ArtifactError, FileExistsError:
            assert list(root.iterdir()) == []
            return
        assert created.parent == root.absolute()
        assert created.name == job_id


@given(st.text(max_size=200))
def test_adb_output_is_parsed_or_refused_with_known_codes(output: str) -> None:
    try:
        devices = parse_devices(output)
    except DeviceError as error:
        assert error.code in {"ADB_OUTPUT_INVALID", "ADB_OUTPUT_TOO_LARGE"}
        return
    assert len({d.serial for d in devices}) == len(devices)
    for device in devices:
        assert len(device.serial) <= 256
        assert device.serial not in repr(device)


@given(
    st.lists(st.text(alphabet="ABCDEF0123456789", min_size=1, max_size=20), min_size=0, max_size=4, unique=True),
    st.text(alphabet="ABCDEF0123456789", min_size=1, max_size=20),
)
def test_device_matching_never_accepts_a_different_serial(serials: list[str], expected: str) -> None:
    from astria_collector.device import Device

    devices = [Device(s, "device") for s in serials]
    try:
        chosen = match_device(devices, serial_sha256(expected))
    except DeviceError:
        return
    assert chosen.serial == expected
    assert len(devices) == 1


@given(
    st.text(max_size=400),
    st.text(max_size=400),
)
def test_probe_parsing_only_raises_androidqf_errors(version: str, helptext: str) -> None:
    try:
        info = parse_probe(version, helptext, "0" * 64)
    except AndroidQFError as error:
        assert error.code == "TOOL_VERSION_UNSUPPORTED"
    else:
        assert info.version == androidqf.RELEASE_VERSION


@given(st.text(max_size=300))
def test_command_construction_refuses_unsafe_serials(serial: str) -> None:
    scope = dict(job_document()["scope_flags"])  # type: ignore[call-overload]
    try:
        args = build_args(Path("C:/tools/androidqf.exe"), serial, Path("C:/work/out"), scope)
    except AndroidQFError as error:
        assert error.code == "DEVICE_SERIAL_INVALID"
        return
    # Accepted serials are a single argv element made only of safe characters: no shell syntax can ride along.
    assert args[args.index("-serial") + 1] == serial
    assert all(ch.isalnum() or ch in "._-" for ch in serial)


@given(st.dictionaries(st.sampled_from(sorted(androidqf.SCOPE_FLAGS)), st.text(max_size=12), max_size=8))
def test_scope_must_be_exactly_the_authorised_keys_and_values(scope: dict[str, str]) -> None:
    try:
        args = build_args(Path("C:/t/androidqf.exe"), "ABC123", Path("C:/w"), scope)
    except AndroidQFError as error:
        assert error.code == "SCOPE_INVALID"
        return
    assert set(scope) == set(androidqf.SCOPE_FLAGS)
    for key, flag in androidqf.SCOPE_FLAGS.items():
        assert args[args.index(flag) + 1] == scope[key]
        assert scope[key] in androidqf.SCOPE_VALUES[key]


@SLOW
@given(st.lists(st.text(max_size=30), min_size=1, max_size=4))
def test_adoption_never_places_anything_outside_the_job_folder(names: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        job_dir = Path(tmp) / "SJ-1"
        output = job_dir / "output"
        output.mkdir(parents=True)
        created = []
        for name in names:
            try:
                (output / name).write_bytes(AGE)
            except OSError, ValueError:
                continue
            created.append(name)
        try:
            archive = pack.adopt_archive(output, job_dir, 1024 * 1024)
        except pack.ArtifactError, OSError:
            assert not any(p.name == "ACQ.zip.age" and p.parent != output for p in Path(tmp).rglob("*"))
            return
        assert archive.parent == job_dir
        assert pack.ARCHIVE_NAME.fullmatch(archive.name)
        assert {p for p in Path(tmp).rglob("*") if p.is_file()} == {archive}


@SLOW
@given(st.binary(min_size=0, max_size=64))
def test_only_real_age_headers_are_adopted(prefix: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        job_dir = Path(tmp) / "SJ-1"
        output = job_dir / "output"
        output.mkdir(parents=True)
        (output / "A.zip.age").write_bytes(prefix + b"payload" * 8)
        try:
            pack.adopt_archive(output, job_dir, 1024 * 1024)
        except pack.ArtifactError:
            assert (output / "A.zip.age").exists()
        else:
            assert (job_dir / "A.zip.age").read_bytes().startswith(pack.AGE_HEADER)


def test_json_manifest_roundtrip_is_stable() -> None:
    job = Job.model_validate(job_document())
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp) / "SJ-1"
        output = directory / "output"
        output.mkdir(parents=True)
        (output / "A.zip.age").write_bytes(AGE)
        archive = pack.adopt_archive(output, directory, 1024 * 1024)
        from conftest import NOW

        manifest = pack.build_manifest(
            job, archive, androidqf_sha256="a" * 64, adb_version="1", started_at=NOW, ended_at=NOW, exit_code=0
        )
        pack.write_manifest(directory, manifest)
        assert Manifest.model_validate(json.loads((directory / "manifest.json").read_text())) == manifest
