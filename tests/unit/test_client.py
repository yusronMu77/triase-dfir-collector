"""HMAC signing vectors and the transport rules: retries, streaming, safe error mapping."""

import hashlib
import json
import time
from pathlib import Path

import httpx
import pytest
from conftest import AGE, JOB_ID, KEY_ID, SECRET, job_json
from pydantic import ValidationError

from astria_collector.client import EMPTY_BODY, ClientError, IngestClient, sign
from astria_collector.config import Settings
from astria_collector.models import Job, Manifest

# Computed independently of production code (see the test plan); fixed here as known vectors.
VECTORS = [
    (
        "GET",
        "/svc/v1/collector/jobs/next",
        EMPTY_BODY,
        "c3d819ac67fcb989345873ccebacdfcf2f212ea035354bc2decc3e10e64b1e80",
    ),
    (
        "POST",
        f"/svc/v1/collector/jobs/{JOB_ID}/progress",
        hashlib.sha256(b'{"stage":"mengambil"}').hexdigest(),
        "efc545339660ec353799cbb2998c09953e0c0ce02c6967d393ddfa789073b656",
    ),
    (
        "PUT",
        f"/svc/v1/collector/acquisitions/{JOB_ID}",
        "a2bc460d1eb4d2b16e0d8b6557f9e31829ed49477cda761be0ff0f3de265518d",
        "5b09586d278a34f02ba19327b653fafbb4fdb84d3f8921fc5b3033a1cf87ec90",
    ),
]


@pytest.mark.parametrize(("method", "path", "body_hash", "expected"), VECTORS)
def test_hmac_known_vectors(method: str, path: str, body_hash: str, expected: str) -> None:
    assert sign(SECRET, method, path, "1700000000", KEY_ID, body_hash) == expected


def test_hmac_binds_every_field() -> None:
    reference = sign(SECRET, "GET", "/p", "1", "k", EMPTY_BODY)
    assert reference != sign(SECRET, "PUT", "/p", "1", "k", EMPTY_BODY)
    assert reference != sign(SECRET, "GET", "/q", "1", "k", EMPTY_BODY)
    assert reference != sign(SECRET, "GET", "/p", "2", "k", EMPTY_BODY)
    assert reference != sign(SECRET, "GET", "/p", "1", "j", EMPTY_BODY)
    assert reference != sign(SECRET, "GET", "/p", "1", "k", hashlib.sha256(b"x").hexdigest())
    assert reference != sign(bytes(range(1, 33)), "GET", "/p", "1", "k", EMPTY_BODY)
    assert reference == sign(SECRET, "get", "/p", "1", "k", EMPTY_BODY)  # method is canonicalised


def test_short_secret_refused(settings: Settings) -> None:
    with pytest.raises(ClientError, match="SECRET_TOO_SHORT"):
        IngestClient(settings, b"short")


def test_requests_are_signed_and_timestamped(client_factory) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    client_factory(handler).next_job()
    request = seen[0]
    stamp = request.headers["x-astria-timestamp"]
    assert abs(time.time() - int(stamp)) < 5
    assert request.headers["x-astria-key-id"] == KEY_ID
    assert request.headers["x-astria-signature"] == sign(
        SECRET, "GET", "/svc/v1/collector/jobs/next", stamp, KEY_ID, EMPTY_BODY
    )


def test_next_job_returns_none_on_204_and_job_on_200(client_factory) -> None:
    assert client_factory(lambda _r: httpx.Response(204)).next_job() is None
    # A far-future expiry keeps this independent of the wall clock.
    far = "2999-01-01T00:00:00+00:00"
    got = client_factory(lambda _r: httpx.Response(200, content=job_json(expires_at=far))).next_job()
    assert isinstance(got, Job)
    assert got.job_id == JOB_ID


def test_expired_job_from_server_is_not_returned(client_factory) -> None:
    past = "2000-01-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="JOB_EXPIRED"):
        client_factory(lambda _r: httpx.Response(200, content=job_json(expires_at=past))).next_job()


def test_malformed_job_rejected(client_factory) -> None:
    with pytest.raises(ValidationError):
        client_factory(lambda _r: httpx.Response(200, content=b'{"job_id": "x"}')).next_job()


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "AUTH_OR_CLOCK_INVALID"),
        (403, "CONSENT_DENIED"),
        (409, "JOB_CONFLICT"),
        (410, "JOB_EXPIRED"),
        (404, "SERVER_REJECTED"),
        (422, "SERVER_REJECTED"),
    ],
)
def test_rejections_map_to_safe_codes_without_server_text(client_factory, status: int, code: str) -> None:
    server_text = "internal path C:\\secret and token abc"

    def handler(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=server_text)

    with pytest.raises(ClientError) as raised:
        client_factory(handler).next_job()
    assert raised.value.code == code
    assert server_text not in str(raised.value)


def test_transient_errors_retry_with_bounded_attempts(client_factory) -> None:
    calls = []

    def handler(_r: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503)

    with pytest.raises(ClientError, match="SERVER_UNAVAILABLE"):
        client_factory(handler).next_job()
    assert len(calls) == 3  # upload_retries in the fixture


def test_network_interruption_is_retried_then_reported(client_factory) -> None:
    calls = []

    def handler(_r: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("boom")

    with pytest.raises(ClientError, match="NETWORK_UNAVAILABLE"):
        client_factory(handler).next_job()
    assert len(calls) == 3


def test_recovers_after_transient_failure(client_factory) -> None:
    answers = iter([httpx.Response(502), httpx.Response(204)])
    assert client_factory(lambda _r: next(answers)).next_job() is None


def test_progress_body_is_signed(client_factory, job: Job) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    client_factory(handler).progress(job, "gagal", "SERIAL_MISMATCH")
    request = seen[0]
    body = request.content
    assert json.loads(body) == {"stage": "gagal", "code": "SERIAL_MISMATCH"}
    assert request.headers["x-astria-signature"] == sign(
        SECRET,
        "POST",
        request.url.path,
        request.headers["x-astria-timestamp"],
        KEY_ID,
        hashlib.sha256(body).hexdigest(),
    )
    assert request.headers["x-trace-id"] == job.trace_id


def manifest_for(job: Job, archive: Path) -> Manifest:
    from astria_collector import pack

    return pack.build_manifest(
        job,
        archive,
        androidqf_sha256="a" * 64,
        adb_version="1.0.41",
        started_at=job.expires_at,
        ended_at=job.expires_at,
        exit_code=0,
    )


def receipt_body(manifest: Manifest, **overrides: object) -> bytes:
    body = {
        "acquisition_id": "AQ-1",
        "job_id": manifest.job.job_id,
        "status": "received",
        "archive_sha256": manifest.archive_sha256,
        "archive_size": manifest.archive_size,
        "metadata_status": "pending_verification",
    }
    body.update(overrides)
    return json.dumps(body).encode()


def test_upload_streams_with_hash_length_and_signature(client_factory, job: Job, tmp_path: Path) -> None:
    archive = tmp_path / "ACQ.zip.age"
    archive.write_bytes(AGE)
    manifest = manifest_for(job, archive)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.read() == AGE
        return httpx.Response(201, content=receipt_body(manifest))

    receipt = client_factory(handler).upload(archive, manifest)
    request = seen[0]
    assert receipt.archive_sha256 == manifest.archive_sha256
    assert request.headers["x-archive-sha256"] == manifest.archive_sha256
    assert request.headers["content-length"] == str(len(AGE))
    assert "transfer-encoding" not in request.headers
    assert request.headers["x-astria-signature"] == sign(
        SECRET, "PUT", request.url.path, request.headers["x-astria-timestamp"], KEY_ID, manifest.archive_sha256
    )


def test_upload_retries_resend_whole_archive_with_fresh_signature(client_factory, job: Job, tmp_path: Path) -> None:
    archive = tmp_path / "ACQ.zip.age"
    archive.write_bytes(AGE)
    manifest = manifest_for(job, archive)
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.read())
        if len(bodies) < 3:
            return httpx.Response(503)
        return httpx.Response(201, content=receipt_body(manifest))

    client_factory(handler).upload(archive, manifest)
    assert bodies == [AGE, AGE, AGE]


def test_upload_refuses_archive_changed_since_hashing(client_factory, job: Job, tmp_path: Path) -> None:
    archive = tmp_path / "ACQ.zip.age"
    archive.write_bytes(AGE)
    manifest = manifest_for(job, archive)
    archive.write_bytes(AGE + b"tamper")
    sent: list[int] = []
    with pytest.raises(ClientError, match="ARCHIVE_CHANGED"):
        client_factory(lambda r: sent.append(1) or httpx.Response(201)).upload(archive, manifest)
    assert sent == []


@pytest.mark.parametrize("override", [{"job_id": "SJ-other"}, {"archive_sha256": "0" * 64}, {"archive_size": 1}])
def test_upload_rejects_mismatched_acknowledgement(client_factory, job: Job, tmp_path: Path, override) -> None:
    archive = tmp_path / "ACQ.zip.age"
    archive.write_bytes(AGE)
    manifest = manifest_for(job, archive)
    with pytest.raises(ClientError, match="ACK_MISMATCH"):
        client_factory(lambda _r: httpx.Response(201, content=receipt_body(manifest, **override))).upload(
            archive, manifest
        )


def test_config_recipient_hash_is_verified(client_factory) -> None:
    recipient = "age1" + "q" * 58
    good = {
        "age_recipient": recipient,
        "age_recipient_sha256": hashlib.sha256(recipient.encode()).hexdigest(),
        "androidqf_version": "1.8.3",
    }
    assert client_factory(lambda _r: httpx.Response(200, json=good)).config().age_recipient == recipient
    bad = dict(good, age_recipient_sha256="0" * 64)
    with pytest.raises(ClientError, match="RECIPIENT_HASH_MISMATCH"):
        client_factory(lambda _r: httpx.Response(200, json=bad)).config()


def test_redirects_and_environment_proxies_are_not_followed(settings: Settings) -> None:
    client = IngestClient(settings, SECRET, transport=httpx.MockTransport(lambda _r: httpx.Response(204)))
    try:
        assert client.http.follow_redirects is False
        assert client.http.trust_env is False
    finally:
        client.close()
