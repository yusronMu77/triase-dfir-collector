"""Bounded HMAC transport. Each retry signs fresh time and reopens the ciphertext."""

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import httpx
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from .config import Settings
from .models import Job, Manifest, Receipt, ServerConfig
from .pack import sha256_file

T = TypeVar("T")
EMPTY_BODY = hashlib.sha256(b"").hexdigest()


class ClientError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RetryableError(ClientError):
    pass


def sign(secret: bytes, method: str, path_query: str, timestamp: str, key_id: str, body_sha256: str) -> str:
    canonical = "\n".join([method.upper(), path_query, timestamp, key_id, body_sha256])
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


class IngestClient:
    def __init__(
        self,
        settings: Settings,
        secret: bytes,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if len(secret) < 32:
            raise ClientError("SECRET_TOO_SHORT")
        self.settings = settings
        self._secret = secret
        self._sleep = sleep
        self.http = httpx.Client(
            base_url=settings.ingest_base_url,
            transport=transport,
            timeout=settings.request_timeout_s,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self.http.close()

    def _headers(self, method: str, path: str, digest: str, trace_id: str | None) -> dict[str, str]:
        stamp = str(int(time.time()))
        headers = {
            "X-Astria-Key-Id": self.settings.collector_key_id,
            "X-Astria-Timestamp": stamp,
            "X-Astria-Signature": sign(self._secret, method, path, stamp, self.settings.collector_key_id, digest),
        }
        if trace_id:
            headers["X-Trace-Id"] = trace_id
            headers["traceparent"] = f"00-{trace_id}-0000000000000001-01"
        return headers

    def _retry(self, action: Callable[[], T]) -> T:
        try:
            return Retrying(
                stop=stop_after_attempt(self.settings.upload_retries),
                wait=wait_exponential(multiplier=1, max=15),
                sleep=self._sleep,
                retry=retry_if_exception_type((httpx.TransportError, RetryableError)),
                reraise=True,
            )(action)
        except httpx.TransportError as exc:
            raise ClientError("NETWORK_UNAVAILABLE") from exc

    @staticmethod
    def _check(response: httpx.Response, expected: tuple[int, ...]) -> None:
        if response.status_code in {408, 429, 500, 502, 503, 504}:
            raise RetryableError("SERVER_UNAVAILABLE")
        if response.status_code not in expected:
            # Response text may include evidence or secrets. Never surface it to logs.
            raise ClientError(
                {401: "AUTH_OR_CLOCK_INVALID", 403: "CONSENT_DENIED", 409: "JOB_CONFLICT", 410: "JOB_EXPIRED"}.get(
                    response.status_code, "SERVER_REJECTED"
                )
            )
        if len(response.content) > 64 * 1024:
            raise ClientError("RESPONSE_TOO_LARGE")

    def next_job(self) -> Job | None:
        path = "/svc/v1/collector/jobs/next"

        def action() -> Job | None:
            response = self.http.get(path, headers=self._headers("GET", path, EMPTY_BODY, None))
            self._check(response, (200, 204))
            if response.status_code == 204:
                return None
            job = Job.model_validate_json(response.content)
            job.check_expiry()
            return job

        return self._retry(action)

    def config(self) -> ServerConfig:
        path = "/svc/v1/collector/config"

        def action() -> ServerConfig:
            response = self.http.get(path, headers=self._headers("GET", path, EMPTY_BODY, None))
            self._check(response, (200,))
            config = ServerConfig.model_validate_json(response.content)
            if hashlib.sha256(config.age_recipient.encode()).hexdigest() != config.age_recipient_sha256:
                raise ClientError("RECIPIENT_HASH_MISMATCH")
            return config

        return self._retry(action)

    def progress(self, job: Job, stage: str, code: str | None = None) -> None:
        path = f"/svc/v1/collector/jobs/{job.job_id}/progress"
        body = json.dumps({"stage": stage, **({"code": code} if code else {})}, separators=(",", ":")).encode()

        def action() -> None:
            headers = self._headers("POST", path, hashlib.sha256(body).hexdigest(), job.trace_id)
            headers["Content-Type"] = "application/json"
            response = self.http.post(path, content=body, headers=headers)
            self._check(response, (204,))

        self._retry(action)

    def upload(self, archive: Path, manifest: Manifest) -> Receipt:
        path = f"/svc/v1/collector/acquisitions/{manifest.job.job_id}"

        def action() -> Receipt:
            if archive.stat().st_size != manifest.archive_size or sha256_file(archive) != manifest.archive_sha256:
                raise ClientError("ARCHIVE_CHANGED")
            headers = self._headers("PUT", path, manifest.archive_sha256, manifest.job.trace_id)
            headers.update(
                {
                    "X-Archive-Sha256": manifest.archive_sha256,
                    "Content-Length": str(manifest.archive_size),
                    "Content-Type": "application/octet-stream",
                }
            )
            with archive.open("rb") as stream:
                response = self.http.put(
                    path,
                    headers=headers,
                    content=iter(lambda: stream.read(1024 * 1024), b""),
                    timeout=self.settings.upload_timeout_s,
                )
            self._check(response, (201,))
            receipt = Receipt.model_validate_json(response.content)
            if (
                receipt.job_id != manifest.job.job_id
                or receipt.archive_sha256 != manifest.archive_sha256
                or receipt.archive_size != manifest.archive_size
            ):
                raise ClientError("ACK_MISMATCH")
            return receipt

        return self._retry(action)
