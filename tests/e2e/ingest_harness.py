"""Runs the real Ingest app (uvicorn + PostgreSQL) for the live Collector test.

Run it inside Ingest's own environment, never Collector's:

    uv run --project ..\\ingest python tests\\e2e\\ingest_harness.py

Needs ASTRIA_TEST_DATABASE_URL (a disposable PostgreSQL) and ASTRIA_HARNESS_READY (a file path). Writes
one JSON document to that file when ready, serves until stdin closes, then drops its schema.
The HMAC key and signing key are synthetic and live in a temp folder.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import uvicorn
from astria_common.auth import JwksSource, ServiceTokenVerifier, issue_service_token, load_or_create_signing_key
from astria_common.db import Database
from astria_ingest.main import build_app
from astria_ingest.settings import Settings
from pydantic import SecretStr
from sqlalchemy import text

KEY_ID = "collector-1"
KEY = bytes(range(32))
# The physical-device run (scripts in the collector note) overrides both; tests use the synthetic values.
SERIAL = os.environ.get("ASTRIA_HARNESS_SERIAL", "SYNTHETIC0017K2A")
AUTHORIZER = "harness-authorizer"


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    db_url = os.environ["ASTRIA_TEST_DATABASE_URL"]
    port = free_port()
    schema = "collector_e2e_" + uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        key_file = tmp / "hmac-key"
        key_file.write_text(KEY.hex(), encoding="ascii")
        key_file.chmod(0o600)
        signing = load_or_create_signing_key(tmp / "identity.pem")
        verifier = ServiceTokenVerifier(
            JwksSource("http://unused.invalid", fetch=lambda: {"keys": [signing.public_jwk()]})
        )
        recipient = os.environ.get("ASTRIA_HARNESS_RECIPIENT", "age1" + "q" * 58)
        settings = Settings(
            env="test",
            database_url=SecretStr(db_url),
            db_schema=schema,
            collector_enabled=True,
            collector_keys={KEY_ID: key_file},
            collector_age_recipient=recipient,
            collector_archive_root=tmp / "archives",
            device_scan_users=[AUTHORIZER],
        )
        server = uvicorn.Server(
            uvicorn.Config(
                build_app(settings, token_verifier=verifier), host="127.0.0.1", port=port, log_level="warning"
            )
        )

        def serve() -> None:
            with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
                runner.run(server.serve())

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 30
        while True:
            try:
                if httpx.get(base + "/ready", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                print("ingest did not become ready", file=sys.stderr)
                return 1
            time.sleep(0.2)

        token, _ = issue_service_token(
            signing, subject="svc:api", audience="svc:ingest", act={"sub": AUTHORIZER, "roles": ["dfir"]}
        )
        ready = Path(os.environ["ASTRIA_HARNESS_READY"])
        ready.with_suffix(".tmp").write_text(
            json.dumps(
                {
                    "url": base,
                    "key_id": KEY_ID,
                    "key_hex": KEY.hex(),
                    "serial": SERIAL,
                    "serial_sha256": hashlib.sha256(SERIAL.encode()).hexdigest(),
                    "manager_token": token,
                    "recipient": recipient,
                    "archive_root": str(tmp / "archives"),
                    "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
                }
            ),
            encoding="utf-8",
        )
        ready.with_suffix(".tmp").replace(ready)  # appears atomically
        sys.stdin.read()  # the test closes stdin to stop the server
        server.should_exit = True
        thread.join(timeout=15)

        async def cleanup() -> None:
            db = Database(SecretStr(db_url))
            await db.start()
            await db.wait_ready(10)
            async with db.engine.begin() as conn:
                await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            await db.stop()

        with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
            runner.run(cleanup())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
