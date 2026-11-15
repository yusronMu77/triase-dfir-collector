"""Allowlisted JSON events; untrusted subprocess/HTTP text never enters logs."""

import logging
from collections.abc import MutableMapping
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any

import structlog

ALLOWED = {"event", "job_id", "trace_id", "stage", "code", "level", "timestamp"}


def redact(_logger: Any, _method: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    return {key: value for key, value in event.items() if key in ALLOWED}


def configure(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    handler = TimedRotatingFileHandler(
        directory / "collector.jsonl", when="midnight", backupCount=30, encoding="utf-8", utc=True
    )
    logging.basicConfig(handlers=[handler], level=logging.INFO, format="%(message)s", force=True)
    structlog.configure(
        processors=[
            redact,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
