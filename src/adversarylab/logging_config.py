"""Structured logging configuration.

The default formatter is human-readable for the CLI; ``json=True`` emits one JSON object
per line, which is what the evidence pipeline ingests.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

_CONFIGURED = False


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key.startswith("lab_"):
                payload[key[4:]] = value
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", path: str | Path | None = None, json: bool = False) -> None:
    global _CONFIGURED
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler: logging.Handler
    if path is not None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(path, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if json else logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s | %(message)s"
    ))
    root.handlers.clear()
    root.addHandler(handler)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
