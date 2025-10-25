"""Structured logging helpers for ReconScript."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

DEFAULT_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
DEFAULT_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

SENSITIVE_HEADERS = {"cookie", "set-cookie", "authorization", "proxy-authorization"}


class JsonFormatter(logging.Formatter):
    """Emit logs as structured JSON objects."""

    def format(
        self, record: logging.LogRecord
    ) -> str:  # pragma: no cover - straightforward structure
        payload = {
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


class SensitiveDataFilter(logging.Filter):
    """Redact sensitive header values in structured arguments."""

    def filter(
        self, record: logging.LogRecord
    ) -> bool:  # pragma: no cover - deterministic behaviour
        if isinstance(record.args, dict):
            sanitized = {}
            for key, value in record.args.items():
                if isinstance(key, str) and key.lower() in SENSITIVE_HEADERS:
                    sanitized[key] = "[redacted]"
                else:
                    sanitized[key] = value
            record.args = sanitized
        return True


def _rich_handler(level: int) -> logging.Handler:
    try:  # pragma: no cover - optional dependency handling
        from rich.logging import RichHandler

        handler = RichHandler(
            rich_tracebacks=True,
            markup=True,
            show_path=False,
            level=level,
        )
        return handler
    except Exception:  # pragma: no cover - fallback to stdlib handler
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        return stream_handler


def configure_logging(
    level: int = logging.INFO,
    *,
    json_logs: bool = False,
    logfile: Optional[Path | str] = None,
    suppress: Optional[Iterable[str]] = None,
) -> None:
    """Configure root logging with rotation and optional JSON output."""

    handlers: list[logging.Handler] = []

    console_handler = _rich_handler(level)
    console_handler.addFilter(SensitiveDataFilter())
    handlers.append(console_handler)

    if logfile:
        path = Path(logfile)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            path,
            maxBytes=DEFAULT_MAX_BYTES,
            backupCount=DEFAULT_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.addFilter(SensitiveDataFilter())
        if json_logs:
            file_handler.setFormatter(JsonFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
            )
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers, force=True)

    for name in suppress or ("werkzeug", "urllib3", "PIL"):
        logging.getLogger(name).setLevel(max(level, logging.WARNING))
