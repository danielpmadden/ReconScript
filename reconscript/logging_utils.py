"""Structured logging helpers for ReconScript."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
DEFAULT_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))
LOG_BUFFER_SIZE = int(os.environ.get("LOG_BUFFER_SIZE", "200"))

SENSITIVE_HEADERS = {"cookie", "set-cookie", "authorization", "proxy-authorization"}

_LOG_BUFFER: deque[dict[str, str]] = deque(maxlen=LOG_BUFFER_SIZE)
_BUFFER_LOCK = threading.Lock()


class JsonFormatter(logging.Formatter):
    """Emit logs as structured JSON objects."""

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - straightforward structure
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

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - deterministic behaviour
        if isinstance(record.args, dict):
            sanitized = {}
            for key, value in record.args.items():
                if isinstance(key, str) and key.lower() in SENSITIVE_HEADERS:
                    sanitized[key] = "[redacted]"
                else:
                    sanitized[key] = value
            record.args = sanitized
        return True


class HostnameRedactionFilter(logging.Filter):
    """Redact hostnames/IP addresses when anonymisation is enabled."""

    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, anonymize: bool) -> None:
        super().__init__(name="hostname-redactor")
        self.anonymize = anonymize

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - deterministic
        if not self.anonymize:
            return True
        if isinstance(record.msg, str):
            record.msg = self.IP_PATTERN.sub("[redacted-ip]", record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(self.IP_PATTERN.sub("[redacted-ip]", str(arg)) for arg in record.args)
        elif isinstance(record.args, dict):
            record.args = {
                key: self.IP_PATTERN.sub("[redacted-ip]", str(value)) for key, value in record.args.items()
            }
        return True


class _BufferingHandler(logging.Handler):
    """Capture log messages for UI streaming."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - simple buffering
        message = self.format(record)
        entry = {
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        with _BUFFER_LOCK:
            _LOG_BUFFER.append(entry)


def get_recent_logs(*, limit: int = 50) -> list[dict[str, str]]:
    limit = max(1, min(limit, LOG_BUFFER_SIZE))
    with _BUFFER_LOCK:
        return list(_LOG_BUFFER)[-limit:]


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
    anonymize = os.environ.get("ANONYMIZE_LOGS", "false").lower() == "true"

    console_handler = _rich_handler(level)
    console_handler.addFilter(SensitiveDataFilter())
    console_handler.addFilter(HostnameRedactionFilter(anonymize))
    handlers.append(console_handler)

    buffer_handler = _BufferingHandler()
    buffer_handler.addFilter(SensitiveDataFilter())
    buffer_handler.addFilter(HostnameRedactionFilter(anonymize))
    handlers.append(buffer_handler)

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
        file_handler.addFilter(HostnameRedactionFilter(anonymize))
        if json_logs:
            file_handler.setFormatter(JsonFormatter())
        else:
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers, force=True)

    for name in suppress or ("werkzeug", "urllib3", "PIL"):
        logging.getLogger(name).setLevel(max(level, logging.WARNING))


__all__ = [
    "configure_logging",
    "JsonFormatter",
    "SensitiveDataFilter",
    "HostnameRedactionFilter",
    "get_recent_logs",
]


