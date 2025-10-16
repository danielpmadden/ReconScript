"""Shared logging helpers providing Rich-formatted output."""

from __future__ import annotations

import logging
from typing import Iterable, Optional

try:  # pragma: no cover - optional dependency fallback
    from rich.logging import RichHandler
except ModuleNotFoundError:  # pragma: no cover - degrade gracefully when Rich missing
    class RichHandler(logging.StreamHandler):  # type: ignore[misc]
        """Fallback stream handler mimicking ``rich.logging.RichHandler``."""

        def __init__(self, *args, **kwargs) -> None:
            super().__init__()


def configure_rich_logging(
    level: int = logging.INFO,
    *,
    suppress: Optional[Iterable[str]] = None,
) -> None:
    """Initialise the root logger with a Rich handler and optional suppressions."""

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True, show_path=False)],
    )

    for name in suppress or ("werkzeug", "urllib3", "PIL"):
        logging.getLogger(name).setLevel(max(level, logging.WARNING))
