"""Configuration helpers and .env loading for ReconScript."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv

DEFAULT_ENV_FILES: tuple[Path, ...] = (
    Path(".env"),
    Path("config/.env"),
)


@lru_cache(maxsize=1)
def load_environment(*, extra_files: Iterable[Path] | None = None) -> dict[str, str]:
    """Load environment variables from .env files once per process."""

    candidates = list(DEFAULT_ENV_FILES)
    if extra_files:
        candidates = [*candidates, *extra_files]

    for path in candidates:
        try:
            if path.exists():
                load_dotenv(path, override=False)
        except OSError:
            continue

    load_dotenv(override=False)
    return dict(os.environ)


def require_setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Required environment variable '{name}' is not set")
    return value


__all__ = ["load_environment", "require_setting", "DEFAULT_ENV_FILES"]
