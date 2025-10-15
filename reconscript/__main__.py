"""Module entry point for ``python -m reconscript``."""

from __future__ import annotations

from .cli import main


if __name__ == "__main__":  # pragma: no cover - CLI bootstrap
    raise SystemExit(main())
