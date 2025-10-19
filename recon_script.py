"""Compatibility wrapper around the new ReconScript package CLI."""

from __future__ import annotations

from reconscript.cli import main

if __name__ == "__main__":  # pragma: no cover - CLI bootstrap
    raise SystemExit(main())
