"""Compatibility module that exposes the ReconScript web dashboard."""

from __future__ import annotations

from reconscript.ui import create_app, main

# Expose the Flask application for ``flask run`` style workflows.
app = create_app()


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    main()
