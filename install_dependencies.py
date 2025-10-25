#!/usr/bin/env python3
from __future__ import annotations

"""Helper script to ensure ReconScript runtime dependencies are installed."""

import argparse
import hashlib
import importlib
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT / "requirements.txt"
MARKER_IN_VENV = ROOT / ".venv" / ".requirements-hash"
MARKER_FALLBACK = ROOT / ".requirements-hash"

# Mapping of requirement name to import name so we can detect missing modules quickly.
REQUIREMENT_IMPORTS: Dict[str, str] = {
    "requests": "requests",
    "urllib3": "urllib3",
    "jinja2": "jinja2",
    "flask": "flask",
    "rich": "rich",
    "tabulate": "tabulate",
    "colorama": "colorama",
    "weasyprint": "weasyprint",
    "fonttools": "fontTools",
    "tinycss2": "tinycss2",
    "cssselect2": "cssselect2",
    "pyphen": "pyphen",
    "pydyf": "pydyf",
    "markupsafe": "markupsafe",
    "itsdangerous": "itsdangerous",
    "werkzeug": "werkzeug",
    "python-dotenv": "dotenv",
}


def create_console():  # type: ignore[return-value]
    """Return a ``rich`` console if available, otherwise a simple fallback printer."""

    try:  # pragma: no cover - gracefully degrade if Rich is absent
        from rich.console import Console

        return Console(highlight=False)
    except Exception:

        class _PlainConsole:
            def print(self, *values: object, sep: str = " ", end: str = "\n") -> None:
                text = sep.join(str(v) for v in values)
                sys.stdout.write(text + end)
                sys.stdout.flush()

            def rule(self, text: str) -> None:
                self.print(f"--- {text} ---")

            def log(self, *values: object, **kwargs: object) -> None:
                self.print(*values)

        return _PlainConsole()


def _hash_requirements(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _marker_path() -> Path:
    preferred_parent = MARKER_IN_VENV.parent
    if preferred_parent.exists():
        return MARKER_IN_VENV
    return MARKER_FALLBACK


def _missing_modules(modules: Dict[str, str]) -> Iterable[str]:
    for requirement, module_name in modules.items():
        try:
            importlib.import_module(module_name)
        except Exception:
            yield requirement


def install_dependencies(
    python_executable: str | Path | None = None,
    requirements_path: str | Path | None = None,
    *,
    force: bool = False,
    console=None,
) -> None:
    """Ensure project requirements are installed for the supplied interpreter."""

    py_exec = Path(python_executable or sys.executable)
    requirements = Path(requirements_path or REQUIREMENTS_FILE)
    output = console or create_console()

    if not requirements.exists():
        raise FileNotFoundError(f"Requirements file not found at {requirements}")

    marker = _marker_path()
    expected_hash = _hash_requirements(requirements)
    recorded_hash = marker.read_text().strip() if marker.exists() else None

    missing = list(_missing_modules(REQUIREMENT_IMPORTS))
    if missing:
        output.print(
            f"Installing missing dependencies: {', '.join(sorted(set(missing)))} …"
        )

    if force:
        output.print("Force flag supplied — reinstalling requirements…")

    if missing or force or recorded_hash != expected_hash:
        command = [
            str(py_exec),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-warn-script-location",
            "--quiet",
            "-r",
            str(requirements),
        ]
        output.print("Resolving Python requirements (this may take a moment)…")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            combined_output = "\n".join(
                part for part in (result.stdout, result.stderr) if part
            )
            raise RuntimeError(
                "Dependency installation failed with exit code"
                f" {result.returncode}:\n{combined_output or '(no output)'}"
            )
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(expected_hash)
        output.print("Dependencies installed successfully.")
    else:
        output.print("Dependencies already satisfied.")


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install ReconScript runtime dependencies."
    )
    parser.add_argument(
        "--python",
        dest="python",
        default=sys.executable,
        help="Python interpreter to use when invoking pip (defaults to current interpreter).",
    )
    parser.add_argument(
        "--requirements",
        dest="requirements",
        default=str(REQUIREMENTS_FILE),
        help="Path to the requirements.txt file (defaults to the project root).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force reinstall dependencies even if hashes match and modules are present.",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> None:
    args = _parse_args(argv)
    console = create_console()
    try:
        install_dependencies(
            args.python, args.requirements, force=args.force, console=console
        )
    except Exception as exc:  # pragma: no cover - invoked from CLI
        console.print(f"[red]Failed to install dependencies: {exc}[/red]")
        raise SystemExit(1)


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
