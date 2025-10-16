#!/usr/bin/env python3
"""Portable launcher for the ReconScript web interface."""

from __future__ import annotations

import hashlib
import importlib
import os
import subprocess
import sys
import threading
import time
import venv
import webbrowser
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent
REQUIREMENTS_FILE = ROOT / "requirements.txt"
DEFAULT_PORT = 5000
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
}


def _create_console():  # type: ignore[return-value]
    try:
        from rich.console import Console

        return Console(highlight=False)
    except Exception:  # pragma: no cover - fallback path when Rich is absent
        class _PlainConsole:
            def print(self, *values, **kwargs) -> None:
                print(*values)

            def rule(self, text: str) -> None:
                print(f"--- {text} ---")

            def log(self, *values, **kwargs) -> None:
                print(*values)

        return _PlainConsole()


console = _create_console()


def render_banner() -> None:
    banner = "\n".join(
        [
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓",
            "┃ ReconScript v0.4.2           ┃",
            "┃ Author: David █████          ┃",
            "┃ \"Automated Reconnaissance\"   ┃",
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛",
        ]
    )
    try:  # pragma: no cover - enhanced output when Rich is present
        from rich.panel import Panel

        console.print(Panel(banner, expand=False, border_style="bright_cyan", style="bold cyan"))
    except Exception:
        console.print(banner)


def in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(os.environ.get("VIRTUAL_ENV"))


def in_docker() -> bool:
    if Path("/.dockerenv").exists():
        return True
    return os.environ.get("RUNNING_IN_DOCKER") == "1"


def venv_python_path(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_virtualenv() -> Path:
    venv_dir = ROOT / ".venv"
    python_path = venv_python_path(venv_dir)
    if python_path.exists():
        return python_path

    console.print("Creating isolated Python environment in .venv …")
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)
    return python_path


def _hash_requirements(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def _marker_path() -> Path:
    preferred = ROOT / ".venv" / ".requirements-hash"
    if preferred.parent.exists():
        return preferred
    return ROOT / ".requirements-hash"


def _load_marker(marker: Path) -> str | None:
    try:
        return marker.read_text().strip()
    except FileNotFoundError:
        return None


def _store_marker(marker: Path, value: str) -> None:
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(value)


def _missing_modules(modules: Dict[str, str]) -> List[str]:
    missing: List[str] = []
    for requirement, module_name in modules.items():
        try:
            importlib.import_module(module_name)
        except Exception:
            missing.append(requirement)
    return missing


def ensure_dependencies(python_executable: Path) -> None:
    if not REQUIREMENTS_FILE.exists():
        raise FileNotFoundError("requirements.txt is missing; cannot install dependencies.")

    expected_hash = _hash_requirements(REQUIREMENTS_FILE)
    marker = _marker_path()
    recorded_hash = _load_marker(marker)
    missing = _missing_modules(REQUIREMENT_IMPORTS)
    if missing:
        console.print(f"Installing missing dependencies: {', '.join(missing)} …")
    if recorded_hash != expected_hash or missing:
        command = [
            str(python_executable),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-warn-script-location",
            "--quiet",
            "-r",
            str(REQUIREMENTS_FILE),
        ]
        console.print("Resolving Python requirements (this may take a moment)…")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            combined_output = "\n".join(part for part in (result.stdout, result.stderr) if part)
            if "permission" in combined_output.lower() or "access is denied" in combined_output.lower():
                console.print(
                    "[red]Permission error while installing dependencies. Please re-run this launcher as an administrator or with sudo.[/red]"
                )
            else:
                console.print("[red]Dependency installation failed. Output follows:[/red]")
                console.print(combined_output or "(no output)")
            sys.exit(result.returncode)
        _store_marker(marker, expected_hash)
        missing_after = _missing_modules(REQUIREMENT_IMPORTS)
        if missing_after:
            console.print(
                "[red]Dependencies are still missing after installation. Please check your Python environment and try again.[/red]"
            )
            sys.exit(1)
        console.print("[green]Dependencies installed successfully.[/green]")
    else:
        console.print("Dependencies already satisfied.")


def _open_browser_when_ready(url: str, delay: float = 1.5) -> None:
    def _open() -> None:
        time.sleep(delay)
        try:
            webbrowser.open_new(url)
        except Exception:
            console.print("Unable to open browser automatically. Please navigate to " + url)

    thread = threading.Thread(target=_open, daemon=True)
    thread.start()


def _run_app(host: str, port: int) -> None:
    from reconscript.ui import create_app

    app = create_app()
    try:
        app.run(host=host, port=port, threaded=True)
    except OSError as exc:
        console.print(f"[red]Failed to start the web server: {exc}[/red]")
        sys.exit(1)


def main() -> None:
    global console  # must be declared before first use
    os.chdir(ROOT)

    version_warning: str | None = None
    if sys.version_info < (3, 9) or sys.version_info > (3, 13):
        version_warning = (
            "[yellow]Warning: ReconScript targets Python versions 3.9 through 3.13. You are running"
            f" Python {'.'.join(map(str, sys.version_info[:3]))}. Proceeding anyway…[/yellow]"
        )

    docker = in_docker()
    venv_active = in_virtualenv()
    post_launch_messages: List[str] = []

    if not docker and not venv_active:
        python_path = ensure_virtualenv()
        if Path(sys.executable).resolve() != python_path.resolve() and os.environ.get("RECONSCRIPT_BOOTSTRAPPED") != "1":
            console.print("Switching to the project virtual environment …")
            env = os.environ.copy()
            env["RECONSCRIPT_BOOTSTRAPPED"] = "1"
            command = [str(python_path), str(ROOT / "start.py"), *sys.argv[1:]]
            raise SystemExit(subprocess.call(command, env=env))
        post_launch_messages.append(f"Using virtual environment at {python_path.parent}")
    elif docker:
        post_launch_messages.append("Running inside a Docker container — using system interpreter.")
    else:
        post_launch_messages.append("Virtual environment detected — continuing with current interpreter.")

    python_executable = Path(sys.executable)
    ensure_dependencies(python_executable)

    # ✅ Reinitialize Rich console after dependencies are ensured
    console = _create_console()
    render_banner()
    if version_warning:
        console.print(version_warning)
    for message in post_launch_messages:
        console.print(message)

    try:
        from reconscript.report import ensure_results_dir
    except ModuleNotFoundError as exc:
        console.print(f"[red]Unable to import ReconScript package: {exc}[/red]")
        sys.exit(1)

    try:
        results_dir = ensure_results_dir()
    except PermissionError as exc:
        console.print(
            "[red]Cannot create the results/ directory. Please adjust permissions or run as administrator.[/red]"
        )
        console.print(f"System error: {exc}")
        sys.exit(1)

    console.print(f"Results will be stored in {results_dir.resolve()}")

    url = f"http://127.0.0.1:{DEFAULT_PORT}"
    if not docker:
        _open_browser_when_ready(url)
    else:
        console.print("Browser auto-open disabled inside Docker. Access the UI from your host machine.")

    host = "0.0.0.0" if docker else "127.0.0.1"
    console.print(f"Starting ReconScript web UI on {host}:{DEFAULT_PORT} …")
    try:
        _run_app(host, DEFAULT_PORT)
    except KeyboardInterrupt:
        console.print("Exiting. Goodbye!")


if __name__ == "__main__":
    main()
