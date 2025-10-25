#!/usr/bin/env python3
"""Portable launcher for the ReconScript web interface."""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import threading
import time
import venv
import webbrowser
from pathlib import Path
from typing import List

try:  # pragma: no cover - optional dependency fallback
    from dotenv import load_dotenv
except (
    ModuleNotFoundError
):  # pragma: no cover - minimal shim when python-dotenv missing

    def load_dotenv() -> None:  # type: ignore[return-value]
        """Fallback no-op when python-dotenv is unavailable."""

        return None


from install_dependencies import create_console, install_dependencies

load_dotenv()

ROOT = Path(__file__).resolve().parent
DEFAULT_PORT = int(os.environ.get("DEFAULT_PORT", "5000"))


class _StreamMultiplexer:
    """Mirror writes to stdout/stderr into the on-disk log."""

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data: str) -> None:
        for stream in self._streams:
            stream.write(data)
            stream.flush()

    def flush(self) -> None:  # pragma: no cover - compatibility shim
        for stream in self._streams:
            stream.flush()


console = create_console()


def render_banner(version: str, environment: str) -> None:
    lines = [
        f"ReconScript v{version}",
        f"Mode: {environment.capitalize()}",
        '"Automated Reconnaissance"',
    ]
    banner_lines = ["┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"]
    banner_lines.extend(f"┃ {text:<26} ┃" for text in lines)
    banner_lines.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    banner = "\n".join(banner_lines)
    try:  # pragma: no cover - enhanced output when Rich is present
        from rich.panel import Panel

        console.print(
            Panel(banner, expand=False, border_style="bright_cyan", style="bold cyan")
        )
    except Exception:
        console.print(banner)


def in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix) or bool(
        os.environ.get("VIRTUAL_ENV")
    )


def in_docker() -> bool:
    if Path("/.dockerenv").exists():
        return True
    if os.environ.get("RUNNING_IN_DOCKER") == "1":
        return True
    if Path("/var/run/docker.sock").exists():
        return True
    try:
        cgroup = Path("/proc/self/cgroup")
        if cgroup.exists() and "docker" in cgroup.read_text():
            return True
    except OSError:
        pass
    return False


def in_wsl() -> bool:
    return bool(os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"))


def describe_environment() -> str:
    if in_docker():
        return "docker"
    if in_wsl():
        return "wsl"
    return "local"


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


def _wait_and_open_browser(url: str, health_url: str, environment: str) -> None:
    def _open() -> None:
        console.print(
            "Waiting for ReconScript to pass health check before opening browser…"
        )
        import requests  # Lazily import so dependency installation can complete first

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                response = requests.get(health_url, timeout=2)
                if response.ok:
                    if environment == "docker":
                        console.print(
                            "ReconScript UI is ready inside Docker — open your browser at "
                            + url
                        )
                        return
                    console.print(
                        "ReconScript UI is ready — launching default browser."
                    )
                    try:
                        if environment == "wsl" and shutil.which("wslview"):
                            subprocess.Popen(
                                ["wslview", url]
                            )  # noqa: S603,S607 - best effort helper
                        else:
                            webbrowser.open_new(url)
                    except Exception:
                        console.print(
                            "Unable to open browser automatically. Please navigate to "
                            + url
                        )
                    return
            except requests.RequestException:
                pass
            time.sleep(1)
        console.print(
            "[yellow]Timed out waiting for health check. Please open the UI manually at "
            f"{url}[/yellow]"
        )

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

    configured_results = Path(os.environ.get("RESULTS_DIR", "results")).expanduser()
    if not configured_results.is_absolute():
        configured_results = (ROOT / configured_results).resolve()

    log_root = configured_results
    log_root.mkdir(parents=True, exist_ok=True)
    log_path = log_root / "latest.log"
    log_handle = log_path.open("w", encoding="utf-8")
    atexit.register(log_handle.close)
    sys.stdout = _StreamMultiplexer(sys.__stdout__, log_handle)
    sys.stderr = _StreamMultiplexer(sys.__stderr__, log_handle)

    console = create_console()

    version_warning: str | None = None
    if sys.version_info < (3, 9) or sys.version_info > (3, 13):
        version_warning = (
            "[yellow]Warning: ReconScript targets Python versions 3.9 through 3.13. You are running"
            f" Python {'.'.join(map(str, sys.version_info[:3]))}. Proceeding anyway…[/yellow]"
        )

    environment = describe_environment()
    venv_active = in_virtualenv()
    post_launch_messages: List[str] = []

    if environment != "docker" and not venv_active:
        python_path = ensure_virtualenv()
        if (
            Path(sys.executable).resolve() != python_path.resolve()
            and os.environ.get("RECONSCRIPT_BOOTSTRAPPED") != "1"
        ):
            console.print("Switching to the project virtual environment …")
            env = os.environ.copy()
            env["RECONSCRIPT_BOOTSTRAPPED"] = "1"
            command = [str(python_path), str(ROOT / "start.py"), *sys.argv[1:]]
            raise SystemExit(subprocess.call(command, env=env))
        post_launch_messages.append(
            f"Using virtual environment at {python_path.parent}"
        )
    elif environment == "docker":
        post_launch_messages.append(
            "Running inside a Docker container — using system interpreter."
        )
    else:
        post_launch_messages.append(
            "Virtual environment detected — continuing with current interpreter."
        )

    python_executable = Path(sys.executable)
    try:
        install_dependencies(python_executable, console=console)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    # ✅ Reinitialize Rich console after dependencies are ensured
    console = create_console()
    post_launch_messages.append(f"Session log: {log_path.resolve()}")

    try:
        from reconscript import __version__ as package_version
    except ModuleNotFoundError:
        package_version = "unknown"

    render_banner(package_version, environment)
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

    if environment == "wsl":
        console.print("Detected Windows Subsystem for Linux environment.")

    public_url = f"http://127.0.0.1:{DEFAULT_PORT}"
    health_url = f"http://127.0.0.1:{DEFAULT_PORT}/health"
    if environment == "docker":
        console.print(
            "Browser auto-launch disabled inside Docker. Access the UI at " + public_url
        )
    else:
        _wait_and_open_browser(public_url, health_url, environment)

    host = "0.0.0.0" if environment in {"docker", "wsl"} else "127.0.0.1"
    console.print(f"Starting ReconScript web UI on {host}:{DEFAULT_PORT} …")
    try:
        _run_app(host, DEFAULT_PORT)
    except KeyboardInterrupt:
        console.print("Exiting. Goodbye!")


if __name__ == "__main__":
    main()
