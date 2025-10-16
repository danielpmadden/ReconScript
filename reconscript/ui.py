"""Flask-powered dashboard for running ReconScript scans from the browser."""

from __future__ import annotations

import json
import logging
import threading
import uuid
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from requests import exceptions as requests_exceptions

from . import __version__
from .core import run_recon
from .report import default_output_path, ensure_results_dir
from .reporters import write_report


LOGGER = logging.getLogger(__name__)

PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATE_FOLDER = PACKAGE_ROOT / "templates"
STATIC_FOLDER = PACKAGE_ROOT / "static"
DEFAULT_PORTS_DISPLAY = "80,443,8080,8443,8000,3000"


@dataclass
class JobState:
    """Track the lifecycle of a browser-triggered scan."""

    id: str
    target: str
    ports: List[int]
    format: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "queued"
    error: Optional[str] = None
    report_path: Optional[Path] = None
    queue: "Queue[Optional[Dict[str, object]]]" = field(default_factory=Queue)

    def to_public_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "target": self.target,
            "ports": self.ports,
            "format": self.format,
            "status": self.status,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "report_path": str(self.report_path) if self.report_path else None,
        }


def create_app() -> Flask:
    """Factory that configures and returns the Flask application instance."""

    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_FOLDER),
        static_folder=str(STATIC_FOLDER),
    )
    app.config.update(TEMPLATES_AUTO_RELOAD=True)

    changelog_summary = _read_changelog_summary()
    changelog_path = PACKAGE_ROOT.parent / "CHANGELOG.md"

    @app.context_processor
    def _inject_globals() -> Dict[str, object]:
        return {
            "version": __version__,
            "changelog_summary": changelog_summary,
            "changelog_filename": changelog_path.name if changelog_path.exists() else None,
        }

    results_dir = ensure_results_dir()
    jobs: Dict[str, JobState] = {}
    jobs_lock = threading.Lock()

    def _register_event(job: JobState, payload: Dict[str, object]) -> None:
        """Push an event payload onto the Server-Sent Events queue."""

        job.queue.put(payload)

    def _complete_event(job: JobState) -> None:
        job.queue.put(None)

    def _emit_status(job: JobState, message: str, progress: float, icon: str) -> None:
        _register_event(
            job,
            {
                "type": "status",
                "message": message,
                "progress": progress,
                "icon": icon,
            },
        )

    def _emit_log(job: JobState, message: str, level: str = "info") -> None:
        _register_event(job, {"type": "log", "message": message, "level": level})

    def _handle_job_error(job: JobState, message: str) -> None:
        job.error = message
        job.status = "error"
        status_message = f"Scan failed: {message}" if message else "Scan failed."
        _emit_status(job, status_message, 1.0, "❌")
        _emit_log(job, message or "Unknown error", level="error")
        _register_event(job, {"type": "error", "message": message})
        _render_console_error(message)

    def _run_job(job: JobState, hostname: Optional[str], report_format: str) -> None:
        """Execute a scan and stream lifecycle updates back to the browser."""

        job.status = "running"
        _emit_status(job, "Scan queued — preparing to start…", 0.05, "⌛")
        _emit_log(job, f"Starting scan for {job.target} on ports {job.ports}")

        started_at = datetime.utcnow()
        seen_messages: set[str] = set()

        def _progress(message: str, progress: float) -> None:
            _emit_status(job, message, progress, "⚙️" if progress < 1.0 else "✅")
            if message not in seen_messages:
                seen_messages.add(message)
                _emit_log(job, message)

        try:
            report = run_recon(
                job.target,
                hostname,
                job.ports,
                progress_callback=_progress,
            )
            extension = {
                "html": ".html",
                "json": ".json",
                "markdown": ".md",
                "pdf": ".pdf",
            }.get(report_format.lower(), ".html")
            outfile = default_output_path(job.target, started_at, extension, directory=results_dir)
            saved_path, final_format = write_report(report, outfile, report_format)
            job.report_path = saved_path
            job.status = "completed"

            stats = _build_scan_stats(report)
            summary_rows = _collect_summary_rows(report, stats)
            summary_payload = [{"label": label, "value": value} for label, value in summary_rows]
            duration_display = _duration_display(report, stats)

            _emit_log(job, f"Report saved to {saved_path}")
            _emit_log(job, f"Open ports: {stats['open_ports_display']}")
            with app.app_context():
                report_url = url_for("serve_report", filename=saved_path.name)
            _register_event(
                job,
                {
                    "type": "complete",
                    "message": "Report ready!",
                    "report_url": report_url,
                    "format": final_format,
                    "summary": summary_payload,
                    "duration": duration_display,
                    "target": report.get("target", job.target),
                    "open_ports": stats["open_ports"],
                    "findings": stats["findings"],
                    "report_path": str(saved_path),
                    "duration_seconds": stats.get("duration_seconds"),
                },
            )
            _render_console_summary(report, saved_path, summary_rows, stats)
        except ValueError as exc:
            LOGGER.warning("Validation error for job %s: %s", job.id, exc)
            _handle_job_error(job, str(exc))
        except requests_exceptions.RequestException as exc:
            LOGGER.warning("Network error during job %s: %s", job.id, exc)
            _handle_job_error(job, f"Network operation failed or timed out: {exc}")
        except PermissionError as exc:
            LOGGER.error("Permission error while saving report for job %s", job.id)
            _handle_job_error(job, f"Permission denied while saving results: {exc}")
        except OSError as exc:
            LOGGER.error("Filesystem error while saving report for job %s: %s", job.id, exc)
            _handle_job_error(job, f"Filesystem error while saving results: {exc}")
        except Exception as exc:  # pragma: no cover - defensive safety net
            LOGGER.exception("Scan job %s failed", job.id)
            _handle_job_error(job, str(exc) or "Unexpected error")
        finally:
            _complete_event(job)

    @app.route("/")
    def dashboard() -> str:
        return render_template(
            "index.html",
            default_ports=DEFAULT_PORTS_DISPLAY,
        )

    @app.post("/scan")
    def start_scan() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        target = (payload.get("target") or "").strip()
        ports_raw = payload.get("ports") or DEFAULT_PORTS_DISPLAY
        hostname = payload.get("hostname") or None
        report_format = (payload.get("format") or "html").lower()

        if report_format not in {"html", "json", "markdown", "pdf"}:
            return jsonify({"error": "Unsupported report format."}), 400

        if not target:
            return jsonify({"error": "Target IP or hostname is required."}), 400

        try:
            ports = _parse_ports(ports_raw)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        job = JobState(id=uuid.uuid4().hex[:8], target=target, ports=ports, format=report_format)

        with jobs_lock:
            jobs[job.id] = job

        thread = threading.Thread(target=_run_job, args=(job, hostname, report_format), daemon=True)
        thread.start()

        return jsonify({"job_id": job.id})

    @app.get("/stream/<job_id>")
    def stream(job_id: str) -> Response:
        with jobs_lock:
            job = jobs.get(job_id)
        if job is None:
            abort(404)

        def generate() -> Iterable[str]:
            # Yield JSON-encoded events so the front-end can render live progress updates via SSE.
            while True:
                event = job.queue.get()
                if event is None:
                    break
                yield f"data: {json.dumps(event)}\n\n"

        headers = {"Cache-Control": "no-cache", "Content-Type": "text/event-stream"}
        return Response(generate(), headers=headers)

    @app.get("/reports")
    def list_reports() -> str:
        records = _discover_reports(results_dir)
        return render_template("reports.html", reports=records)

    @app.post("/reports/<path:filename>/delete")
    def delete_report(filename: str):
        target_path = (results_dir / filename).resolve()
        if not str(target_path).startswith(str(results_dir.resolve())) or not target_path.exists():
            abort(404)
        target_path.unlink()
        return redirect(url_for("list_reports"))

    @app.get("/results/<path:filename>")
    def serve_report(filename: str):
        return send_from_directory(results_dir, filename, as_attachment=False)

    @app.get("/healthz")
    def healthcheck() -> Response:
        return jsonify({"status": "ok", "jobs": len(jobs)})

    return app


def _read_changelog_summary() -> Optional[str]:
    """Extract the most recent changelog heading for display in the UI footer."""

    changelog_path = PACKAGE_ROOT.parent / "CHANGELOG.md"
    if not changelog_path.exists():
        return None
    try:
        for line in changelog_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("##"):
                return stripped.lstrip("#").strip()
    except OSError:
        return None
    return None


def _normalise_ports(value: object) -> List[int]:
    ports: List[int] = []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535:
                ports.append(port)
    return ports


def _format_port_sequence(value: object) -> str:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        items: List[str] = []
        for item in value:
            if isinstance(item, (int, float)):
                items.append(str(int(item)))
            else:
                text = str(item).strip()
                if text:
                    items.append(text)
        return ", ".join(items) if items else "None"
    if value:
        return str(value)
    return "None"


def _duration_seconds(report: Dict[str, object]) -> Optional[float]:
    runtime = report.get("runtime")
    if isinstance(runtime, dict):
        duration = runtime.get("duration")
        if isinstance(duration, (int, float)):
            return float(duration)
    duration = report.get("duration")
    if isinstance(duration, (int, float)):
        return float(duration)
    return None


def _duration_display(report: Dict[str, object], stats: Dict[str, object]) -> Optional[str]:
    duration_value = stats.get("duration_seconds")
    if isinstance(duration_value, (int, float)):
        return f"{duration_value:.2f} seconds"

    runtime = report.get("runtime")
    if isinstance(runtime, dict):
        raw = runtime.get("duration")
        if isinstance(raw, str):
            return raw

    duration = report.get("duration")
    if isinstance(duration, str):
        return duration
    return None


def _build_scan_stats(report: Dict[str, object]) -> Dict[str, object]:
    open_ports = _normalise_ports(report.get("open_ports"))
    findings_value = report.get("findings", [])
    findings_count = len(findings_value) if isinstance(findings_value, Sequence) else 0
    duration_seconds = _duration_seconds(report)
    open_ports_display = ", ".join(str(port) for port in open_ports) if open_ports else "None detected"

    return {
        "open_ports": open_ports,
        "open_ports_display": open_ports_display,
        "findings": findings_count,
        "duration_seconds": duration_seconds,
    }


def _collect_summary_rows(report: Dict[str, object], stats: Dict[str, object]) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = [
        ("Target", str(report.get("target", "unknown"))),
        ("Hostname", str(report.get("hostname") or "N/A")),
        ("Ports Scanned", _format_port_sequence(report.get("ports"))),
        ("Open Ports", stats.get("open_ports_display", "None detected")),
        ("Findings", str(stats.get("findings", 0))),
    ]

    duration_label = _duration_display(report, stats)
    if duration_label:
        rows.append(("Scan Duration", duration_label))

    return rows


def _render_console_summary(
    report: Dict[str, object],
    saved_path: Path,
    summary_rows: Sequence[Tuple[str, str]],
    stats: Dict[str, object],
) -> None:
    target = report.get("target", "scan")
    findings = stats.get("findings", 0)
    open_ports_display = stats.get("open_ports_display", "None detected")

    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console(highlight=False)
        table = Table(show_header=False, box=box.SIMPLE_HEAVY)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Details", style="white")
        for label, value in summary_rows:
            table.add_row(label, value)

        subtitle = f"Open ports: {open_ports_display} • Findings: {findings} • Saved to {saved_path}"
        panel = Panel(
            table,
            title=f"Scan complete — {target}",
            subtitle=subtitle,
            border_style="green",
            expand=False,
        )
        console.print(panel)
    except Exception:
        print(f"Scan complete — {target} (saved to {saved_path})")
        for label, value in summary_rows:
            print(f" - {label}: {value}")


def _render_console_error(message: str) -> None:
    description = message or "Scan failed."
    try:
        from rich.console import Console
        from rich.panel import Panel

        console = Console(highlight=False)
        console.print(Panel(description, title="Scan failed", border_style="red", expand=False))
    except Exception:
        print(f"Scan failed: {description}")


def _parse_ports(raw: str) -> List[int]:
    """Parse a human-friendly string of ports (including ranges) into integers."""

    tokens = raw.replace(",", " ").replace(";", " ").split()
    ports: List[int] = []
    seen: set[int] = set()

    for token in tokens:
        chunk = token.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:
                raise ValueError("Port ranges must use numeric values (for example 80-90).") from exc
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                _validate_port(port)
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise ValueError("Ports must be numbers or ranges like 80-90.") from exc
            _validate_port(port)
            if port not in seen:
                seen.add(port)
                ports.append(port)

    if not ports:
        raise ValueError("Please provide at least one port to scan.")
    return ports


def _validate_port(port: int) -> None:
    if port <= 0 or port > 65535:
        raise ValueError("Ports must be between 1 and 65535.")


def _discover_reports(results_dir: Path) -> List[Dict[str, object]]:
    """Return metadata about saved reports sorted by recency."""

    items: List[Dict[str, object]] = []
    if not results_dir.exists():
        return items
    for path in sorted(results_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.is_file():
            stat = path.stat()
            items.append(
                {
                    "name": path.name,
                    "url": url_for("serve_report", filename=path.name),
                    "timestamp": datetime.fromtimestamp(stat.st_mtime),
                    "size": stat.st_size,
                    "type": _determine_type(path.suffix),
                    "folder": results_dir.resolve().as_uri(),
                }
            )
    return items


def _determine_type(extension: str) -> str:
    mapping = {
        ".html": "HTML",
        ".htm": "HTML",
        ".json": "JSON",
        ".md": "Markdown",
        ".markdown": "Markdown",
        ".pdf": "PDF",
    }
    return mapping.get(extension.lower(), extension.lstrip(".").upper() or "File")


def main() -> None:
    """Command-line entry point used by ``python -m reconscript.ui``."""

    app = create_app()

    def _open_browser() -> None:
        try:
            webbrowser.open_new("http://127.0.0.1:5000/")
        except Exception:  # pragma: no cover - best-effort convenience
            LOGGER.debug("Browser auto-open failed", exc_info=True)

    threading.Timer(1.0, _open_browser).start()
    app.run(host="0.0.0.0", port=5000, threaded=True)


if __name__ == "__main__":  # pragma: no cover - manual execution helper
    main()

