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
from typing import Dict, Iterable, List, Optional

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

from . import __version__
from .core import run_recon
from .report import default_output_path, ensure_results_dir
from .reporters import write_report


LOGGER = logging.getLogger(__name__)

PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATE_FOLDER = PACKAGE_ROOT / "templates"
STATIC_FOLDER = PACKAGE_ROOT / "static"


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
            # Persist the operator's chosen report format beside the traditional HTML output.
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
            _emit_log(job, f"Report saved to {saved_path}")
            with app.app_context():
                report_url = url_for("serve_report", filename=saved_path.name)
            _register_event(
                job,
                {
                    "type": "complete",
                    "message": "Report ready!",
                    "report_url": report_url,
                    "format": final_format,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive safety net
            LOGGER.exception("Scan job %s failed", job.id)
            job.error = str(exc)
            job.status = "error"
            _emit_status(job, "Scan failed.", 1.0, "❌")
            _emit_log(job, job.error or "Unknown error", level="error")
            _register_event(job, {"type": "error", "message": job.error})
        finally:
            _complete_event(job)

    @app.route("/")
    def dashboard() -> str:
        return render_template(
            "index.html",
            default_ports="80 443 8080 8443 3000",
            version=__version__,
        )

    @app.post("/scan")
    def start_scan() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        target = (payload.get("target") or "").strip()
        ports_raw = payload.get("ports") or "80 443 8080 8443 3000"
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
        return render_template("reports.html", reports=records, version=__version__)

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


def _parse_ports(raw: str) -> List[int]:
    """Parse a human-friendly string of ports into integers."""

    tokens = raw.replace(",", " ").split()
    ports: List[int] = []
    for token in tokens:
        if not token.strip():
            continue
        port = int(token)
        if port <= 0 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535.")
        ports.append(port)
    if not ports:
        raise ValueError("Please provide at least one port to scan.")
    return ports


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

