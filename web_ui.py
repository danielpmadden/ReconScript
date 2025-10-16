"""Local-only Flask web UI for ReconScript."""

from __future__ import annotations

import ipaddress
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

from flask import Flask, abort, redirect, render_template, request, url_for

from reconscript.core import run_recon
from reconscript.report import default_output_path, ensure_results_dir
from reconscript.reporters import (
    PDF_FALLBACK_MESSAGE,
    render_html,
    render_json,
    write_report,
)

APP_ROOT = Path(__file__).resolve().parent
TEMPLATE_FOLDER = APP_ROOT / "templates"

app = Flask(__name__, template_folder=str(TEMPLATE_FOLDER))
app.config.update({"TEMPLATES_AUTO_RELOAD": False})

LOGGER = logging.getLogger("reconscript.web_ui")

RESULTS_DIR = ensure_results_dir()

_jobs: Dict[str, Dict[str, object]] = {}
_jobs_lock = threading.Lock()


def _is_local_target(value: str) -> bool:
    candidate = value.strip()
    if not candidate:
        return False
    if candidate.lower() in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def _parse_ports(raw: str) -> List[int]:
    tokens = raw.replace(",", " ").split()
    ports: List[int] = []
    for token in tokens:
        port = int(token)
        if port <= 0 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535")
        ports.append(port)
    if not ports:
        raise ValueError("At least one port is required")
    return ports


def _parse_iso8601(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.utcnow()


def _ensure_local_request() -> None:
    remote = request.remote_addr or ""
    if remote not in {"127.0.0.1", "::1"}:
        abort(403)


@app.before_request
def _guard_requests() -> None:
    _ensure_local_request()


@app.get("/")
def index():
    with _jobs_lock:
        jobs = list(_jobs.values())
    jobs.sort(key=lambda item: item.get("created", ""), reverse=True)
    return render_template(
        "ui.html",
        view="dashboard",
        title="ReconScript Local UI",
        jobs=_prepare_jobs_for_display(jobs),
        message=request.args.get("message"),
    )


@app.post("/start")
def start_job():
    form = request.form
    target = form.get("target", "").strip()
    allow_external = form.get("allow_external") == "1"

    if not target:
        return redirect(url_for("index", message="Target is required."))
    if not allow_external and not _is_local_target(target):
        return redirect(
            url_for(
                "index",
                message="Target must be localhost or RFC1918 unless explicitly allowed.",
            )
        )

    try:
        ports = _parse_ports(form.get("ports", "80 443"))
        throttle = float(form.get("throttle", "0.2"))
        socket_timeout = float(form.get("socket_timeout", "3"))
        http_timeout = float(form.get("http_timeout", "8"))
        report_format = form.get("format", "html")
    except ValueError as exc:
        return redirect(url_for("index", message=str(exc)))

    job_id = uuid.uuid4().hex[:8]
    created = datetime.utcnow().isoformat(timespec="seconds")
    job: Dict[str, object] = {
        "id": job_id,
        "target": target,
        "ports": ports,
        "status": "queued",
        "created": created,
        "started": created,
        "finished": None,
        "format": report_format,
        "outputs": {},
        "error": None,
        "warning": None,
    }
    with _jobs_lock:
        _jobs[job_id] = job

    thread = threading.Thread(
        target=_execute_job,
        args=(job_id, target, ports, report_format, throttle, socket_timeout, http_timeout),
        daemon=True,
    )
    thread.start()

    return redirect(url_for("job_status", job_id=job_id))


@app.get("/status/<job_id>")
def job_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        abort(404)

    return render_template(
        "ui.html",
        view="job",
        title=f"Job {job_id} · ReconScript Local UI",
        job=_prepare_job_detail(job),
    )


def _prepare_jobs_for_display(jobs: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    prepared: List[Dict[str, object]] = []
    for job in jobs:
        prepared.append(
            {
                "id": job.get("id"),
                "target": job.get("target"),
                "status": job.get("status", "queued"),
                "started": job.get("started"),
                "finished": job.get("finished"),
                "format": job.get("format"),
            }
        )
    return prepared


def _prepare_job_detail(job: Dict[str, object]) -> Dict[str, object]:
    outputs: Dict[str, str] = {}
    for label, path in job.get("outputs", {}).items():
        outputs[label] = _as_uri(path)
    detail = dict(job)
    detail["outputs"] = outputs
    ports = job.get("ports")
    if isinstance(ports, Iterable) and not isinstance(ports, (str, bytes)):
        detail["ports"] = " ".join(str(port) for port in ports)
    return detail


def _as_uri(path: object) -> str:
    if isinstance(path, Path):
        return path.resolve().as_uri()
    text = str(path)
    if text.startswith("file://"):
        return text
    resolved = Path(text).resolve()
    return resolved.as_uri()


def _execute_job(
    job_id: str,
    target: str,
    ports: List[int],
    report_format: str,
    throttle: float,
    socket_timeout: float,
    http_timeout: float,
) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = "running"
        job["started"] = datetime.utcnow().isoformat(timespec="seconds")

    try:
        report = run_recon(
            target=target,
            hostname=None,
            ports=ports,
            socket_timeout=socket_timeout,
            http_timeout=http_timeout,
            max_retries=3,
            backoff=0.5,
            throttle=throttle,
            enable_ipv6=False,
            dry_run=False,
        )
        report["cli_args"] = {
            "source": "web_ui",
            "ports": ports,
            "throttle": throttle,
            "socket_timeout": socket_timeout,
            "http_timeout": http_timeout,
            "format": report_format,
        }

        started_dt = _parse_iso8601(str(report.get("started_at") or report.get("timestamp")))
        base_candidate = default_output_path(target, started_dt, "html")
        base_html = base_candidate.with_stem(f"{base_candidate.stem}-{job_id}")

        desired_path = base_html.with_suffix(f".{report_format}")
        primary_path, actual_format = write_report(report, desired_path, report_format)

        outputs: Dict[str, object] = {actual_format: primary_path.resolve()}
        warning: str | None = None

        if actual_format != "html":
            html_path = render_html(report, base_html)
            outputs.setdefault("html", html_path)
        else:
            html_path = primary_path

        json_path = html_path.with_suffix(".json")
        json_path.write_text(render_json(report), encoding="utf-8")
        outputs["json"] = json_path.resolve()

        if report_format == "pdf" and actual_format != "pdf":
            outputs["pdf"] = f"fallback to HTML: {html_path.resolve()}"
            warning = PDF_FALLBACK_MESSAGE
        elif report_format == "pdf":
            outputs.setdefault("pdf", primary_path.resolve())
        if report_format == "markdown":
            outputs.setdefault("markdown", primary_path.resolve())

        with _jobs_lock:
            job = _jobs[job_id]
            job["status"] = "completed"
            job["finished"] = datetime.utcnow().isoformat(timespec="seconds")
            job["outputs"] = outputs
            job["warning"] = warning
    except Exception as exc:  # pragma: no cover - UI safety net
        LOGGER.exception("UI job %s failed: %s", job_id, exc)
        with _jobs_lock:
            job = _jobs[job_id]
            job["status"] = "error"
            job["finished"] = datetime.utcnow().isoformat(timespec="seconds")
            job["error"] = str(exc)
            job["outputs"] = {}


if __name__ == "__main__":  # pragma: no cover - manual execution path
    logging.basicConfig(level=logging.INFO)
    app.run(host="127.0.0.1", port=5000, debug=False)
