# Modified by codex: 2024-05-08
"""Minimal local-only Flask interface for ReconScript."""

from __future__ import annotations

import ipaddress
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from flask import Flask, abort, redirect, render_template_string, request, url_for

from reconscript.core import run_recon
from reconscript.reporters import render_html, render_json, write_report

APP_TITLE = "ReconScript Local UI"
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = False

_jobs: Dict[str, dict] = {}
_jobs_lock = threading.Lock()

INDEX_TEMPLATE = """
<!doctype html>
<title>{{ title }}</title>
<style>
  body { font-family: "Segoe UI", Arial, sans-serif; margin: 2rem auto; max-width: 840px; }
  header { margin-bottom: 1.5rem; }
  form label { display: block; margin-top: 0.75rem; }
  input[type=text], input[type=number], select { width: 100%; padding: 0.5rem; }
  .jobs { margin-top: 2rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.6rem; border-bottom: 1px solid #e2e8f0; text-align: left; }
  .status-running { color: #d97706; }
  .status-completed { color: #047857; }
  .status-error { color: #b91c1c; }
  .warning { background: #fef3c7; padding: 0.75rem; border-left: 4px solid #f59e0b; margin-bottom: 1rem; }
</style>
<header>
  <h1>{{ title }}</h1>
  <p>This interface runs strictly on <strong>127.0.0.1</strong>. Do not expose it to untrusted networks.</p>
</header>
{% if message %}
<div class="warning">{{ message }}</div>
{% endif %}
<form method="post" action="{{ url_for('start_job') }}">
  <label>Target IP (localhost or RFC1918 ranges only)
    <input name="target" type="text" required value="127.0.0.1" />
  </label>
  <label>Ports (space separated)
    <input name="ports" type="text" value="80 443 3000" />
  </label>
  <label>Throttle (seconds between probes)
    <input name="throttle" type="number" step="0.1" value="0.2" />
  </label>
  <label>Socket timeout (seconds)
    <input name="socket_timeout" type="number" step="0.1" value="3" />
  </label>
  <label>HTTP timeout (seconds)
    <input name="http_timeout" type="number" step="0.1" value="8" />
  </label>
  <label>Format
    <select name="format">
      <option value="html" selected>HTML</option>
      <option value="json">JSON</option>
      <option value="markdown">Markdown</option>
      <option value="pdf">PDF</option>
    </select>
  </label>
  <label>
    <input type="checkbox" name="verbose" value="1" /> Enable verbose logging
  </label>
  <label>
    <input type="checkbox" name="allow_external" value="1" /> Allow non-local targets (use with caution)
  </label>
  <button type="submit">Start Scan</button>
</form>
<section class="jobs">
  <h2>Recent Jobs</h2>
  <table>
    <thead>
      <tr><th>ID</th><th>Target</th><th>Status</th><th>Started</th><th>Result</th></tr>
    </thead>
    <tbody>
    {% for job in jobs %}
      <tr>
        <td><a href="{{ url_for('job_status', job_id=job['id']) }}">{{ job['id'] }}</a></td>
        <td>{{ job['target'] }}</td>
        <td class="status-{{ job['status'] }}">{{ job['status'].title() }}</td>
        <td>{{ job['started'] }}</td>
        <td>{% if job['status'] == 'completed' %}<a href="{{ url_for('job_status', job_id=job['id']) }}">View</a>{% elif job['status'] == 'error' %}Error{% else %}Pending{% endif %}</td>
      </tr>
    {% endfor %}
    {% if not jobs %}
      <tr><td colspan="5">No jobs yet.</td></tr>
    {% endif %}
    </tbody>
  </table>
</section>
"""

STATUS_TEMPLATE = """
<!doctype html>
<title>Job {{ job['id'] }} · {{ title }}</title>
<style>
  body { font-family: "Segoe UI", Arial, sans-serif; margin: 2rem auto; max-width: 720px; }
  dt { font-weight: bold; }
  dd { margin-bottom: 0.5rem; }
  pre { background: #0f172a; color: #f8fafc; padding: 0.75rem; overflow-x: auto; }
</style>
<h1>Job {{ job['id'] }}</h1>
<p>Status: <strong>{{ job['status'].title() }}</strong></p>
<dl>
  <dt>Target</dt><dd>{{ job['target'] }}</dd>
  <dt>Ports</dt><dd>{{ job['ports'] }}</dd>
  <dt>Started</dt><dd>{{ job['started'] }}</dd>
  <dt>Finished</dt><dd>{{ job.get('finished', 'running…') }}</dd>
</dl>
{% if job['error'] %}
  <p style="color: #b91c1c;">{{ job['error'] }}</p>
{% endif %}
{% if job['outputs'] %}
<h2>Reports</h2>
<ul>
  {% for label, path in job['outputs'].items() %}
  <li>{{ label.upper() }}: <a href="{{ path }}">{{ path }}</a></li>
  {% endfor %}
</ul>
{% endif %}
<p><a href="{{ url_for('index') }}">Back to dashboard</a></p>
"""


def _is_local_target(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value.lower() in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def _parse_ports(raw: str) -> List[int]:
    tokens = raw.replace(",", " ").split()
    ports: List[int] = []
    for token in tokens:
        if not token:
            continue
        port = int(token)
        if port <= 0 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535")
        ports.append(port)
    if not ports:
        raise ValueError("At least one port is required")
    return ports


def _ensure_local_request() -> None:
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)


@app.before_request
def _guard_requests() -> None:
    _ensure_local_request()


@app.get("/")
def index():
    with _jobs_lock:
        jobs = list(_jobs.values())
    jobs = sorted(jobs, key=lambda item: item["started"], reverse=True)
    message = request.args.get("message")
    return render_template_string(INDEX_TEMPLATE, title=APP_TITLE, jobs=jobs, message=message)


@app.post("/start")
def start_job():
    _ensure_local_request()
    form = request.form
    target = form.get("target", "").strip()
    allow_external = form.get("allow_external") == "1"
    if not target:
        return redirect(url_for("index", message="Target is required."))
    if not _is_local_target(target) and not allow_external:
        return redirect(url_for("index", message="Target must be localhost or RFC1918 unless explicitly allowed."))

    try:
        ports = _parse_ports(form.get("ports", "80 443"))
        throttle = float(form.get("throttle", "0.2"))
        socket_timeout = float(form.get("socket_timeout", "3"))
        http_timeout = float(form.get("http_timeout", "8"))
        report_format = form.get("format", "html")
        verbose = form.get("verbose") == "1"
    except ValueError as exc:
        return redirect(url_for("index", message=str(exc)))

    job_id = uuid.uuid4().hex[:8]
    job = {
        "id": job_id,
        "target": target,
        "ports": " ".join(str(p) for p in ports),
        "status": "queued",
        "started": datetime.utcnow().isoformat(timespec="seconds"),
        "finished": None,
        "outputs": {},
        "error": None,
    }
    with _jobs_lock:
        _jobs[job_id] = job

    thread = threading.Thread(
        target=_execute_job,
        args=(job_id, target, ports, report_format, throttle, socket_timeout, http_timeout, verbose),
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
    display_job = job.copy()
    outputs = {
        label: Path(path).resolve().as_uri() if not path.startswith("file:") else path
        for label, path in display_job["outputs"].items()
    }
    display_job["outputs"] = outputs
    return render_template_string(STATUS_TEMPLATE, title=APP_TITLE, job=display_job)


def _execute_job(
    job_id: str,
    target: str,
    ports: List[int],
    report_format: str,
    throttle: float,
    socket_timeout: float,
    http_timeout: float,
    verbose: bool,
) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = "running"

    try:
        report = run_recon(
            target=target,
            hostname=None,
            ports=ports,
            socket_timeout=socket_timeout,
            http_timeout=http_timeout,
            max_retries=2 if not verbose else 4,
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
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        base_name = f"{target.replace(':', '_').replace('.', '-')}-{timestamp}-{job_id}"
        base_path = RESULTS_DIR / base_name

        primary_path, actual_format = write_report(report, base_path.with_suffix(f".{report_format}"), report_format)
        outputs = {actual_format: str(primary_path.resolve())}

        html_path = render_html(report, base_path.with_suffix(".html"))
        outputs["html"] = str(html_path.resolve())

        json_path = html_path.with_suffix(".json")
        json_path.write_text(render_json(report), encoding="utf-8")
        outputs.setdefault("json", str(json_path.resolve()))

        if report_format == "markdown":
            outputs.setdefault("markdown", str(primary_path.resolve()))
        if report_format == "pdf" and actual_format != "pdf":
            outputs["pdf"] = f"fallback to HTML: {html_path.resolve()}"
        elif report_format == "pdf":
            outputs.setdefault("pdf", str(primary_path.resolve()))

        with _jobs_lock:
            job["status"] = "completed"
            job["finished"] = datetime.utcnow().isoformat(timespec="seconds")
            job["outputs"] = outputs
    except Exception as exc:  # pragma: no cover - safety net for UI thread
        with _jobs_lock:
            job["status"] = "error"
            job["finished"] = datetime.utcnow().isoformat(timespec="seconds")
            job["error"] = str(exc)
            job["outputs"] = {}


if __name__ == "__main__" or os.getenv("RECON_UI", "false").lower() == "true":
    app.run(host="127.0.0.1", port=5000, debug=False)
