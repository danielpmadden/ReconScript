"""Flask UI for ReconScript without authentication or RBAC."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    Response,
    request,
    send_from_directory,
    url_for,
)

from .core import ReconError, run_recon
from .logging import configure_logging
from .metrics import metrics_payload
from .report import ensure_results_dir, persist_report
from .scope import validate_target

LOGGER = logging.getLogger(__name__)
DEV_KEYS_DIR = Path(__file__).resolve().parents[1] / "keys"


def _allow_dev_secrets() -> bool:
    return os.environ.get("ALLOW_DEV_SECRETS", "false").lower() == "true"


def _enforce_secret_path(path: Path, *, env_var: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise RuntimeError(
            f"{env_var} must point to an existing file (got {resolved})."
        )
    if DEV_KEYS_DIR in resolved.parents and not _allow_dev_secrets():
        raise RuntimeError(
            f"{env_var} refers to a developer sample key. Provide deployment-specific "
            "secrets or set ALLOW_DEV_SECRETS=true for local testing."
        )
    return resolved


def _load_secret_key() -> bytes:
    secret_env = os.environ.get("FLASK_SECRET_KEY_FILE")
    if not secret_env:
        raise RuntimeError(
            "FLASK_SECRET_KEY_FILE environment variable must reference a secure secret key file."
        )
    secret_path = _enforce_secret_path(Path(secret_env), env_var="FLASK_SECRET_KEY_FILE")
    try:
        secret = secret_path.read_bytes().strip()
    except OSError as exc:
        raise RuntimeError(
            f"Unable to read Flask secret key from {secret_path}: {exc}"
        ) from exc
    if not secret:
        raise RuntimeError(f"Secret key file {secret_path} is empty.")
    return secret


def create_app() -> Flask:
    configure_logging()

    app = Flask(__name__)
    app.config["PUBLIC_UI"] = os.environ.get("ENABLE_PUBLIC_UI", "false").lower() == "true"
    app.secret_key = _load_secret_key()

    @app.context_processor
    def inject_globals():
        return {
            "public_ui": app.config["PUBLIC_UI"],
        }

    @app.route("/healthz")
    def health() -> tuple[str, int]:
        return "ok", 200

    @app.route("/metrics")
    def metrics() -> Response:
        payload, content_type = metrics_payload()
        if not payload:
            return Response("", status=204)
        return Response(payload, mimetype=content_type)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            target = request.form.get("target", "")
            expected_ip = request.form.get("expected_ip") or None
            hostname = request.form.get("hostname") or None
            evidence_level = request.form.get("evidence_level", "low")
            ports_raw = request.form.get("ports", "")
            ports = (
                [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
                if ports_raw
                else None
            )
            try:
                validate_target(target, expected_ip=expected_ip)
            except Exception as exc:
                flash(str(exc), "error")
                return render_template("index.html")

            try:
                LOGGER.info(
                    "ui.scan.request",
                    extra={
                        "event": "ui.scan.request",
                        "target": target,
                        "hostname": hostname,
                        "ports": ports,
                        "expected_ip": expected_ip,
                        "evidence_level": evidence_level,
                    },
                )
                report = run_recon(
                    target=target,
                    hostname=hostname,
                    ports=ports,
                    expected_ip=expected_ip,
                    evidence_level=evidence_level,
                )
            except ReconError as exc:
                flash(str(exc), "error")
                LOGGER.error(
                    "ui.scan.failed",
                    extra={
                        "event": "ui.scan.failed",
                        "target": target,
                        "error": str(exc),
                    },
                )
                return render_template("index.html")

            persisted = persist_report(report, sign=False)
            LOGGER.info(
                "ui.scan.completed",
                extra={
                    "event": "ui.scan.completed",
                    "target": target,
                    "report_id": persisted.report_id,
                    "open_ports": report.get("open_ports", []),
                },
            )
            return redirect(url_for("report_detail", report_id=persisted.report_id))
        return render_template("index.html")

    @app.route("/reports/<report_id>")
    def report_detail(report_id: str):
        report_dir = ensure_results_dir() / report_id
        report_file = report_dir / "report.json"
        if not report_file.exists():
            abort(404)
        report_data = json.loads(report_file.read_text(encoding="utf-8"))
        return render_template(
            "report_detail.html", report=report_data, report_id=report_id
        )

    @app.route("/results/<path:filename>")
    def download_result(filename: str):
        return send_from_directory(
            ensure_results_dir(), filename, as_attachment=True
        )

    return app


def main() -> None:
    app = create_app()
    host = "0.0.0.0" if app.config["PUBLIC_UI"] else "127.0.0.1"
    port = int(os.environ.get("DEFAULT_PORT", "5000"))
    if app.config["PUBLIC_UI"]:
        LOGGER.warning(
            "Public UI mode enabled — ensure reverse proxy protections are in place."
        )
    else:
        LOGGER.warning(
            "Running ReconScript UI without authentication. Restrict access appropriately."
        )
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()
