"""Flask UI for ReconScript with consent enforcement and RBAC."""

from __future__ import annotations

import json
import logging
import os
import uuid
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
    current_app,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from .consent import ConsentError, load_manifest, validate_manifest
from .core import ReconError, run_recon
from .logging import configure_logging
from .report import ensure_results_dir, persist_report
from .scope import validate_target

LOGGER = logging.getLogger(__name__)


class StaticUser(UserMixin):
    def __init__(self, username: str, role: str) -> None:
        self.id = username
        self.role = role


def _load_secret_key() -> bytes:
    secret_path = Path(os.environ.get("FLASK_SECRET_KEY_FILE", "keys/dev_flask_secret.key"))
    try:
        return secret_path.read_bytes().strip()
    except OSError as exc:
        raise RuntimeError(f"Unable to read Flask secret key from {secret_path}: {exc}") from exc


def _rbac_required(role: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_app.config.get("RBAC_ENABLED") and getattr(current_user, "role", None) != role:
                abort(403)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def _load_user_credentials() -> tuple[str, str]:
    username = os.environ.get("ADMIN_USER", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "changeme")
    return username, password


def _store_upload(file_storage) -> Path:
    upload_dir = ensure_results_dir() / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    filename = f"manifest-{uuid.uuid4().hex}.json"
    path = upload_dir / filename
    file_storage.save(path)
    return path


def create_app() -> Flask:
    configure_logging()

    public_ui = os.environ.get("ENABLE_PUBLIC_UI", "false").lower() == "true"
    rbac_enabled = os.environ.get("ENABLE_RBAC", "false").lower() == "true"
    if public_ui and not rbac_enabled:
        raise RuntimeError("ENABLE_PUBLIC_UI=true requires ENABLE_RBAC=true to protect access.")

    app = Flask(__name__)
    app.config["RBAC_ENABLED"] = rbac_enabled
    app.config["PUBLIC_UI"] = public_ui
    app.config["UPLOAD_FOLDER"] = str(ensure_results_dir() / "uploads")
    app.secret_key = _load_secret_key()

    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    username, password = _load_user_credentials()
    user = StaticUser(username, "admin")

    @login_manager.user_loader
    def load_user(user_id: str) -> Optional[StaticUser]:  # pragma: no cover - simple lookup
        if user_id == user.id:
            return user
        return None

    @app.context_processor
    def inject_globals():
        return {
            "public_ui": app.config["PUBLIC_UI"],
            "rbac_enabled": app.config["RBAC_ENABLED"],
        }

    @app.route("/healthz")
    def health() -> tuple[str, int]:
        return "ok", 200

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            submitted_user = request.form.get("username", "")
            submitted_pass = request.form.get("password", "")
            if submitted_user == username and submitted_pass == password:
                login_user(user)
                return redirect(url_for("index"))
            flash("Invalid credentials", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for("login"))

    def _handle_manifest() -> tuple[Optional[Path], Optional[object]]:
        file = request.files.get("consent_file")
        if not file or not file.filename:
            return None, None
        temp_path = _store_upload(file)
        manifest = load_manifest(temp_path)
        validate_manifest(manifest)
        return temp_path, manifest

    @app.route("/", methods=["GET", "POST"])
    @login_required
    @_rbac_required("admin")
    def index():
        if request.method == "POST":
            target = request.form.get("target", "")
            expected_ip = request.form.get("expected_ip") or None
            hostname = request.form.get("hostname") or None
            evidence_level = request.form.get("evidence_level", "low")
            ports_raw = request.form.get("ports", "")
            ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip()] if ports_raw else None
            try:
                validate_target(target, expected_ip=expected_ip)
            except Exception as exc:
                flash(str(exc), "error")
                return render_template("index.html")

            consent_path: Optional[Path] = None
            consent_manifest = None
            try:
                consent_path, consent_manifest = _handle_manifest()
            except ConsentError as exc:
                flash(f"Consent manifest invalid: {exc}", "error")
                if consent_path:
                    consent_path.unlink(missing_ok=True)
                return render_template("index.html")

            try:
                report = run_recon(
                    target=target,
                    hostname=hostname,
                    ports=ports,
                    expected_ip=expected_ip,
                    evidence_level=evidence_level,
                    consent_manifest=consent_manifest,
                )
            except ReconError as exc:
                flash(str(exc), "error")
                if consent_path:
                    consent_path.unlink(missing_ok=True)
                return render_template("index.html")

            persisted = persist_report(report, consent_source=consent_path, sign=False)
            if consent_path:
                consent_path.unlink(missing_ok=True)
            return redirect(url_for("report_detail", report_id=persisted.report_id))
        return render_template("index.html")

    @app.route("/reports/<report_id>")
    @login_required
    @_rbac_required("admin")
    def report_detail(report_id: str):
        report_dir = ensure_results_dir() / report_id
        report_file = report_dir / "report.json"
        if not report_file.exists():
            abort(404)
        report_data = json.loads(report_file.read_text(encoding="utf-8"))
        return render_template("report_detail.html", report=report_data, report_id=report_id)

    @app.route("/results/<path:filename>")
    @login_required
    @_rbac_required("admin")
    def download_result(filename: str):
        return send_from_directory(ensure_results_dir(), filename, as_attachment=True)

    return app


def main() -> None:
    app = create_app()
    host = "0.0.0.0" if app.config["PUBLIC_UI"] else "127.0.0.1"
    port = int(os.environ.get("DEFAULT_PORT", "5000"))
    LOGGER.warning("UI running with RBAC %s", "enabled" if app.config["RBAC_ENABLED"] else "disabled")
    if app.config["PUBLIC_UI"]:
        LOGGER.warning("Public UI mode enabled — ensure reverse proxy protections are in place.")
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()


