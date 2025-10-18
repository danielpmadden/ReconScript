"""Flask UI for ReconScript with consent enforcement and RBAC."""

from __future__ import annotations

import json
import logging
import os
import platform
import secrets
import socket
import threading
import time
import uuid
import webbrowser
from functools import wraps
from pathlib import Path
from typing import Optional

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_talisman import Talisman

from . import __version__
from .config import load_environment
from .consent import ConsentError, load_manifest, validate_manifest
from .core import ReconError, run_recon
from .logging_utils import configure_logging, get_recent_logs
from .report import ensure_results_dir, persist_report
from .scope import validate_target

LOGGER = logging.getLogger(__name__)

CSP_POLICY = {
    "default-src": "'self'",
    "script-src": "'self' 'unsafe-inline'",
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data:",
}

CSRF_HEADER_NAME = "X-CSRF-Token"


def _generate_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _validate_csrf() -> None:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = session.get("_csrf_token")
        submitted = request.form.get("csrf_token") or request.headers.get(CSRF_HEADER_NAME)
        if not token or not submitted or not secrets.compare_digest(str(token), str(submitted)):
            abort(400)


def _normalize_download_path(filename: str) -> str:
    path = Path(filename)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        abort(400)
    return str(path)


def _preferred_browser_host(bound_host: str) -> str:
    if os.environ.get("WSL_INTEROP"):
        return "localhost"
    if bound_host in {"0.0.0.0", "::"}:
        for candidate in ("host.docker.internal", "docker.for.mac.host.internal", "127.0.0.1"):
            try:
                socket.gethostbyname(candidate)
                return candidate
            except socket.gaierror:
                continue
        return "127.0.0.1"
    return bound_host


def _auto_launch_browser(host: str, port: int) -> None:
    if os.environ.get("RECON_AUTOLAUNCH", "true").lower() != "true":
        return

    url = f"http://{_preferred_browser_host(host)}:{port}/"

    def _opener() -> None:
        time.sleep(1.5)
        try:
            webbrowser.open(url, new=2, autoraise=True)
        except Exception as exc:  # pragma: no cover - best effort helper
            LOGGER.debug("Browser auto-launch failed: %s", exc)

    threading.Thread(target=_opener, name="reconscript-browser", daemon=True).start()


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
    load_environment()
    configure_logging()

    public_ui = os.environ.get("ENABLE_PUBLIC_UI", "false").lower() == "true"
    rbac_enabled = os.environ.get("ENABLE_RBAC", "false").lower() == "true"
    if public_ui and not rbac_enabled:
        raise RuntimeError("ENABLE_PUBLIC_UI=true requires ENABLE_RBAC=true to protect access.")

    app = Flask(__name__)
    app.config["RBAC_ENABLED"] = rbac_enabled
    app.config["PUBLIC_UI"] = public_ui
    app.config["UPLOAD_FOLDER"] = str(ensure_results_dir() / "uploads")
    app.config["DEPLOYMENT_ENV"] = os.environ.get("RECON_ENV", "production")
    app.secret_key = _load_secret_key()

    Talisman(
        app,
        content_security_policy=CSP_POLICY,
        frame_options="DENY",
        referrer_policy="no-referrer",
        force_https=False,
        session_cookie_secure=public_ui,
        session_cookie_http_only=True,
        session_cookie_samesite="Strict",
        permissions_policy={
            "geolocation": "()",
            "camera": "()",
            "microphone": "()",
        },
    )

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
            "csrf_token": _generate_csrf_token,
            "recon_version": __version__,
            "deployment_env": app.config["DEPLOYMENT_ENV"],
            "python_version": platform.python_version(),
        }

    @app.before_request
    def _csrf_hook() -> None:
        _validate_csrf()

    @app.errorhandler(500)
    def handle_internal_error(exc: Exception):  # pragma: no cover - defensive
        LOGGER.exception("Unhandled exception in UI: %s", exc)
        return render_template("error.html", message="An unexpected error occurred. Please review the logs."), 500

    @app.route("/health", methods=["GET"])
    def health() -> tuple[str, int]:
        return jsonify(status="ok", version=__version__), 200

    @app.route("/healthz", methods=["GET"])
    def legacy_health() -> tuple[str, int]:
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
        safe_name = _normalize_download_path(filename)
        return send_from_directory(ensure_results_dir(), safe_name, as_attachment=True)

    @app.route("/logs/feed")
    @login_required
    @_rbac_required("admin")
    def logs_feed():
        limit = int(request.args.get("limit", "50"))
        return jsonify(entries=get_recent_logs(limit=limit))

    return app


def main() -> None:
    app = create_app()
    host = os.environ.get("RECON_HOST") or ("0.0.0.0" if app.config["PUBLIC_UI"] else "127.0.0.1")
    port = int(os.environ.get("DEFAULT_PORT", "5000"))
    LOGGER.warning("UI running with RBAC %s", "enabled" if app.config["RBAC_ENABLED"] else "disabled")
    if app.config["PUBLIC_UI"]:
        LOGGER.warning("Public UI mode enabled — ensure reverse proxy protections are in place.")
    _auto_launch_browser(host, port)
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":  # pragma: no cover - manual invocation
    main()


