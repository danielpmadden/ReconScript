from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("flask")

import web_ui


@pytest.fixture(autouse=True)
def clean_jobs():
    with web_ui._jobs_lock:
        web_ui._jobs.clear()
    yield
    with web_ui._jobs_lock:
        web_ui._jobs.clear()


def test_web_ui_start_job_creates_report(tmp_path, monkeypatch):
    def fake_run_recon(**kwargs):
        return {
            "target": kwargs["target"],
            "ports": kwargs["ports"],
            "open_ports": kwargs["ports"],
            "findings": [],
            "started_at": "2024-05-01T12:00:00Z",
            "runtime": {"duration": 1.0},
        }

    def fake_default_output_path(target, started_at, extension):
        return tmp_path / f"{target}.{extension}"

    def fake_write_report(report, outfile, fmt):
        path = Path(outfile)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ok", encoding="utf-8")
        return path, "html"

    def fake_render_html(report, out_path):
        Path(out_path).write_text("<html></html>", encoding="utf-8")
        return Path(out_path)

    def fake_render_json(report):
        return "{}"

    class ImmediateThread:
        def __init__(self, target, args=(), kwargs=None, daemon=None):
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self):
            self._target(*self._args, **self._kwargs)

    monkeypatch.setattr(web_ui, "run_recon", fake_run_recon)
    monkeypatch.setattr(web_ui, "default_output_path", fake_default_output_path)
    monkeypatch.setattr(web_ui, "write_report", fake_write_report)
    monkeypatch.setattr(web_ui, "render_html", fake_render_html)
    monkeypatch.setattr(web_ui, "render_json", fake_render_json)
    monkeypatch.setattr(web_ui.threading, "Thread", ImmediateThread)

    client = web_ui.app.test_client()
    response = client.post(
        "/start",
        data={
            "target": "127.0.0.1",
            "ports": "8080",
            "format": "html",
            "socket_timeout": "1",
            "http_timeout": "1",
            "throttle": "0.1",
        },
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    location = response.headers["Location"]
    job_id = location.rsplit("/", 1)[-1]

    status_response = client.get(location, environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert status_response.status_code == 200
    assert "Reports" in status_response.get_data(as_text=True)

    with web_ui._jobs_lock:
        job = web_ui._jobs[job_id]
    assert job["status"] == "completed"
    assert "html" in job["outputs"]
    assert job["outputs"]["html"].endswith("127.0.0.1.html")
