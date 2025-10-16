from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("flask")

from reconscript import ui


@pytest.fixture
def configured_app(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))

    def fake_run_recon(target, hostname, ports, **_):
        return {
            "target": target,
            "hostname": hostname,
            "ports": ports,
            "open_ports": ports,
            "findings": [],
            "runtime": {"duration": 1.2},
        }

    def fake_write_report(report, outfile, fmt):
        path = Path(outfile)
        path.write_text("<html></html>", encoding="utf-8")
        return path, fmt

    class ImmediateThread:
        def __init__(self, target, args=(), kwargs=None, daemon=None):
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self):
            self._target(*self._args, **self._kwargs)

    monkeypatch.setattr(ui, "run_recon", fake_run_recon)
    monkeypatch.setattr(ui, "write_report", fake_write_report)
    monkeypatch.setattr(ui.threading, "Thread", ImmediateThread)

    app = ui.create_app()
    app.config.update(TESTING=True)
    return app


def test_scan_endpoint_requires_target(configured_app):
    client = configured_app.test_client()
    response = client.post("/api/scan", json={"ports": "80"})
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert "Target" in payload["message"]


def test_scan_endpoint_generates_report_and_lists_results(configured_app, tmp_path):
    client = configured_app.test_client()
    response = client.post(
        "/api/scan",
        json={"target": "127.0.0.1", "ports": "8080", "format": "html"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    job_id = payload["job_id"]

    # Consume the stream to ensure the background job completed.
    stream_response = client.get(f"/stream/{job_id}")
    stream_body = b"".join(stream_response.response)
    assert b"complete" in stream_body

    results_page = client.get("/results")
    assert results_page.status_code == 200
    assert "Saved Reports" in results_page.get_data(as_text=True)

    files = sorted(tmp_path.glob("*.html"))
    assert files, "Expected report file to be written"


def test_health_endpoint_ready(configured_app):
    client = configured_app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
