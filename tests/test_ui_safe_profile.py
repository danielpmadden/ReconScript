# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""UI tests ensuring authorization gating and report persistence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reconscript.ui import create_app


@pytest.fixture()
def ui_app(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("RESULTS_DIR", str(tmp_path))

    saved_report: dict[str, Any] = {
        "metadata": {
            "target": "127.0.0.1",
            "resolved_target": "127.0.0.1",
            "hostname": None,
            "version": "test",
            "evidence_level": "low",
            "profile": {
                "name": "test",
                "max_tcp_ports": 10,
                "tcp_concurrency": 2,
                "udp_pass": True,
                "dns_active": True,
                "dns_passive": True,
                "dir_enum": "low",
                "allow_credentialed": False,
                "timeouts": {},
                "rate_limits": {},
            },
            "consent_present": False,
            "scanned_tcp_ports": [80],
            "scanned_udp_ports": [53],
        },
        "artifacts": {},
        "findings": [
            {
                "tool": "test",
                "cmdline": "cmd --arg",
                "summary": "ok",
                "started_at": "2024-01-01T00:00:00Z",
                "completed_at": "2024-01-01T00:00:01Z",
                "raw_snippet": "evidence",
            }
        ],
    }

    def fake_run_recon(**_: Any) -> dict[str, Any]:
        return json.loads(json.dumps(saved_report))

    monkeypatch.setattr("reconscript.ui.run_recon", fake_run_recon)

    app = create_app()
    app.config.update(TESTING=True)
    return app


def test_ui_requires_authorization(ui_app) -> None:
    client = ui_app.test_client()
    response = client.post(
        "/",
        data={
            "target": "127.0.0.1",
            "evidence_level": "low",
            # No authorization checkbox
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "I have authorization" in response.get_data(as_text=True)


def test_ui_runs_scan_without_consent(ui_app, tmp_path: Path) -> None:
    client = ui_app.test_client()
    response = client.post(
        "/",
        data={
            "target": "127.0.0.1",
            "evidence_level": "low",
            "authorization": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    results_dir = Path(ui_app.config["UPLOAD_FOLDER"]).parent
    report_dirs = [path for path in results_dir.iterdir() if path.is_dir()]
    assert report_dirs, "Expected a persisted report directory"
    report_file = report_dirs[0] / "report.json"
    stored = json.loads(report_file.read_text(encoding="utf-8"))
    assert stored["findings"][0]["cmdline"] == "cmd --arg"
    assert len(stored["findings"][0]["raw_snippet"]) <= 400
