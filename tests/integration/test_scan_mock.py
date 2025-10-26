# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""Integration tests for safe-profile scans against a local mock server."""

import http.server
import json
import shutil
import socketserver
import threading

import pytest

from reconscript.core import run_recon
from reconscript.report import compute_report_hash, persist_report


class MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "session=abc; HttpOnly")
        self.end_headers()
        self.wfile.write(b"mock response body")

    def log_message(self, format: str, *args) -> None:  # noqa: N802
        return


@pytest.fixture(scope="module")
def mock_server() -> tuple[str, int]:
    server = socketserver.TCPServer(("127.0.0.1", 0), MockHandler)
    server.allow_reuse_address = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address
    server.shutdown()
    server.server_close()


@pytest.mark.integration
def test_safe_profile_generates_required_metadata(mock_server) -> None:
    host, port = mock_server
    report = run_recon(target=host, ports=[port], evidence_level="low")

    tcp_artifacts = report["artifacts"]["tcp"]
    assert port in tcp_artifacts["open_ports"]

    for finding in report["findings"]:
        assert {
            "tool",
            "cmdline",
            "summary",
            "started_at",
            "completed_at",
            "raw_snippet",
        }.issubset(finding)
        assert len(finding["raw_snippet"]) <= 400

    persisted = persist_report(report)
    try:
        report_data = json.loads(persisted.report_file.read_text(encoding="utf-8"))
        stored_hash = report_data["report_hash"]
        assert stored_hash == compute_report_hash(report_data)
        assert report_data["metadata"]["profile"]["name"].startswith("safe")
        assert all(len(f["raw_snippet"]) <= 400 for f in report_data["findings"])
    finally:
        shutil.rmtree(persisted.base, ignore_errors=True)
