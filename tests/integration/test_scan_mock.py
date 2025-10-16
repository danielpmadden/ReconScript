from __future__ import annotations

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
def test_scan_low_and_medium_levels(mock_server) -> None:
    host, port = mock_server
    report_low = run_recon(target=host, ports=[port], evidence_level="low")
    assert port in report_low["open_ports"]

    persisted = persist_report(report_low)
    try:
        report_data = json.loads(persisted.report_file.read_text(encoding="utf-8"))
        stored_hash = report_data["report_hash"]
        assert stored_hash == compute_report_hash(report_data)

        http_data = report_data["http_checks"][str(port)]
        assert "raw_request" not in http_data
        assert "raw_response" not in http_data
        assert http_data["headers"]["Set-Cookie"] == "[redacted]"

        report_medium = run_recon(target=host, ports=[port], evidence_level="medium")
        http_medium = report_medium["http_checks"][port]
        assert http_medium.get("screenshots") == []
        assert "raw_response" not in http_medium
    finally:
        shutil.rmtree(persisted.base, ignore_errors=True)
