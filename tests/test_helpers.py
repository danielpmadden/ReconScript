"""Unit tests for helper functions in the ReconScript package."""

from __future__ import annotations

from typing import Dict

import pytest
from requests import Response
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict

from reconscript.core import (
    check_security_headers,
    generate_findings,
    parse_cookie_flags,
    run_recon,
)
from reconscript.scanner import create_http_session, fetch_robots


class _HeaderCollector:
    """Utility header container emulating urllib3's API."""

    def __init__(self, header_map: Dict[str, list[str]]):
        self._header_map = header_map

    def getlist(self, name: str):
        return self._header_map.get(name, [])


class _RawResponse:
    """Simple stand-in for ``response.raw`` used in cookie parsing."""

    def __init__(self, header_map: Dict[str, list[str]]):
        self.headers = _HeaderCollector(header_map)


def _build_response(
    headers: Dict[str, str],
    raw_headers: Dict[str, list[str]] | None = None,
) -> Response:
    """Create a minimal ``Response`` object for testing."""

    response = Response()
    response.status_code = 200
    response._content = b"test"  # type: ignore[attr-defined]
    response.headers = CaseInsensitiveDict(headers)
    if raw_headers is not None:
        response.raw = _RawResponse(raw_headers)  # type: ignore[attr-defined]
    return response


def test_check_security_headers_identifies_missing_headers():
    headers = {"Content-Security-Policy": "default-src 'self'"}

    result = check_security_headers(headers)

    assert "Content-Security-Policy" in result["present"]
    assert "Strict-Transport-Security" in result["missing"]


@pytest.mark.parametrize(
    "raw_headers,expected",
    [
        ({"Set-Cookie": ["session=value; Secure; HttpOnly"]}, {"secure": True, "httponly": True}),
        (
            {"Set-Cookie": ["session=value; Secure", "prefs=test; HttpOnly"]},
            {"secure": True, "httponly": True},
        ),
    ],
)
def test_parse_cookie_flags_handles_multiple_headers(raw_headers, expected):
    response = _build_response({}, raw_headers)

    result = parse_cookie_flags(response)

    assert result == expected


def test_generate_findings_reports_issues():
    http_results = {
        80: {
            "security_headers_check": {"missing": ["Strict-Transport-Security"]},
            "cookie_flags": {"secure": False, "httponly": True},
            "status_code": 503,
        }
    }

    findings = generate_findings(http_results)

    issues = {finding["issue"] for finding in findings}
    assert {"missing_security_headers", "session_cookie_flags", "server_error"} <= issues


def test_parse_cookie_flags_uses_cookie_jar():
    response = _build_response({})
    jar = RequestsCookieJar()
    jar.set("session", "value", secure=True, rest={"HttpOnly": True})
    response.cookies = jar  # type: ignore[attr-defined]

    result = parse_cookie_flags(response)

    assert result == {"secure": True, "httponly": True}


def test_run_recon_dry_run_skips_network(monkeypatch):
    def _fail(*_args, **_kwargs):
        raise AssertionError("network helper should not be invoked during dry-run")

    monkeypatch.setattr("reconscript.core.tcp_connect_scan", _fail)
    monkeypatch.setattr("reconscript.core.probe_http_service", _fail)
    monkeypatch.setattr("reconscript.core.fetch_tls_certificate", _fail)
    monkeypatch.setattr("reconscript.core.fetch_robots", _fail)

    report = run_recon(
        target="127.0.0.1",
        hostname=None,
        ports=[80, 443],
        dry_run=True,
    )

    assert report["plan"]["tcp_ports_to_probe"] == [80, 443]
    assert report["scan_config"]["dry_run"] is True


def test_fetch_robots_prefers_https():
    responses = pytest.importorskip("responses")
    with responses.RequestsMock() as rs:
        rs.add(
            method=responses.GET,
            url="https://example.com/robots.txt",
            body="User-agent: *\nAllow: /",
            status=200,
        )

        session = create_http_session(timeout=1)
        result = fetch_robots(session, "example.com", max_retries=0, backoff=0.1)

    assert result["url"].startswith("https://")
    assert "User-agent" in result["body"]
