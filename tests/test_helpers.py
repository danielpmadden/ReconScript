"""Unit tests for helper functions in the ReconScript package."""

from __future__ import annotations

from typing import Dict

import pytest
from requests import Response
from requests.structures import CaseInsensitiveDict

from reconscript.core import check_security_headers, generate_findings, parse_cookie_flags


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


def _build_response(headers: Dict[str, str], raw_headers: Dict[str, list[str]] | None = None) -> Response:
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
