"""Core scanning primitives for ReconScript.

This module provides the reusable building blocks for the ReconScript
command-line interface. It keeps all network interactions narrowly scoped
and auditable so that the tool remains appropriate for defensive, read-only
assessments.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie, CookieError
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

LOGGER = logging.getLogger(__name__)

# Default port list focuses on common web stacks and developer tooling.
DEFAULT_PORTS: Tuple[int, ...] = (80, 443, 8080, 8443, 8000, 3000)

# HTTP ports to probe for additional metadata after the TCP scan.
HTTP_PORTS: Tuple[int, ...] = (80, 443, 8080, 8443, 8000, 3000)

# Default timeouts are conservative to keep the tool responsive while polite.
DEFAULT_SOCKET_TIMEOUT: float = 3.0
DEFAULT_HTTP_TIMEOUT: float = 8.0

# Default retry/backoff guidance balances resilience with restraint.
DEFAULT_MAX_RETRIES: int = 2
DEFAULT_BACKOFF: float = 0.5

# User agent string highlights defensive purpose for transparency.
USER_AGENT: str = "ReconScript/0.2 (authorized security review)"


@dataclass
class ScanConfig:
    """Configuration values controlling the reconnaissance workflow."""

    target: str
    hostname: Optional[str]
    ports: Sequence[int]
    socket_timeout: float
    http_timeout: float
    max_retries: int
    backoff: float
    throttle: float
    enable_ipv6: bool


def validate_port_list(ports: Iterable[int]) -> Tuple[int, ...]:
    """Return a sanitized tuple of TCP ports.

    This guard prevents accidental scanning of invalid or privileged ranges.
    """

    validated: List[int] = []
    for port in ports:
        if not isinstance(port, int):
            raise TypeError(f"Port values must be integers; received {port!r}")
        if port <= 0 or port > 65535:
            raise ValueError(f"Port out of valid range (1-65535): {port}")
        validated.append(port)
    return tuple(dict.fromkeys(validated))


def normalize_target(target: str) -> str:
    """Ensure that the supplied target string is a valid IP address."""

    try:
        ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Target must be a valid IPv4 or IPv6 address") from exc
    return target


def resolve_addresses(target: str, enable_ipv6: bool) -> List[Tuple[int, int, int, str, Tuple[str, int]]]:
    """Resolve the given target into socket address tuples.

    The result mirrors ``socket.getaddrinfo`` output to support both IPv4 and
    IPv6 lookups. IPv6 resolution remains opt-in to minimise unexpected
    traffic.
    """

    family = socket.AF_UNSPEC if enable_ipv6 else socket.AF_INET
    try:
        return socket.getaddrinfo(target, None, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise RuntimeError(f"Unable to resolve target address: {error}") from error


def create_http_session(timeout: float, max_retries: int, backoff: float) -> requests.Session:
    """Construct a ``requests`` session with retry handling."""

    # Retry policy avoids aggressive traffic while handling transient network errors.
    retry_policy = Retry(
        total=max_retries,
        read=max_retries,
        connect=max_retries,
        backoff_factor=backoff,
        status_forcelist=(408, 429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
    )

    adapter = HTTPAdapter(max_retries=retry_policy)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Store timeout on the session for consistent caller behaviour.
    session.request = _timeout_wrapper(session.request, timeout)  # type: ignore[assignment]
    return session


def _timeout_wrapper(original_request, timeout: float):  # type: ignore[no-untyped-def]
    """Wrap ``Session.request`` to inject a default timeout."""

    def wrapper(method: str, url: str, **kwargs):  # type: ignore[no-untyped-def]
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        return original_request(method, url, **kwargs)

    return wrapper


def tcp_connect_scan(
    config: ScanConfig,
    ports: Sequence[int],
    throttle: float,
) -> List[int]:
    """Perform TCP connect scans against each requested port.

    The scan uses ``socket.create_connection`` with strict timeouts and
    optional throttling to remain polite within authorised scopes.
    """

    open_ports: List[int] = []
    # Resolve addresses once to avoid repeated DNS lookups during the scan.
    addresses = resolve_addresses(config.target, config.enable_ipv6)
    for port in ports:
        # ``time.sleep`` offers a straightforward rate limiter between probes.
        if throttle:
            time.sleep(throttle)
        success = False
        for family, _socktype, _proto, _canon, sockaddr in addresses:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            host = sockaddr[0]
            try:
                with socket.create_connection((host, port), timeout=config.socket_timeout) as sock:
                    sock.settimeout(config.socket_timeout)
                success = True
                break
            except (socket.timeout, ConnectionRefusedError, OSError) as error:
                LOGGER.debug("Port %s closed on %s (%s)", port, host, error)
                continue
        if success:
            open_ports.append(port)
    return open_ports


def parse_cookie_flags(response: Response) -> Optional[Dict[str, bool]]:
    """Extract Secure/HttpOnly attributes from HTTP cookies."""

    # Collect raw Set-Cookie header strings to retain attribute flags.
    header_values: List[str] = []
    if hasattr(response.raw, "headers"):
        raw_headers = response.raw.headers
        if hasattr(raw_headers, "getlist"):
            header_values.extend(raw_headers.getlist("Set-Cookie"))  # type: ignore[attr-defined]
        elif hasattr(raw_headers, "get_all"):
            header_values.extend(raw_headers.get_all("Set-Cookie"))  # type: ignore[attr-defined]
    if not header_values:
        header = response.headers.get("Set-Cookie")
        if header:
            header_values.append(header)
    if not header_values:
        return None

    secure_flag = False
    httponly_flag = False
    for value in header_values:
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except (CookieError, AttributeError):
            # Fallback: simple string matching when parsing fails.
            lowered = value.lower()
            secure_flag = secure_flag or ("secure" in lowered)
            httponly_flag = httponly_flag or ("httponly" in lowered)
            continue
        for morsel in cookie.values():
            secure_flag = secure_flag or bool(morsel["secure"])
            httponly_flag = httponly_flag or bool(morsel["httponly"])
    return {"secure": secure_flag, "httponly": httponly_flag}


def check_security_headers(headers: Dict[str, str]) -> Dict[str, object]:
    """Evaluate a response for common security headers."""

    required_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "Referrer-Policy": "Referrer policy",
        "Permissions-Policy": "Permissions policy",
        "X-Content-Type-Options": "MIME sniffing protection",
        "X-XSS-Protection": "Legacy XSS filter",
    }

    present: Dict[str, str] = {}
    missing: List[str] = []
    header_keys = {key.lower(): key for key in headers.keys()}
    for header in required_headers:
        lowered = header.lower()
        if lowered in header_keys:
            present[header] = headers[header_keys[lowered]]
        else:
            missing.append(header)

    return {"present": present, "missing": missing}


def probe_http_service(
    session: requests.Session,
    host_or_ip: str,
    port: int,
) -> Dict[str, object]:
    """Request HTTP(S) metadata for the specified endpoint."""

    scheme = "https" if port in (443, 8443) else "http"
    # Avoid duplicating the port in the URL for default schemes.
    if port in (80, 443):
        url = f"{scheme}://{host_or_ip}"
    else:
        url = f"{scheme}://{host_or_ip}:{port}"

    try:
        response = session.get(url, allow_redirects=True)
    except requests.exceptions.SSLError as error:
        LOGGER.warning("TLS negotiation failed for %s:%s: %s", host_or_ip, port, error)
        return {"error": f"TLS error: {error}"}
    except requests.exceptions.Timeout:
        LOGGER.warning("HTTP request to %s timed out", url)
        return {"error": "request timed out"}
    except requests.exceptions.RequestException as error:
        LOGGER.warning("HTTP request to %s failed: %s", url, error)
        return {"error": str(error)}

    result: Dict[str, object] = {
        "url": response.url,
        "status_code": response.status_code,
        "server_headers": dict(response.headers),
        "body_snippet": response.text[:2000].replace("\n", " "),
    }

    cookie_flags = parse_cookie_flags(response)
    if cookie_flags:
        result["cookie_flags"] = cookie_flags

    result["security_headers_check"] = check_security_headers(result["server_headers"])
    return result


def fetch_tls_certificate(
    config: ScanConfig,
    port: int,
) -> Dict[str, object]:
    """Collect TLS certificate details for the endpoint."""

    context = ssl.create_default_context()
    context.check_hostname = False

    addresses = resolve_addresses(config.target, config.enable_ipv6)
    for family, _, _, _, sockaddr in addresses:
        host = sockaddr[0]
        try:
            with socket.create_connection((host, port), timeout=config.socket_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=config.hostname or config.target) as wrapped:
                    certificate = wrapped.getpeercert()
                    if not certificate:
                        continue
                    return {
                        "subject": dict(entry[0] for entry in certificate.get("subject", [])),
                        "issuer": dict(entry[0] for entry in certificate.get("issuer", [])),
                        "notBefore": certificate.get("notBefore"),
                        "notAfter": certificate.get("notAfter"),
                        "serialNumber": certificate.get("serialNumber"),
                    }
        except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as error:
            LOGGER.warning("TLS retrieval failed on %s:%s: %s", host, port, error)
            continue
    return {"error": "unable to retrieve TLS certificate"}


def fetch_robots(session: requests.Session, host_or_ip: str) -> Dict[str, object]:
    """Fetch robots.txt with preference for HTTPS."""

    for scheme in ("https", "http"):
        url = f"{scheme}://{host_or_ip}/robots.txt"
        try:
            response = session.get(url, allow_redirects=True)
        except requests.exceptions.RequestException as error:
            LOGGER.debug("Robots fetch failed for %s: %s", url, error)
            continue
        if response.status_code == 200 and response.text.strip():
            return {"url": url, "body": response.text[:2000]}
    return {"note": "robots.txt not present or inaccessible"}


def generate_findings(http_results: Dict[int, Dict[str, object]]) -> List[Dict[str, object]]:
    """Create a summary of noteworthy observations for the report."""

    findings: List[Dict[str, object]] = []
    for port, result in http_results.items():
        headers = result.get("security_headers_check")
        if isinstance(headers, dict):
            missing = headers.get("missing", [])
            if missing:
                findings.append(
                    {
                        "port": port,
                        "issue": "missing_security_headers",
                        "details": missing,
                    }
                )
        cookie_flags = result.get("cookie_flags")
        if isinstance(cookie_flags, dict) and (
            not cookie_flags.get("secure") or not cookie_flags.get("httponly")
        ):
            findings.append(
                {
                    "port": port,
                    "issue": "session_cookie_flags",
                    "details": cookie_flags,
                }
            )
        status_code = result.get("status_code")
        if isinstance(status_code, int) and status_code >= 500:
            findings.append(
                {
                    "port": port,
                    "issue": "server_error",
                    "details": status_code,
                }
            )
    return findings


def serialize_results(data: Dict[str, object]) -> str:
    """Return a JSON-formatted string for reporting."""

    return json.dumps(data, indent=2)
