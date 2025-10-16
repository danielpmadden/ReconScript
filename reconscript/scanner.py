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
from http.cookies import CookieError, SimpleCookie
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests import Response

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
USER_AGENT: str = "ReconScript/0.3 (authorized security review)"


def _max_attempts(max_retries: int) -> int:
    """Return the total number of attempts including the first try."""

    return max(1, min(3, 1 + max_retries))


def _backoff_delay(backoff: float, attempt: int) -> float:
    """Calculate the exponential backoff delay for the next retry."""

    if attempt <= 1 or backoff <= 0:
        return 0.0
    return backoff * (2 ** (attempt - 2))


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


def create_http_session(timeout: float) -> requests.Session:
    """Construct a ``requests`` session with consistent timeout handling."""

    # Retrying is handled explicitly in the HTTP helper to keep policy visible.
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

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
    optional throttling (expressed in seconds) to remain polite within
    authorised scopes.
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

    secure_flag = False
    httponly_flag = False

    # Leverage ``requests`` cookies first as they handle folding across headers.
    cookie_jar = getattr(response, "cookies", None)
    if cookie_jar is not None:
        for cookie in cookie_jar:  # type: ignore[not-an-iterable]
            secure_flag = secure_flag or getattr(cookie, "secure", False)
            rest = getattr(cookie, "rest", {})
            httponly_flag = httponly_flag or bool(
                rest.get("HttpOnly") or rest.get("httponly")
            )
            has_nonstandard = getattr(cookie, "has_nonstandard_attr", None)
            if callable(has_nonstandard):
                httponly_flag = httponly_flag or bool(has_nonstandard("HttpOnly"))

    # Collect raw Set-Cookie header strings to retain attribute flags.
    header_values: List[str] = []
    if hasattr(response, "raw") and hasattr(response.raw, "headers"):
        raw_headers = response.raw.headers
        if hasattr(raw_headers, "getlist"):
            header_values.extend(raw_headers.getlist("Set-Cookie"))  # type: ignore[attr-defined]
        elif hasattr(raw_headers, "get_all"):
            header_values.extend(raw_headers.get_all("Set-Cookie"))  # type: ignore[attr-defined]
    if not header_values:
        header = response.headers.get("Set-Cookie")
        if header:
            header_values.append(header)

    observed_cookies = bool(header_values) or bool(cookie_jar and len(cookie_jar))
    if not observed_cookies:
        return None

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
            # ``morsel['secure']`` and ``morsel['httponly']`` are empty strings when
            # present, so check for non-None values rather than relying on truthiness.
            secure_flag = secure_flag or morsel["secure"] is not None and morsel["secure"] != ""
            httponly_flag = httponly_flag or (
                morsel["httponly"] is not None and morsel["httponly"] != ""
            )

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
    max_retries: int,
    backoff: float,
) -> Dict[str, object]:
    """Request HTTP(S) metadata for the specified endpoint."""

    scheme = "https" if port in (443, 8443) else "http"
    # Avoid duplicating the port in the URL for default schemes.
    if port in (80, 443):
        url = f"{scheme}://{host_or_ip}"
    else:
        url = f"{scheme}://{host_or_ip}:{port}"

    attempts = _max_attempts(max_retries)
    last_error: Optional[Exception] = None
    response: Optional[Response] = None
    for attempt in range(1, attempts + 1):
        try:
            response = session.get(url, allow_redirects=True)
            break
        except requests.exceptions.SSLError as error:
            LOGGER.warning("TLS negotiation failed for %s:%s: %s", host_or_ip, port, error)
            return {"error": f"TLS error: {error}"}
        except requests.exceptions.Timeout as error:
            last_error = error
            LOGGER.warning("HTTP request to %s timed out (attempt %s/%s)", url, attempt, attempts)
        except requests.exceptions.RequestException as error:
            last_error = error
            LOGGER.warning("HTTP request to %s failed (attempt %s/%s): %s", url, attempt, attempts, error)

        if attempt == attempts:
            if isinstance(last_error, requests.exceptions.Timeout):
                return {"error": "request timed out"}
            return {"error": str(last_error) if last_error else "request failed"}

        delay = _backoff_delay(backoff, attempt + 1)
        if delay:
            time.sleep(delay)

    if response is None:
        return {"error": str(last_error) if last_error else "request failed"}

    result: Dict[str, object] = {
        "url": response.url,
        "status_code": response.status_code,
        "server_headers": dict(response.headers),
        "body_snippet": response.text[:2000].replace("\n", " "),
    }

    cookie_flags = parse_cookie_flags(response)
    if cookie_flags is not None:
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
    attempts = _max_attempts(config.max_retries)
    for attempt in range(1, attempts + 1):
        for family, _, _, _, sockaddr in addresses:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            host = sockaddr[0]
            try:
                with socket.create_connection((host, port), timeout=config.socket_timeout) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=config.hostname or config.target
                    ) as wrapped:
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
                LOGGER.warning(
                    "TLS retrieval failed on %s:%s (attempt %s/%s): %s",
                    host,
                    port,
                    attempt,
                    attempts,
                    error,
                )
                continue
        if attempt < attempts:
            delay = _backoff_delay(config.backoff, attempt + 1)
            if delay:
                time.sleep(delay)
    return {"error": "unable to retrieve TLS certificate"}


def fetch_robots(
    session: requests.Session,
    host_or_ip: str,
    max_retries: int,
    backoff: float,
) -> Dict[str, object]:
    """Fetch robots.txt with preference for HTTPS."""

    attempts = _max_attempts(max_retries)
    for scheme in ("https", "http"):
        url = f"{scheme}://{host_or_ip}/robots.txt"
        last_error: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                response = session.get(url, allow_redirects=True)
            except requests.exceptions.RequestException as error:
                last_error = error
                LOGGER.debug(
                    "Robots fetch failed for %s (attempt %s/%s): %s",
                    url,
                    attempt,
                    attempts,
                    error,
                )
            else:
                if response.status_code == 200 and response.text.strip():
                    return {"url": url, "body": response.text[:2000]}
                if response.status_code == 404:
                    break
            if attempt == attempts:
                break
            delay = _backoff_delay(backoff, attempt + 1)
            if delay:
                time.sleep(delay)
        if last_error:
            LOGGER.debug("Robots retrieval ultimately failed for %s: %s", url, last_error)
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
