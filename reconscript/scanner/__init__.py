"""Scanning primitives for ReconScript with strict rate limiting."""

from __future__ import annotations

import json
import logging
import os
import random
import socket
import ssl
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie

import requests
from requests import Response
from requests import exceptions as requests_exceptions

from .throttle import TokenBucket

LOGGER = logging.getLogger(__name__)

DEFAULT_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 3000)
HTTP_PORTS: tuple[int, ...] = DEFAULT_PORTS
USER_AGENT = "ReconScript/secure"
RANDOM = random.SystemRandom()

TOKEN_RATE = float(os.environ.get("TOKEN_RATE", "5"))
TOKEN_CAPACITY = float(os.environ.get("TOKEN_CAPACITY", "10"))
HTTP_WORKERS = int(os.environ.get("HTTP_WORKERS", "2"))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "5"))
READ_TIMEOUT = float(os.environ.get("READ_TIMEOUT", "10"))
MAX_HTTP_RETRIES = int(os.environ.get("MAX_HTTP_RETRIES", "3"))

DEFAULT_REDACTIONS = {
    "cookie",
    "authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

_env_redactions = {
    entry.strip().lower()
    for entry in os.environ.get("REDACT_KEYS", "").split(",")
    if entry.strip()
}
REDACTION_KEYS = DEFAULT_REDACTIONS | _env_redactions


@dataclass(frozen=True)
class ScanConfig:
    target: str
    hostname: str | None
    ports: Sequence[int]
    enable_ipv6: bool
    evidence_level: str
    redaction_keys: set[str]
    connect_timeout: float = CONNECT_TIMEOUT
    read_timeout: float = READ_TIMEOUT
    http_workers: int = HTTP_WORKERS
    max_retries: int = MAX_HTTP_RETRIES


def validate_port_list(ports: Iterable[int]) -> tuple[int, ...]:
    validated: list[int] = []
    for port in ports:
        if not isinstance(port, int):
            raise TypeError("Ports must be integers.")
        if port <= 0 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535.")
        if port not in validated:
            validated.append(port)
    return tuple(validated)


def resolve_addresses(
    target: str, enable_ipv6: bool
) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    family = socket.AF_UNSPEC if enable_ipv6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(target, None, family=family, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"Unable to resolve target address: {exc}") from exc
    unique = []
    seen = set()
    for info in infos:
        sockaddr = info[-1]
        key = (info[0], sockaddr[0])
        if key in seen:
            continue
        seen.add(key)
        unique.append(info)
    return unique


def tcp_connect_scan(config: ScanConfig, bucket: TokenBucket) -> list[int]:
    LOGGER.info("Commencing TCP connect scan with token bucket rate limiting.")
    addresses = resolve_addresses(config.target, config.enable_ipv6)
    open_ports: list[int] = []
    for port in config.ports:
        bucket.consume()
        success = False
        for _family, _, _, _, sockaddr in addresses:
            host = sockaddr[0]
            try:
                with socket.create_connection(
                    (host, port), timeout=config.connect_timeout
                ):
                    success = True
                    break
            except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                LOGGER.debug("Port %s closed on %s (%s)", port, host, exc)
                continue
        if success:
            open_ports.append(port)
    return open_ports


def _build_url(hostname: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    if port in (80, 443):
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _redact_headers(
    headers: dict[str, str], redaction_keys: set[str]
) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        redact = lower in redaction_keys
        if lower.startswith("x-") and any(
            token in lower for token in ("auth", "token", "key")
        ):
            redact = True
        sanitized[key] = "[redacted]" if redact else value
    return sanitized


def _parse_cookie_flags(response: Response) -> dict[str, bool] | None:
    header_values: list[str] = []
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
        except CookieError:
            lowered = value.lower()
            secure_flag = secure_flag or ("secure" in lowered)
            httponly_flag = httponly_flag or ("httponly" in lowered)
            continue
        for morsel in cookie.values():
            secure_flag = secure_flag or bool(morsel["secure"])
            httponly_flag = httponly_flag or bool(morsel["httponly"])
    return {"secure": secure_flag, "httponly": httponly_flag}


def check_security_headers(headers: dict[str, str]) -> dict[str, object]:
    required_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "Referrer-Policy": "Referrer policy",
        "Permissions-Policy": "Permissions policy",
        "X-Content-Type-Options": "MIME sniffing protection",
        "X-XSS-Protection": "Legacy XSS filter",
    }

    present: dict[str, str] = {}
    missing: list[str] = []
    header_keys = {key.lower(): key for key in headers.keys()}
    for header in required_headers:
        lowered = header.lower()
        if lowered in header_keys:
            present[header] = headers[header_keys[lowered]]
        else:
            missing.append(header)
    return {"present": present, "missing": missing}


def _detect_external_redirect(expected_host: str, response: Response) -> str | None:
    expected = expected_host.lower()
    for hop in (*response.history, response):
        parsed = requests.utils.urlparse(hop.url)
        host = (parsed.hostname or "").lower()
        if host and host != expected:
            return hop.url
    return None


def _http_request(
    url: str, max_retries: int, connect_timeout: float, read_timeout: float
) -> tuple[Response | None, str | None]:
    headers = {"User-Agent": USER_AGENT}
    attempt = 0
    while attempt <= max_retries:
        try:
            response = requests.get(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=(connect_timeout, read_timeout),
            )
            return response, None
        except requests_exceptions.RequestException as exc:
            if attempt >= max_retries:
                return None, str(exc)
            sleep = min(4.0, (2**attempt) * 0.5)
            jitter = RANDOM.uniform(0, 0.25)
            time.sleep(sleep + jitter)
            attempt += 1
    return None, "unreachable"


def _http_probe_single(
    config: ScanConfig,
    hostname: str,
    port: int,
) -> dict[str, object]:
    url = _build_url(hostname, port)
    response, error = _http_request(
        url, config.max_retries, config.connect_timeout, config.read_timeout
    )
    if error:
        LOGGER.debug("HTTP probe for %s failed: %s", url, error)
        return {"error": error}

    assert response is not None

    redirect = _detect_external_redirect(hostname, response)
    if redirect:
        LOGGER.warning("Blocked redirect from %s to external host %s", url, redirect)
        return {"error": "redirected externally", "redirect_url": redirect}

    headers = dict(response.headers)
    sanitized_headers = _redact_headers(headers, config.redaction_keys)
    metadata: dict[str, object] = {
        "url": response.url,
        "status_code": response.status_code,
        "headers": sanitized_headers,
    }
    cookie_flags = _parse_cookie_flags(response)
    if cookie_flags:
        metadata["cookie_flags"] = cookie_flags
    metadata["security_headers_check"] = check_security_headers(sanitized_headers)

    if config.evidence_level == "low":
        return metadata

    metadata["screenshots"] = []
    if config.evidence_level == "medium":
        return metadata

    request_info = response.request
    metadata["raw_request"] = {
        "method": request_info.method,
        "headers": dict(request_info.headers),
        "body": (
            request_info.body.decode("utf-8", errors="replace")
            if isinstance(request_info.body, bytes)
            else request_info.body
        ),
    }
    metadata["raw_response"] = {
        "status_code": response.status_code,
        "headers": headers,
        "body": response.text,
    }
    return metadata


def http_probe_services(
    config: ScanConfig, hostname: str, ports: Sequence[int]
) -> dict[int, dict[str, object]]:
    results: dict[int, dict[str, object]] = {}
    http_ports = list(ports)
    if not http_ports:
        return results

    with ThreadPoolExecutor(max_workers=config.http_workers) as executor:
        future_map = {
            executor.submit(_http_probe_single, config, hostname, port): port
            for port in http_ports
        }
        for future in as_completed(future_map):
            port = future_map[future]
            try:
                results[port] = future.result()
            except Exception as exc:  # pragma: no cover - defensive guard
                LOGGER.error(
                    "HTTP probe for port %s raised unexpected error: %s", port, exc
                )
                results[port] = {"error": str(exc)}
    return results


def fetch_tls_certificate(config: ScanConfig, port: int) -> dict[str, object]:
    context = ssl.create_default_context()
    context.check_hostname = False
    addresses = resolve_addresses(config.target, config.enable_ipv6)
    for _family, _, _, _, sockaddr in addresses:
        host = sockaddr[0]
        try:
            with socket.create_connection(
                (host, port), timeout=config.connect_timeout
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=config.hostname or config.target
                ) as wrapped:
                    certificate = wrapped.getpeercert()
                    if not certificate:
                        continue
                    return {
                        "subject": dict(
                            entry[0] for entry in certificate.get("subject", [])
                        ),
                        "issuer": dict(
                            entry[0] for entry in certificate.get("issuer", [])
                        ),
                        "notBefore": certificate.get("notBefore"),
                        "notAfter": certificate.get("notAfter"),
                        "serialNumber": certificate.get("serialNumber"),
                    }
        except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as error:
            LOGGER.debug("TLS retrieval failed on %s:%s: %s", host, port, error)
            continue
    return {"error": "unable to retrieve TLS certificate"}


def fetch_robots(config: ScanConfig, hostname: str) -> dict[str, object]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/robots.txt"
        response, error = _http_request(
            url, config.max_retries, config.connect_timeout, config.read_timeout
        )
        if error:
            continue
        assert response is not None
        redirect = _detect_external_redirect(hostname, response)
        if redirect:
            continue
        if response.status_code == 200 and response.text.strip():
            body = (
                response.text
                if config.evidence_level == "high"
                else response.text[:2000]
            )
            return {"url": response.url, "body": body}
    return {"note": "robots.txt not present or inaccessible"}


def generate_findings(
    http_results: dict[int, dict[str, object]],
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
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
                {"port": port, "issue": "session_cookie_flags", "details": cookie_flags}
            )
        status_code = result.get("status_code")
        if isinstance(status_code, int) and status_code >= 500:
            findings.append(
                {"port": port, "issue": "server_error", "details": status_code}
            )
    return findings


def serialize_results(data: dict[str, object]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


__all__ = [
    "DEFAULT_PORTS",
    "HTTP_PORTS",
    "TOKEN_RATE",
    "TOKEN_CAPACITY",
    "HTTP_WORKERS",
    "CONNECT_TIMEOUT",
    "READ_TIMEOUT",
    "MAX_HTTP_RETRIES",
    "REDACTION_KEYS",
    "ScanConfig",
    "validate_port_list",
    "resolve_addresses",
    "tcp_connect_scan",
    "http_probe_services",
    "fetch_tls_certificate",
    "fetch_robots",
    "generate_findings",
    "check_security_headers",
    "serialize_results",
]
