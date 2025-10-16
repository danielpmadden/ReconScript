"""High-level orchestration for ReconScript scans."""

from __future__ import annotations

import datetime as _dt
import logging
from pathlib import Path
from typing import Dict, Optional

from . import __version__
from .scanner import (
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_SOCKET_TIMEOUT,
    DEFAULT_BACKOFF,
    HTTP_PORTS,
    ScanConfig,
    check_security_headers,
    create_http_session,
    fetch_robots,
    fetch_tls_certificate,
    generate_findings,
    normalize_target,
    parse_cookie_flags,
    probe_http_service,
    serialize_results,
    tcp_connect_scan,
    validate_port_list,
)

LOGGER = logging.getLogger(__name__)
REPORT_LOGGER = logging.getLogger("reconscript.report")


def run_recon(
    target: str,
    hostname: Optional[str],
    ports,
    socket_timeout: float = DEFAULT_SOCKET_TIMEOUT,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    throttle: float = 0.0,
    enable_ipv6: bool = False,
    outfile: Optional[Path] = None,
) -> Dict[str, object]:
    """Execute the ReconScript workflow and optionally persist the report."""

    # Validate that the operator supplied an explicit in-scope IP address.
    normalized_target = normalize_target(target)
    # Normalise and deduplicate the requested ports for predictable scanning.
    validated_ports = validate_port_list(ports)

    config = ScanConfig(
        target=normalized_target,
        hostname=hostname,
        ports=validated_ports,
        socket_timeout=socket_timeout,
        http_timeout=http_timeout,
        max_retries=max_retries,
        backoff=backoff,
        throttle=throttle,
        enable_ipv6=enable_ipv6,
    )

    # Reuse a single HTTP session to amortise connection setup and share retries.
    session = create_http_session(timeout=http_timeout, max_retries=max_retries, backoff=backoff)

    report: Dict[str, object] = {
        "target": normalized_target,
        "hostname": hostname,
        "ports": list(validated_ports),
        "version": __version__,
        "timestamp": _dt.datetime.utcnow().isoformat() + "Z",
    }

    LOGGER.info("Starting TCP connect scan of %s on %s", normalized_target, list(validated_ports))
    open_ports = tcp_connect_scan(config, validated_ports, throttle)
    report["open_ports"] = open_ports

    http_results: Dict[int, Dict[str, object]] = {}
    if open_ports:
        LOGGER.info("Evaluating HTTP services on detected ports")
    for port in open_ports:
        if port in HTTP_PORTS:
            LOGGER.debug("Fetching HTTP metadata from port %s", port)
            http_results[port] = probe_http_service(session, hostname or normalized_target, port)
    report["http_checks"] = http_results

    if any(port in (443, 8443) for port in open_ports):
        tls_port = 443 if 443 in open_ports else 8443
        LOGGER.info("Gathering TLS certificate details from port %s", tls_port)
        report["tls_cert"] = fetch_tls_certificate(config, tls_port)

    LOGGER.info("Requesting robots.txt for situational awareness")
    report["robots"] = fetch_robots(session, hostname or normalized_target)

    report["findings"] = generate_findings(http_results)

    if outfile:
        LOGGER.info("Writing report to %s", outfile)
        outfile.write_text(serialize_results(report), encoding="utf-8")
    else:
        # Emit the report via logging so operators can capture structured output.
        REPORT_LOGGER.info(serialize_results(report))

    return report

__all__ = [
    "run_recon",
    "check_security_headers",
    "generate_findings",
    "parse_cookie_flags",
]
