"""High-level orchestration for ReconScript scans.

This module coordinates the individual scanning building blocks and enforces
safety-centric defaults such as throttling, dry-run support, and atomic report
writing. All functions remain focused on read-only reconnaissance workflows.
"""

from __future__ import annotations

import datetime as _dt
import logging
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Optional, Sequence

from . import __version__
from .scanner import (
    DEFAULT_BACKOFF,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_SOCKET_TIMEOUT,
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
    ports: Sequence[int],
    socket_timeout: float = DEFAULT_SOCKET_TIMEOUT,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    throttle_ms: float = 250.0,
    enable_ipv6: bool = False,
    max_ports: int = 12,
    dry_run: bool = False,
    outfile: Optional[Path] = None,
) -> Dict[str, object]:
    """Execute the ReconScript workflow and optionally persist the report.

    Parameters are deliberately explicit so that operators must opt into any
    deviation from the conservative defaults. ``max_ports`` ensures the scan
    remains focused even when a long port list is supplied, and ``dry_run`` lets
    reviewers verify planned activity without touching the network.
    """

    start_time = time.perf_counter()

    # Validate that the operator supplied an explicit in-scope IP address.
    normalized_target = normalize_target(target)
    # Normalise and deduplicate the requested ports for predictable scanning.
    validated_ports = validate_port_list(ports)
    effective_ports = validated_ports[:max_ports]
    if len(effective_ports) < len(validated_ports):
        LOGGER.info(
            "Limiting requested ports from %s to %s per max-ports policy",
            len(validated_ports),
            len(effective_ports),
        )

    throttle_seconds = max(throttle_ms / 1000.0, 0.0)

    config = ScanConfig(
        target=normalized_target,
        hostname=hostname,
        ports=effective_ports,
        socket_timeout=socket_timeout,
        http_timeout=http_timeout,
        max_retries=max_retries,
        backoff=backoff,
        throttle=throttle_seconds,
        enable_ipv6=enable_ipv6,
    )

    report: Dict[str, object] = {
        "target": normalized_target,
        "hostname": hostname,
        "ports": list(effective_ports),
        "tool_version": __version__,
        "timestamp": _dt.datetime.utcnow().isoformat() + "Z",
    }
    report["scan_config"] = {
        "requested_ports": list(validated_ports),
        "effective_ports": list(effective_ports),
        "socket_timeout": socket_timeout,
        "http_timeout": http_timeout,
        "throttle_ms": throttle_ms,
        "max_ports": max_ports,
        "enable_ipv6": enable_ipv6,
        "dry_run": dry_run,
        "max_retries": max_retries,
        "backoff": backoff,
    }

    if dry_run:
        LOGGER.info("Dry-run enabled; no network operations will be performed")
        report.update(
            {
                "open_ports": [],
                "http_checks": {},
                "tls_cert": {"note": "dry-run"},
                "robots": {"note": "dry-run"},
                "findings": [],
                "plan": {
                    "tcp_ports_to_probe": list(effective_ports),
                    "http_ports_to_probe": [
                        port for port in effective_ports if port in HTTP_PORTS
                    ],
                    "will_attempt_tls": any(
                        port in (443, 8443) for port in effective_ports
                    ),
                    "will_fetch_robots": True,
                },
            }
        )
        report["runtime"] = round(time.perf_counter() - start_time, 4)
        _emit_report(report, outfile)
        return report

    # Reuse a single HTTP session to amortise connection setup and respect
    # retry/backoff policies applied inside the HTTP helper routines.
    session = create_http_session(timeout=http_timeout)

    LOGGER.info(
        "Starting TCP connect scan of %s on %s",
        normalized_target,
        list(effective_ports),
    )
    open_ports = tcp_connect_scan(config, effective_ports, throttle_seconds)
    report["open_ports"] = open_ports

    http_results: Dict[int, Dict[str, object]] = {}
    if open_ports:
        LOGGER.info("Evaluating HTTP services on detected ports")
    for port in open_ports:
        if port in HTTP_PORTS:
            LOGGER.debug("Fetching HTTP metadata from port %s", port)
            http_results[port] = probe_http_service(
                session=session,
                host_or_ip=hostname or normalized_target,
                port=port,
                max_retries=max_retries,
                backoff=backoff,
            )
    report["http_checks"] = http_results

    if any(port in (443, 8443) for port in open_ports):
        tls_port = 443 if 443 in open_ports else 8443
        LOGGER.info("Gathering TLS certificate details from port %s", tls_port)
        report["tls_cert"] = fetch_tls_certificate(config, tls_port)
    else:
        report["tls_cert"] = {"note": "TLS not in scope"}

    if open_ports:
        LOGGER.info("Requesting robots.txt for situational awareness")
    report["robots"] = fetch_robots(
        session=session,
        host_or_ip=hostname or normalized_target,
        max_retries=max_retries,
        backoff=backoff,
    )

    report["findings"] = generate_findings(http_results)
    report["runtime"] = round(time.perf_counter() - start_time, 4)

    _emit_report(report, outfile)
    return report


def _emit_report(report: Dict[str, object], outfile: Optional[Path]) -> None:
    """Emit the report either to disk or logging in an atomic fashion."""

    if outfile:
        LOGGER.info("Writing report to %s", outfile)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        json_payload = serialize_results(report)
        with NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=outfile.parent
        ) as handle:
            handle.write(json_payload)
            temp_name = handle.name
        Path(temp_name).replace(outfile)
        return

    # Emit the report via logging so operators can capture structured output.
    REPORT_LOGGER.info(serialize_results(report))


__all__ = [
    "run_recon",
    "check_security_headers",
    "generate_findings",
    "parse_cookie_flags",
]
