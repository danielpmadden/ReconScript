"""High-level orchestration for ReconScript scan execution."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone

from . import __version__
from .consent import ConsentManifest
from .metrics import record_scan_completed, record_scan_failed, record_scan_started
from .report import embed_runtime_metadata
from .scanner import (
    DEFAULT_PORTS,
    REDACTION_KEYS,
    TOKEN_CAPACITY,
    TOKEN_RATE,
    ScanConfig,
    check_security_headers,
    fetch_robots,
    fetch_tls_certificate,
    generate_findings,
    http_probe_services,
    serialize_results,
    tcp_connect_scan,
    validate_port_list,
)
from .scanner.throttle import TokenBucket
from .scope import ScopeError, ScopeValidation, ensure_within_allowlist, validate_target

LOGGER = logging.getLogger(__name__)
REPORT_LOGGER = logging.getLogger("reconscript.report")

EVIDENCE_LEVELS = {"low", "medium", "high"}


class ReconError(RuntimeError):
    """Raised when a scan cannot proceed."""


def _determine_redactions(extra: Iterable[str] | None) -> set[str]:
    redactions = set(REDACTION_KEYS)
    for item in extra or []:
        redactions.add(str(item).lower())
    return redactions


def _validate_consent(
    *,
    manifest: ConsentManifest | None,
    target: ScopeValidation,
    requested_ports: Sequence[int],
    evidence_level: str,
) -> ConsentManifest | None:
    if target.is_local:
        return manifest
    if manifest is None:
        raise ReconError("Consent manifest is required for non-local targets.")
    if manifest.target not in {target.target, target.resolved_ip or ""}:
        raise ReconError("Consent manifest target does not match the requested target.")
    if evidence_level == "high" and manifest.evidence_level != "high":
        raise ReconError(
            "High evidence level requires a manifest authorising high evidence collection."
        )
    if any(port not in manifest.allowed_ports for port in requested_ports):
        raise ReconError(
            "Requested ports exceed the approved scope in the consent manifest."
        )
    return manifest


def _hostname_for_requests(scope: ScopeValidation, override: str | None) -> str:
    if override:
        return override
    if scope.kind == "hostname":
        return scope.target
    return scope.resolved_ip or scope.target


def run_recon(
    *,
    target: str,
    hostname: str | None = None,
    ports: Sequence[int] | None = None,
    expected_ip: str | None = None,
    enable_ipv6: bool = False,
    dry_run: bool = False,
    evidence_level: str = "low",
    consent_manifest: ConsentManifest | None = None,
    extra_redactions: Iterable[str] | None = None,
    progress_callback: Callable[[str, float], None] | None = None,
) -> dict[str, object]:
    """Execute the ReconScript workflow with safety controls."""

    evidence_level = evidence_level.lower()
    if evidence_level not in EVIDENCE_LEVELS:
        raise ReconError(f"Evidence level must be one of {sorted(EVIDENCE_LEVELS)}")

    record_scan_started(target)
    failure_reason: str | None = None

    try:
        scope = validate_target(target, expected_ip=expected_ip)
        ensure_within_allowlist(scope)

        candidates = list(ports) if ports else list(DEFAULT_PORTS)
        try:
            port_list = validate_port_list(candidates)
        except ReconError:
            failure_reason = "port_validation_failed"
            raise

        try:
            manifest = _validate_consent(
                manifest=consent_manifest,
                target=scope,
                requested_ports=port_list,
                evidence_level=evidence_level,
            )
        except ReconError:
            failure_reason = "consent_validation_failed"
            raise

        redactions = _determine_redactions(extra_redactions)
        bucket = TokenBucket(rate=TOKEN_RATE, capacity=TOKEN_CAPACITY)

        started_at = datetime.now(timezone.utc)
        report: dict[str, object] = {
            "target": scope.target,
            "hostname": hostname,
            "ports": list(port_list),
            "version": __version__,
            "evidence_level": evidence_level,
        }
        if manifest:
            report["consent_signed_by"] = manifest.signer_display

        embed_runtime_metadata(report, started_at)

        if dry_run:
            LOGGER.info(
                "Dry-run requested; network operations skipped.",
                extra={"event": "scan.dry_run", "target": scope.target},
            )
            report.update(
                {
                    "open_ports": [],
                    "http_checks": {},
                    "tls_cert": None,
                    "robots": {"note": "dry-run"},
                    "findings": [],
                }
            )
            embed_runtime_metadata(
                report, started_at, completed_at=started_at, duration=0.0
            )
            record_scan_completed(scope.target, 0.0, 0)
            REPORT_LOGGER.info(serialize_results(report))
            return report

        config = ScanConfig(
            target=scope.resolved_ip or scope.target,
            hostname=hostname,
            ports=port_list,
            enable_ipv6=enable_ipv6,
            evidence_level=evidence_level,
            redaction_keys=redactions,
        )

        http_host = _hostname_for_requests(scope, hostname)
        started_clock = time.perf_counter()

        if progress_callback:
            progress_callback("Starting TCP connect scan", 0.1)
        try:
            open_ports = tcp_connect_scan(config, bucket)
        except Exception:
            failure_reason = "tcp_scan_failed"
            raise
        report["open_ports"] = open_ports

        http_results: dict[int, dict[str, object]] = {}
        if open_ports:
            if progress_callback:
                progress_callback("Collecting HTTP metadata", 0.4)
            try:
                http_results = http_probe_services(config, http_host, open_ports)
            except Exception:
                failure_reason = "http_probe_failed"
                raise
        report["http_checks"] = http_results

        tls_details = None
        if any(port in (443, 8443) for port in open_ports):
            if progress_callback:
                progress_callback("Retrieving TLS certificates", 0.6)
            tls_port = 443 if 443 in open_ports else 8443
            try:
                tls_details = fetch_tls_certificate(config, tls_port)
            except Exception:
                failure_reason = "tls_probe_failed"
                raise
        report["tls_cert"] = tls_details

        if progress_callback:
            progress_callback("Fetching robots.txt", 0.75)
        try:
            report["robots"] = fetch_robots(config, http_host)
        except Exception:
            failure_reason = "robots_fetch_failed"
            raise

        if progress_callback:
            progress_callback("Generating findings", 0.9)
        try:
            report["findings"] = generate_findings(http_results)
        except Exception:
            failure_reason = "finding_generation_failed"
            raise

        completed_at = datetime.now(timezone.utc)
        duration = time.perf_counter() - started_clock
        embed_runtime_metadata(
            report, started_at, completed_at=completed_at, duration=duration
        )
        record_scan_completed(scope.target, duration, len(open_ports))
        REPORT_LOGGER.info(serialize_results(report))

        if progress_callback:
            progress_callback("Reconnaissance complete", 1.0)

        return report
    except ScopeError as exc:
        failure_reason = failure_reason or "scope_validation_failed"
        raise ReconError(str(exc)) from exc
    except ReconError:
        failure_reason = failure_reason or "recon_error"
        raise
    except Exception:
        failure_reason = failure_reason or "unexpected_error"
        raise
    finally:
        if failure_reason is not None:
            record_scan_failed(target, failure_reason)


__all__ = [
    "run_recon",
    "ReconError",
    "check_security_headers",
]
