# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""High-level orchestration for ReconScript safe recon execution."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone

from . import __version__
from .consent import ConsentManifest
from .metrics import (
    record_scan_completed,
    record_scan_failed,
    record_scan_started,
)
from .report import embed_runtime_metadata
from .scanner import (
    DEFAULT_UDP_PORTS,
    ReconProfile,
    active_dns_sweep,
    http_checks,
    passive_dns_collection,
    profile_for_evidence,
    serialize_results,
    tcp_syn_scan,
    udp_scan_pass,
)
from .scanner.throttle import TokenBucket
from .scope import ScopeError, ScopeValidation, ensure_within_allowlist, validate_target

LOGGER = logging.getLogger(__name__)
REPORT_LOGGER = logging.getLogger("reconscript.report")

EVIDENCE_LEVELS = {"low", "medium", "high"}


class ReconError(RuntimeError):
    """Raised when a scan cannot proceed."""


def _hostname_for_requests(scope: ScopeValidation, override: str | None) -> str:
    if override:
        return override
    if scope.kind == "hostname":
        return scope.target
    return scope.resolved_ip or scope.target


def _bucket(profile: ReconProfile, key: str) -> TokenBucket:
    rate, burst = profile.rate_limits[key]
    return TokenBucket(rate=rate, capacity=burst)


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
    profile: ReconProfile | None = None,
) -> dict[str, object]:
    """Execute the ReconScript workflow with safety controls."""

    evidence_level = evidence_level.lower()
    if evidence_level not in EVIDENCE_LEVELS:
        raise ReconError(f"Evidence level must be one of {sorted(EVIDENCE_LEVELS)}")

    selected_profile = profile or profile_for_evidence(evidence_level)
    LOGGER.info(
        "Using recon profile %s",
        selected_profile.name,
        extra={"profile": selected_profile.as_dict()},
    )

    record_scan_started(target)
    failure_reason: str | None = None
    start_clock = time.perf_counter()

    if enable_ipv6:
        LOGGER.info(
            "IPv6 scanning requested; safe profile limits probes to IPv4 endpoints.",
            extra={"event": "scan.ipv6", "requested": True},
        )
    if extra_redactions:
        LOGGER.info(
            "Ignoring additional redactions under safe profile.",
            extra={"event": "scan.redactions", "redactions": list(extra_redactions)},
        )

    try:
        scope = validate_target(target, expected_ip=expected_ip)
        ensure_within_allowlist(scope)

        limited_ports = selected_profile.limit_ports(ports)
        udp_ports = list(DEFAULT_UDP_PORTS)

        started_at = datetime.now(timezone.utc)
        report: dict[str, object] = {
            "metadata": {
                "target": scope.target,
                "resolved_target": scope.resolved_ip or scope.target,
                "hostname": hostname,
                "version": __version__,
                "evidence_level": evidence_level,
                "profile": selected_profile.as_dict(),
                "consent_present": bool(consent_manifest),
                "scanned_tcp_ports": list(limited_ports),
                "scanned_udp_ports": list(udp_ports),
            },
            "artifacts": {},
            "findings": [],
        }

        embed_runtime_metadata(report, started_at)

        LOGGER.info(
            "Consent manifest provided? %s",
            bool(consent_manifest),
            extra={"event": "scan.consent", "consent_present": bool(consent_manifest)},
        )

        if dry_run:
            LOGGER.info(
                "Dry-run requested; network operations skipped.",
                extra={"event": "scan.dry_run", "target": scope.target},
            )
            report["artifacts"] = {
                "tcp": {"scanned_ports": list(limited_ports), "open_ports": []},
                "udp": {"scanned_ports": udp_ports, "responses": {}},
            }
            embed_runtime_metadata(
                report, started_at, completed_at=started_at, duration=0.0
            )
            record_scan_completed(scope.target, 0.0, 0)
            REPORT_LOGGER.info(serialize_results(report))
            return report

        dns_bucket = _bucket(selected_profile, "dns")
        tcp_bucket = _bucket(selected_profile, "tcp")
        udp_bucket = _bucket(selected_profile, "udp")
        http_bucket = _bucket(selected_profile, "http")

        findings: list[dict[str, object]] = []
        artifacts: dict[str, object] = {}

        if progress_callback:
            progress_callback("Collecting passive DNS", 0.1)
        passive_metadata, passive_findings = passive_dns_collection(
            scope.target, selected_profile
        )
        artifacts["dns_passive"] = passive_metadata
        findings.extend(passive_findings)

        if progress_callback:
            progress_callback("Performing active DNS", 0.25)
        active_metadata, active_findings = active_dns_sweep(
            scope.target, selected_profile, dns_bucket
        )
        artifacts["dns_active"] = active_metadata
        findings.extend(active_findings)

        if progress_callback:
            progress_callback("Running TCP SYN scan", 0.4)
        tcp_metadata, tcp_findings = tcp_syn_scan(
            scope.resolved_ip or scope.target,
            selected_profile,
            limited_ports,
            tcp_bucket,
        )
        artifacts["tcp"] = tcp_metadata
        findings.extend(tcp_findings)

        if progress_callback:
            progress_callback("Running UDP probes", 0.55)
        udp_metadata, udp_findings = udp_scan_pass(
            scope.resolved_ip or scope.target, selected_profile, udp_ports, udp_bucket
        )
        artifacts["udp"] = udp_metadata
        findings.extend(udp_findings)

        http_host = _hostname_for_requests(scope, hostname)
        if tcp_metadata.get("open_ports"):
            if progress_callback:
                progress_callback("Performing HTTP checks", 0.7)
            http_metadata, http_findings = http_checks(
                scope.resolved_ip or scope.target,
                http_host,
                tcp_metadata.get("open_ports", []),
                selected_profile,
                http_bucket,
            )
            artifacts["http"] = http_metadata
            findings.extend(http_findings)
        else:
            artifacts["http"] = {"services": {}}

        report["artifacts"] = artifacts
        report["findings"] = findings

        completed_at = datetime.now(timezone.utc)
        duration = time.perf_counter() - start_clock
        embed_runtime_metadata(
            report, started_at, completed_at=completed_at, duration=duration
        )
        record_scan_completed(
            scope.target, duration, len(tcp_metadata.get("open_ports", []))
        )
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
]
