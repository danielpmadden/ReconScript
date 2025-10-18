"""Command-line interface for ReconScript."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Iterable, Optional

from . import __version__
from .config import load_environment
from .consent import ConsentError, ConsentManifest, load_manifest, validate_manifest
from .core import ReconError, run_recon
from .logging_utils import configure_logging
from .report import persist_report
from .reporters import render_json, write_report


def _port(value: str) -> int:
    port = int(value)
    if port <= 0 or port > 65535:
        raise argparse.ArgumentTypeError("Ports must be between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconscript",
        description="Safe reconnaissance with consent enforcement and evidence controls.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--target", required=True, help="Target IP address or hostname within scope")
    parser.add_argument("--expected-ip", help="Require hostnames to resolve to this IP address")
    parser.add_argument("--hostname", help="Override HTTP Host header")
    parser.add_argument("--ports", nargs="+", type=_port, help="Ports to scan")
    parser.add_argument(
        "--evidence-level",
        choices=("low", "medium", "high"),
        default="low",
        help="Control the level of evidence captured during the scan",
    )
    parser.add_argument("--consent-file", type=Path, help="Path to signed scope manifest JSON")
    parser.add_argument("--format", choices=("json", "markdown", "html", "pdf"), help="Optional report format")
    parser.add_argument("--outfile", type=Path, help="Explicit output path for rendered report")
    parser.add_argument("--sign-report", action="store_true", help="Sign the report hash using the local signing key")
    parser.add_argument("--log-json", action="store_true", help="Emit structured JSON logs to the log file")
    parser.add_argument("--log-file", type=Path, help="Write logs to the specified path")
    parser.add_argument("--enable-ipv6", action="store_true", help="Resolve IPv6 addresses where available")
    parser.add_argument("--dry-run", action="store_true", help="Generate a report skeleton without network activity")
    parser.add_argument("--extra-redact", action="append", default=[], help="Additional header names to redact")

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="Enable debug logging")
    verbosity.add_argument("--quiet", action="store_true", help="Reduce logging output")
    return parser


def configure_cli_logging(args: argparse.Namespace) -> None:
    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    configure_logging(level=level, json_logs=args.log_json, logfile=args.log_file)


def _load_and_validate_manifest(path: Path) -> ConsentManifest:
    manifest = load_manifest(path)
    validate_manifest(manifest)
    return manifest


def main(argv: Optional[Iterable[str]] = None) -> int:
    load_environment()
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_cli_logging(args)
    logger = logging.getLogger("reconscript.cli")

    consent_manifest: ConsentManifest | None = None
    if args.consent_file:
        try:
            consent_manifest = _load_and_validate_manifest(args.consent_file)
        except ConsentError as exc:
            logger.error("Consent manifest invalid: %s", exc)
            return 1

    try:
        report = run_recon(
            target=args.target,
            hostname=args.hostname,
            ports=args.ports,
            expected_ip=args.expected_ip,
            enable_ipv6=args.enable_ipv6,
            dry_run=args.dry_run,
            evidence_level=args.evidence_level,
            consent_manifest=consent_manifest,
            extra_redactions=args.extra_redact,
        )
    except (ReconError) as exc:
        logger.error("Failed to execute scan: %s", exc)
        return 1

    consent_source = args.consent_file if consent_manifest else None
    persisted = persist_report(report, consent_source=consent_source, sign=args.sign_report)

    summary_lines = [
        f"Report ID: {persisted.report_id}",
        f"Target: {report.get('target')}",
        f"Open ports: {', '.join(map(str, report.get('open_ports', [])))}",
        f"Evidence level: {report.get('evidence_level')}",
        f"Report hash: {report.get('report_hash')}",
    ]
    if report.get("consent_signed_by"):
        summary_lines.append(f"Consent signed by: {report['consent_signed_by']}")
    logger.info("\n" + "\n".join(summary_lines))

    if args.format:
        output_path = args.outfile
        if output_path is None:
            output_path = persisted.base / f"report.{args.format}"
        try:
            write_report(report, output_path, args.format)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.error("Unable to render requested format: %s", exc)
            return 1
    else:
        print(render_json(report))

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())


