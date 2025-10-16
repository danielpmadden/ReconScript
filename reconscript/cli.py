"""Command-line interface for ReconScript."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Iterable, Optional

from .core import run_recon
from .scanner import (
    DEFAULT_BACKOFF,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PORTS,
    DEFAULT_SOCKET_TIMEOUT,
)


def _port(value: str) -> int:
    """Argparse helper ensuring each port value is within TCP bounds."""

    port = int(value)
    if port <= 0 or port > 65535:
        raise argparse.ArgumentTypeError("Ports must be between 1 and 65535")
    return port


def _positive_float(value: str) -> float:
    """Ensure supplied float arguments are positive."""

    result = float(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("Value must be greater than zero")
    return result


def _non_negative_float(value: str) -> float:
    """Validate floats that may be zero (e.g. throttle)."""

    result = float(value)
    if result < 0:
        raise argparse.ArgumentTypeError("Value must be zero or greater")
    return result


def _non_negative_int(value: str) -> int:
    """Validate retry counts and similar integers."""

    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("Value must be zero or greater")
    return result


def _positive_int(value: str) -> int:
    """Validate positive integer arguments."""

    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("Value must be greater than zero")
    return result


def build_parser() -> argparse.ArgumentParser:
    """Create a configured argument parser for the CLI."""

    parser = argparse.ArgumentParser(
        prog="reconscript",
        description=(
            "Safe, read-only reconnaissance for authorised web application assessment."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--target",
        required=True,
        help="IP address (IPv4 or IPv6) within your approved assessment scope",
    )
    parser.add_argument(
        "--hostname",
        help="Optional hostname for HTTP Host header and TLS SNI",
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=_port,
        default=list(DEFAULT_PORTS),
        help="Ports to scan for TCP connectivity",
    )
    parser.add_argument(
        "--outfile",
        type=Path,
        help="Write JSON output to the specified file path",
    )
    parser.add_argument(
        "--timeout-socket",
        type=_positive_float,
        default=DEFAULT_SOCKET_TIMEOUT,
        help="TCP socket timeout in seconds",
    )
    parser.add_argument(
        "--timeout-http",
        type=_positive_float,
        default=DEFAULT_HTTP_TIMEOUT,
        help="HTTP(S) request timeout in seconds",
    )
    parser.add_argument(
        "--max-retries",
        type=_non_negative_int,
        default=DEFAULT_MAX_RETRIES,
        help="Maximum HTTP retry attempts for transient issues",
    )
    parser.add_argument(
        "--backoff",
        type=_non_negative_float,
        default=DEFAULT_BACKOFF,
        help="Backoff factor between HTTP retries",
    )
    parser.add_argument(
        "--throttle-ms",
        type=_non_negative_float,
        default=250.0,
        help="Delay in milliseconds between TCP port probes",
    )
    parser.add_argument(
        "--enable-ipv6",
        action="store_true",
        help="Also resolve and scan IPv6 addresses for the target",
    )
    parser.add_argument(
        "--max-ports",
        type=_positive_int,
        default=12,
        help="Maximum number of TCP ports to probe in a single run",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned probes and exit without performing network access",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging for troubleshooting",
    )
    verbosity.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce logging to warnings and errors only",
    )
    return parser


def configure_logging(args: argparse.Namespace) -> None:
    """Configure logging according to CLI verbosity flags."""

    if args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments using the shared parser builder."""

    parser = build_parser()
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Entry point used by both ``python -m`` and the console script."""

    args = parse_args(argv)
    configure_logging(args)

    try:
        run_recon(
            target=args.target,
            hostname=args.hostname,
            ports=args.ports,
            socket_timeout=args.timeout_socket,
            http_timeout=args.timeout_http,
            max_retries=args.max_retries,
            backoff=args.backoff,
            throttle_ms=args.throttle_ms,
            enable_ipv6=args.enable_ipv6,
            max_ports=args.max_ports,
            dry_run=args.dry_run,
            outfile=args.outfile,
        )
    except (ValueError, RuntimeError) as error:
        logging.getLogger(__name__).error("Failed to execute scan: %s", error)
        return 1

    return 0


__all__ = ["build_parser", "parse_args", "main"]
