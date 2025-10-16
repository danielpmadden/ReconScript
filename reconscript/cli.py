"""Command-line interface for ReconScript."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Iterable, Optional, Set

try:  # pragma: no cover - import guarded for constrained environments
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover - fallback when Rich is unavailable
    class Table:  # type: ignore[no-redef]
        def __init__(self, title: str | None = None, show_lines: bool = False, header_style: str | None = None):
            self.title = title
            self.headers: list[str] = []
            self.rows: list[tuple[str, ...]] = []

        def add_column(self, header: str, justify: str = "left") -> None:
            self.headers.append(header)

        def add_row(self, *values: str) -> None:
            self.rows.append(tuple(values))

        def render(self) -> str:
            if self.rows:
                columns = zip(self.headers, *self.rows)
                width = [max(len(str(value)) for value in column) for column in columns]
            else:
                width = [len(h) for h in self.headers]
            lines = []
            if self.title:
                lines.append(self.title)
            header_line = " | ".join(h.ljust(width[idx]) for idx, h in enumerate(self.headers))
            lines.append(header_line)
            lines.append("-+-".join("-" * w for w in width))
            for row in self.rows:
                lines.append(" | ".join(str(cell).ljust(width[idx]) for idx, cell in enumerate(row)))
            return "\n".join(lines)

        def __str__(self) -> str:
            return self.render()

    class Console:  # type: ignore[no-redef]
        def __init__(self, *_, **__):
            pass

        def print(self, value) -> None:  # noqa: D401 - compatibility shim
            print(getattr(value, "render", lambda: str(value))())

from . import __version__
from .core import run_recon
from .reporters import render_json, write_report
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


def build_parser() -> argparse.ArgumentParser:
    """Create a configured argument parser for the CLI."""

    parser = argparse.ArgumentParser(
        prog="reconscript",
        description=(
            "Safe, read-only reconnaissance for authorised web application assessment."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

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
        help="Write the report to a file (format inferred from extension when omitted)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown", "html", "pdf"),
        help="Explicit report format; defaults to JSON or infers from --outfile extension",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Shortcut for --format pdf",
    )
    parser.add_argument(
        "--socket-timeout",
        type=_positive_float,
        default=DEFAULT_SOCKET_TIMEOUT,
        help="TCP socket timeout in seconds",
    )
    parser.add_argument(
        "--http-timeout",
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
        "--throttle",
        type=_non_negative_float,
        default=0.2,
        help="Delay in seconds between TCP port probes",
    )
    parser.add_argument(
        "--enable-ipv6",
        action="store_true",
        help="Also resolve and scan IPv6 addresses for the target",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse arguments and emit a skeleton report without network activity",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colourised console summaries",
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
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    if any(flag in ("-h", "--help") for flag in argv_list):
        parser.print_help()
        print("\nFull guide available in HELP.md or online README.")
        raise SystemExit(0)
    return parser.parse_args(argv_list)


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Entry point used by both ``python -m`` and the console script."""

    try:
        args = parse_args(argv)
    except SystemExit as exit_code:
        return exit_code.code if isinstance(exit_code.code, int) else 0

    configure_logging(args)

    try:
        report = run_recon(
            target=args.target,
            hostname=args.hostname,
            ports=args.ports,
            socket_timeout=args.socket_timeout,
            http_timeout=args.http_timeout,
            max_retries=args.max_retries,
            backoff=args.backoff,
            throttle=args.throttle,
            enable_ipv6=args.enable_ipv6,
            dry_run=args.dry_run,
        )
    except (ValueError, RuntimeError) as error:
        logging.getLogger(__name__).error("Failed to execute scan: %s", error)
        return 1

    console = Console(force_terminal=True, color_system="auto", no_color=args.no_color)
    format_name = _resolve_format(args)

    if format_name != "json" and not args.outfile:
        logging.getLogger(__name__).error("The %s format requires --outfile", format_name)
        return 2

    if args.outfile:
        try:
            write_report(report, args.outfile, format_name)
        except (OSError, RuntimeError) as error:
            logging.getLogger(__name__).error("Unable to write report: %s", error)
            return 1
        logging.getLogger(__name__).info("Report saved to %s (%s)", args.outfile, format_name)
    else:
        console.print(render_json(report))

    _render_summary_table(console, report)

    return 0


def _resolve_format(args: argparse.Namespace) -> str:
    if getattr(args, "pdf", False):
        return "pdf"
    if getattr(args, "format", None):
        return str(args.format)
    if args.outfile:
        suffix = args.outfile.suffix.lower()
        if suffix in {".md", ".markdown"}:
            return "markdown"
        if suffix in {".html", ".htm"}:
            return "html"
        if suffix == ".pdf":
            return "pdf"
        if suffix == ".json":
            return "json"
    return "json"


def _render_summary_table(console: Console, report: dict[str, object]) -> None:
    ports = report.get("ports", [])
    open_ports = set(report.get("open_ports") or [])
    findings = report.get("findings", [])
    findings_by_port = {}
    if isinstance(findings, list):
        for item in findings:
            port = item.get("port") if isinstance(item, dict) else None
            if port is None:
                continue
            findings_by_port.setdefault(port, []).append(item.get("issue"))

    table = Table(title="Scan Summary", show_lines=True, header_style="bold white")
    table.add_column("PORT", justify="center")
    table.add_column("SERVICE", justify="left")
    table.add_column("STATUS", justify="center")
    table.add_column("NOTES", justify="left")

    for port in ports:
        status, notes, colour = _summarise_port(port, open_ports, findings_by_port.get(port, []))
        table.add_row(str(port), _service_name(port), f"[{colour}]{status}[/{colour}]", notes)

    extra_ports = sorted(open_ports.difference(set(ports)))
    for port in extra_ports:
        status, notes, colour = _summarise_port(port, open_ports, findings_by_port.get(port, []))
        table.add_row(str(port), _service_name(port), f"[{colour}]{status}[/{colour}]", notes)

    console.print(table)


def _summarise_port(port: int, open_ports: Set[int], issues: Optional[Iterable[str]]) -> tuple[str, str, str]:
    if port not in open_ports:
        return ("closed", "Filtered or closed", "green")

    issues = list(issues or [])
    if not issues:
        return ("open", "No issues observed", "green")

    unique = sorted({str(issue) for issue in issues if issue})
    if "server_error" in unique:
        colour = "red"
    else:
        colour = "yellow"
    notes = ", ".join(text.replace("_", " ") for text in unique)
    return ("open", notes or "Observations recorded", colour)


def _service_name(port: int) -> str:
    mapping = {
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP-alt",
        8443: "HTTPS-alt",
        8000: "HTTP-dev",
        3000: "Dev server",
    }
    return mapping.get(port, "TCP service")


__all__ = ["build_parser", "parse_args", "main"]
