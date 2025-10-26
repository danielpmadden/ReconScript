# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""Scanner primitives for ReconScript safe, non-intrusive reconnaissance."""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import socket
from collections import defaultdict
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from requests import Response
from requests import exceptions as requests_exceptions

from .throttle import TokenBucket

LOGGER = logging.getLogger(__name__)

WHOIS_SAFE_PATTERN = re.compile(r"^[A-Za-z0-9.-]{1,253}$")

PRIORITY_TCP_PORTS: tuple[int, ...] = (
    80,
    443,
    22,
    21,
    25,
    110,
    143,
    53,
    123,
    3389,
    5900,
    8080,
    8443,
    8000,
    3306,
    5432,
    6379,
    27017,
    5985,
    9200,
)
DEFAULT_TCP_PORTS: tuple[int, ...] = PRIORITY_TCP_PORTS
DEFAULT_UDP_PORTS: tuple[int, ...] = (53, 123, 161)
HTTP_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 3000)
DIR_ENUM_LEVELS = {"none", "low", "medium"}
MAX_RAW_SNIPPET = 400

DEFAULT_TIMEOUTS: Mapping[str, float] = {
    "tcp_connect": 2.5,
    "tcp_syn": 2.5,
    "udp": 2.0,
    "http": 5.0,
    "dns": 3.0,
}

DEFAULT_RATE_LIMITS: Mapping[str, tuple[float, float]] = {
    "tcp": (5.0, 5.0),
    "udp": (2.0, 2.0),
    "dns": (2.0, 2.0),
    "http": (2.0, 2.0),
}

SAFE_WORDLIST_LOW: tuple[str, ...] = (
    "robots.txt",
    "sitemap.xml",
    "admin",
    "login",
    "static",
    "health",
    "status",
)
SAFE_WORDLIST_MEDIUM: tuple[str, ...] = SAFE_WORDLIST_LOW + (
    ".well-known/security.txt",
    "server-status",
    "config",
    "api",
    "assets",
    "dashboard",
    "docs",
)


@dataclass
class ReconProfile:
    """Profile encapsulating the safe scanning parameters."""

    name: str
    max_tcp_ports: int = 100
    tcp_concurrency: int = 10
    udp_pass: bool = True
    dns_active: bool = True
    dns_passive: bool = True
    dir_enum: str = "low"
    allow_credentialed: bool = False
    timeouts: MutableMapping[str, float] = field(
        default_factory=lambda: dict(DEFAULT_TIMEOUTS)
    )
    rate_limits: MutableMapping[str, tuple[float, float]] = field(
        default_factory=lambda: dict(DEFAULT_RATE_LIMITS)
    )

    def __post_init__(self) -> None:
        if self.max_tcp_ports <= 0:
            raise ValueError("max_tcp_ports must be positive")
        if self.tcp_concurrency <= 0:
            raise ValueError("tcp_concurrency must be positive")
        if self.dir_enum not in DIR_ENUM_LEVELS:
            raise ValueError(f"dir_enum must be one of {sorted(DIR_ENUM_LEVELS)}")
        normalized_timeouts = dict(DEFAULT_TIMEOUTS)
        normalized_timeouts.update(self.timeouts)
        self.timeouts = normalized_timeouts
        normalized_rates = dict(DEFAULT_RATE_LIMITS)
        normalized_rates.update(self.rate_limits)
        self.rate_limits = normalized_rates
        if self.allow_credentialed:
            LOGGER.warning(
                "Credentialed scanning remains disabled despite profile flag."
            )

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "max_tcp_ports": self.max_tcp_ports,
            "tcp_concurrency": self.tcp_concurrency,
            "udp_pass": self.udp_pass,
            "dns_active": self.dns_active,
            "dns_passive": self.dns_passive,
            "dir_enum": self.dir_enum,
            "allow_credentialed": self.allow_credentialed,
            "timeouts": dict(self.timeouts),
            "rate_limits": {
                key: {"rate": rate, "burst": burst}
                for key, (rate, burst) in self.rate_limits.items()
            },
        }

    def limit_ports(self, ports: Sequence[int] | None) -> tuple[int, ...]:
        candidate_ports = (
            validate_port_list(ports) if ports is not None else DEFAULT_TCP_PORTS
        )
        prioritized: list[int] = []
        for port in PRIORITY_TCP_PORTS:
            if port in candidate_ports and port not in prioritized:
                prioritized.append(port)
        for port in candidate_ports:
            if port not in prioritized:
                prioritized.append(port)
        return tuple(prioritized[: self.max_tcp_ports])


def profile_for_evidence(evidence_level: str) -> ReconProfile:
    level = evidence_level.lower()
    if level not in {"low", "medium", "high"}:
        raise ValueError("Evidence level must be low, medium, or high")
    if level == "low":
        return ReconProfile(
            name="safe-low",
            max_tcp_ports=80,
            tcp_concurrency=6,
            dir_enum="low",
        )
    if level == "medium":
        return ReconProfile(
            name="safe-medium",
            max_tcp_ports=120,
            tcp_concurrency=8,
            dir_enum="medium",
        )
    return ReconProfile(
        name="safe-high",
        max_tcp_ports=150,
        tcp_concurrency=10,
        dir_enum="none",
    )


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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _clip_snippet(snippet: str) -> str:
    if len(snippet) <= MAX_RAW_SNIPPET:
        return snippet
    return snippet[: MAX_RAW_SNIPPET - 3] + "..."


def _make_finding(
    *,
    tool: str,
    cmdline: str,
    summary: str,
    raw_snippet: str,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, object]:
    return {
        "tool": tool,
        "cmdline": cmdline,
        "summary": summary,
        "started_at": _isoformat(started_at),
        "completed_at": _isoformat(completed_at),
        "raw_snippet": _clip_snippet(raw_snippet),
    }


def _build_url(hostname: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    if port in (80, 443):
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        redact = lower in {"cookie", "authorization", "set-cookie"}
        if lower.startswith("x-") and any(
            token in lower for token in ("auth", "token", "key")
        ):
            redact = True
        sanitized[key] = "[redacted]" if redact else value
    return sanitized


def passive_dns_collection(
    target: str, profile: ReconProfile
) -> tuple[dict[str, object], list[dict[str, object]]]:
    metadata: dict[str, object] = {"addresses": [], "aliases": []}
    findings: list[dict[str, object]] = []
    if not profile.dns_passive:
        return metadata, findings

    started = _utcnow()
    lines: list[str] = []
    summary = "Passive DNS lookup executed."
    try:
        host, aliases, addresses = socket.gethostbyname_ex(target)
        metadata["hostname"] = host
        metadata["aliases"] = aliases
        metadata["addresses"] = addresses
        lines.append(f"Host: {host}")
        if aliases:
            lines.append("Aliases: " + ", ".join(aliases))
        if addresses:
            lines.append("Addresses: " + ", ".join(addresses))
        else:
            lines.append("No A records discovered.")
        summary = f"Passive DNS resolved {len(addresses)} address(es)."
    except socket.gaierror as exc:
        lines.append(f"DNS resolution failed: {exc}")
        summary = "Passive DNS resolution failed."
    completed = _utcnow()
    findings.append(
        _make_finding(
            tool="passive-dns",
            cmdline=f"passive_dns --target {target}",
            summary=summary,
            raw_snippet="\n".join(lines) or "No passive DNS data",
            started_at=started,
            completed_at=completed,
        )
    )

    whois_lines: list[str] = []
    whois_summary = "WHOIS lookup skipped."
    whois_started = _utcnow()
    try:
        import subprocess

        if not WHOIS_SAFE_PATTERN.fullmatch(target):
            whois_lines.append("WHOIS target contains unsupported characters.")
        else:
            executable = shutil.which("whois")
            if executable is None:
                whois_lines.append("whois binary not available.")
            else:
                try:
                    result = subprocess.run(  # noqa: S603, S607 - sanitized target and explicit binary
                        [executable, target],
                        capture_output=True,
                        text=True,
                        timeout=profile.timeouts.get("dns", 3.0),
                        check=False,
                    )
                    stdout = result.stdout.strip()
                    stderr = result.stderr.strip()
                    if stdout:
                        whois_lines.append(stdout[:300])
                    elif stderr:
                        whois_lines.append(stderr[:300])
                    else:
                        whois_lines.append("WHOIS returned no output.")
                    whois_summary = "WHOIS lookup executed."
                except subprocess.SubprocessError as exc:
                    whois_lines.append(f"WHOIS error: {exc}")
                    whois_summary = "WHOIS lookup encountered an error."
    except ImportError:
        whois_lines.append("subprocess module unavailable for WHOIS.")
    except Exception as exc:  # pragma: no cover - defensive
        whois_lines.append(f"Unexpected WHOIS error: {exc}")
        whois_summary = "WHOIS lookup encountered an error."
    whois_completed = _utcnow()
    findings.append(
        _make_finding(
            tool="passive-dns",
            cmdline=f"whois {target}",
            summary=whois_summary,
            raw_snippet="\n".join(whois_lines) or "No WHOIS data",
            started_at=whois_started,
            completed_at=whois_completed,
        )
    )

    ct_started = _utcnow()
    findings.append(
        _make_finding(
            tool="passive-dns",
            cmdline=f"ct-lookup --domain {target}",
            summary="Certificate transparency lookup not performed (offline mode).",
            raw_snippet=(
                "CT log queries require external network access and are disabled in "
                "the safe default profile."
            ),
            started_at=ct_started,
            completed_at=_utcnow(),
        )
    )
    return metadata, findings


def active_dns_sweep(
    target: str, profile: ReconProfile, bucket: TokenBucket
) -> tuple[dict[str, list[str]], list[dict[str, object]]]:
    metadata: dict[str, list[str]] = defaultdict(list)
    findings: list[dict[str, object]] = []
    if not profile.dns_active:
        return metadata, findings

    resolver = None
    with contextlib.suppress(ImportError):
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = profile.timeouts.get("dns", 3.0)

    record_types = ("A", "AAAA", "CNAME", "TXT", "MX")
    for record_type in record_types:
        bucket.consume()
        started = _utcnow()
        snippet_lines: list[str] = []
        summary = "Active DNS query executed."
        try:
            if record_type in {"A", "AAAA"}:
                family = socket.AF_INET if record_type == "A" else socket.AF_INET6
                answers = socket.getaddrinfo(target, None, family=family)
                seen: list[str] = []
                for answer in answers:
                    host = answer[4][0]
                    if host not in seen:
                        seen.append(host)
                if seen:
                    metadata[record_type].extend(seen)
                    snippet_lines.append(f"{record_type} records: " + ", ".join(seen))
                    summary = f"{record_type} query returned {len(seen)} record(s)."
                else:
                    snippet_lines.append(f"No {record_type} records discovered.")
                    summary = f"No {record_type} records discovered."
            elif resolver is not None:
                import dns.resolver  # type: ignore

                answers = resolver.resolve(target, record_type)
                values = [str(item).strip() for item in answers]
                metadata[record_type].extend(values)
                snippet_lines.append(
                    f"{record_type} records: " + ", ".join(values)
                    if values
                    else "No records"
                )
                summary = f"{record_type} query completed with {len(values)} result(s)."
            else:
                summary = f"{record_type} query skipped (dnspython not installed)."
                snippet_lines.append("dnspython not installed; skipping.")
        except Exception as exc:
            snippet_lines.append(f"{record_type} lookup error: {exc}")
            summary = f"{record_type} query failed."
        completed = _utcnow()
        findings.append(
            _make_finding(
                tool="dns-active",
                cmdline=f"dnsquery --type {record_type} --target {target}",
                summary=summary,
                raw_snippet="\n".join(snippet_lines) or f"No {record_type} data",
                started_at=started,
                completed_at=completed,
            )
        )
    return metadata, findings


def udp_scan_pass(
    target: str,
    profile: ReconProfile,
    ports: Sequence[int],
    bucket: TokenBucket,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    metadata: dict[str, object] = {"scanned_ports": list(ports), "responses": {}}
    findings: list[dict[str, object]] = []
    if not profile.udp_pass:
        return metadata, findings

    for port in ports:
        bucket.consume()
        started = _utcnow()
        response_text = ""
        summary = f"UDP port {port} did not respond."
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(profile.timeouts.get("udp", 2.0))
                sock.sendto(b"", (target, port))
                try:
                    data, _ = sock.recvfrom(128)
                    response_text = f"Received {len(data)} bytes"
                    summary = f"UDP port {port} responded with data."
                    metadata["responses"][port] = "response"
                except socket.timeout:
                    response_text = "No UDP response before timeout."
                    metadata["responses"][port] = "timeout"
        except OSError as exc:
            response_text = f"UDP error: {exc}"
            summary = f"UDP port {port} unreachable."
            metadata["responses"][port] = "error"
        completed = _utcnow()
        findings.append(
            _make_finding(
                tool="udp-scan",
                cmdline=f"udp_probe --target {target} --port {port}",
                summary=summary,
                raw_snippet=response_text or "No UDP data returned.",
                started_at=started,
                completed_at=completed,
            )
        )
    return metadata, findings


def tcp_syn_scan(
    target: str,
    profile: ReconProfile,
    ports: Sequence[int],
    bucket: TokenBucket,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    metadata: dict[str, object] = {
        "scanned_ports": list(ports),
        "open_ports": [],
    }
    if not ports:
        return metadata, []

    open_ports: list[int] = []
    errors: list[str] = []
    started = _utcnow()

    def probe_port(port: int) -> None:
        bucket.consume()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(profile.timeouts.get("tcp_syn", 2.5))
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
        except OSError as exc:
            errors.append(f"{port}:{exc}")

    with ThreadPoolExecutor(max_workers=profile.tcp_concurrency) as executor:
        futures = [executor.submit(probe_port, port) for port in ports]
        for future in as_completed(futures):
            future.result()
    metadata["open_ports"] = sorted(open_ports)
    summary = f"TCP SYN scan completed. Open ports: {', '.join(map(str, open_ports)) or 'none'}."
    raw_lines = [summary]
    if errors:
        raw_lines.append("Errors: " + "; ".join(errors[:5]))
    completed = _utcnow()
    findings = [
        _make_finding(
            tool="tcp-syn",
            cmdline=f"tcp_syn_scan --target {target} --ports {','.join(map(str, ports))}",
            summary=summary,
            raw_snippet="\n".join(raw_lines),
            started_at=started,
            completed_at=completed,
        )
    ]
    return metadata, findings


def _http_request(
    method: str,
    url: str,
    profile: ReconProfile,
    bucket: TokenBucket,
    *,
    allow_redirects: bool = True,
) -> tuple[Response | None, str | None]:
    headers = {"User-Agent": "ReconScript/safe"}
    timeout = (
        profile.timeouts.get("http", 5.0),
        profile.timeouts.get("http", 5.0),
    )
    bucket.consume()
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            allow_redirects=allow_redirects,
            timeout=timeout,
        )
        return response, None
    except requests_exceptions.RequestException as exc:
        return None, str(exc)


def http_checks(
    target: str,
    hostname: str,
    ports: Sequence[int],
    profile: ReconProfile,
    bucket: TokenBucket,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    metadata: dict[str, object] = {"services": {}}
    findings: list[dict[str, object]] = []
    http_ports = [port for port in ports if port in HTTP_PORTS]
    for port in http_ports:
        url = _build_url(hostname, port)
        started = _utcnow()
        response, error = _http_request("GET", url, profile, bucket)
        completed = _utcnow()
        if error:
            findings.append(
                _make_finding(
                    tool="http",
                    cmdline=f"http-get {url}",
                    summary=f"HTTP GET failed for {url}",
                    raw_snippet=error,
                    started_at=started,
                    completed_at=completed,
                )
            )
            metadata["services"][port] = {"error": error}
            continue
        assert response is not None
        headers = _redact_headers(dict(response.headers))
        metadata["services"][port] = {
            "url": response.url,
            "status_code": response.status_code,
            "headers": headers,
        }
        findings.append(
            _make_finding(
                tool="http",
                cmdline=f"http-get {url}",
                summary=f"HTTP {response.status_code} received from {url}",
                raw_snippet=f"Status {response.status_code}; {len(response.text)} bytes",
                started_at=started,
                completed_at=completed,
            )
        )
        head_started = _utcnow()
        head_response, head_error = _http_request("HEAD", url, profile, bucket)
        head_completed = _utcnow()
        if head_error:
            findings.append(
                _make_finding(
                    tool="http",
                    cmdline=f"http-head {url}",
                    summary=f"HTTP HEAD failed for {url}",
                    raw_snippet=head_error,
                    started_at=head_started,
                    completed_at=head_completed,
                )
            )
        else:
            assert head_response is not None
            findings.append(
                _make_finding(
                    tool="http",
                    cmdline=f"http-head {url}",
                    summary=f"HTTP HEAD returned {head_response.status_code}",
                    raw_snippet="Headers only response recorded.",
                    started_at=head_started,
                    completed_at=head_completed,
                )
            )
        if profile.dir_enum in {"low", "medium"}:
            dir_findings = _directory_enum(url, profile, bucket)
            findings.extend(dir_findings)
    return metadata, findings


def _directory_enum(
    base_url: str, profile: ReconProfile, bucket: TokenBucket
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    if profile.dir_enum == "none":
        return findings
    wordlist = list(
        SAFE_WORDLIST_LOW if profile.dir_enum == "low" else SAFE_WORDLIST_MEDIUM
    )
    if profile.dir_enum == "medium":
        combos = [
            "admin/login",
            "admin/config",
            "api/v1",
            "api/status",
        ]
        wordlist.extend(combos)
    wordlist = wordlist[:200]
    discovered: list[str] = []
    for path in wordlist:
        url = base_url.rstrip("/") + "/" + path
        response, error = _http_request("HEAD", url, profile, bucket)
        if error:
            continue
        assert response is not None
        if response.status_code < 400:
            discovered.append(f"{path} ({response.status_code})")
    if discovered:
        findings.append(
            _make_finding(
                tool="http-dir-enum",
                cmdline=f"dir-enum --base {base_url} --level {profile.dir_enum}",
                summary=f"Directory enumeration discovered {len(discovered)} path(s).",
                raw_snippet=", ".join(discovered),
                started_at=_utcnow(),
                completed_at=_utcnow(),
            )
        )
    else:
        findings.append(
            _make_finding(
                tool="http-dir-enum",
                cmdline=f"dir-enum --base {base_url} --level {profile.dir_enum}",
                summary="Directory enumeration completed with no findings.",
                raw_snippet="No accessible directories identified within safe wordlist.",
                started_at=_utcnow(),
                completed_at=_utcnow(),
            )
        )
    return findings


def serialize_results(data: dict[str, object]) -> str:
    import json

    return json.dumps(data, indent=2, sort_keys=True)


__all__ = [
    "DEFAULT_TCP_PORTS",
    "DEFAULT_UDP_PORTS",
    "HTTP_PORTS",
    "ReconProfile",
    "active_dns_sweep",
    "http_checks",
    "passive_dns_collection",
    "profile_for_evidence",
    "serialize_results",
    "tcp_syn_scan",
    "udp_scan_pass",
    "validate_port_list",
]
