from __future__ import annotations

"""Target scope validation helpers for ReconScript."""

import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from typing import Optional

__all__ = ["ScopeValidation", "ScopeError", "validate_target", "ensure_within_allowlist"]

WHITESPACE_PATTERN = re.compile(r"\s")
INVALID_CHAR_PATTERN = re.compile(r"[*,]")
RANGE_PATTERN = re.compile(r"\d+\s*-\s*\d+")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}\.?)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class ScopeError(ValueError):
    """Raised when a supplied scope target fails validation."""


@dataclass(frozen=True)
class ScopeValidation:
    """Normalized information about an approved scan target."""

    original: str
    target: str
    kind: str  # "ip" or "hostname"
    resolved_ip: Optional[str] = None

    @property
    def is_local(self) -> bool:
        address = self.resolved_ip if self.kind == "hostname" else self.target
        try:
            return ipaddress.ip_address(address).is_loopback
        except ValueError:
            return False


def _default_allow_cidr() -> bool:
    return os.environ.get("ALLOW_CIDR", "false").lower() == "true"


def _validate_ip(target: str, allow_cidr: bool) -> ScopeValidation:
    if "/" in target:
        if not allow_cidr:
            raise ScopeError(
                "CIDR notation is not permitted unless ALLOW_CIDR=true is set in the environment."
            )
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ScopeError("Invalid CIDR notation supplied for target.") from exc
        if network.num_addresses != 1:
            raise ScopeError("Only single-host CIDR ranges (/32 or /128) are permitted.")
        normalized = str(network.network_address)
        return ScopeValidation(original=target, target=normalized, kind="ip")
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ScopeError("Target must be a valid IPv4 or IPv6 address or hostname.") from exc
    return ScopeValidation(original=target, target=str(address), kind="ip")


def _lookup_hostname(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"Unable to resolve hostname '{hostname}': {exc}") from exc
    results: list[str] = []
    for info in infos:
        sockaddr = info[-1]
        host_ip = sockaddr[0]
        try:
            ipaddress.ip_address(host_ip)
        except ValueError:
            continue
        if host_ip not in results:
            results.append(host_ip)
    return results


def validate_target(
    target: str,
    *,
    expected_ip: str | None = None,
    allow_cidr: Optional[bool] = None,
) -> ScopeValidation:
    """Validate a CLI/UI supplied target string."""

    if not isinstance(target, str) or not target.strip():
        raise ScopeError("A single target must be provided.")
    target = target.strip()

    allow_cidr = _default_allow_cidr() if allow_cidr is None else allow_cidr

    if WHITESPACE_PATTERN.search(target) or INVALID_CHAR_PATTERN.search(target):
        raise ScopeError("Target must be a single host/IP without ranges or wildcards.")
    if RANGE_PATTERN.search(target):
        raise ScopeError("Target ranges are not permitted.")
    if "/" in target and not allow_cidr:
        raise ScopeError("CIDR notation is not permitted unless ALLOW_CIDR=true is set in the environment.")

    try:
        return _validate_ip(target, allow_cidr)
    except ScopeError:
        pass

    if not HOSTNAME_PATTERN.fullmatch(target):
        raise ScopeError("Target must be a valid IPv4 or IPv6 address or hostname.")

    resolved = _lookup_hostname(target)
    if not resolved:
        raise ScopeError("Hostname did not resolve to any IP addresses.")
    if expected_ip:
        normalized_expected = str(ipaddress.ip_address(expected_ip))
        if len(resolved) != 1:
            raise ScopeError("Hostname must resolve to exactly one address when expected IP is provided.")
        if resolved[0] != normalized_expected:
            raise ScopeError("Hostname resolution did not match the expected IP address.")
        return ScopeValidation(original=target, target=target, kind="hostname", resolved_ip=normalized_expected)
    if len(resolved) != 1:
        raise ScopeError("Hostname resolves to multiple addresses; supply --expected-ip to continue.")
    return ScopeValidation(original=target, target=target, kind="hostname", resolved_ip=resolved[0])


def ensure_within_allowlist(target: ScopeValidation) -> None:
    """Basic guardrail preventing scanning of prohibited ranges."""

    address = target.resolved_ip if target.kind == "hostname" else target.target
    try:
        ip_obj = ipaddress.ip_address(address)
    except ValueError as exc:  # pragma: no cover - defensive safety
        raise ScopeError("Target resolved to an invalid IP address.") from exc
    if ip_obj.is_multicast or ip_obj.is_reserved:
        raise ScopeError("Scanning multicast or reserved IP ranges is not permitted by default.")
