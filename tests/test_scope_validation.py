from __future__ import annotations

import os
import socket

import pytest

from reconscript.scope import ScopeError, validate_target


def test_validate_ipv4() -> None:
    result = validate_target("127.0.0.1")
    assert result.kind == "ip"
    assert result.target == "127.0.0.1"


def test_validate_hostname_with_expected_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host, port, proto=socket.IPPROTO_TCP, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr("reconscript.scope.socket.getaddrinfo", fake_getaddrinfo)
    result = validate_target("example.local", expected_ip="127.0.0.1")
    assert result.kind == "hostname"
    assert result.resolved_ip == "127.0.0.1"


def test_cidr_rejected_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOW_CIDR", raising=False)
    with pytest.raises(ScopeError):
        validate_target("192.168.0.0/24")


def test_single_host_cidr_allowed_when_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALLOW_CIDR", "true")
    result = validate_target("192.0.2.10/32")
    assert result.target == "192.0.2.10"


def test_rejects_multi_target_input() -> None:
    with pytest.raises(ScopeError):
        validate_target("192.0.2.1 192.0.2.2")
    with pytest.raises(ScopeError):
        validate_target("10.0.0.1,10.0.0.2")
