# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""Unit tests for ReconProfile defaults and helpers."""

from __future__ import annotations

import pytest

from reconscript.scanner import ReconProfile, profile_for_evidence


def test_recon_profile_defaults() -> None:
    profile = ReconProfile(name="test-profile")
    assert profile.max_tcp_ports == 100
    assert profile.tcp_concurrency == 10
    assert profile.dir_enum == "low"
    assert profile.timeouts["http"] == pytest.approx(5.0)
    assert profile.rate_limits["tcp"] == (5.0, 5.0)


def test_profile_for_evidence_levels() -> None:
    low = profile_for_evidence("low")
    medium = profile_for_evidence("medium")
    high = profile_for_evidence("high")

    assert low.dir_enum == "low"
    assert medium.dir_enum == "medium"
    assert high.dir_enum == "none"
    assert high.max_tcp_ports > medium.max_tcp_ports >= low.max_tcp_ports


def test_limit_ports_enforces_cap() -> None:
    profile = ReconProfile(name="cap-test", max_tcp_ports=3)
    ports = profile.limit_ports([80, 443, 8080, 8443])
    assert len(ports) == 3
    assert ports[0] == 80
    assert 443 in ports
