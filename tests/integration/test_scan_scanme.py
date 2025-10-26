# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
from __future__ import annotations

import os

import pytest

from reconscript.core import run_recon


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("INTEGRATION_SCANME", "false").lower() != "true",
    reason="Set INTEGRATION_SCANME=true to enable",
)
def test_scan_scanme() -> None:
    report = run_recon(target="scanme.nmap.org", evidence_level="low")
    assert "artifacts" in report
    assert "findings" in report
