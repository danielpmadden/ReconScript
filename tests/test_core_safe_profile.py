# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""Tests for the safe default recon workflow."""

from __future__ import annotations

from reconscript.core import run_recon
from reconscript.scanner import profile_for_evidence


def test_run_recon_safe_defaults() -> None:
    profile = profile_for_evidence("low")
    report = run_recon(
        target="127.0.0.1", ports=[80], evidence_level="low", profile=profile
    )

    metadata = report["metadata"]
    assert metadata["profile"]["allow_credentialed"] is False
    assert metadata["profile"]["dir_enum"] in {"low", "medium", "none"}

    findings = report["findings"]
    assert isinstance(findings, list)
    assert findings, "Expected at least one finding even if target is quiet"
    for finding in findings:
        assert {
            "tool",
            "cmdline",
            "summary",
            "started_at",
            "completed_at",
            "raw_snippet",
        }.issubset(finding.keys())
        assert len(finding["raw_snippet"]) <= 400
