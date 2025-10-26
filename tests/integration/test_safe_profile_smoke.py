# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
"""Smoke test ensuring a safe profile run persists a report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reconscript.core import run_recon
from reconscript.report import persist_report


@pytest.mark.integration
def test_safe_profile_persists_report(tmp_path: Path) -> None:
    report = run_recon(target="127.0.0.1", ports=[80], evidence_level="low")
    persisted = persist_report(report)
    try:
        stored = json.loads(persisted.report_file.read_text(encoding="utf-8"))
        assert stored["metadata"]["profile"]["name"].startswith("safe")
        assert stored["findings"], "Expected findings in persisted report"
        assert all(len(f["raw_snippet"]) <= 400 for f in stored["findings"])
    finally:
        import shutil

        shutil.rmtree(persisted.base, ignore_errors=True)
