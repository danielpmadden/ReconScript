from __future__ import annotations

# Modified by codex: 2024-05-08
# Modified by codex: 2024-05-08

from pathlib import Path
import sys

import pytest

from reconscript import __version__
from reconscript.reporters import render_html, render_markdown, write_report


@pytest.fixture()
def sample_report() -> dict[str, object]:
    return {
        "target": "203.0.113.5",
        "hostname": "example.com",
        "ports": [80, 443],
        "open_ports": [80],
        "version": __version__,
        "timestamp": "2024-04-30T12:00:00Z",
        "http_checks": {},
        "robots": {"note": "sample data"},
        "findings": [
            {"port": 80, "issue": "missing_security_headers", "details": ["HSTS"]},
        ],
    }


def test_markdown_renderer_includes_sections(sample_report):
    output = render_markdown(sample_report)
    assert "## Summary" in output
    assert "## Findings" in output
    assert "## Metadata" in output


def test_html_renderer_uses_template(sample_report, tmp_path):
    path = tmp_path / "report.html"
    written = render_html(sample_report, path)
    assert written.exists()
    assert written.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert "ReconScript" in written.read_text(encoding="utf-8")


def test_write_report_generates_markdown(sample_report, tmp_path):
    md_path = tmp_path / "report.md"
    written_path, actual_format = write_report(sample_report, md_path, "markdown")
    assert actual_format == "markdown"
    assert written_path.exists()
    assert "## Summary" in written_path.read_text(encoding="utf-8")


def test_write_report_generates_json(sample_report, tmp_path):
    json_path = tmp_path / "report.json"
    written_path, actual_format = write_report(sample_report, json_path, "json")
    assert actual_format == "json"
    assert written_path.exists()
    assert "target" in written_path.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform.startswith("win"), reason="GTK PDF backend unavailable on Windows CI")
def test_pdf_renderer_produces_file(sample_report, tmp_path):
    pytest.importorskip("weasyprint")
    pdf_path = tmp_path / "report.pdf"
    written_path, actual_format = write_report(sample_report, pdf_path, "pdf")
    if actual_format != "pdf":  # pragma: no cover - depends on system libraries
        pytest.skip(f"PDF fallback triggered: {written_path}")
    assert written_path.exists()
    assert written_path.stat().st_size > 0
