from __future__ import annotations

from pathlib import Path

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
    html_output = render_html(sample_report)
    assert "<section id=\"summary\">" in html_output
    path = tmp_path / "report.html"
    write_report(sample_report, path, "html")
    assert path.exists()
    assert path.stat().st_size > 0


def test_pdf_renderer_produces_file(sample_report, tmp_path):
    pytest.importorskip("weasyprint")
    pdf_path = tmp_path / "report.pdf"
    try:
        write_report(sample_report, pdf_path, "pdf")
    except RuntimeError as exc:  # pragma: no cover - environment limitation
        pytest.skip(f"PDF generation unavailable: {exc}")
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0
    html_path = Path(str(pdf_path).replace(".pdf", ".html"))
    assert html_path.exists()
