from __future__ import annotations

from pathlib import Path

from reconscript.reporters import render_markdown, write_report


def sample_report() -> dict[str, object]:
    return {
        "target": "example.com",
        "hostname": "example.com",
        "ports": [80, 443],
        "open_ports": [80],
        "findings": [
            {
                "port": 80,
                "issue": "missing_security_headers",
                "details": {"header": "Strict-Transport-Security"},
            }
        ],
        "runtime": {"started_at": "2024-01-01T00:00:00Z"},
    }


def test_render_markdown_fallback_contains_sections() -> None:
    markdown = render_markdown(sample_report())
    assert "# ReconScript Report" in markdown
    assert "## Findings" in markdown
    assert "## Recommendations" in markdown
    assert "Strict-Transport-Security" in markdown


def test_write_report_markdown(tmp_path: Path) -> None:
    report_file = tmp_path / "report.md"
    written_path, format_used = write_report(sample_report(), report_file, "markdown")
    assert written_path.exists()
    assert format_used == "markdown"
    content = written_path.read_text(encoding="utf-8")
    assert "## Metadata" in content
