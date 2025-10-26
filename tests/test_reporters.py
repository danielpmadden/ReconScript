from __future__ import annotations

from pathlib import Path

from reconscript.reporters import render_markdown, write_report


def sample_report() -> dict[str, object]:
    return {
        "metadata": {
            "target": "example.com",
            "hostname": "example.com",
            "scanned_tcp_ports": [80, 443],
            "profile": {
                "name": "safe-default",
                "max_tcp_ports": 100,
                "tcp_concurrency": 10,
                "dir_enum": "low",
                "allow_credentialed": False,
            },
        },
        "artifacts": {
            "http": {
                "services": {80: {"status_code": 200, "url": "http://example.com"}}
            },
            "tcp": {"open_ports": [80]},
        },
        "findings": [
            {
                "tool": "http-check",
                "cmdline": "http --url http://example.com",
                "summary": "HTTP responded with 200 OK without Strict-Transport-Security.",
                "raw_snippet": "Header Strict-Transport-Security missing",
                "started_at": "2024-01-01T00:00:00Z",
                "completed_at": "2024-01-01T00:00:01Z",
            }
        ],
        "runtime": {"started_at": "2024-01-01T00:00:00Z"},
    }


def test_render_markdown_fallback_contains_sections() -> None:
    markdown = render_markdown(sample_report())
    assert "# ReconScript Report" in markdown
    assert "## Findings" in markdown
    assert "## Recommendations" in markdown
    assert "http --url http://example.com" in markdown


def test_write_report_markdown(tmp_path: Path) -> None:
    report_file = tmp_path / "report.md"
    written_path, format_used = write_report(sample_report(), report_file, "markdown")
    assert written_path.exists()
    assert format_used == "markdown"
    content = written_path.read_text(encoding="utf-8")
    assert "## Metadata" in content
