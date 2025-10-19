from __future__ import annotations

from pathlib import Path

from reconscript import cli, report as report_module


def test_cli_generates_markdown_report(tmp_path: Path, monkeypatch) -> None:
    results_dir = tmp_path / "results"
    monkeypatch.setenv("RESULTS_DIR", str(results_dir))
    monkeypatch.setattr(report_module, "RESULTS_DIR", results_dir)
    monkeypatch.setattr(report_module, "INDEX_FILE", results_dir / "index.json")
    monkeypatch.setattr(report_module, "LOCK_PATH", results_dir / ".index.lock")
    exit_code = cli.main(
        [
            "--target",
            "127.0.0.1",
            "--dry-run",
            "--ports",
            "80",
            "--format",
            "markdown",
        ]
    )
    assert exit_code == 0

    report_dirs = [path for path in results_dir.iterdir() if path.is_dir()]
    assert report_dirs, "CLI should create a timestamped report directory"
    markdown_files = list(report_dirs[0].glob("report.*"))
    assert any(file.suffix in {".markdown", ".md"} for file in markdown_files)
    markdown_path = next(
        file for file in markdown_files if file.suffix in {".markdown", ".md"}
    )
    content = markdown_path.read_text(encoding="utf-8")
    assert "## Findings" in content
    assert "## HTTP" in content
