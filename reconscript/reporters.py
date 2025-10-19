"""Report rendering utilities for ReconScript."""

from __future__ import annotations

# Modified by codex: 2024-05-08
import html
import json
import logging
import textwrap
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_TEMPLATES = PACKAGE_DIR.parent / "templates"
PACKAGE_TEMPLATES = PACKAGE_DIR / "templates"
TEMPLATE_DIRS = [
    path for path in (PROJECT_TEMPLATES, PACKAGE_TEMPLATES) if path.exists()
]
HTML_TEMPLATE_NAME = "report.html"

LOGGER = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency may be unavailable in CI
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except ImportError as exc:  # pragma: no cover - fallback for minimal environments
    LOGGER.warning("Jinja2 not available; HTML rendering will use fallback: %s", exc)
    Environment = None  # type: ignore[assignment]
    FileSystemLoader = None  # type: ignore[assignment]
    select_autoescape = None  # type: ignore[assignment]
    _JINJA_ENV: Environment | None = None
else:  # pragma: no cover - exercised when Jinja2 installed
    loader_paths = [str(path) for path in TEMPLATE_DIRS] or [str(PACKAGE_TEMPLATES)]
    _JINJA_ENV = Environment(
        loader=FileSystemLoader(loader_paths),
        autoescape=select_autoescape(["html", "xml"]),
    )

PDF_FALLBACK_MESSAGE = "PDF dependencies not found — served HTML version instead."


def render_json(data: dict[str, object]) -> str:
    """Return a canonical JSON representation of the scan results."""

    return json.dumps(data, indent=2, sort_keys=True)


def render_markdown(data: dict[str, object]) -> str:
    """Render the report data in Markdown format."""

    if _JINJA_ENV is not None and _JINJA_ENV.loader is not None:
        try:
            template = _JINJA_ENV.get_template("report.md.j2")
            return template.render(data=data)
        except Exception:
            LOGGER.exception("Failed to render markdown via Jinja2; using fallback")

    context = _build_markdown_context(data)
    lines = _render_markdown_sections(context)
    return "\n".join(lines) + "\n"


def render_html(data: dict[str, object], out_path: Path) -> Path:
    """Render the report data as HTML and persist it to ``out_path``."""

    if not isinstance(out_path, Path):
        out_path = Path(out_path)

    context = _build_template_context(data)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    html_output = _render_html_document(context)
    out_path.write_text(html_output, encoding="utf-8")
    return out_path.resolve()


def generate_pdf(html_path: Path, pdf_path: Path) -> tuple[Path, bool]:
    """Generate a PDF from ``html_path`` and return the written file."""

    if not isinstance(html_path, Path):
        html_path = Path(html_path)
    if not isinstance(pdf_path, Path):
        pdf_path = Path(pdf_path)

    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    try:  # pragma: no cover - exercised indirectly via integration tests
        from weasyprint import HTML
    except ImportError as exc:
        LOGGER.warning(
            "%s Install via 'pip install .[pdf]' or rebuild with INCLUDE_PDF=true. (%s)",
            PDF_FALLBACK_MESSAGE,
            exc,
        )
        return html_path.resolve(), False

    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    except OSError as exc:
        LOGGER.warning(
            "%s Install via 'pip install .[pdf]' or rebuild with INCLUDE_PDF=true. (%s)",
            PDF_FALLBACK_MESSAGE,
            exc,
        )
        return html_path.resolve(), False

    return pdf_path.resolve(), True


def write_report(
    data: dict[str, object], outfile: Path, format: str
) -> tuple[Path, str]:
    """Write ``data`` to ``outfile`` using ``format`` and return the resulting path."""

    if not isinstance(outfile, Path):
        outfile = Path(outfile)

    normalized_format = format.lower()

    if normalized_format == "json":
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(render_json(data), encoding="utf-8")
        return outfile.resolve(), "json"

    if normalized_format in {"markdown", "md"}:
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(render_markdown(data), encoding="utf-8")
        return outfile.resolve(), "markdown"

    if normalized_format == "html":
        return render_html(data, outfile), "html"

    if normalized_format == "pdf":
        html_path = outfile.with_suffix(".html")
        html_written = render_html(data, html_path)
        pdf_written, succeeded = generate_pdf(html_written, outfile)
        return pdf_written, "pdf" if succeeded else "html"

    raise ValueError(f"Unsupported report format: {format}")


def _format_list(values: Iterable[object]) -> str:
    items = list(values)
    if not items:
        return ""
    return ", ".join(str(item) for item in items)


def _build_recommendations(findings: Sequence[dict[str, object]]) -> list[str]:
    suggestions: list[str] = []
    issues = {item.get("issue") for item in findings}

    if "missing_security_headers" in issues:
        suggestions.append(
            "Set Strict-Transport-Security and related headers on all web front-ends."
        )
    if "session_cookie_flags" in issues:
        suggestions.append(
            "Configure Secure and HttpOnly attributes on session cookies."
        )
    if "server_error" in issues:
        suggestions.append(
            "Review backend error logs for endpoints returning 5xx responses."
        )
    if not suggestions and findings:
        suggestions.append(
            "Investigate informational findings for context-specific remediation."
        )
    return suggestions


def _build_markdown_context(data: dict[str, object]) -> dict[str, Any]:
    findings = data.get("findings", [])
    context = {
        "target": data.get("target", "unknown"),
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        "hostname": data.get("hostname") or "N/A",
        "ports": _format_list(data.get("ports", [])) or "None",
        "open_ports": _format_list(data.get("open_ports", [])) or "None detected",
        "findings": findings if isinstance(findings, Sequence) else [],
        "recommendations": _build_recommendations(
            findings if isinstance(findings, Sequence) else []
        ),
        "version": data.get("version", __version__),
        "runtime": data.get("runtime", {}),
    }
    return context


def _render_markdown_sections(context: dict[str, Any]) -> list[str]:
    lines: list[str] = [
        f"# ReconScript Report — {context['target']}",
        "",
        f"*Generated:* {context['timestamp']}",
        f"*Hostname:* {context['hostname']}",
        f"*Ports scanned:* {context['ports']}",
        f"*Open ports:* {context['open_ports']}",
        "",
        "## Findings",
    ]

    findings = context.get("findings", [])
    if findings:
        for item in findings:
            port = item.get("port", "n/a") if isinstance(item, dict) else "n/a"
            issue = (
                item.get("issue", "observation")
                if isinstance(item, dict)
                else str(item)
            )
            lines.append(f"- Port `{port}` — `{issue}`")
            if isinstance(item, dict) and item.get("details") is not None:
                details = item["details"]
                if isinstance(details, (dict, list)):
                    rendered = json.dumps(details, indent=2, sort_keys=True)
                    lines.append("  ```json")
                    lines.extend(f"  {line}" for line in rendered.splitlines())
                    lines.append("  ```")
                else:
                    lines.append(f"  {details}")
    else:
        lines.append("No findings reported.")

    lines.append("")
    lines.append("## Recommendations")
    recommendations = context.get("recommendations", [])
    if recommendations:
        for recommendation in recommendations:
            lines.append(f"- {recommendation}")
    else:
        lines.append("- Maintain current controls; no immediate actions identified.")

    runtime = json.dumps(context.get("runtime", {}), indent=2, sort_keys=True)
    lines.extend(
        [
            "",
            "## Metadata",
            f"- **Report version:** {context['version']}",
            f"- **Runtime:** {runtime}",
        ]
    )
    return lines


def _build_template_context(data: dict[str, object]) -> dict[str, object]:
    timestamp_raw = str(data.get("timestamp", datetime.utcnow().isoformat() + "Z"))
    findings = data.get("findings", [])
    findings_count = len(findings) if isinstance(findings, Sequence) else 0
    runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    summary_rows = _summary_rows(data)
    recommendations = _build_recommendations(findings)
    duration_value = runtime.get("duration") if isinstance(runtime, dict) else None
    if isinstance(duration_value, (int, float)):
        duration_display = f"{duration_value:.2f}"
    else:
        duration_display = None

    return {
        "title": f"ReconScript Report — {data.get('target', 'unknown')}",
        "target": data.get("target", "unknown"),
        "hostname": data.get("hostname") or "N/A",
        "timestamp": timestamp_raw,
        "summary_rows": summary_rows,
        "findings": _format_findings(findings),
        "recommendations": recommendations,
        "metadata": _metadata_entries(data, timestamp_raw),
        "version": data.get("version", __version__),
        "generated_human": _format_human_date(timestamp_raw),
        "findings_count": findings_count,
        "runtime": runtime,
        "runtime_duration": duration_display,
    }


def _summary_rows(data: dict[str, object]) -> list[tuple[str, str]]:
    ports = _format_list(data.get("ports", [])) or "None"
    open_ports = _format_list(data.get("open_ports", [])) or "None detected"
    findings = data.get("findings", [])
    findings_count = len(findings) if isinstance(findings, Sequence) else 0
    runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    duration = (
        runtime.get("duration") if isinstance(runtime, dict) else data.get("duration")
    )

    rows: list[tuple[str, str]] = [
        ("Target", str(data.get("target", "unknown"))),
        ("Hostname", str(data.get("hostname") or "N/A")),
        ("Ports Scanned", ports),
        ("Open Ports", open_ports),
        ("Findings", str(findings_count)),
    ]

    if duration is not None:
        if isinstance(duration, (int, float)):
            rows.append(("Scan Duration", f"{duration:.2f} seconds"))
        else:
            rows.append(("Scan Duration", str(duration)))

    return rows


def _format_findings(findings: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    formatted: list[dict[str, object]] = []
    for item in findings or []:
        formatted.append(
            {
                "port": item.get("port", "n/a"),
                "issue": item.get("issue", "observation"),
                "details": item.get("details"),
            }
        )
    return formatted


def _metadata_entries(data: dict[str, object], timestamp: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = [
        ("Tool Version", str(data.get("version", __version__))),
        ("Report Generated", timestamp),
    ]

    runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    if isinstance(runtime, dict):
        if runtime.get("started_at"):
            entries.append(("Scan Started", str(runtime["started_at"])))
        if runtime.get("completed_at"):
            entries.append(("Scan Completed", str(runtime["completed_at"])))
        if runtime.get("duration") is not None:
            duration_value = runtime.get("duration")
            if isinstance(duration_value, (int, float)):
                entries.append(("Scan Duration", f"{duration_value:.2f} seconds"))
            else:
                entries.append(("Scan Duration", str(duration_value)))

    cli_args = data.get("cli_args")
    if cli_args:
        entries.append(("CLI Arguments", json.dumps(cli_args, indent=2)))

    robots = data.get("robots")
    if isinstance(robots, dict):
        if robots.get("url"):
            entries.append(("robots.txt", str(robots["url"])))
        elif robots.get("note"):
            entries.append(("robots.txt", str(robots["note"])))

    return entries


def _format_human_date(timestamp: str) -> str:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return timestamp
    return parsed.strftime("%d %B %Y %H:%M UTC")


def _render_html_document(context: dict[str, object]) -> str:
    if _JINJA_ENV is not None:
        try:
            template = _JINJA_ENV.get_template(HTML_TEMPLATE_NAME)
            return template.render(**context)
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("Jinja2 rendering failed: %s; using fallback renderer.", exc)
    return _render_html_fallback(context)


def _render_html_fallback(context: dict[str, object]) -> str:
    summary_rows = context.get("summary_rows", [])
    findings = context.get("findings", [])
    recommendations = context.get("recommendations", [])
    metadata = context.get("metadata", [])

    summary_html = "".join(
        f'<tr><th scope="row">{html.escape(str(label))}</th><td>{html.escape(str(value))}</td></tr>'
        for label, value in summary_rows
    )

    if findings:
        findings_html = "".join(
            """
            <li>
              <strong>Port {port}</strong> — <code>{issue}</code>
              {details}
            </li>
            """.strip().format(
                port=html.escape(str(item.get("port", "n/a"))),
                issue=html.escape(str(item.get("issue", "observation"))),
                details=(
                    f"<pre>{html.escape(json.dumps(item.get('details'), indent=2))}</pre>"
                    if item.get("details") is not None
                    else "<p>No additional context supplied.</p>"
                ),
            )
            for item in findings
        )
        findings_section = f'<ul class="findings">{findings_html}</ul>'
    else:
        findings_section = "<p>No issues detected during the assessment.</p>"

    if recommendations:
        recommendations_html = (
            '<ul class="recommendations">'
            + "".join(f"<li>{html.escape(str(item))}</li>" for item in recommendations)
            + "</ul>"
        )
    else:
        recommendations_html = (
            "<p>Continue monitoring and maintain existing controls.</p>"
        )

    metadata_html = (
        '<dl class="meta">'
        + "".join(
            f"<dt>{html.escape(str(label))}</dt><dd>{html.escape(str(value))}</dd>"
            for label, value in metadata
        )
        + "</dl>"
    )

    return textwrap.dedent(
        f"""<!DOCTYPE html>
        <html lang=\"en\">
          <head>
            <meta charset=\"utf-8\" />
            <title>{html.escape(str(context.get('title')))}</title>
            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
            <style>
              body {{
                font-family: 'Segoe UI', 'Liberation Sans', Arial, sans-serif;
                margin: 0;
                background: #f5f7fa;
                color: #1f2937;
              }}
              header.cover {{
                background: linear-gradient(135deg, #0f172a, #1f2937);
                color: #f8fafc;
                padding: 48px 32px;
                text-align: center;
              }}
              header.cover .logo {{
                display: inline-block;
                padding: 10px 28px;
                border: 2px dashed rgba(255, 255, 255, 0.45);
                border-radius: 10px;
                letter-spacing: 0.18rem;
                text-transform: uppercase;
                margin-bottom: 24px;
              }}
              main {{
                padding: 36px 48px 64px;
              }}
              section {{
                margin-bottom: 48px;
              }}
              h2 {{
                border-bottom: 2px solid #1f2937;
                padding-bottom: 6px;
              }}
              table.summary {{
                width: 100%;
                border-collapse: collapse;
                background: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 6px rgba(15, 23, 42, 0.08);
              }}
              table.summary th,
              table.summary td {{
                padding: 14px 18px;
                border-bottom: 1px solid #e2e8f0;
              }}
              table.summary th {{
                width: 30%;
                background: #f1f5f9;
                font-weight: 600;
                letter-spacing: 0.02rem;
              }}
              ul.findings {{
                list-style: none;
                padding-left: 0;
              }}
              ul.findings li {{
                background: #ffffff;
                border-left: 4px solid #f97316;
                padding: 16px 20px;
                margin-bottom: 14px;
                box-shadow: 0 1px 3px rgba(15, 23, 42, 0.1);
              }}
              ul.findings li pre {{
                background: #0f172a;
                color: #f8fafc;
                padding: 12px;
                border-radius: 6px;
                overflow-x: auto;
                font-size: 0.85rem;
              }}
              ul.recommendations {{
                padding-left: 18px;
              }}
              dl.meta {{
                display: grid;
                grid-template-columns: 220px 1fr;
                gap: 12px 18px;
                background: #ffffff;
                padding: 18px 22px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
              }}
              dl.meta dt {{
                font-weight: 600;
              }}
              dl.meta dd {{
                margin: 0;
                font-family: 'Fira Code', 'Source Code Pro', monospace;
                white-space: pre-wrap;
              }}
              footer {{
                text-align: center;
                padding: 24px;
                background: #f1f5f9;
                border-top: 1px solid #e2e8f0;
                font-size: 0.85rem;
                color: #475569;
              }}
            </style>
          </head>
          <body>
            <header class=\"cover\">
              <div class=\"logo\">ReconScript</div>
              <h1>Security Reconnaissance Report</h1>
              <p><strong>Target:</strong> {html.escape(str(context.get('target')))}</p>
              <p><strong>Hostname:</strong> {html.escape(str(context.get('hostname')))}</p>
              <p><strong>Generated:</strong> {html.escape(str(context.get('generated_human')))}</p>
              <p>Total findings: {html.escape(str(context.get('findings_count')))}</p>
            </header>
            <main>
              <section id=\"summary\">
                <h2>Summary</h2>
                <table class=\"summary\"><tbody>{summary_html}</tbody></table>
              </section>
              <section id=\"findings\">
                <h2>Findings</h2>
                {findings_section}
              </section>
              <section id=\"recommendations\">
                <h2>Recommendations</h2>
                {recommendations_html}
              </section>
              <section id=\"metadata\">
                <h2>Metadata</h2>
                {metadata_html}
              </section>
            </main>
            <footer>
              ReconScript v{html.escape(str(context.get('version')))}<br />
              Generated {html.escape(str(context.get('timestamp')))}
            </footer>
          </body>
        </html>"""
    )


__all__ = [
    "render_json",
    "render_markdown",
    "render_html",
    "generate_pdf",
    "write_report",
]
