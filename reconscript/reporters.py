# Authorized testing only — do not scan targets without explicit permission.
# This tool is non-intrusive by default and will not perform exploitation or credentialed checks.
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

try:  # pragma: no cover - optional dependency may be unavailable in CI
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except Exception:  # pragma: no cover - fallback for minimal environments
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

LOGGER = logging.getLogger(__name__)
PDF_FALLBACK_MESSAGE = "PDF dependencies not found — served HTML version instead."
MAX_RAW_SNIPPET = 400


def _merge_runtime(
    metadata: dict[str, object], data: dict[str, object]
) -> dict[str, object]:
    runtime = data.get("runtime")
    if not isinstance(runtime, dict):
        runtime = {}
    merged: dict[str, object] = dict(runtime)
    for key in ("started_at", "completed_at"):
        candidate = data.get(key) or metadata.get(key)
        if candidate and key not in merged:
            merged[key] = candidate
    duration = data.get("duration")
    if duration is not None and "duration" not in merged:
        merged["duration"] = duration
    return merged


def _clip_snippet(value: str) -> str:
    snippet = value.strip()
    if len(snippet) <= MAX_RAW_SNIPPET:
        return snippet
    return snippet[: MAX_RAW_SNIPPET - 3] + "..."


def _sanitize_findings(findings: object) -> list[dict[str, object]]:
    sanitized: list[dict[str, object]] = []
    if not isinstance(findings, Sequence):
        return sanitized

    for item in findings:
        if not isinstance(item, dict):
            continue

        summary = str(item.get("summary") or item.get("issue") or "observation").strip()
        tool = str(item.get("tool") or "unknown").strip()
        cmdline = str(item.get("cmdline") or "").strip()
        started_at = str(item.get("started_at") or "").strip()
        completed_at = str(item.get("completed_at") or "").strip()
        raw_snippet_obj = item.get("raw_snippet")
        raw_snippet = "" if raw_snippet_obj is None else str(raw_snippet_obj)
        severity = item.get("severity")
        port = item.get("port")

        sanitized_entry: dict[str, object] = {
            "summary": summary or "observation",
            "tool": tool,
            "cmdline": cmdline,
            "started_at": started_at,
            "completed_at": completed_at,
            "raw_snippet": _clip_snippet(raw_snippet),
        }

        if port is not None:
            sanitized_entry["port"] = port

        if severity:
            sanitized_entry["severity"] = str(severity)

        evidence = item.get("evidence")
        if isinstance(evidence, dict) and evidence:
            sanitized_entry["evidence"] = evidence

        sanitized.append(sanitized_entry)

    return sanitized


def _normalize_report(data: dict[str, object]) -> dict[str, object]:
    if not isinstance(data, dict):
        return {
            "target": "unknown",
            "hostname": "N/A",
            "ports": [],
            "open_ports": [],
            "findings": [],
            "runtime": {},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}

    normalized: dict[str, object] = dict(data)
    normalized["target"] = metadata.get("target", data.get("target", "unknown"))
    normalized["hostname"] = metadata.get("hostname", data.get("hostname"))
    normalized["ports"] = list(metadata.get("scanned_tcp_ports", data.get("ports", [])))
    normalized["udp_ports"] = list(metadata.get("scanned_udp_ports", []))
    normalized["open_ports"] = list(
        artifacts.get("tcp", {}).get("open_ports", data.get("open_ports", []))
    )
    normalized["http_services"] = artifacts.get("http", {}).get("services", {})
    normalized["runtime"] = _merge_runtime(metadata, data)
    normalized["timestamp"] = (
        normalized.get("timestamp")
        or normalized["runtime"].get("started_at")
        or datetime.utcnow().isoformat() + "Z"
    )
    normalized_findings = _sanitize_findings(data.get("findings"))
    normalized["findings"] = normalized_findings
    normalized["legacy_findings"] = [
        {
            "port": item.get("port", "n/a"),
            "issue": item.get("summary"),
            "details": {
                "tool": item.get("tool"),
                "cmdline": item.get("cmdline"),
                "started_at": item.get("started_at"),
                "completed_at": item.get("completed_at"),
                "raw_snippet": item.get("raw_snippet"),
            },
        }
        for item in normalized_findings
    ]
    normalized["profile"] = metadata.get("profile", {})
    normalized["evidence_level"] = metadata.get(
        "evidence_level", data.get("evidence_level")
    )
    normalized["consent_present"] = metadata.get(
        "consent_present", data.get("consent_present")
    )
    normalized["version"] = metadata.get("version", data.get("version", __version__))
    return normalized


def render_json(data: dict[str, object]) -> str:
    """Return a canonical JSON representation of the scan results."""

    return json.dumps(data, indent=2, sort_keys=True)


def render_markdown(data: dict[str, object]) -> str:
    """Render the report data in Markdown format."""

    normalized = _normalize_report(data)

    if _JINJA_ENV is not None and _JINJA_ENV.loader is not None:
        try:
            template = _JINJA_ENV.get_template("report.md.j2")
            return template.render(data=normalized)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOGGER.debug("Falling back to builtin Markdown renderer: %s", exc)

    context = _build_markdown_context(normalized)
    lines = _render_markdown_sections(context)
    return "\n".join(lines) + "\n"


def render_html(data: dict[str, object], out_path: Path) -> Path:
    """Render the report data as HTML and persist it to ``out_path``."""

    if not isinstance(out_path, Path):
        out_path = Path(out_path)

    normalized = _normalize_report(data)
    context = _build_template_context(normalized)

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
    summaries = {str(item.get("summary")) for item in findings}

    for summary in summaries:
        lowered = summary.lower()
        if "security header" in lowered:
            header_message = (
                "Review HTTP response headers and enable Strict-Transport-"
                "Security where appropriate."
            )
            suggestions.append(header_message)
        if "cookie" in lowered:
            suggestions.append(
                "Verify cookies include Secure and HttpOnly attributes on production systems."
            )
        if "error" in lowered or "5xx" in lowered:
            suggestions.append(
                "Investigate server error responses for potential misconfigurations."
            )

    if not suggestions and findings:
        suggestions.append(
            "Review informational observations for context-specific improvements."
        )

    return suggestions


def _build_markdown_context(data: dict[str, object]) -> dict[str, Any]:
    findings = data.get("findings", [])
    http_services = data.get("http_services", {})
    profile = data.get("profile", {})
    context = {
        "target": data.get("target", "unknown"),
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        "hostname": data.get("hostname") or "N/A",
        "ports": _format_list(data.get("ports", [])) or "None",
        "udp_ports": _format_list(data.get("udp_ports", [])) or "None",
        "open_ports": _format_list(data.get("open_ports", [])) or "None detected",
        "findings": findings if isinstance(findings, Sequence) else [],
        "recommendations": _build_recommendations(
            findings if isinstance(findings, Sequence) else []
        ),
        "version": data.get("version", __version__),
        "runtime": data.get("runtime", {}),
        "http_services": http_services if isinstance(http_services, dict) else {},
        "profile": profile if isinstance(profile, dict) else {},
        "profile_name": profile.get("name") if isinstance(profile, dict) else "N/A",
        "evidence_level": data.get("evidence_level", "unknown"),
        "consent_present": data.get("consent_present"),
    }
    return context


def _render_markdown_sections(context: dict[str, Any]) -> list[str]:
    lines: list[str] = [
        f"# ReconScript Report — {context['target']}",
        "",
        f"*Generated:* {context['timestamp']}",
        f"*Hostname:* {context['hostname']}",
        f"*Evidence level:* {context['evidence_level']}",
        f"*Profile:* {context['profile_name']}",
        f"*Ports scanned:* {context['ports']}",
        f"*UDP ports scanned:* {context['udp_ports']}",
        f"*Open ports:* {context['open_ports']}",
        "",
        "## Recon Profile",
    ]

    profile = context.get("profile", {})
    if profile:
        lines.extend(
            [
                f"- Max TCP ports: {profile.get('max_tcp_ports', 'unknown')}",
                f"- TCP concurrency: {profile.get('tcp_concurrency', 'unknown')}",
                f"- Directory enumeration: {profile.get('dir_enum', 'unknown')}",
            ]
        )
    else:
        lines.append("- Profile details unavailable.")

    lines.append("")
    lines.append("## HTTP")
    services = context.get("http_services", {})
    if services:
        for port, info in sorted(services.items(), key=lambda item: item[0]):
            if isinstance(info, dict):
                status = info.get("status_code", "n/a")
                url = info.get("url", "")
                lines.append(f"- Port {port}: status {status} — {url}")
            else:
                lines.append(f"- Port {port}: {info}")
    else:
        lines.append("No HTTP services detected.")

    lines.append("")
    lines.append("## Findings")
    findings = context.get("findings", [])
    if findings:
        for index, item in enumerate(findings, start=1):
            if not isinstance(item, dict):
                lines.append(f"- {item}")
                continue

            summary = item.get("summary", "Observation")
            lines.append(f"### Finding {index}: {summary}")

            tool = item.get("tool")
            if tool:
                lines.append(f"- **Tool:** {tool}")

            cmdline = item.get("cmdline")
            if cmdline:
                lines.append(f"- **Command:** `{cmdline}`")

            started = item.get("started_at")
            completed = item.get("completed_at")
            if started or completed:
                timing_parts: list[str] = []
                if started:
                    timing_parts.append(f"started {started}")
                if completed:
                    timing_parts.append(f"completed {completed}")
                lines.append(f"- **Timing:** {', '.join(timing_parts)}")

            severity = item.get("severity")
            if severity:
                lines.append(f"- **Severity:** {severity}")

            snippet = item.get("raw_snippet")
            if snippet:
                lines.append("```text")
                lines.extend(str(snippet).splitlines())
                lines.append("```")
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
    consent = context.get("consent_present")
    if consent is not None:
        lines.append(f"- **Consent provided:** {bool(consent)}")
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
        if not isinstance(item, dict):
            continue
        formatted.append(
            {
                "summary": item.get("summary", "Observation"),
                "tool": item.get("tool", "unknown"),
                "cmdline": item.get("cmdline", ""),
                "started_at": item.get("started_at", ""),
                "completed_at": item.get("completed_at", ""),
                "raw_snippet": item.get("raw_snippet", ""),
                "severity": item.get("severity"),
                "port": item.get("port"),
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


def _format_html_timing(item: dict[str, object]) -> str:
    started = item.get("started_at")
    completed = item.get("completed_at")
    parts: list[str] = []
    if started:
        parts.append(f"<p><strong>Started:</strong> {html.escape(str(started))}</p>")
    if completed:
        parts.append(
            f"<p><strong>Completed:</strong> {html.escape(str(completed))}</p>"
        )
    return "".join(parts)


def _format_html_command(item: dict[str, object]) -> str:
    cmdline = item.get("cmdline")
    if not cmdline:
        return ""
    escaped = html.escape(str(cmdline))
    return f"<p><strong>Command:</strong> <code>{escaped}</code></p>"


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
              <strong>{summary}</strong>
              <div class="meta">
                <p><strong>Tool:</strong> {tool}</p>
                {command}
                {timing}
                {severity}
              </div>
              <details>
                <summary>View evidence</summary>
                <pre>{snippet}</pre>
              </details>
            </li>
            """.strip().format(
                summary=html.escape(str(item.get("summary", "Observation"))),
                tool=html.escape(str(item.get("tool", "unknown"))),
                command=_format_html_command(item),
                timing=_format_html_timing(item),
                severity=(
                    f"<p><strong>Severity:</strong> {html.escape(str(item.get('severity')))}</p>"
                    if item.get("severity")
                    else ""
                ),
                snippet=html.escape(str(item.get("raw_snippet", "")))
                or "No evidence recorded.",
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

    styles = textwrap.dedent(
        """
        body {
          font-family: 'Segoe UI', 'Liberation Sans', Arial, sans-serif;
          margin: 0;
          background: #f5f7fa;
          color: #1f2937;
        }

        header.cover {
          background: linear-gradient(135deg, #0f172a, #1f2937);
          color: #f8fafc;
          padding: 48px 32px;
          text-align: center;
        }

        header.cover .logo {
          display: inline-block;
          padding: 10px 28px;
          border: 2px dashed rgba(255, 255, 255, 0.45);
          border-radius: 10px;
          letter-spacing: 0.18rem;
          text-transform: uppercase;
          margin-bottom: 24px;
        }

        main {
          padding: 36px 48px 64px;
        }

        section {
          margin-bottom: 48px;
        }

        h2 {
          border-bottom: 2px solid #1f2937;
          padding-bottom: 6px;
        }

        table.summary {
          width: 100%;
          border-collapse: collapse;
          background: #ffffff;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 2px 6px rgba(15, 23, 42, 0.08);
        }

        table.summary th,
        table.summary td {
          padding: 14px 18px;
          border-bottom: 1px solid #e2e8f0;
        }

        table.summary th {
          width: 30%;
          background: #f1f5f9;
          font-weight: 600;
          letter-spacing: 0.02rem;
        }

        ul.findings {
          list-style: none;
          padding-left: 0;
        }

        ul.findings li {
          background: #ffffff;
          border-left: 4px solid #f97316;
          padding: 16px 20px;
          margin-bottom: 14px;
          box-shadow: 0 1px 3px rgba(15, 23, 42, 0.1);
        }

        ul.findings li pre {
          background: #0f172a;
          color: #f8fafc;
          padding: 12px;
          border-radius: 6px;
          overflow-x: auto;
          font-size: 0.85rem;
        }

        ul.recommendations {
          padding-left: 18px;
        }

        dl.meta {
          display: grid;
          grid-template-columns: 220px 1fr;
          gap: 12px 18px;
          background: #ffffff;
          padding: 18px 22px;
          border-radius: 8px;
          box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
        }

        dl.meta dt {
          font-weight: 600;
        }

        dl.meta dd {
          margin: 0;
          font-family: 'Fira Code', 'Source Code Pro', monospace;
          white-space: pre-wrap;
        }

        footer {
          text-align: center;
          padding: 24px;
          background: #f1f5f9;
          border-top: 1px solid #e2e8f0;
          font-size: 0.85rem;
          color: #475569;
        }
        """
    ).strip()

    return f"""<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>{html.escape(str(context.get('title')))}</title>
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <style>
    {styles}
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
      ReconScript v{html.escape(str(context.get('version')))}
      · Generated {html.escape(str(context.get('timestamp')))}
    </footer>
  </body>
</html>"""


__all__ = [
    "render_json",
    "render_markdown",
    "render_html",
    "generate_pdf",
    "write_report",
]
