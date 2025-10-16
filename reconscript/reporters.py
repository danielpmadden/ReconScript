"""Report rendering utilities for ReconScript."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from . import __version__

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
HTML_TEMPLATE = TEMPLATE_DIR / "report.html"


def render_json(data: Dict[str, object]) -> str:
    """Return a canonical JSON representation of the scan results."""

    return json.dumps(data, indent=2, sort_keys=True)


def render_markdown(data: Dict[str, object]) -> str:
    """Render the report data in Markdown format."""

    target = data.get("target", "unknown")
    timestamp = data.get("timestamp", datetime.utcnow().isoformat() + "Z")
    hostname = data.get("hostname") or "N/A"
    ports = _format_list(data.get("ports", []))
    open_ports = _format_list(data.get("open_ports", []))
    findings = data.get("findings", [])
    recommendations = _build_recommendations(findings)

    lines: List[str] = [
        f"# ReconScript Report for {target}",
        "",
        "## Summary",
        f"- **Target:** {target}",
        f"- **Hostname:** {hostname}",
        f"- **Ports Scanned:** {ports or 'None'}",
        f"- **Open Ports:** {open_ports or 'None detected'}",
        f"- **Findings:** {len(findings)}",
        f"- **Generated:** {timestamp}",
        "",
        "## Findings",
    ]

    if findings:
        for item in findings:
            issue = item.get("issue", "observation")
            port = item.get("port", "n/a")
            details = item.get("details")
            formatted_details = json.dumps(details, indent=2, sort_keys=True) if details else "n/a"
            lines.extend(
                [
                    f"- **Port {port}** — `{issue}`",
                    "",
                    f"  ```json\n{formatted_details}\n  ```",
                ]
            )
    else:
        lines.append("- No issues detected during the assessment.")

    lines.extend(["", "## Recommendations"])
    if recommendations:
        lines.extend([f"- {text}" for text in recommendations])
    else:
        lines.append("- Continue monitoring and maintain existing controls.")

    lines.extend(
        [
            "",
            "## Metadata",
            f"- **Tool Version:** {data.get('version', __version__)}",
            f"- **Report Generated:** {timestamp}",
        ]
    )

    return "\n".join(lines)


def render_html(data: Dict[str, object]) -> str:
    """Render the report data as HTML using the project template."""

    if not HTML_TEMPLATE.exists():
        raise FileNotFoundError(f"Missing HTML template: {HTML_TEMPLATE}")

    target = str(data.get("target", "unknown"))
    timestamp = str(data.get("timestamp", datetime.utcnow().isoformat() + "Z"))
    hostname = str(data.get("hostname") or "N/A")
    findings = data.get("findings", [])
    recommendations = _build_recommendations(findings)

    summary_rows = _build_summary_rows(data)
    findings_html = _build_findings_html(findings)
    recommendations_html = _build_list_html(recommendations, empty_message="Continue monitoring and maintain existing controls.")
    metadata_html = _build_metadata_html(data, timestamp)
    cover_summary = _build_cover_summary(data)

    template = HTML_TEMPLATE.read_text(encoding="utf-8")
    context = {
        "title": f"ReconScript Report — {html.escape(target)}",
        "target": html.escape(target),
        "hostname": html.escape(hostname),
        "timestamp": html.escape(timestamp),
        "summary_rows": summary_rows,
        "findings_section": findings_html,
        "recommendations_section": recommendations_html,
        "metadata_section": metadata_html,
        "version": html.escape(str(data.get("version", __version__))),
        "cover_date": html.escape(_format_human_date(timestamp)),
        "cover_target": html.escape(target),
        "cover_hostname": html.escape(hostname),
        "cover_summary": html.escape(cover_summary),
    }

    return template.format(**context)


def generate_pdf(html_path: Path, pdf_path: Path) -> None:
    """Generate a PDF from an HTML report using WeasyPrint."""

    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover - handled in tests via importorskip
        raise RuntimeError(
            "PDF export requires WeasyPrint. Install the optional dependencies or "
            "build the Docker image with INCLUDE_PDF=true."
        ) from exc

    HTML(filename=str(html_path)).write_pdf(str(pdf_path))


def write_report(data: Dict[str, object], outfile: Path, format: str) -> Path:
    """Write the report data to disk in the requested format."""

    if not isinstance(outfile, Path):
        outfile = Path(outfile)

    outfile.parent.mkdir(parents=True, exist_ok=True)
    normalized_format = format.lower()

    if normalized_format == "json":
        outfile.write_text(render_json(data), encoding="utf-8")
        return outfile

    if normalized_format in {"markdown", "md"}:
        outfile.write_text(render_markdown(data), encoding="utf-8")
        return outfile

    if normalized_format == "html":
        outfile.write_text(render_html(data), encoding="utf-8")
        return outfile

    if normalized_format == "pdf":
        html_path = Path(str(outfile).rsplit(".pdf", 1)[0] + ".html") if str(outfile).lower().endswith(".pdf") else outfile.with_suffix(".html")
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(data), encoding="utf-8")
        generate_pdf(html_path, outfile)
        return outfile

    raise ValueError(f"Unsupported report format: {format}")


def _format_list(values: Iterable[object]) -> str:
    items = list(values)
    if not items:
        return ""
    return ", ".join(str(item) for item in items)


def _build_recommendations(findings: Sequence[Dict[str, object]]) -> List[str]:
    suggestions: List[str] = []
    issues = {item.get("issue") for item in findings}

    if "missing_security_headers" in issues:
        suggestions.append("Set Strict-Transport-Security and related headers on all web front-ends.")
    if "session_cookie_flags" in issues:
        suggestions.append("Configure Secure and HttpOnly attributes on session cookies.")
    if "server_error" in issues:
        suggestions.append("Review backend error logs for endpoints returning 5xx responses.")
    if not suggestions and findings:
        suggestions.append("Investigate informational findings for context-specific remediation.")
    return suggestions


def _build_summary_rows(data: Dict[str, object]) -> str:
    target = html.escape(str(data.get("target", "unknown")))
    hostname = html.escape(str(data.get("hostname") or "N/A"))
    ports = html.escape(_format_list(data.get("ports", [])) or "None")
    open_ports = html.escape(_format_list(data.get("open_ports", [])) or "None detected")
    findings = data.get("findings", [])
    findings_count = len(findings) if isinstance(findings, Sequence) else 0

    rows = [
        f"<tr><th>Target</th><td>{target}</td></tr>",
        f"<tr><th>Hostname</th><td>{hostname}</td></tr>",
        f"<tr><th>Ports Scanned</th><td>{ports}</td></tr>",
        f"<tr><th>Open Ports</th><td>{open_ports}</td></tr>",
        f"<tr><th>Findings</th><td>{findings_count}</td></tr>",
    ]
    return "\n".join(rows)


def _build_findings_html(findings: Sequence[Dict[str, object]]) -> str:
    if not findings:
        return "<p>No issues detected during the assessment.</p>"

    parts = ["<ul class=\"findings\">"]
    for item in findings:
        issue = html.escape(str(item.get("issue", "observation")))
        port = html.escape(str(item.get("port", "n/a")))
        details = item.get("details")
        formatted_details = html.escape(json.dumps(details, indent=2, sort_keys=True)) if details is not None else "n/a"
        parts.append(
            """
            <li>
              <strong>Port {port}</strong> — <code>{issue}</code>
              <pre>{details}</pre>
            </li>
            """.strip().format(port=port, issue=issue, details=formatted_details)
        )
    parts.append("</ul>")
    return "\n".join(parts)


def _build_list_html(items: Sequence[str], empty_message: str) -> str:
    if not items:
        return f"<p>{html.escape(empty_message)}</p>"

    parts = ["<ul>"]
    for item in items:
        parts.append(f"  <li>{html.escape(item)}</li>")
    parts.append("</ul>")
    return "\n".join(parts)


def _build_metadata_html(data: Dict[str, object], timestamp: str) -> str:
    version = html.escape(str(data.get("version", __version__)))
    generated = html.escape(timestamp)
    metadata = data.get("robots", {})
    robots_note = ""
    if isinstance(metadata, dict):
        if "url" in metadata:
            robots_note = f"Robots reference: {html.escape(str(metadata['url']))}"
        elif "note" in metadata:
            robots_note = html.escape(str(metadata["note"]))

    parts = ["<ul class=\"metadata\">"]
    parts.append(f"  <li>Tool Version: {version}</li>")
    parts.append(f"  <li>Report Generated: {generated}</li>")
    if robots_note:
        parts.append(f"  <li>{robots_note}</li>")
    parts.append("</ul>")
    return "\n".join(parts)


def _build_cover_summary(data: Dict[str, object]) -> str:
    open_ports = list(data.get("open_ports") or [])
    ports = list(data.get("ports") or [])
    return f"{len(open_ports)} open ports discovered across {len(ports)} scanned endpoints."


def _format_human_date(timestamp: str) -> str:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return timestamp
    return parsed.strftime("%d %B %Y %H:%M UTC")


__all__ = [
    "render_json",
    "render_markdown",
    "render_html",
    "generate_pdf",
    "write_report",
]

