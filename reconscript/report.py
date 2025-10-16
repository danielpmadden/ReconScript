"""Utilities for ReconScript report metadata and filesystem layout."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

__all__ = [
    "ReportPaths",
    "RESULTS_DIR",
    "ensure_results_dir",
    "slugify_target",
    "timestamped_name",
    "default_output_path",
    "embed_runtime_metadata",
]


RESULTS_DIR = Path("results")


@dataclass(frozen=True)
class ReportPaths:
    """Normalized locations for report artefacts."""

    base: Path
    html: Optional[Path] = None
    json: Optional[Path] = None
    pdf: Optional[Path] = None
    markdown: Optional[Path] = None


def ensure_results_dir() -> Path:
    """Create and return the shared ``results`` directory."""

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR


def slugify_target(target: str) -> str:
    """Return a filesystem-safe slug derived from the supplied target."""

    slug = re.sub(r"[^A-Za-z0-9]+", "-", str(target)).strip("-")
    return slug or "scan"


def timestamped_name(target: str, started_at: datetime, extension: str) -> str:
    """Generate a timestamped filename for the given ``target`` and extension."""

    stamp = started_at.strftime("%Y%m%d-%H%M%S")
    normalized_ext = extension.lstrip(".")
    return f"{slugify_target(target)}-{stamp}.{normalized_ext}"


def default_output_path(
    target: str,
    started_at: datetime,
    extension: str,
    directory: Path | None = None,
) -> Path:
    """Return the default output path under ``results/`` for the scan."""

    base_dir = directory or ensure_results_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / timestamped_name(target, started_at, extension)


def embed_runtime_metadata(
    report: Dict[str, object],
    started_at: datetime,
    completed_at: Optional[datetime] = None,
    duration: Optional[float] = None,
) -> Dict[str, object]:
    """Attach runtime metadata fields to ``report`` in a consistent structure."""

    start_iso = started_at.replace(microsecond=0).isoformat() + "Z"
    report["timestamp"] = report.get("timestamp", start_iso)
    report["started_at"] = report.get("started_at", start_iso)

    runtime: Dict[str, object] = {
        "started_at": report["started_at"],
    }

    if completed_at is not None:
        completed_iso = completed_at.replace(microsecond=0).isoformat() + "Z"
        report["completed_at"] = completed_iso
        runtime["completed_at"] = completed_iso

    if duration is not None:
        rounded = round(duration, 2)
        report["duration"] = rounded
        runtime["duration"] = rounded

    report["runtime"] = {**runtime, **report.get("runtime", {})}
    return report

