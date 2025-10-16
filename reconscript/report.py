"""Report persistence and integrity helpers."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from .consent import sign_report_hash

RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", "results")).expanduser()
INDEX_FILE = RESULTS_DIR / "index.json"
LOCK_PATH = RESULTS_DIR / ".index.lock"


@dataclass(frozen=True)
class ReportPaths:
    report_id: str
    base: Path
    report_file: Path
    manifest_path: Optional[Path] = None
    signature_path: Optional[Path] = None


class FileLock(AbstractContextManager):
    def __init__(self, path: Path, timeout: float = 10.0) -> None:
        self.path = path
        self.timeout = timeout
        self._fd: Optional[int] = None

    def __enter__(self) -> "FileLock":
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out acquiring lock {self.path}")
                time.sleep(0.1)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fd is not None:
            os.close(self._fd)
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def ensure_results_dir() -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR


def slugify_target(target: str) -> str:
    import re

    slug = re.sub(r"[^A-Za-z0-9]+", "-", str(target)).strip("-")
    return slug or "scan"


def timestamped_name(target: str, started_at: datetime, extension: str) -> str:
    stamp = started_at.strftime("%Y%m%d-%H%M%S")
    normalized_ext = extension.lstrip(".")
    return f"{slugify_target(target)}-{stamp}.{normalized_ext}"


def default_output_path(
    target: str,
    started_at: datetime,
    extension: str,
    directory: Path | None = None,
) -> Path:
    base_dir = directory or ensure_results_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / timestamped_name(target, started_at, extension)


def embed_runtime_metadata(
    report: Dict[str, object],
    started_at: datetime,
    completed_at: Optional[datetime] = None,
    duration: Optional[float] = None,
) -> Dict[str, object]:
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


def _canonical_report_bytes(report: Dict[str, object]) -> bytes:
    payload = {key: value for key, value in report.items() if key != "report_hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_report_hash(report: Dict[str, object]) -> str:
    digest = hashlib.sha256(_canonical_report_bytes(report)).hexdigest()
    return digest


def _load_index() -> list[dict[str, object]]:
    if not INDEX_FILE.exists():
        return []
    try:
        content = INDEX_FILE.read_text(encoding="utf-8")
        return json.loads(content)
    except json.JSONDecodeError:
        return []


def _write_index(entries: list[dict[str, object]]) -> None:
    INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    INDEX_FILE.write_text(json.dumps(entries, indent=2, sort_keys=True), encoding="utf-8")


def _index_entry(report_id: str, report: Dict[str, object]) -> dict[str, object]:
    return {
        "report_id": report_id,
        "target": report.get("target"),
        "tester": os.environ.get("RECON_OPERATOR", os.environ.get("USER", "unknown")),
        "start_ts": report.get("started_at"),
        "end_ts": report.get("completed_at"),
        "report_hash": report.get("report_hash"),
        "consent_signed_by": report.get("consent_signed_by"),
    }


def persist_report(
    report: Dict[str, object],
    *,
    consent_source: Optional[Path] = None,
    sign: bool = False,
) -> ReportPaths:
    ensure_results_dir()
    report_id = uuid.uuid4().hex
    report_dir = RESULTS_DIR / report_id
    report_dir.mkdir(parents=True, exist_ok=True)

    report_hash = compute_report_hash(report)
    report["report_hash"] = report_hash

    report_file = report_dir / "report.json"
    report_file.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    manifest_path: Optional[Path] = None
    if consent_source:
        manifest_dir = report_dir / "consent"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = manifest_dir / "manifest.json"
        manifest_path.write_bytes(Path(consent_source).read_bytes())

    signature_path: Optional[Path] = None
    if sign:
        signature_bytes = sign_report_hash(report_hash)
        signature_path = report_dir / "report.sig"
        signature_path.write_bytes(signature_bytes)

    with FileLock(LOCK_PATH):
        entries = _load_index()
        entries.append(_index_entry(report_id, report))
        _write_index(entries)

    return ReportPaths(report_id=report_id, base=report_dir, report_file=report_file, manifest_path=manifest_path, signature_path=signature_path)


__all__ = [
    "ReportPaths",
    "RESULTS_DIR",
    "ensure_results_dir",
    "slugify_target",
    "timestamped_name",
    "default_output_path",
    "embed_runtime_metadata",
    "compute_report_hash",
    "persist_report",
]


