"""Prometheus metrics scaffolding for ReconScript."""

from __future__ import annotations

import logging
from typing import Iterable, Optional

try:  # pragma: no cover - optional dependency handling
    from prometheus_client import (  # type: ignore
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )
    from prometheus_client import CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover - fall back to no-op metrics
    CollectorRegistry = None  # type: ignore[assignment]
    Counter = None  # type: ignore[assignment]
    Histogram = None  # type: ignore[assignment]
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    def generate_latest(_: object) -> bytes:  # type: ignore[override]
        return b""

LOGGER = logging.getLogger(__name__)


class _NoopMetric:
    def observe(self, *_: object, **__: object) -> None:
        return None

    def labels(self, *_: object, **__: object) -> "_NoopMetric":
        return self

    def inc(self, *_: object, **__: object) -> None:
        return None


_REGISTRY = CollectorRegistry() if CollectorRegistry is not None else None


def _histogram(name: str, documentation: str, *, buckets: Iterable[float]):
    if Histogram is None or _REGISTRY is None:  # pragma: no cover - optional dependency
        return _NoopMetric()
    return Histogram(name, documentation, buckets=buckets, registry=_REGISTRY)


def _counter(name: str, documentation: str, *, label_names: Optional[Iterable[str]] = None):
    if Counter is None or _REGISTRY is None:  # pragma: no cover - optional dependency
        return _NoopMetric()
    if label_names:
        return Counter(name, documentation, labelnames=list(label_names), registry=_REGISTRY)
    return Counter(name, documentation, registry=_REGISTRY)


SCAN_ATTEMPTS = _counter(
    "recon_scans_total",
    "Number of ReconScript scans grouped by result status.",
    label_names=["status"],
)
SCAN_DURATION = _histogram(
    "recon_scan_duration_seconds",
    "Histogram of ReconScript scan durations in seconds.",
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)
OPEN_PORTS = _histogram(
    "recon_scan_open_ports",
    "Histogram of open ports discovered per scan.",
    buckets=(0, 1, 2, 5, 10, 20, 50, 100),
)


def record_scan_started(target: str) -> None:
    """Emit a metrics event for a scan attempt."""

    LOGGER.debug("metrics.scan_started", extra={"event": "scan.started", "target": target})
    SCAN_ATTEMPTS.labels(status="started").inc()


def record_scan_completed(target: str, duration: float, open_ports: int) -> None:
    """Record metrics when a scan successfully completes."""

    LOGGER.debug(
        "metrics.scan_completed",
        extra={
            "event": "scan.completed",
            "target": target,
            "duration": duration,
            "open_ports": open_ports,
        },
    )
    SCAN_ATTEMPTS.labels(status="completed").inc()
    SCAN_DURATION.observe(duration)
    OPEN_PORTS.observe(float(open_ports))


def record_scan_failed(target: str, reason: str) -> None:
    """Record metrics when a scan attempt fails."""

    LOGGER.warning(
        "metrics.scan_failed",
        extra={"event": "scan.failed", "target": target, "reason": reason},
    )
    SCAN_ATTEMPTS.labels(status=reason).inc()


def metrics_payload() -> tuple[bytes, str]:
    """Return the Prometheus metrics payload for HTTP responses."""

    if _REGISTRY is None:  # pragma: no cover - metrics disabled
        return b"", "text/plain"
    return generate_latest(_REGISTRY), CONTENT_TYPE_LATEST


__all__ = [
    "metrics_payload",
    "record_scan_completed",
    "record_scan_failed",
    "record_scan_started",
]
