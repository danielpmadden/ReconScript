"""Lightweight HTTP request/response primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass
class Request:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None


class _RawHeaders:
    def __init__(self, pairs: Iterable[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def getlist(self, name: str) -> List[str]:
        lowered = name.lower()
        return [value for key, value in self._pairs if key.lower() == lowered]

    def get_all(self, name: str) -> List[str]:  # pragma: no cover - alias
        return self.getlist(name)


@dataclass
class Response:
    status_code: int
    url: str
    headers: Dict[str, str]
    content: bytes
    request: Request
    history: List["Response"] = field(default_factory=list)
    raw: object | None = None

    def __post_init__(self) -> None:
        if self.raw is None:
            self.raw = type("Raw", (), {"headers": _RawHeaders(self.headers.items())})()

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")
