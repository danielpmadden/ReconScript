"""Token bucket implementation for scan rate limiting."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

TimeFunc = Callable[[], float]
SleepFunc = Callable[[float], None]


@dataclass
class TokenBucket:
    rate: float
    capacity: float
    time_func: TimeFunc = time.monotonic
    sleep_func: SleepFunc = time.sleep

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("Token bucket rate must be positive.")
        if self.capacity <= 0:
            raise ValueError("Token bucket capacity must be positive.")
        self._tokens = float(self.capacity)
        self._timestamp = self.time_func()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self.time_func()
        elapsed = max(0.0, now - self._timestamp)
        if elapsed <= 0:
            return
        self._timestamp = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def consume(self, tokens: float = 1.0) -> None:
        if tokens <= 0:
            return
        slept_total = 0.0
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    if slept_total:
                        self._timestamp -= slept_total
                    return
                needed = max(0.0, (tokens - self._tokens) / self.rate)
            if needed == 0.0:
                # No tokens available and zero rate would have raised earlier
                continue
            self.sleep_func(needed)
            slept_total += needed

    @property
    def tokens_available(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens
