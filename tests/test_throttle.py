from __future__ import annotations

import pytest

from reconscript.scanner.throttle import TokenBucket


class FakeClock:
    def __init__(self) -> None:
        self.current = 0.0

    def time(self) -> float:
        return self.current

    def advance(self, value: float) -> None:
        self.current += value


def test_token_bucket_refill_and_consume() -> None:
    clock = FakeClock()
    sleeps: list[float] = []

    def sleeper(duration: float) -> None:
        sleeps.append(duration)
        clock.advance(duration)

    bucket = TokenBucket(
        rate=2.0, capacity=4.0, time_func=clock.time, sleep_func=sleeper
    )

    bucket.consume(3)
    assert bucket.tokens_available == 1.0

    bucket.consume(2)
    assert sleeps == [0.5]
    assert pytest.approx(bucket.tokens_available, rel=1e-6) == 1.0

    clock.advance(1.0)
    assert pytest.approx(bucket.tokens_available, rel=1e-6) == 3.0
