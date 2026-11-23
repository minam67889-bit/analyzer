"""Clock abstraction and host/device skew estimation.

Using a clock abstraction keeps the core testable and lets the platform record both
absolute UTC and monotonic time for every observation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...
    def monotonic(self) -> float: ...


class SystemClock:
    """Real system clock. ``now`` returns timezone-aware UTC."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class FrozenClock:
    """Deterministic clock for tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=UTC)
        self._mono = 0.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        from datetime import timedelta

        self._now += timedelta(seconds=seconds)
        self._mono += seconds


@dataclass
class SkewEstimate:
    """Estimated device-minus-host clock offset in seconds (positive = device ahead)."""

    offset_seconds: float
    samples: int
    rtt_seconds: float | None = None

    @property
    def reliable(self) -> bool:
        return self.samples >= 3 and abs(self.offset_seconds) < 300


class SkewEstimator:
    """Simple round-trip skew estimator.

    For each sample we assume the network RTT is symmetric: the device timestamp closest to
    the midpoint of the host send/receive times gives the offset. Samples are averaged with
    an outlier rejection pass.
    """

    def __init__(self) -> None:
        self._samples: list[tuple[float, float]] = []

    def add_sample(self, host_send: float, device_time: float, host_recv: float) -> None:
        if host_recv <= host_send:
            return
        mid = (host_send + host_recv) / 2.0
        self._samples.append((device_time - mid, host_recv - host_send))

    def estimate(self) -> SkewEstimate | None:
        if not self._samples:
            return None
        offsets = sorted(s[0] for s in self._samples)
        # Drop the outermost 25% on each side when we have enough samples.
        if len(offsets) >= 5:
            trim = max(1, len(offsets) // 4)
            offsets = offsets[trim:-trim]
        mean = sum(offsets) / len(offsets)
        rtts = [s[1] for s in self._samples if abs(s[0] - mean) < 5.0]
        rtt = (sum(rtts) / len(rtts)) if rtts else None
        return SkewEstimate(offset_seconds=mean, samples=len(self._samples), rtt_seconds=rtt)
