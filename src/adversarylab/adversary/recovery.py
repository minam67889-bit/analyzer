"""Recovery manager: revert adversarial conditions and verify restoration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..clock import Clock, SystemClock
from ..logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class RecoveryEntry:
    name: str
    reverted: bool
    error: str | None = None
    verified: bool | None = None
    verify_error: str | None = None


@dataclass
class RecoveryReport:
    entries: list[RecoveryEntry] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(e.reverted and (e.verified is not False) for e in self.entries)

    @property
    def reverted_count(self) -> int:
        return sum(1 for e in self.entries if e.reverted)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "reverted_count": self.reverted_count,
            "entries": [
                {
                    "name": e.name, "reverted": e.reverted, "error": e.error,
                    "verified": e.verified, "verify_error": e.verify_error,
                }
                for e in self.entries
            ],
        }


class RecoveryManager:
    def __init__(self, *, clock: Clock | None = None) -> None:
        self.clock = clock or SystemClock()
        self._items: list[tuple[str, Callable[[], None], Callable[[], bool] | None]] = []

    def register(
        self,
        name: str,
        revert: Callable[[], None],
        verify: Callable[[], bool] | None = None,
    ) -> None:
        self._items.append((name, revert, verify))

    def recover_all(self) -> RecoveryReport:
        report = RecoveryReport()
        for name, revert, verify in reversed(self._items):
            entry = RecoveryEntry(name=name, reverted=False)
            try:
                revert()
                entry.reverted = True
            except Exception as exc:
                entry.error = str(exc)
                logger.exception("revert failed for %s", name)
            if verify is not None and entry.reverted:
                try:
                    entry.verified = bool(verify())
                except Exception as exc:
                    entry.verified = False
                    entry.verify_error = str(exc)
            report.entries.append(entry)
        return report

    def clear(self) -> None:
        self._items.clear()
