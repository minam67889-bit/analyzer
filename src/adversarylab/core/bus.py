"""Thread-safe publish/subscribe event bus.

Handlers run synchronously on the publishing thread. Exceptions in a handler are logged
and do not prevent other handlers from running, so a broken UI subscriber can never break
the capture pipeline.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..logging_config import get_logger
from .events import EventCategory, EventSeverity, EventSource, NetworkEvent, severity_at_least

logger = get_logger(__name__)

Handler = Callable[[NetworkEvent], None]


@dataclass(frozen=True)
class EventFilter:
    categories: frozenset[EventCategory] | None = None
    sources: frozenset[EventSource] | None = None
    min_severity: EventSeverity = EventSeverity.DEBUG
    session_id: str | None = None
    device_id: str | None = None
    test_id: str | None = None

    def matches(self, event: NetworkEvent) -> bool:
        if self.categories is not None and event.category not in self.categories:
            return False
        if self.sources is not None and event.source not in self.sources:
            return False
        if not severity_at_least(event.severity, self.min_severity):
            return False
        if self.session_id is not None and event.session_id != self.session_id:
            return False
        if self.device_id is not None and event.device_id != self.device_id:
            return False
        if self.test_id is not None and event.test_id != self.test_id:
            return False
        return True


@dataclass
class _Subscription:
    handler: Handler
    filt: EventFilter
    active: bool = True


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subs: list[_Subscription] = []
        self._history: list[NetworkEvent] = []
        self._history_limit = 10_000

    def subscribe(self, handler: Handler, filt: EventFilter | None = None) -> Handler:
        sub = _Subscription(handler=handler, filt=filt or EventFilter())
        with self._lock:
            self._subs.append(sub)
        return handler

    def unsubscribe(self, handler: Handler) -> bool:
        with self._lock:
            for sub in self._subs:
                if sub.handler is handler:
                    sub.active = False
                    self._subs.remove(sub)
                    return True
        return False

    def publish(self, event: NetworkEvent) -> None:
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._history_limit:
                del self._history[: len(self._history) - self._history_limit]
            targets = [s for s in self._subs if s.active and s.filt.matches(event)]
        for sub in targets:
            try:
                sub.handler(event)
            except Exception:  # pragma: no cover - defensive
                logger.exception("event handler failed", extra={"lab_event_id": event.event_id})

    def history(self, filt: EventFilter | None = None, limit: int | None = None) -> list[NetworkEvent]:
        with self._lock:
            events = list(self._history)
        if filt is not None:
            events = [e for e in events if filt.matches(e)]
        if limit is not None:
            events = events[-limit:]
        return events

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len([s for s in self._subs if s.active])


class RecordingSink:
    """Convenience adapter that appends events to a list (used by tests and collectors)."""

    def __init__(self, events: list[NetworkEvent] | None = None) -> None:
        self.events: list[NetworkEvent] = events if events is not None else []

    def __call__(self, event: NetworkEvent) -> None:
        self.events.append(event)


def filter_for(
    *,
    categories: Iterable[EventCategory] | None = None,
    sources: Iterable[EventSource] | None = None,
    min_severity: EventSeverity = EventSeverity.DEBUG,
    session_id: str | None = None,
    device_id: str | None = None,
    test_id: str | None = None,
) -> EventFilter:
    return EventFilter(
        categories=frozenset(categories) if categories is not None else None,
        sources=frozenset(sources) if sources is not None else None,
        min_severity=min_severity,
        session_id=session_id,
        device_id=device_id,
        test_id=test_id,
    )
