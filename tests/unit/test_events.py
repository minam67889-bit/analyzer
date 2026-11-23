from __future__ import annotations

from adversarylab.core.bus import EventBus, EventFilter, RecordingSink
from adversarylab.core.events import (
    EventCategory,
    EventSeverity,
    EventSource,
    make_event,
)


def test_event_roundtrip(clock):
    event = make_event(
        session_id="s1", category=EventCategory.DNS, source=EventSource.PACKET_CAPTURE,
        summary="test", severity=EventSeverity.NOTICE, clock=clock,
        src_addr="10.0.0.1", dst_addr="10.0.0.2", details={"k": "v"},
    )
    restored = type(event).from_dict(event.to_dict())
    assert restored.event_id == event.event_id
    assert restored.category is EventCategory.DNS
    assert restored.details["k"] == "v"


def test_bus_filter_and_history(clock):
    bus = EventBus()
    sink = RecordingSink()
    bus.subscribe(sink, EventFilter(categories={EventCategory.DNS}, min_severity=EventSeverity.INFO))
    bus.publish(make_event(session_id="s", category=EventCategory.HTTP,
                           source=EventSource.PACKET_CAPTURE, summary="http", clock=clock))
    bus.publish(make_event(session_id="s", category=EventCategory.DNS,
                           source=EventSource.PACKET_CAPTURE, summary="dns", clock=clock))
    assert len(sink.events) == 1
    assert sink.events[0].category is EventCategory.DNS


def test_broken_handler_does_not_break_bus(clock):
    bus = EventBus()

    def bad(event):
        raise RuntimeError("boom")

    bus.subscribe(bad)
    bus.subscribe(lambda e: None)
    bus.publish(make_event(session_id="s", category=EventCategory.SYSTEM,
                           source=EventSource.ORCHESTRATOR, summary="x", clock=clock))
    assert bus.subscriber_count == 2
