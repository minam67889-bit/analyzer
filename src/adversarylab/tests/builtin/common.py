"""Shared helpers for built-in test modules."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from ...adversary.actions import ActionResult
from ...core.bus import EventFilter
from ...core.events import EventCategory, EventSource, NetworkEvent
from ...core.results import Observation
from ..module import TestContext, TestModule


def observation(source: str, kind: str, summary: str, **details: Any) -> Observation:
    return Observation(
        source=source,
        kind=kind,
        timestamp=datetime.now(UTC),
        summary=summary,
        details=details,
    )


def run_action(ctx: TestContext, action: str, **params: Any) -> ActionResult:
    if ctx.action_runner is None:
        return ActionResult(action, False, error="no action runner configured")
    result = ctx.action_runner.perform(action, **params)
    ctx.collected.extend(result.observations)
    return result


def sink_hits(ctx: TestContext, name: str) -> int:
    if ctx.action_runner is None:
        return 0
    status = ctx.action_runner.status() or {}
    sinks = status.get("sinks", {})
    if isinstance(sinks, dict):
        return int(sinks.get(name, 0))
    return 0


def bus_events(
    ctx: TestContext,
    *,
    categories: Iterable[EventCategory] | None = None,
    sources: Iterable[EventSource] | None = None,
    test_id: str | None = None,
) -> list[NetworkEvent]:
    if ctx.bus is None:
        return []
    filt = EventFilter(
        categories=frozenset(categories) if categories else None,
        sources=frozenset(sources) if sources else None,
        test_id=test_id,
    )
    return ctx.bus.history(filt)


def register_cookie(ctx: TestContext, site_id: str, domain: str, name: str, value: str,
                    **attributes: Any) -> bool:
    """Record a synthetic cookie in the laboratory ground-truth store."""
    if ctx.cookie_ground_truth is None:
        return False
    from ...cookies.model import CookieSpec, SameSite

    samesite = attributes.pop("samesite", SameSite.UNSPECIFIED)
    if isinstance(samesite, str):
        try:
            samesite = SameSite(samesite)
        except ValueError:
            samesite = SameSite.UNSPECIFIED
    ctx.cookie_ground_truth.register(CookieSpec(
        site_id=site_id, domain=domain, name=name, value=value,
        samesite=samesite, **attributes,
    ))
    return True


def http_events(ctx: TestContext, *, host: str = "", direction: str = "") -> list[NetworkEvent]:
    events = [
        e for e in bus_events(ctx, categories={EventCategory.HTTP})
        if e.source in {EventSource.PACKET_CAPTURE, EventSource.LAB_SERVER}
    ]
    if host:
        events = [
            e for e in events
            if str((e.details or {}).get("host") or "").lower().split(":")[0] == host.lower()
        ]
    if direction:
        events = [e for e in events if (e.details or {}).get("direction") == direction]
    return events


def cookie_header_events(ctx: TestContext) -> list[NetworkEvent]:
    """Events whose headers carry a Cookie header (plaintext exposure on the wire)."""
    found = []
    for event in http_events(ctx):
        headers = {str(k).lower(): v for k, v in ((event.details or {}).get("headers") or {}).items()}
        if headers.get("cookie"):
            found.append(event)
    return found


def capture_events(ctx: TestContext) -> list[NetworkEvent]:
    return bus_events(ctx, sources={EventSource.PACKET_CAPTURE})


def firewall_events(ctx: TestContext) -> list[NetworkEvent]:
    return bus_events(
        ctx,
        sources={EventSource.FIREWALL, EventSource.ANDROID_DEVICE},
    )


def has_rst_to(obs: Iterable[Observation], target: str | None = None) -> bool:
    for item in obs:
        details = item.details or {}
        flags = details.get("tcp_flags") or []
        if isinstance(flags, str):
            flags = [f.strip() for f in flags.split(",")]
        if "RST" in flags and (target is None or details.get("dst") == target or item.dst_addr == target):
            return True
    return False


def has_flag(obs: Iterable[Observation], flag: str) -> bool:
    for item in obs:
        flags = item.details.get("tcp_flags") or []
        if isinstance(flags, str):
            flags = [f.strip() for f in flags.split(",")]
        if flag in flags:
            return True
    return False


class BuiltinModule(TestModule):
    """Convenience base that records action observations into the context."""

    def _run(self, action: str, **params: Any) -> ActionResult:
        return run_action(self.ctx, action, **params)
