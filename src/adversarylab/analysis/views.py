"""Attacker-view and defender-view projections of one test result.

The two views are derived from disjoint evidence sources on purpose:

* Attacker view uses what a same-Wi-Fi observer could see or do (capture, lab servers,
  DNS/DHCP/ARP state, plaintext HTTP).
* Defender view uses what the Android firewall reported (firewall API/log/ADB telemetry).

Neither view is allowed to borrow the other's conclusions. A firewall log is never used
to claim interception, and a captured packet is never used to claim a firewall block.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..core.events import EventSource
from ..core.results import TestResult

_ATTACKER_SOURCES = {
    EventSource.PACKET_CAPTURE.value,
    EventSource.LAB_SERVER.value,
    EventSource.INFRASTRUCTURE.value,
    EventSource.WINDOWS_HOST.value,
}
_DEFENDER_SOURCES = {
    EventSource.FIREWALL.value,
    EventSource.ANDROID_DEVICE.value,
}


def attacker_view(result: TestResult) -> dict[str, Any]:
    """What the network attacker could observe, manipulate, obtain or infer."""

    observable_domains: set[str] = set()
    observable_ips: set[str] = set()
    plaintext_cookie_names: set[str] = set()
    tls_domains: set[str] = set()
    http_hosts: set[str] = set()
    redirects: list[dict[str, Any]] = []
    manipulations: list[str] = []
    disruptions: list[str] = []

    for observation in result.observations:
        details = dict(observation.details or {})
        source = observation.source
        if source in (EventSource.PACKET_CAPTURE.value, EventSource.LAB_SERVER.value):
            host = details.get("host") or details.get("sni")
            if host:
                observable_domains.add(str(host))
                http_hosts.add(str(host))
            dst = details.get("dst") or details.get("dst_addr")
            if dst:
                observable_ips.add(str(dst))
            if (details.get("cookie_header_present") or details.get("cookie_header")
                    or details.get("names")):
                plaintext_cookie_names.update(details.get("names") or [])
            if observation.kind in {"deauth_frames", "assoc_events", "arp_spoof", "gw_impersonation"}:
                disruptions.append(observation.summary)
        if source == EventSource.LAB_SERVER.value:
            if details.get("manipulation"):
                manipulations.append(str(details["manipulation"]))
        if "tls" in (observation.kind or "") or details.get("sni"):
            tls_domains.add(str(details.get("sni") or details.get("host") or ""))
        location = details.get("location")
        if location:
            redirects.append({"to": str(location), "cleartext": str(location).startswith("http://")})

    return {
        "perspective": "attacker",
        "position": "same Wi-Fi segment; no device access, no CA, no custom application",
        "observable_domains": sorted(observable_domains),
        "observable_destinations": sorted(observable_ips),
        "plaintext_cookie_names": sorted(plaintext_cookie_names),
        "tls_domains_metadata_only": sorted(tls_domains),
        "http_hosts": sorted(http_hosts),
        "redirects_observed": redirects,
        "manipulations_applied": manipulations,
        "disruptions_observed": disruptions,
        "not_observable": [
            "TLS application payloads",
            "certificate-pinned traffic content",
            "cookie values inside encrypted tunnels",
        ],
        "inferences": [],
        "caveat": (
            "Observable describes what crossed the network in a form the attacker could read. "
            "It is not evidence that the firewall allowed, blocked or failed anything."
        ),
    }


def defender_view(result: TestResult) -> dict[str, Any]:
    """What the Android firewall detected, blocked, allowed or failed to report."""

    firewall_observations = [
        o for o in result.observations
        if o.source in (EventSource.FIREWALL.value, EventSource.ANDROID_DEVICE.value)
        or o.kind in {"firewall_block", "firewall_detect", "firewall_allow"}
    ]
    detected = [o for o in firewall_observations
                if "detect" in (o.kind or "") or "alert" in (o.kind or "")]
    blocked = [o for o in firewall_observations if "block" in (o.kind or "")]
    allowed = [o for o in firewall_observations if o.kind in {"allow", "allowed", "firewall_allow"}]
    missing = [o for o in result.observations if o.kind == "no_observations"]

    confirmed_by_capture = any(
        o.source == EventSource.PACKET_CAPTURE.value
        and ("rst" in (o.kind or "").lower()
             or "rst" in str((o.details or {}).get("kind", "")).lower())
        for o in result.observations
    )

    return {
        "perspective": "defender",
        "subject": "Android mobile firewall under test",
        "firewall_reports": [o.to_dict() if hasattr(o, "to_dict") else {
            "source": o.source, "kind": o.kind, "summary": o.summary,
            "details": dict(o.details), "timestamp": o.timestamp.isoformat(),
        } for o in firewall_observations],
        "detected_count": len(detected),
        "blocked_count": len(blocked),
        "allowed_count": len(allowed),
        "corroborated_by_independent_capture": confirmed_by_capture,
        "missing_telemetry": [o.summary for o in missing],
        "block_cause": result.block_cause.value,
        "caveat": (
            "A firewall report is a claim by the firewall under test. It is not proof of "
            "interception, and a block claim is only treated as confirmed when independent "
            "capture evidence agrees."
        ),
    }


def dual_view(result: TestResult) -> dict[str, Any]:
    return {
        "test_id": result.test_id,
        "verdict": result.verdict.value,
        "confidence": result.confidence.value,
        "attacker": attacker_view(result),
        "defender": defender_view(result),
        "independence_note": (
            "The attacker view and the defender view are computed from disjoint evidence "
            "sources and are never used to confirm each other."
        ),
    }


def attacker_visible_inventory(results: Iterable[TestResult]) -> dict[str, Any]:
    """Aggregate everything the attacker could see across an assessment."""

    domains: set[str] = set()
    ips: set[str] = set()
    cookie_names: set[str] = set()
    tls_domains: set[str] = set()
    plaintext_values_observed = 0
    for result in results:
        view = attacker_view(result)
        domains.update(view["observable_domains"])
        ips.update(view["observable_destinations"])
        cookie_names.update(view["plaintext_cookie_names"])
        tls_domains.update(view["tls_domains_metadata_only"])
        plaintext_values_observed += sum(
            1 for o in result.observations
            if o.source == EventSource.LAB_SERVER.value
            and (o.details or {}).get("cookie_header")
        )
    return {
        "domains_observed": sorted(domains),
        "destinations_observed": sorted(ips),
        "plaintext_cookie_names": sorted(cookie_names),
        "tls_domains_metadata_only": sorted(tls_domains),
        "plaintext_cookie_exposures": plaintext_values_observed,
        "caveat": (
            "Inventory lists what was visible to the network attacker. It never states that "
            "an encrypted value was read, and it never labels a server-known value as stolen."
        ),
    }
