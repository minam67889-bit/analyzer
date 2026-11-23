"""Configurable adversary profiles."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.capability import Capability


@dataclass
class AdversaryProfile:
    id: str
    name: str
    description: str
    objectives: list[str] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    observables: list[str] = field(default_factory=list)
    scenario_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "objectives": list(self.objectives),
            "capabilities": [c.value for c in self.capabilities],
            "techniques": list(self.techniques),
            "prerequisites": list(self.prerequisites),
            "observables": list(self.observables),
            "scenario_ids": list(self.scenario_ids),
        }


_BUILTINS = [
    AdversaryProfile(
        id="passive-observer",
        name="Passive network observer",
        description="Observes traffic and metadata without transmitting.",
        objectives=["inventory", "metadata collection"],
        capabilities=[Capability.PACKET_CAPTURE],
        techniques=["T1040"],
        observables=["packets", "DNS metadata", "TLS metadata", "routes"],
        scenario_ids=["DISC-DNS-PASSIVE"],
    ),
    AdversaryProfile(
        id="rogue-infra",
        name="Rogue network infrastructure operator",
        description="Controls DHCP, DNS, gateway and lab service endpoints.",
        objectives=["redirect", "intercept", "impersonate"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1557.003", "T1557"],
        prerequisites=["lab infrastructure control"],
        observables=["DHCP leases", "DNS answers", "server hits", "routes"],
        scenario_ids=["DHCP-ROGUE-GATEWAY", "DNS-SPOOF-A", "GW-IMPERSONATION"],
    ),
    AdversaryProfile(
        id="dns-manipulator",
        name="DNS manipulation adversary",
        description="Spoofs, poisons, rebinds and steers DNS resolution.",
        objectives=["redirect resolution", "bypass policy"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1557"],
        observables=["DNS answers", "resolver selection", "connection paths"],
        scenario_ids=["DNS-SPOOF-A", "DNS-REBIND-PRIVATE", "DNS-REBIND-CNAME", "DNS-LEAK-UNDERLYING"],
    ),
    AdversaryProfile(
        id="gateway-impersonator",
        name="Gateway impersonator",
        description="Impersonates the default gateway at L2/L3.",
        objectives=["traffic interception", "route manipulation"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1557.002"],
        prerequisites=["on-path position"],
        observables=["ARP", "routes", "egress paths"],
        scenario_ids=["ARP-SPOOF-GATEWAY", "GW-IMPERSONATION"],
    ),
    AdversaryProfile(
        id="captive-portal",
        name="Captive portal adversary",
        description="Clones captive portals to capture credentials or drive interactions.",
        objectives=["credential capture", "interception"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1185", "T1557.004"],
        observables=["portal probes", "form submissions"],
        scenario_ids=["CAPTIVE-PORTAL-CLONE"],
    ),
    AdversaryProfile(
        id="http-manipulator",
        name="HTTP manipulation adversary",
        description="Serves lab HTTP/WebSocket endpoints and observes cleartext behavior.",
        objectives=["protocol testing", "metadata exposure"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1040", "T1102"],
        observables=["HTTP headers", "WebSocket frames"],
        scenario_ids=["HTTP-CLEARTEXT", "WS-ENDPOINT", "QUIC-H3"],
    ),
    AdversaryProfile(
        id="tls-adversary",
        name="TLS configuration adversary",
        description="Presents misconfigured certificates and legacy protocol versions.",
        objectives=["trust testing", "downgrade testing"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.LAB_CA],
        techniques=["T1557", "T1562"],
        prerequisites=["lab CA (cryptography)"],
        observables=["handshake outcomes", "SNI", "ALPN", "versions"],
        scenario_ids=["TLS-WRONG-CERT", "TLS-WRONG-HOSTNAME", "TLS-DOWNGRADE", "TLS-PINNING"],
    ),
    AdversaryProfile(
        id="service-impersonator",
        name="Malicious service impersonator",
        description="Impersonates lab services to test identity validation and pinning.",
        objectives=["identity spoofing", "pinning bypass testing"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.LAB_CA],
        techniques=["T1557"],
        observables=["TLS handshakes", "HTTP requests"],
        scenario_ids=["TLS-PINNING", "TLS-WRONG-HOSTNAME"],
    ),
    AdversaryProfile(
        id="disruptor",
        name="Network disruption adversary",
        description="Interrupts connectivity at L2/L3 and wireless layers.",
        objectives=["availability testing", "recovery testing"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1498"],
        observables=["connection resets", "timeouts", "recovery time"],
        scenario_ids=["DEAUTH-FLOOD", "DHCP-OPTION-MANIP"],
    ),
    AdversaryProfile(
        id="wireless-attacker",
        name="Wireless attacker",
        description="Rogue AP, evil twin, deauthentication and PMF downgrade.",
        objectives=["forced roaming", "interception", "DoS"],
        capabilities=[Capability.WIFI_MONITOR_MODE, Capability.WIFI_INJECTION, Capability.RAW_80211],
        techniques=["T1557.004", "T1498", "T1562"],
        prerequisites=["monitor-mode injection radio", "Npcap raw 802.11"],
        observables=["management frames", "associations", "PMF state"],
        scenario_ids=["DEAUTH-FLOOD", "EVIL-TWIN", "PMF-DOWNGRADE"],
    ),
    AdversaryProfile(
        id="ipv6-adversary",
        name="IPv6 / dual-stack adversary",
        description="Explores IPv6 bypass, RA injection and dual-stack inconsistencies.",
        objectives=["policy bypass", "route manipulation"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV6],
        techniques=["T1065", "T1557"],
        observables=["IPv6 flows", "RA/NA", "routes"],
        scenario_ids=["IPV6-BYPASS", "ND-RA-INJECTION"],
    ),
    AdversaryProfile(
        id="multi-stage",
        name="Multi-stage network attacker",
        description="Chains DNS, gateway and service impersonation across stages.",
        objectives=["sustained interception", "policy bypass"],
        capabilities=[Capability.PACKET_CAPTURE, Capability.IPV4],
        techniques=["T1557", "T1557.002", "T1557.003"],
        observables=["correlated timeline", "recovery behavior"],
        scenario_ids=["MULTI-STAGE-AITM"],
    ),
]


class ProfileLibrary:
    def __init__(self) -> None:
        self._profiles: dict[str, AdversaryProfile] = {p.id: p for p in _BUILTINS}

    def register(self, profile: AdversaryProfile) -> None:
        self._profiles[profile.id] = profile

    def get(self, profile_id: str) -> AdversaryProfile | None:
        return self._profiles.get(profile_id)

    def all(self) -> list[AdversaryProfile]:
        return sorted(self._profiles.values(), key=lambda p: p.id)

    def to_dict(self) -> list[dict]:
        return [p.to_dict() for p in self.all()]
