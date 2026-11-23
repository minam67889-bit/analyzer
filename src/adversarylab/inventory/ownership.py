"""Laboratory ownership boundary.

The operator configures scope once (domain roots, wildcard subdomains, IP ranges, lab
subnets, lab infrastructure addresses). Every discovered destination is classified against
that boundary. Unknown/external destinations are reported and are never used as active
attack targets without explicit operator authorization.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from ..config.schema import ScopeConfig


class OwnershipStatus(str, Enum):
    LAB_INFRA = "LAB_INFRA"
    LAB_OWNED = "LAB_OWNED"
    EXTERNAL = "EXTERNAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class OwnershipDecision:
    status: OwnershipStatus
    reason: str


def _normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _host_matches(host: str, patterns: Iterable[str]) -> bool:
    host = _normalize_host(host)
    if not host:
        return False
    for pattern in patterns:
        pat = _normalize_host(pattern)
        if not pat:
            continue
        if pat.startswith("*."):
            suffix = pat[1:]  # ".lab.test"
            if host.endswith(suffix):
                return True
        elif host == pat or host.endswith("." + pat):
            return True
    return False


class OwnershipPolicy:
    def __init__(self, scope: ScopeConfig) -> None:
        self.scope = scope
        self._infra = {ipaddress.ip_address(a) for a in scope.lab_infra_addresses}
        self._ranges = [ipaddress.ip_network(n, strict=False) for n in scope.ip_ranges]
        self._subnets = [ipaddress.ip_network(n, strict=False) for n in scope.lab_subnets]

    def classify(self, host: str | None, ip: str | None) -> OwnershipDecision:
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr is not None:
                if addr in self._infra:
                    return OwnershipDecision(
                        OwnershipStatus.LAB_INFRA, f"{ip} is a configured lab infrastructure address"
                    )
                for network in self._ranges + self._subnets:
                    if addr in network:
                        return OwnershipDecision(
                            OwnershipStatus.LAB_OWNED, f"{ip} is inside lab range {network}"
                        )
        if host:
            if _host_matches(host, self.scope.domain_roots):
                return OwnershipDecision(
                    OwnershipStatus.LAB_OWNED, f"{host} is under a configured lab domain root"
                )
            if _host_matches(host, self.scope.wildcard_subdomains):
                return OwnershipDecision(
                    OwnershipStatus.LAB_OWNED, f"{host} matches a configured wildcard subdomain"
                )
        if host or ip:
            return OwnershipDecision(
                OwnershipStatus.EXTERNAL, "destination is outside every configured lab boundary"
            )
        return OwnershipDecision(OwnershipStatus.UNKNOWN, "no host or address was observed")

    def is_lab_owned(self, host: str | None, ip: str | None) -> bool:
        return self.classify(host, ip).status in {
            OwnershipStatus.LAB_OWNED,
            OwnershipStatus.LAB_INFRA,
        }

    def require_lab_owned(self, host: str | None, ip: str | None) -> None:
        from ..errors import SafetyError

        decision = self.classify(host, ip)
        if decision.status in {OwnershipStatus.EXTERNAL, OwnershipStatus.UNKNOWN}:
            raise SafetyError(
                f"refusing to target non-lab destination host={host!r} ip={ip!r}: {decision.reason}"
            )
