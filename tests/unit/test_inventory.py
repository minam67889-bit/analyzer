from __future__ import annotations

from adversarylab.config.schema import ScopeConfig
from adversarylab.inventory.discovery import DestinationInventory
from adversarylab.inventory.ownership import OwnershipPolicy, OwnershipStatus


def _inventory():
    return DestinationInventory(
        "s1", OwnershipPolicy(ScopeConfig(
            domain_roots=["lab.test"], ip_ranges=["10.10.0.0/16"],
            lab_subnets=["10.10.0.0/16"], lab_infra_addresses=["10.10.0.1"],
        ))
    )


def test_dns_answer_creates_destination():
    inv = _inventory()
    dest = inv.record_dns_answer("api.lab.test", "10.10.0.50")
    assert dest.ownership == OwnershipStatus.LAB_OWNED.value
    assert dest.ip == "10.10.0.50"
    assert dest.host == "api.lab.test"


def test_connection_updates_existing():
    inv = _inventory()
    inv.record_dns_answer("api.lab.test", "10.10.0.50")
    second = inv.record_connection(ip="10.10.0.50", port=443, protocol="tcp")
    # The host learned from DNS is associated with the connection by IP.
    assert second.host == "api.lab.test"
    third = inv.record_connection(ip="10.10.0.50", port=443, protocol="tcp")
    assert third.destination_id == second.destination_id
    assert third.hit_count == 2
    assert third.port == 443
    assert third.service_guess == "https"


def test_external_is_not_active_target():
    inv = _inventory()
    inv.record_connection(ip="203.0.113.5", port=443)
    assert inv.active_targets() == []
    assert len(inv.external_destinations()) == 1


def test_service_ports():
    inv = _inventory()
    inv.record_connection(ip="10.10.0.50", port=443)
    inv.record_connection(ip="10.10.0.50", port=80)
    assert inv.service_ports() == {80: 1, 443: 1}
