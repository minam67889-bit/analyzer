from __future__ import annotations

import pytest

from adversarylab.config.schema import ScopeConfig
from adversarylab.errors import SafetyError
from adversarylab.inventory.ownership import OwnershipPolicy, OwnershipStatus


def _policy():
    return OwnershipPolicy(ScopeConfig(
        domain_roots=["lab.test"],
        wildcard_subdomains=["*.wild.lab.test"],
        ip_ranges=["10.10.0.0/16"],
        lab_subnets=["10.10.0.0/16"],
        lab_infra_addresses=["10.10.0.1"],
    ))


def test_domain_root_owned():
    decision = _policy().classify("api.lab.test", None)
    assert decision.status is OwnershipStatus.LAB_OWNED


def test_wildcard_owned():
    assert _policy().classify("x.wild.lab.test", None).status is OwnershipStatus.LAB_OWNED


def test_infra_address():
    assert _policy().classify(None, "10.10.0.1").status is OwnershipStatus.LAB_INFRA


def test_range_owned():
    assert _policy().classify(None, "10.10.5.5").status is OwnershipStatus.LAB_OWNED


def test_external():
    decision = _policy().classify("evil.example", "203.0.113.5")
    assert decision.status is OwnershipStatus.EXTERNAL
    assert "outside" in decision.reason


def test_unknown():
    assert _policy().classify(None, None).status is OwnershipStatus.UNKNOWN


def test_require_lab_owned_rejects_external():
    with pytest.raises(SafetyError):
        _policy().require_lab_owned("evil.example", "203.0.113.5")
