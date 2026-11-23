from __future__ import annotations

import pytest

from adversarylab.config.loader import load_config, save_config
from adversarylab.config.schema import default_config
from adversarylab.errors import ConfigError


def test_default_config_is_valid():
    cfg = default_config()
    cfg.validate()
    assert cfg.scope.domain_roots
    assert cfg.tests.include_categories


def test_load_valid_toml(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text(
        """
[scope]
domain_roots = ["example.lab"]
ip_ranges = ["10.0.0.0/8"]

[infrastructure]
ssid = "TestLab"
passphrase = "password123"
ipv4_subnet = "10.0.0.0/24"
ipv4_gateway = "10.0.0.1"
ipv4_dhcp_start = "10.0.0.10"
ipv4_dhcp_end = "10.0.0.20"
"""
    )
    cfg = load_config(path)
    assert cfg.scope.domain_roots == ["example.lab"]
    assert cfg.infrastructure.ssid == "TestLab"


def test_invalid_toml_raises(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("[scope\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_missing_file_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml")


def test_bad_network_raises(tmp_path):
    path = tmp_path / "lab.toml"
    path.write_text('[scope]\nip_ranges = ["not-a-network"]\n')
    with pytest.raises(ConfigError):
        load_config(path)


def test_save_and_reload_roundtrip(tmp_path):
    cfg = default_config()
    cfg.infrastructure.ssid = "RoundTrip"
    path = tmp_path / "round.toml"
    save_config(cfg, path)
    loaded = load_config(path)
    assert loaded.infrastructure.ssid == "RoundTrip"
