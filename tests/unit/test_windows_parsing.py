from __future__ import annotations

from adversarylab.platform.windows import (
    parse_interface_list,
    parse_wireless_capabilities,
    parse_wlan_drivers,
)


def test_parse_wlan_drivers():
    text = """
Interface name: Wi-Fi
Driver                    : Intel(R) Wi-Fi 6 AX201
Driver version            : 22.250.1.6
Hosted network supported  : No
Soft AP                   : Not supported
Network monitor mode      : Not supported
Protected Management Frames: Supported
"""
    parsed = parse_wlan_drivers(text)
    assert parsed["hosted_network_supported"] is False
    assert parsed["monitor_mode_supported"] is False
    assert parsed["protected_management_frames"] is True
    assert parsed["driver_version"] == "22.250.1.6"


def test_parse_wireless_capabilities():
    text = """
Wireless Device Capabilities
Station                 : Supported
Soft AP                 : Not supported
Network monitor mode    : Not supported
Protected Management Frames : Supported
MAC Randomization       : Supported
"""
    parsed = parse_wireless_capabilities(text)
    assert parsed["soft_ap"] is False
    assert parsed["pmf"] is True


def test_parse_interface_list():
    text = """
Interface name : Wi-Fi
State          : connected
SSID           : AdversaryLab
BSSID          : 02:00:00:00:00:01
Channel        : 36

Interface name : Wi-Fi 2
State          : disconnected
"""
    interfaces = parse_interface_list(text)
    assert len(interfaces) == 2
    assert interfaces[0]["SSID"] == "AdversaryLab"
    assert interfaces[1]["State"] == "disconnected"
