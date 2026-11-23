# Adversary Lab — Executive Summary

**Project:** Wireless Adversary Emulation & Mobile Firewall Security Research Lab
**Target platform:** Windows 10/11 (22H2 or later recommended) x64
**Subject under test:** An authorized Android device running a third-party mobile firewall
**Repository:** `minam67889-bit/analyzer`
**Document status:** Baseline engineering release — research complete, core implemented, hardware-dependent paths require on-target validation.

## 1. What this platform is

Adversary Lab is a Windows desktop application that creates and controls a contained
wireless laboratory, connects an authorized Android test device to it, passively observes
the device's real network behavior, automatically builds an inventory of destinations,
reproduces adversarial network conditions (rogue DNS, DHCP spoofing, ARP poisoning,
gateway impersonation, TLS/HTTP manipulation, IPv6 anomalies, deauthentication/evil-twin
setup), and independently evaluates whether the mobile firewall detects, blocks, permits,
or fails to handle each condition.

It is **not** a port scanner, a Wi-Fi analyzer, or a static rule checker. Every verdict is
evidence-backed and classified by observation source and confidence.

## 2. Honest capability statement (critical)

This development workspace is a Linux sandbox (`Debian 12`, `Python 3.11.2`). The Windows
target hardware (Wi-Fi adapters, Npcap, WFP, Mobile Hotspot, ADB device) is **not present
here**. Therefore:

| Layer | Status in this workspace |
|---|---|
| Cross-platform core (config, events, verdict engine, inventory, test framework, evidence store, DNS/DHCP/HTTP/TLS lab services, parsers, reports, CLI) | Implemented and unit/integration tested on Linux |
| Windows capability detection, netsh/PowerShell/WinRT adapters, WFP wrappers, Npcap capture, ADB transport | Implemented against documented APIs; **not executed** on Windows here; requires on-target validation |
| PySide6 desktop UI | Implemented; **not rendered/executed** in this headless Linux sandbox |
| Real wireless management-frame injection / monitor mode | Implemented as scapy-backed actions; requires Npcap raw 802.11 + capable adapter |

No unsupported capability is silently replaced by a "fake simulation". The platform records
an explicit `ExecutionMode` (`REAL_NETWORK`, `PROTOCOL_SIMULATION`, `VIRTUALIZED`,
`PASSIVE_OBSERVATION`, `PARTIAL`, `UNSUPPORTED`) for every test and refuses to label a
simulation as proof of wireless resistance.

## 3. Key research conclusions

1. **Windows Mobile Hotspot ≠ legacy hosted network.** Modern hotspot is WinRT
   `NetworkOperatorTetheringManager`; `netsh wlan start hostednetwork` controls a
   different, often-unsupported legacy feature. The application drives WinRT via a
   generated PowerShell bridge and falls back to a documented external-AP/OpenWrt backend.
2. **Most consumer Wi-Fi adapters do not expose AP+monitor+injection simultaneously.**
   The strongest realistic lab uses an external managed AP or a second USB adapter in
   monitor mode; the platform treats this as a first-class backend, not an afterthought.
3. **Android firewall architectures differ fundamentally.** VPNService is device-wide and
   can have IPv6/DNS bypass and tunnel-setup leaks; root/iptables firewalls are per-UID but
   need root; Private DNS (DoT) can override a VPN's resolver. The platform supports
   architecture-specific evaluation adapters and never assumes VPNService.
4. **Encrypted DNS is now the norm.** DoH (RFC 8484), DoT (RFC 7858), DoQ (RFC 9250) change
   both the attack surface and the observation strategy; DNS tests must distinguish
   plaintext resolver traffic from encrypted transport and must not infer payload contents.
5. **TLS pinning and certificate validation are testable without breaking TLS.** The
   platform presents lab-controlled certificates and observes handshake outcomes, SNI, ALPN
   and failure behavior rather than claiming to decrypt application data.

## 4. Deliverables produced

- 12 research/engineering documents in `docs/` (this file included).
- Full source tree in `src/adversarylab/` with modular platform adapters.
- Plugin-based test framework with a catalog of **38 adversarial tests** across 12 categories.
- Cookie Exposure Assessment Engine with laboratory ground truth, redaction, verification, and
  a per-finding `evidence_ref` resolving to a hashed lab-server exchange record.
- Longitudinal, session-aware correlation engine with attacker/defender dual views.
- Multi-stage campaign orchestrator (predefined + dynamically assembled from discovered conditions).
- Nine mandatory reports (cookie exposure, session security, downgrade resistance, TLS/certificate,
  attacker capability, attack chain, longitudinal analysis, attacker-visible inventory, defender
  detection/prevention).
- Automated test suite: **146 tests passing** on the Linux development sandbox.
- CLI (`python -m adversarylab`) and PySide6 desktop UI (`python -m adversarylab.ui`).
- End-to-end dry-run assessment: 37 single-test executions plus 6 campaigns, hashed evidence
  manifest, recovery verified; verdicts `INCONCLUSIVE`/`UNSUPPORTED` where no device traffic
  existed, with no manufactured `PASS` or `FAIL`.

## 5. Acceptance posture

Acceptance is evidence-driven. The final coverage matrix (`docs/11_coverage_matrix.md`)
distinguishes *implemented*, *executed*, *independently verified*, *hardware-dependent*,
and *unsupported*. Any row marked unsupported includes the exact technical reason and the
strongest available alternative.
