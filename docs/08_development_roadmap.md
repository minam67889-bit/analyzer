# 08 — Development Roadmap

## Phase 0 — Research & architecture (complete)
- Independent research and bibliography.
- Threat model, attack surface, feasibility, architecture, coverage matrix.

## Phase 1 — Foundation (implemented)
- Config schema + TOML loader.
- Clock/IDs/logging/error taxonomy.
- Event model, event bus, SQLite event store.
- Verdict/confidence/block-cause model.
- Evidence store with hashing and session directories.
- Plugin/test framework and registry.

## Phase 2 — Observation (implemented cross-platform; Windows capture on target)
- Pure-Python PCAP/PCAPNG reader.
- Parsers: DNS, DHCP, ARP, IPv6 ND, TLS ClientHello, HTTP metadata, QUIC metadata.
- Capture source abstraction (Npcap live, offline pcap).
- ADB telemetry adapter.
- Inventory discovery and ownership boundary.

## Phase 3 — Lab services (implemented cross-platform)
- DNS server (authoritative answers, spoofing, TTL, logging).
- DHCP server (OFFER/ACK, options, rogue mode).
- HTTP/WebSocket lab endpoints + captive portal.
- TLS server with lab CA / misconfiguration profiles.
- Gateway/route/NAT controls via OS primitives.

## Phase 4 — Adversary engine (implemented; RF paths hardware-gated)
- Profiles and scenario definitions.
- Reversible network actions.
- Orchestrator state machine with pause/resume/stop/emergency.
- Assessment planner and automatic test selection.
- Recovery manager.

## Phase 5 — Evaluation & reporting (implemented)
- Multi-source correlation.
- Verdict engine with block-cause classification.
- Coverage matrix generation.
- JSON/CSV/HTML reports + evidence viewer data.

## Phase 6 — UI (implemented; requires on-target visual validation)
- PySide6 dashboard and tabs bound to the controller.
- Live timeline, device monitor, scenario catalog, report browser.

## Phase 7 — On-target validation (requires Windows + hardware; not started)
1. Run capability probe; record adapter matrix.
2. Bring up lab Wi-Fi; connect device; verify discovery.
3. Execute each scenario; attach evidence.
4. Independently verify a sample of verdicts via manual capture analysis.
5. Regression run; compare results.
6. Update coverage matrix with executed/verified states.

## Phase 8 — Hardening
- Signed WFP callout (optional extension).
- Installer/uninstaller.
- Locked dependency set; reproducible build.
- Performance tuning for high-rate capture.

## Continuous research
Each phase reviews new advisories, protocol edge cases, bypass methods, and adds catalog
entries; the coverage matrix is updated accordingly.
