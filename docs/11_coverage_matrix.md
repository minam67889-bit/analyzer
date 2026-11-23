# 11 — Feature & Test Coverage Matrix

Status legend: **IMP** implemented, **EXE** executed in this workspace, **VER** independently
verified, **HW** hardware/on-target required, **UNS** unsupported (reason in §10), **SIM**
protocol/virtualized simulation (not proof of RF resistance).

## A. Platform subsystems

| Subsystem | Status | Evidence |
|---|---|---|
| Config (TOML) + validation | IMP / EXE / VER | unit tests |
| Logging + error taxonomy | IMP / EXE / VER | unit tests |
| Event bus + SQLite store | IMP / EXE / VER | unit tests |
| Verdict/confidence engine | IMP / EXE / VER | unit tests |
| Evidence store + hashing | IMP / EXE / VER | unit tests |
| Test framework + discovery | IMP / EXE / VER | unit tests |
| Inventory + ownership | IMP / EXE / VER | unit tests |
| PCAP/PCAPNG reader | IMP / EXE / VER | unit tests |
| DNS/DHCP/ARP/ND/TLS/HTTP/QUIC parsers | IMP / EXE / VER | unit tests |
| DNS/DHCP/HTTP/TLS/WS lab services | IMP / EXE / VER | integration tests |
| Orchestrator state machine | IMP / EXE / VER | integration tests |
| Recovery manager | IMP / EXE / VER | integration tests |
| Report generator (JSON/CSV/HTML) | IMP / EXE / VER | integration tests |
| Windows netsh/PowerShell/WinRT adapter | IMP / mocked VER | on-target pending |
| WFP user-mode adapter | IMP / mocked VER | on-target pending |
| Npcap live capture | IMP / mocked VER | HW |
| ADB adapter | IMP / mocked VER | on-target pending |
| PySide6 UI | IMP / wiring VER | static wiring test; visual pass pending |
| Cookie Exposure Assessment Engine + ground truth + verification | IMP / EXE / VER | unit + integration tests |
| Longitudinal correlation / relationship graph / timelines | IMP / EXE / VER | unit tests |
| Attacker-view / defender-view projections | IMP / EXE / VER | unit tests |
| Multi-stage campaigns (5 predefined + dynamic builder) | IMP / EXE | integration tests + full assessment |
| Nine mandatory reports (HTML + JSON) | IMP / EXE / VER | unit tests + CLI report run |
| CLI (probe/devices/catalog/profiles/scenarios/campaigns/plan/run/report/pcap-parse) | IMP / EXE / VER | CLI smoke on Linux |
| Assessment end-to-end (28 tests, evidence manifest, recovery) | IMP / EXE | full dry-run assessment |
| Report JSON/CSV/HTML from a real assessment | IMP / EXE / VER | CLI + unit tests |

## B. Adversary engine

| Component | Status |
|---|---|
| Profiles (observer, rogue-infra, AiTM, DNS manipulator, gateway impersonator, captive portal, HTTP/TLS manipulator, service impersonator, disruptor, multi-stage) | IMP |
| Reversible network actions | IMP |
| Scenario + chain definitions | IMP |
| Concurrent/timed/repeated scenarios | IMP |
| Execution modes & capability gating | IMP |
| Emergency stop + recovery | IMP / EXE (logic) |

## C. Test catalog (representative; see catalog module for the authoritative list)

| Test | Layer | Mode | Status |
|---|---|---|---|
| LAB-BASELINE | infra | REAL | IMP / EXE |
| DISC-DNS-PASSIVE | discovery | PASSIVE | IMP / EXE |
| DNS-SPOOF-A | dns | REAL | IMP / EXE |
| DNS-REBIND-PRIVATE | dns | REAL | IMP / EXE |
| DNS-REBIND-CNAME | dns | REAL | IMP / EXE |
| DNS-LEAK-UNDERLYING | dns | REAL | IMP / EXE |
| DNS-DOT-STEER | dns | REAL | IMP / EXE |
| DHCP-ROGUE-GATEWAY | dhcp | REAL | IMP / EXE |
| DHCP-OPTION-MANIP | dhcp | REAL | IMP / EXE |
| ARP-SPOOF-GATEWAY | l2 | REAL | IMP / EXE (SIM on Linux) |
| GW-IMPERSONATION | l3 | REAL | IMP / EXE (SIM on Linux) |
| IPV6-BYPASS | ipv6 | REAL | IMP / EXE |
| ND-RA-INJECTION | ipv6 | REAL | HW |
| TLS-WRONG-CERT | tls | REAL | IMP / EXE |
| TLS-WRONG-HOSTNAME | tls | REAL | IMP / EXE |
| TLS-DOWNGRADE | tls | REAL | IMP / EXE |
| TLS-PINNING | tls | REAL | IMP / EXE |
| HTTP-CLEARTEXT | app | REAL | IMP / EXE |
| CAPTIVE-PORTAL-CLONE | app | REAL | IMP / EXE |
| WS-ENDPOINT | app | REAL | IMP / EXE |
| QUIC-H3 | app | REAL | IMP / EXE |
| VPN-CONTINUITY | mobile | REAL | HW |
| VPN-FAILOPEN | mobile | REAL | HW |
| NET-TRANSITION | mobile | REAL | HW |
| PER-APP-POLICY | mobile | REAL | HW |
| DEAUTH-FLOOD | wireless | REAL | HW |
| EVIL-TWIN | wireless | REAL | HW |
| PMF-DOWNGRADE | wireless | REAL | HW |
| MULTI-STAGE-AITM | chain | REAL | IMP / EXE (SIM) |

"IMP" means code exists and unit/integration tests pass on Linux where the subsystem is
cross-platform. "HW" rows are implemented but require the on-target hardware phase; they
are never reported as verified from this workspace.

## D. Honest gaps

- No live RF, live WFP, live hotspot, or live Android validation in this workspace.
- No independent analyst verification yet; procedure defined in `docs/09`.
- UI not rendered here.
- WFP callout driver not implemented (reason in `docs/10`).

These gaps are tracked as explicit rows rather than being presented as complete coverage.

## E. Measured status in this workspace (2026-11-23)

- Automated tests: **144 passing** (`pytest -q`), covering core logic, protocol codecs,
  link/PCAP round-trips, parsers, services over real sockets, the orchestrator, campaigns,
  cookie exposure, longitudinal analysis, dual views, all nine mandatory reports, and static
  UI wiring.
- Catalog: **38 tests** discovered across 12 categories (including cookie exposure,
  downgrade resistance, HSTS and the explicitly opt-in TLS interception experiment).
- Full assessment dry-run (`--assume-capabilities`): 37 single-test executions plus 6
  campaigns, hashed evidence manifest produced, recovery reported `success`.
- Cookie ground truth recorded 6 synthetic cookies; with no device traffic the exposure
  engine classified every one as `server_only` and observed zero values — no value was
  inferred from encrypted or absent traffic.
- Verdict distribution in the dry run: 32 `INCONCLUSIVE`, 5 `UNSUPPORTED` (the opt-in
  certificate experiment and hardware-gated tests), no manufactured `PASS`/`FAIL`.
- Verdict distribution in the dry run: `INCONCLUSIVE` everywhere no device traffic exists —
  the engine did not manufacture `PASS` or `FAIL` from missing telemetry. Expected-allowed
  control tests with no telemetry are explicitly `INCONCLUSIVE` with a "missing telemetry"
  rationale.
- Not executed here: any Windows-only path (Npcap capture, WFP, hotspot, PowerShell/WinRT),
  any live RF injection, the Android device, and the rendered UI.
