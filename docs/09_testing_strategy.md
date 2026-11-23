# 09 — Testing Strategy

## 1. Levels

| Level | Scope | Runs where | Current status |
|---|---|---|---|
| Unit | Pure logic: parsers, verdict engine, inventory, DNS/DHCP codec, config, evidence | Linux CI / dev | Implemented & passing |
| Integration | In-process services + event bus + orchestrator with fake actions/backend | Linux CI | Implemented & passing |
| Platform-mocked | Windows netsh/PowerShell/WFP/ADB with fixtures/mocks | Linux CI | Implemented |
| Hardware-in-loop | Real adapter, real hotspot, real device | Windows lab | Deferred to on-target phase |
| Independent verification | Manual analysis of a verdict sample by a second analyst/tool | Windows lab | Procedure defined |

## 2. Unit/integration coverage targets

- Config parsing and validation (valid + invalid TOML).
- Event bus publish/subscribe ordering and filtering.
- Verdict engine: each `Verdict` and `BlockCause` reachable from a constructed evidence set.
- Inventory: DNS answer → destination, ownership classification, external flagging.
- DNS codec: query/response build/parse round-trip; spoof and rebinding responses.
- DHCP codec: Discover→Offer→Request→Ack option handling.
- Parsers: synthetic Ethernet/IPv4/UDP/TCP frames for DNS/DHCP/ARP/ND/TLS/HTTP.
- PCAP: write then read a frame; hash manifest.
- Evidence: append-only, no overwrite, hash verification, filtering by test/session.
- Orchestrator: start/pause/resume/stop/emergency; recovery invoked on failure.
- ADB adapter: mock subprocess transport.
- Report: JSON/CSV/HTML generation from a synthetic session.

## 3. Orchestrator test scenarios

1. **Happy path:** planner → scenario → verdict → report → recovery.
2. **Capability-gated skip:** a test requiring monitor mode is skipped with reason when the
   capability is absent; coverage matrix shows `UNSUPPORTED`.
3. **Failure injection:** a lab action raises; orchestrator enters `RECOVERING`, reverts
   actions, marks test `INCONCLUSIVE`.
4. **Emergency stop:** token cancel mid-scenario; all injectors stopped; recovery runs.
5. **Recovery verification:** after revert, original DNS/gateway/route observed; recovery
   result recorded.

## 4. Verdict quality gates

- A `PASS` requires at least one primary observation and either a corroborating source or
  an explicit single-source rationale with `Confidence.MEDIUM`.
- A `BLOCKED` requires evidence distinguishing firewall block from network failure
  (`BlockCause`).
- Missing telemetry ⇒ `INCONCLUSIVE`, never `PASS`.
- Simulations are labeled with `ExecutionMode` and cannot produce a wireless-resistance
  claim.

## 5. Regression & reproducibility

- Every session stores its full configuration and environment fingerprint.
- `manifest.sha256` allows integrity verification.
- Re-running the same session config on the same hardware should produce comparable
  verdicts; differences are surfaced in the regression comparison.
- Randomized seeds are recorded in the session.

## 6. On-target validation procedure

1. `adversarylab probe --json > capability.json`; attach to validation record.
2. `adversarylab session init`, bring up infrastructure, connect device.
3. Run a smoke scenario; confirm capture sees traffic and inventory populates.
4. Run the full assessment; export report.
5. Independently re-derive at least 10% of verdicts from raw PCAP/server logs.
6. Record discrepancies and root-cause them (evidence gap vs engine bug).
