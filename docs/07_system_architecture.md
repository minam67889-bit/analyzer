# 07 — System Architecture

## 1. Layering

```
┌───────────────────────────────────────────────────────────────┐
│ Presentation   PySide6 UI (dashboard, tabs, live timeline)     │
│                CLI (automation, CI, headless)                  │
├───────────────────────────────────────────────────────────────┤
│ Orchestration  AssessmentPlanner · ScenarioRunner · State      │
│                machine · Pause/Resume/Stop/EmergencyStop       │
├───────────────────────────────────────────────────────────────┤
│ Evaluation     VerdictEngine · ConfidenceModel · BlockCause    │
│                CoverageMatrix · ReportGenerator                │
├───────────────────────────────────────────────────────────────┤
│ Test framework TestSpec · TestModule · Registry · Discovery    │
│                Scenario · Chain · Profile                       │
├───────────────────────────────────────────────────────────────┤
│ Adversary      Profiles · NetworkActions · Injectors · Lab      │
│                services (DNS/DHCP/HTTP/TLS/WS) · Recovery      │
├───────────────────────────────────────────────────────────────┤
│ Observation    EventBus · EventStore · Capture · Parsers ·     │
│                Inventory/Discovery · ADB telemetry              │
├───────────────────────────────────────────────────────────────┤
│ Platform       Windows: netsh/WinRT/WFP/Npcap; Android: ADB;   │
│                Infra backends: hotspot / external AP / hostapd │
├───────────────────────────────────────────────────────────────┤
│ Foundation     config (TOML) · logging · clock · ids · errors   │
└───────────────────────────────────────────────────────────────┘
```

## 2. Key interfaces

- `EventSink.publish(event)` / `EventBus.subscribe(filter, handler)` — unified telemetry.
- `TestModule` — setup/run/collect/teardown/evaluate; registry discovery via entry points
  and directory scan.
- `InfrastructureBackend` — `start/stop/status/configure`; implementations:
  `WinRtHotspotBackend`, `HostedNetworkBackend`, `ExternalApBackend`, `LinuxHostapdBackend`.
- `CaptureSource` — `start/stop`, yields packets or parsed events.
- `NetworkAction` — reversible action with `apply()`/`revert()` (ARP, DNS, DHCP, RA,
  deauth, route).
- `FirewallTelemetryAdapter` — `device_info()`, `vpn_state()`, `rules_snapshot()`,
  `logs()`.
- `EvidenceStore` — append-only session directory + SQLite index + SHA-256 manifest.
- `VerdictEngine.evaluate(test_id, observations, policy) -> TestResult`.

## 3. Data flow (one test)

1. Planner selects tests whose required capabilities are available.
2. ScenarioRunner sets up, applies `NetworkAction`s, and records setup evidence.
3. Device traffic is captured and parsed into `NetworkEvent`s on the bus.
4. Lab servers log their own events; ADB telemetry contributes device events.
5. After the observation window, actions are reverted; recovery is observed.
6. VerdictEngine correlates evidence, assigns `Verdict`/`BlockCause`/`Confidence`.
7. Evidence is hashed and indexed; reports are generated.

## 4. Concurrency & thread safety

- Capture, DNS/DHCP servers, and ADB pollers run in background threads.
- All shared state is guarded by locks; UI updates go through Qt signals (main thread).
- Cancellation uses a shared `CancellationToken`; emergency stop is a hard cancel plus
  recovery.

## 5. Persistence

- SQLite: sessions, events, destinations, results, coverage, evidence index.
- Session directory: `evidence/<session-id>/` with `config/`, `packets/`, `logs/`,
  `android/`, `manifest.json`, `manifest.sha256`.
- PCAP/PCAPNG, JSON, CSV, HTML exports.

## 6. Extensibility

- New test: subclass `TestModule`, set `spec`, drop into `builtin/` or a configured
  plugin directory; discovered automatically.
- New backend: implement `InfrastructureBackend`.
- New profile: YAML/TOML profile definition merged with built-ins.
- New parser: implement `PacketParser` and register.
