# Adversary Lab

Wireless adversary emulation and mobile-firewall security validation platform for an
authorized lab. Windows 10/11 desktop application (PySide6) with an equivalent CLI, built
around a plugin test framework and an evidence-first verdict engine.

> **Honesty rule.** Nothing in this repository presents a simulation as proof of wireless
> attack resistance. Every test carries an `ExecutionMode`
> (`REAL_NETWORK`, `PROTOCOL_SIMULATION`, `VIRTUALIZED`, `PASSIVE_OBSERVATION`, `PARTIAL`,
> `UNSUPPORTED`), and missing telemetry is reported as missing — never converted into `PASS`.

## What it does

1. **Lab infrastructure** — creates/controls the lab Wi-Fi network (WinRT Mobile Hotspot,
   legacy hosted network, or an external managed AP) with a single ownership configuration.
2. **Device integration** — connects the authorized Android device over ADB, reads firewall
   state, and collects device-side telemetry.
3. **Destination discovery** — automatically inventories the device's destinations from
   traffic and DNS (lab-owned roots, IP ranges, subnets, wildcard subnets). No manual
   per-endpoint registration.
4. **Adversary emulation** — reproducible wireless/L2/L3/DNS/transport/app/mobile conditions
   and multi-stage attack chains, driven by configurable adversary profiles.
5. **Independent evaluation** — verdict engine with `PASS`, `FAIL`, `BLOCKED`, `DETECTED`,
   `DETECTED_AND_BLOCKED`, `NOT_DETECTED`, `NOT_BLOCKED`, `INCONCLUSIVE`, `NOT_APPLICABLE`,
   `UNSUPPORTED`, `PARTIALLY_VERIFIED`, plus confidence and cause attribution
   (firewall-confirmed, DNS rejection, app rejection, OS rejection, server rejection,
   network failure, unknown).
6. **Evidence** — hashed PCAP/PCAPNG/JSON/CSV/HTML/SQLite artifacts in structured session
   directories with manifests and no silent overwrite.
7. **Safety** — lab-only targeting, emergency stop, and configuration restoration with
   verification.

## Quick start

```bash
python -m venv .venv
.venv/bin/pip install -e .            # core
.venv/bin/pip install -e '.[ui]'      # + PySide6 desktop UI
.venv/bin/pip install -e '.[dev]'     # + pytest, ruff

cp config/lab.example.toml config/lab.toml   # edit scope + infrastructure
```

```bash
# 1. See what the host can actually do (never simulated)
adversarylab probe

# 2. Plan an assessment and print the coverage matrix
adversarylab plan --config config/lab.toml

# 3. Run a single test, a scenario, or the full assessment
adversarylab run --config config/lab.toml --test DNS-SPOOF-A
adversarylab run --config config/lab.toml --scenario dns-manipulation
adversarylab run --config config/lab.toml --campaign cookie-exposure-plaintext
adversarylab run --config config/lab.toml            # tests + campaigns

# 4. Render a report from the session's assessment.json
adversarylab report <session-dir>/report/assessment.json \
    --evidence-manifest <session-dir>/manifest.json \
    --config config/lab.toml \
    --output <session-dir>/report/out

# Desktop UI (same orchestrator as the CLI)
python -m adversarylab.ui
```

`--assume-capabilities` exists for dry-run planning only and is labelled as such in the
output. On a host that lacks a capability, planning reports `UNSUPPORTED` with the exact
reason instead of inventing success.

## Commands

| Command | Purpose |
|---|---|
| `probe` | live host capability probe (netsh/WinRT/Npcap/ADB), machine-readable |
| `devices` | list authorized Android devices via ADB (degrades gracefully) |
| `catalog` | list the test catalog with capabilities, prerequisites, techniques |
| `profiles` | list adversary profiles |
| `scenarios` | list multi-stage scenarios |
| `campaigns` | list multi-stage adversary campaigns (predefined + dynamic) |
| `plan` | coverage matrix: selected / unsupported / skipped with reasons |
| `run` | run a test, scenario, or full assessment; writes session evidence |
| `report` | JSON/CSV/HTML report from an assessment file |
| `pcap-parse` | normalize a PCAP/PCAPNG into the unified event format |

## Testing

```bash
.venv/bin/python -m pytest -q
```

The suite covers configuration, protocol codecs (DNS, DHCP, TLS, HTTP), link-layer
decoding, PCAP round-trips, packet parsers, the event bus, results/verdict engine,
ownership/inventory discovery, evidence integrity (including tamper detection), Windows
output parsers, lab services over real sockets, the orchestrator end-to-end, report
rendering, and static UI wiring (every button/action must have a handler).

Current status on the development sandbox: **146 tests pass**; catalog discovers **38 tests**
across 12 categories; a full assessment runs end-to-end (single tests, predefined and dynamic
campaigns, cookie exposure and longitudinal analysis) and writes a hashed evidence manifest.

## Mandatory reports

`adversarylab report` writes the summary report plus a `mandatory/` bundle:

`cookie_exposure`, `session_security`, `http_downgrade_resistance`,
`tls_certificate_security`, `network_attacker_capability`, `multi_stage_attack_chain`,
`longitudinal_traffic_analysis`, `attacker_visible_data_inventory`,
`defender_detection_prevention` — each as HTML and JSON, every finding referencing evidence.

Cookie values are redacted by default (`tests.reveal_cookie_values = false`): reports show a
4-character prefix/suffix plus a short SHA-256 prefix, so two references to the same cookie are
still recognisable without printing the value. `attacker_visible_data_inventory` is redacted
unconditionally, even when the operator opts in for their own cookie-exposure report. Every
cookie finding carries an `evidence_ref` that resolves to a hashed `http_exchange` record in the
session evidence store, so an observed value is always traceable to a reproducible capture.

## Attacker model

The adversary is positioned on the same Wi-Fi as an ordinary Android device. The device needs
no root, no Shizuku, no ADB during attack execution, no installed CA and no custom app. Cookie
values are reported as attacker-observed only when present in plaintext traffic visible to the
attacker; a TLS capture is metadata, never a stolen value. Certificate installation is a
separate opt-in experiment (`tests.allow_certificate_install_opt_in`) and is off by default.

## Architecture

```
src/adversarylab/
  core/       events, bus, state machine, results/verdict engine, capabilities, plugin, store
  config/     typed TOML schema + loader/writer
  evidence/   hashed evidence store + JSON/CSV exporters
  inventory/  ownership policy + passive destination discovery
  cookies/    synthetic cookie ground truth + exposure engine + report
  analysis/   longitudinal correlation, attacker/defender views
  protocols/  DNS, DHCP, TLS, HTTP, QUIC codecs
  capture/    link decoding, PCAP/PCAPNG reader+writer, per-protocol parsers
  services/   lab DNS, DHCP, HTTP, TLS, WebSocket, gateway
  platform/   Windows adapters (netsh/WinRT/Npcap/WFP/TShark) + ADB
  tests/      plugin spec, runner, registry, catalog, builtin modules
  adversary/  reversible actions, profiles, planner, scenarios, recovery, orchestrator
  reporting/  JSON/CSV/HTML report generation
  ui/         PySide6 desktop application
  cli.py      argparse CLI over the same orchestrator
```

Platform-specific code lives behind adapters. On a non-Windows host the probe reports
unavailable; tests that need it are planned as `UNSUPPORTED`, never as passing simulations.

## Safety boundaries

- Targets are restricted to the lab scope (domain roots, IP ranges, subnets, wildcard
  subnets) from configuration; anything outside is `EXTERNAL` and never an active target.
- No unrelated wireless clients are touched.
- No real third-party data is used; lab services present lab-controlled certificates.
- Emergency stop and configuration restoration are first-class, tested paths.

## Documentation

| Doc | Contents |
|---|---|
| `docs/00_executive_summary.md` | scope, honest capability statement, acceptance posture |
| `docs/01_research_report.md` | research findings and conclusions |
| `docs/02_threat_model.md` | threats, assets, trust boundaries |
| `docs/03_attack_surface_inventory.md` | attack surface and techniques |
| `docs/04_technology_comparison.md` | tool/technology comparison |
| `docs/05_feasibility_assessment.md` | Windows + hardware feasibility |
| `docs/06_android_integration.md` | Android firewall integration assessment |
| `docs/07_system_architecture.md` | architecture and data flow |
| `docs/08_development_roadmap.md` | phased roadmap |
| `docs/09_testing_strategy.md` | testing and independent verification procedure |
| `docs/10_known_limitations.md` | limitations with technical reasons |
| `docs/11_coverage_matrix.md` | implemented / executed / verified / hardware / unsupported |
| `docs/12_bibliography.md` | sources with URLs, dates, versions, relevance |

## License & ethics

For authorized laboratory use only. All techniques are confined to lab-owned infrastructure
and an authorized test device.
