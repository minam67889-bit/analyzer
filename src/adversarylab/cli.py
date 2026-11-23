"""Command-line interface for Adversary Lab.

The CLI is a first-class interface: it drives the same orchestrator as the desktop UI and
is the recommended path for automation and CI. On a non-Windows host, live capabilities are
reported unavailable; ``--assume-capabilities`` exists for dry-run planning only and is
clearly labelled as such.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .core.results import TestResult

from . import __version__
from .adversary.actions import FakeActionRunner, ServiceBackedActionRunner
from .adversary.campaigns import CampaignLibrary
from .adversary.orchestrator import Orchestrator
from .adversary.planner import AssessmentPlanner
from .adversary.profiles import ProfileLibrary
from .adversary.scenarios import ScenarioLibrary
from .config.loader import load_config
from .config.schema import default_config
from .core.bus import EventBus
from .core.capability import Capability, CapabilityReport, CapabilitySet
from .core.store import Database
from .errors import PlatformError
from .logging_config import get_logger
from .platform.adb import AdbClient, AndroidTelemetry
from .platform.windows import WindowsCapabilityProbe
from .reporting.report import ReportGenerator
from .tests.catalog import build_default_registry


def _capabilities(assume: bool = False) -> CapabilitySet:
    if assume:
        return CapabilitySet(
            CapabilityReport(cap, True, "assumed for dry-run planning only", backend="assumed")
            for cap in Capability
        )
    return WindowsCapabilityProbe().run()


def _bootstrap(args: argparse.Namespace):
    config = load_config(args.config) if getattr(args, "config", None) else default_config()
    registry = build_default_registry()
    capabilities = _capabilities(getattr(args, "assume_capabilities", False))
    bus = EventBus()
    db = Database(args.db)
    if getattr(args, "dry_run", False):
        action_runner = FakeActionRunner()
    else:
        action_runner = ServiceBackedActionRunner(bus=bus.publish, session_id="")
    device = None
    if getattr(args, "with_device", False):
        client = AdbClient()
        serial = client.select_device(config.device.adb_serial)
        device = AndroidTelemetry(client, serial)
    orchestrator = Orchestrator(
        config=config,
        registry=registry,
        capabilities=capabilities,
        bus=bus,
        db=db,
        evidence_root=args.evidence_root,
        action_runner=action_runner,
        device=device,
        lab=None,
        capture=None,
    )
    return orchestrator, config, registry, capabilities


def cmd_probe(args: argparse.Namespace) -> int:
    caps = _capabilities(args.assume_capabilities)
    print(json.dumps(caps.to_dict(), indent=2, sort_keys=True))
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    client = AdbClient()
    try:
        devices = client.devices()
    except (OSError, PlatformError) as exc:
        # A missing adb binary or a host without Android tooling is a reported
        # condition, not a crash: the operator still gets machine-readable output.
        print(json.dumps({"error": str(exc), "devices": []}, indent=2))
        return 0
    print(json.dumps(devices, indent=2))
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    registry = build_default_registry()
    specs = [s.to_dict() for s in registry.specs()]
    if args.json:
        print(json.dumps(specs, indent=2))
    else:
        for spec in specs:
            print(f"{spec['id']:<22} {spec['category']:<10} {spec['name']}")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    print(json.dumps(ProfileLibrary().to_dict(), indent=2))
    return 0


def cmd_scenarios(args: argparse.Namespace) -> int:
    print(json.dumps(ScenarioLibrary().to_dict(), indent=2))
    return 0


def cmd_campaigns(args: argparse.Namespace) -> int:
    print(json.dumps(CampaignLibrary().to_dict(), indent=2))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    orchestrator, config, registry, capabilities = _bootstrap(args)
    orchestrator.create_session()
    plan = AssessmentPlanner(
        registry, capabilities,
        include_categories=config.tests.include_categories,
        exclude_test_ids=config.tests.exclude_test_ids,
    ).plan(orchestrator.session_id)
    print(json.dumps(plan.to_dict(), indent=2))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    orchestrator, config, registry, capabilities = _bootstrap(args)
    orchestrator.create_session()
    if getattr(args, "no_campaigns", False):
        config.assessment.run_campaigns = False
    prep = orchestrator.prepare()
    if not prep.ok:
        print(json.dumps(prep.to_dict(), indent=2), file=sys.stderr)
        if not args.force:
            return 2
    if args.test:
        result = orchestrator.run_test(args.test, params={"dry_run": args.dry_run})
        print(json.dumps(result.to_dict(), indent=2))
        status = 0
    elif args.scenario:
        scenario = orchestrator.scenarios.get(args.scenario)
        if scenario is None:
            print(f"unknown scenario {args.scenario!r}", file=sys.stderr)
            return 2
        results = orchestrator.run_scenario(scenario)
        print(json.dumps([r.to_dict() for r in results], indent=2))
        status = 0
    elif args.campaign:
        campaign = CampaignLibrary().get(args.campaign)
        if campaign is None:
            print(f"unknown campaign {args.campaign!r}", file=sys.stderr)
            return 2
        run = orchestrator.run_campaign(campaign)
        print(json.dumps(run.to_dict(), indent=2, default=str))
        status = 0
    else:
        assessment = orchestrator.run_assessment()
        print(json.dumps(assessment.to_dict(), indent=2, default=str))
        status = 0
    manifest = orchestrator.finalize()
    if manifest:
        print(f"evidence manifest: {manifest[0]} (sha256 {manifest[1]})", file=sys.stderr)
    return status


def _as_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def cmd_report(args: argparse.Namespace) -> int:
    payload = json.loads(Path(args.assessment).read_text(encoding="utf-8"))
    from .adversary.orchestrator import AssessmentResult

    result = AssessmentResult(
        session_id=payload.get("session_id", "unknown"),
        status=payload.get("status", "unknown"),
        started_at=_as_datetime(payload.get("started_at")) or datetime.now(UTC),
        finished_at=_as_datetime(payload.get("finished_at")),
        environment=payload.get("environment", {}),
    )
    # Results are rendered from their dict form where available.
    for raw in payload.get("results", []):
        result.results.append(_result_from_dict(raw))
    from .tests.registry import CoverageRow

    for raw in payload.get("coverage", []):
        result.coverage.append(CoverageRow(
            test_id=raw["test_id"], name=raw.get("name", ""), category=raw.get("category", ""),
            status=raw.get("status", ""), reason=raw.get("reason", ""),
            execution_mode=raw.get("execution_mode", ""), verdict=raw.get("verdict", ""),
            confidence=raw.get("confidence", ""),
        ))
    result.campaigns = [dict(c) for c in payload.get("campaigns", []) or []]
    result.cookie_exposure = dict(payload.get("cookie_exposure", {}) or {})
    result.longitudinal = dict(payload.get("longitudinal", {}) or {})
    evidence = []
    if args.evidence_manifest:
        manifest = json.loads(Path(args.evidence_manifest).read_text(encoding="utf-8"))
        evidence = manifest.get("entries", [])
    paths = ReportGenerator(result).write(args.output, evidence_records=evidence)
    from .reporting.extra_reports import ReportBundle

    reveal = bool(_report_config(getattr(args, "config", None)).get("reveal_cookie_values", False))
    bundle = ReportBundle(result, reveal_cookie_values=reveal).write(
        Path(args.output) / "mandatory"
    )
    paths.update({f"mandatory/{k}": v for k, v in bundle.items()})
    print(json.dumps({k: str(v) for k, v in paths.items()}, indent=2))
    return 0


def _report_config(config_path: str | None) -> dict[str, Any]:
    """Read the [tests] section that governs how reports may render cookie values."""
    try:
        config = load_config(config_path) if config_path else default_config()
        return config.tests.to_dict()
    except Exception:  # pragma: no cover - report must survive a bad config
        get_logger(__name__).warning(
            "could not read config for report redaction; defaulting to redacted"
        )
        return {}


def _result_from_dict(raw: dict[str, Any]) -> TestResult:
    from .core.results import (
        BlockCause,
        Confidence,
        ExecutionMode,
        Observation,
        TestResult,
        Verdict,
    )

    observations = [
        Observation(
            source=o.get("source", ""),
            kind=o.get("kind", ""),
            timestamp=_as_datetime(o.get("timestamp")) or datetime.now(UTC),
            summary=o.get("summary", ""),
            details=dict(o.get("details", {})),
            evidence_ref=o.get("evidence_ref"),
            count=o.get("count"),
        )
        for o in raw.get("observations", [])
    ]
    return TestResult(
        result_id=raw.get("result_id", ""),
        test_id=raw.get("test_id", ""),
        scenario_id=raw.get("scenario_id"),
        verdict=Verdict(raw.get("verdict", "INCONCLUSIVE")),
        confidence=Confidence(raw.get("confidence", "UNKNOWN")),
        block_cause=BlockCause(raw.get("block_cause", "UNKNOWN")),
        execution_mode=ExecutionMode(raw.get("execution_mode", "UNSUPPORTED")),
        rationale=raw.get("rationale", ""),
        observations=observations,
        evidence_refs=list(raw.get("evidence_refs", [])),
        limitations=list(raw.get("limitations", [])),
        started_at=_as_datetime(raw.get("started_at")),
        ended_at=_as_datetime(raw.get("ended_at")),
    )


def cmd_pcap_parse(args: argparse.Namespace) -> int:
    from .capture.parsers import PacketEventParser
    from .capture.pcap import open_capture

    parser = PacketEventParser(session_id="offline")
    count = 0
    for packet in open_capture(args.pcap):
        for event in parser.parse_raw(packet):
            count += 1
            if args.limit and count > args.limit:
                break
            print(json.dumps(event.to_dict(), sort_keys=True))
    print(f"# parsed {count} events", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="adversarylab", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("probe", help="probe host capabilities")
    p.add_argument("--assume-capabilities", action="store_true",
                   help="dry-run only: report every capability as available")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("devices", help="list connected Android devices")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("catalog", help="list the test catalog")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_catalog)

    p = sub.add_parser("profiles", help="list adversary profiles")
    p.set_defaults(func=cmd_profiles)

    p = sub.add_parser("scenarios", help="list scenarios")
    p.set_defaults(func=cmd_scenarios)

    p = sub.add_parser("campaigns", help="list multi-stage attack campaigns")
    p.set_defaults(func=cmd_campaigns)

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", default=None, help="path to lab TOML configuration")
        sp.add_argument("--evidence-root", default="evidence")
        sp.add_argument("--db", default="adversarylab.db")
        sp.add_argument("--assume-capabilities", action="store_true")
        sp.add_argument("--dry-run", action="store_true",
                        help="use a deterministic fake action runner")
        sp.add_argument("--with-device", action="store_true")

    p = sub.add_parser("plan", help="print the assessment plan and coverage matrix")
    add_common(p)
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("run", help="run a test, scenario or the full assessment")
    add_common(p)
    p.add_argument("--test", default=None)
    p.add_argument("--scenario", default=None)
    p.add_argument("--campaign", default=None)
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-campaigns", action="store_true",
                   help="skip multi-stage campaigns during a full assessment")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("report", help="render a report from an assessment JSON file")
    p.add_argument("assessment")
    p.add_argument("--evidence-manifest", default=None)
    p.add_argument("--output", default="report")
    p.add_argument("--config", default=None,
                   help="assessment config; governs cookie-value redaction in reports")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("pcap-parse", help="parse a PCAP/PCAPNG into normalized events")
    p.add_argument("pcap")
    p.add_argument("--limit", type=int, default=0)
    p.set_defaults(func=cmd_pcap_parse)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
