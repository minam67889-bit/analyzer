"""Multi-stage adversary campaigns.

A campaign is more than a list of tests: it has an initial attacker position, staged
objectives, explicit conditions that each stage establishes or requires, preserved
observations between stages, and a final explanation of where and why the chain succeeded
or failed.

Predefined campaigns are provided for the common laboratory goals; a dynamic builder
assembles a campaign from conditions discovered during the assessment.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..core.results import TestResult, Verdict
from ..logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class CampaignStage:
    name: str
    description: str
    test_id: str
    params: dict[str, Any] = field(default_factory=dict)
    requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    is_objective: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "test_id": self.test_id,
            "params": dict(self.params),
            "requires": list(self.requires),
            "provides": list(self.provides),
            "is_objective": self.is_objective,
        }


@dataclass
class CampaignDefinition:
    id: str
    name: str
    description: str
    profile_id: str
    objective: str
    stages: list[CampaignStage] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "profile_id": self.profile_id,
            "objective": self.objective,
            "stages": [s.to_dict() for s in self.stages],
        }


@dataclass
class CampaignStageResult:
    stage: CampaignStage
    conditions_before: list[str]
    feasible: bool
    result: TestResult | None = None
    conditions_after: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.to_dict(),
            "conditions_before": list(self.conditions_before),
            "feasible": self.feasible,
            "result": self.result.to_dict() if self.result else None,
            "conditions_after": list(self.conditions_after),
            "note": self.note,
        }


@dataclass
class CampaignRun:
    campaign_id: str
    session_id: str
    status: str
    started_at: str
    finished_at: str | None = None
    stages: list[CampaignStageResult] = field(default_factory=list)
    objective_reached: bool = False
    explanation: str = ""
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "session_id": self.session_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stages": [s.to_dict() for s in self.stages],
            "objective_reached": self.objective_reached,
            "explanation": self.explanation,
            "evidence_refs": list(self.evidence_refs),
        }


class CampaignLibrary:
    """Predefined laboratory campaigns."""

    def __init__(self) -> None:
        self._campaigns: dict[str, CampaignDefinition] = {
            campaign.id: campaign for campaign in _predefined()
        }

    def all(self) -> list[CampaignDefinition]:
        return list(self._campaigns.values())

    def get(self, campaign_id: str) -> CampaignDefinition | None:
        return self._campaigns.get(campaign_id)

    def to_dict(self) -> list[dict[str, Any]]:
        return [campaign.to_dict() for campaign in self.all()]


class CampaignRunner:
    """Executes a campaign through an orchestrator, preserving observations between stages."""

    def __init__(self, orchestrator: Any) -> None:
        self.orchestrator = orchestrator

    def run(self, campaign: CampaignDefinition, *, session_id: str = "") -> CampaignRun:
        run = CampaignRun(
            campaign_id=campaign.id,
            session_id=session_id or getattr(self.orchestrator, "session_id", "") or "",
            status="running",
            started_at=datetime.now(UTC).isoformat(),
        )
        conditions: set[str] = {"attacker_on_same_wifi"}
        for stage in campaign.stages:
            missing = [c for c in stage.requires if c not in conditions]
            if missing:
                run.stages.append(CampaignStageResult(
                    stage=stage,
                    conditions_before=sorted(conditions),
                    feasible=False,
                    note=f"skipped: unmet prerequisite conditions {missing}",
                ))
                logger.info("campaign stage skipped", extra={
                    "lab_campaign": campaign.id, "lab_stage": stage.name,
                    "lab_missing_conditions": missing,
                })
                continue
            result = self.orchestrator.run_test(
                stage.test_id, scenario_id=campaign.id, params=dict(stage.params),
            )
            after = set(conditions) | set(stage.provides)
            # A stage that produced no usable evidence does not establish its condition.
            if result.verdict in {Verdict.INCONCLUSIVE, Verdict.UNSUPPORTED}:
                after = set(conditions)
            run.stages.append(CampaignStageResult(
                stage=stage,
                conditions_before=sorted(conditions),
                feasible=True,
                result=result,
                conditions_after=sorted(after),
                note=_stage_note(stage, result),
            ))
            run.evidence_refs.extend(result.evidence_refs)
            conditions = after
            if stage.is_objective:
                run.objective_reached = result.verdict in {
                    Verdict.PASS, Verdict.DETECTED_AND_BLOCKED, Verdict.DETECTED,
                }
        run.finished_at = datetime.now(UTC).isoformat()
        run.status = "completed"
        run.explanation = _explain(campaign, run)
        logger.info("campaign completed", extra={
            "lab_campaign": campaign.id, "lab_objective_reached": run.objective_reached,
        })
        return run


class DynamicCampaignBuilder:
    """Assemble a campaign from conditions discovered during an assessment."""

    def __init__(self, registry: Any) -> None:
        self.registry = registry

    def build(self, *, discovered_domains: Iterable[str], lab_reachable: bool,
              plaintext_http_observed: bool, tls_observed: bool) -> CampaignDefinition:
        stages: list[CampaignStage] = []
        domains = sorted(discovered_domains)
        if not lab_reachable:
            return CampaignDefinition(
                id="dynamic-unreachable", name="Dynamic: lab unreachable",
                description="No reachable laboratory path was discovered; no campaign can proceed.",
                profile_id="observer", objective="establish a reachable laboratory path",
                stages=[],
            )
        stages.append(CampaignStage(
            name="Confirm laboratory reachability",
            description="Reuse the discovery observations to confirm the lab path.",
            test_id="LAB-BASELINE", provides=["lab_reachable"],
        ))
        if plaintext_http_observed:
            stages.append(CampaignStage(
                name="Expose a synthetic session cookie",
                description="Use a plaintext laboratory endpoint to test cookie exposure.",
                test_id="COOKIE-PLAINTEXT-EXPOSURE", requires=["lab_reachable"],
                params={"host": domains[0] if domains else "cookies.lab.test"},
                provides=["cleartext_cookie_path"],
            ))
            stages.append(CampaignStage(
                name="Attempt HTTPS downgrade",
                description="Try to keep the device on the plaintext path.",
                test_id="HTTP-DOWNGRADE", requires=["cleartext_cookie_path"],
                provides=["downgrade_resisted"],
            ))
            stages.append(CampaignStage(
                name="Objective: session cookie exposure",
                description="Determine whether a synthetic session cookie reached the network in cleartext.",
                test_id="COOKIE-PLAINTEXT-EXPOSURE", requires=["cleartext_cookie_path"],
                is_objective=True,
            ))
        elif tls_observed:
            stages.append(CampaignStage(
                name="Objective: encrypted-path non-exposure",
                description="Confirm that cookies on the TLS path were not attacker-observable.",
                test_id="COOKIE-HTTPS-ENCRYPTED", requires=["lab_reachable"], is_objective=True,
            ))
        else:
            stages.append(CampaignStage(
                name="Objective: establish attacker visibility",
                description="No traffic class was observed; the campaign cannot proceed.",
                test_id="DISC-DNS-PASSIVE", requires=["lab_reachable"], is_objective=True,
            ))
        return CampaignDefinition(
            id="dynamic-campaign",
            name="Dynamic campaign from discovered conditions",
            description=(
                "Assembled at runtime from the conditions observed during this assessment: "
                f"domains={domains}, plaintext_http={plaintext_http_observed}, tls={tls_observed}."
            ),
            profile_id="dynamic",
            objective=(
                "expose a synthetic session cookie" if plaintext_http_observed
                else "establish and characterise the attacker's network position"
            ),
            stages=stages,
        )


def _stage_note(stage: CampaignStage, result: TestResult) -> str:
    if result.verdict is Verdict.INCONCLUSIVE:
        return "stage produced no classifiable evidence; its conditions were not established"
    if result.verdict is Verdict.UNSUPPORTED:
        return "stage requires capabilities not present on this host"
    return f"stage executed: verdict={result.verdict.value} confidence={result.confidence.value}"


def _explain(campaign: CampaignDefinition, run: CampaignRun) -> str:
    if not run.stages:
        return "No stages could be assembled for the discovered conditions."
    skipped = [s for s in run.stages if not s.feasible]
    executed = [s for s in run.stages if s.feasible]
    parts = [
        f"Objective: {campaign.objective}.",
        f"{len(executed)} stage(s) executed, {len(skipped)} skipped for unmet prerequisites.",
    ]
    if run.objective_reached:
        parts.append(
            "The objective stage reported a usable outcome. This does not by itself prove "
            "a security failure: the attacker and defender views must be read separately."
        )
    else:
        parts.append(
            "The objective was not reached. The most common laboratory cause is the absence "
            "of device traffic, which is reported as missing telemetry rather than as a pass."
        )
    for stage in skipped:
        parts.append(f"Skipped {stage.stage.name}: {stage.note}")
    return " ".join(parts)


def _predefined() -> list[CampaignDefinition]:
    return [
        CampaignDefinition(
            id="cookie-exposure-plaintext",
            name="Plaintext cookie exposure chain",
            description=(
                "Establish the same-Wi-Fi position, confirm a plaintext laboratory path and "
                "determine whether a synthetic session cookie becomes attacker-observable."
            ),
            profile_id="http-tls-manipulator",
            objective="determine whether a synthetic session cookie is exposed in cleartext",
            stages=[
                CampaignStage(
                    name="Reconnaissance",
                    description="Passively discover the device's destinations.",
                    test_id="DISC-DNS-PASSIVE", provides=["attacker_on_same_wifi"],
                ),
                CampaignStage(
                    name="Plaintext laboratory site",
                    description="Serve a synthetic session cookie over HTTP.",
                    test_id="COOKIE-PLAINTEXT-EXPOSURE",
                    provides=["cleartext_cookie_path"],
                ),
                CampaignStage(
                    name="Insecure redirect",
                    description="Check whether the cookie leaks before an HTTP-to-HTTPS redirect.",
                    test_id="COOKIE-REDIRECT-EXPOSURE",
                    requires=["cleartext_cookie_path"], provides=["redirect_exposure_checked"],
                ),
                CampaignStage(
                    name="Objective: cookie exposure verdict",
                    description="Confirm whether the cookie value was genuinely observed.",
                    test_id="COOKIE-PLAINTEXT-EXPOSURE",
                    requires=["cleartext_cookie_path"], is_objective=True,
                ),
            ],
        ),
        CampaignDefinition(
            id="session-hijack-chain",
            name="Session hijack attempt chain",
            description=(
                "Attempt DNS manipulation and TLS downgrade, then evaluate whether any "
                "session material became observable."
            ),
            profile_id="dns-manipulator",
            objective="obtain observable session material from the device",
            stages=[
                CampaignStage(
                    name="DNS manipulation",
                    description="Spoof an A record to the laboratory sink.",
                    test_id="DNS-SPOOF-A", provides=["dns_manipulated"],
                ),
                CampaignStage(
                    name="TLS downgrade attempt",
                    description="Try to force a weaker TLS configuration.",
                    test_id="TLS-DOWNGRADE", requires=["dns_manipulated"],
                    provides=["downgrade_attempted"],
                ),
                CampaignStage(
                    name="Certificate validation probe",
                    description="Present a wrong-hostname certificate and observe validation.",
                    test_id="TLS-WRONG-HOSTNAME", requires=["downgrade_attempted"],
                    provides=["cert_validation_observed"],
                ),
                CampaignStage(
                    name="Objective: session material exposure",
                    description="Determine whether any session material was observable.",
                    test_id="COOKIE-HTTPS-ENCRYPTED", requires=["cert_validation_observed"],
                    is_objective=True,
                ),
            ],
        ),
        CampaignDefinition(
            id="network-position-escalation",
            name="Network position escalation chain",
            description=(
                "Escalate from passive observation to rogue infrastructure and gateway "
                "impersonation, evaluating feasibility at each step."
            ),
            profile_id="rogue-infrastructure",
            objective="establish a man-in-the-middle network position",
            stages=[
                CampaignStage(
                    name="Passive reconnaissance",
                    description="Observe the device's destinations.",
                    test_id="DISC-DNS-PASSIVE", provides=["attacker_on_same_wifi"],
                ),
                CampaignStage(
                    name="Rogue DHCP",
                    description="Advertise a rogue gateway and resolver.",
                    test_id="DHCP-ROGUE-GATEWAY", requires=["attacker_on_same_wifi"],
                    provides=["rogue_dhcp"],
                ),
                CampaignStage(
                    name="ARP impersonation",
                    description="Impersonate the gateway at L2.",
                    test_id="ARP-SPOOF-GATEWAY", requires=["rogue_dhcp"],
                    provides=["l2_position"],
                ),
                CampaignStage(
                    name="Gateway impersonation",
                    description="Complete the L3 impersonation.",
                    test_id="GW-IMPERSONATION", requires=["l2_position"],
                    provides=["mitm_position"],
                ),
                CampaignStage(
                    name="Objective: multi-stage AiTM",
                    description="Run the full chain and evaluate the outcome.",
                    test_id="MULTI-STAGE-AITM", requires=["mitm_position"], is_objective=True,
                ),
            ],
        ),
        CampaignDefinition(
            id="ipv6-bypass-chain",
            name="IPv6 bypass chain",
            description="Test whether IPv6 provides a path around IPv4-centred firewall policy.",
            profile_id="gateway-impersonator",
            objective="determine whether IPv6 bypasses the applied policy",
            stages=[
                CampaignStage(
                    name="IPv6 capability",
                    description="Observe IPv6 flows from the device.",
                    test_id="IPV6-BYPASS", provides=["ipv6_observed"],
                ),
                CampaignStage(
                    name="Router advertisement injection",
                    description="Inject an RA to advertise a laboratory IPv6 gateway.",
                    test_id="ND-RA-INJECTION", requires=["ipv6_observed"],
                    provides=["rogue_ipv6_gateway"],
                ),
                CampaignStage(
                    name="Objective: IPv6 policy bypass",
                    description="Evaluate whether the bypass changed the outcome.",
                    test_id="IPV6-BYPASS", requires=["rogue_ipv6_gateway"], is_objective=True,
                ),
            ],
        ),
        CampaignDefinition(
            id="downgrade-resistance-chain",
            name="Downgrade and trust chain",
            description=(
                "Move from plaintext exposure through TLS downgrade attempts to certificate "
                "validation, and record which protection stopped the chain."
            ),
            profile_id="http-tls-manipulator",
            objective="determine which layer prevents cleartext cookie exposure",
            stages=[
                CampaignStage(
                    name="Plaintext control",
                    description="Confirm the cleartext exposure path.",
                    test_id="HTTP-CLEARTEXT", provides=["cleartext_control"],
                ),
                CampaignStage(
                    name="HTTPS downgrade attempt",
                    description="Attempt to redirect HTTPS to the plaintext endpoint.",
                    test_id="HTTP-DOWNGRADE", requires=["cleartext_control"],
                    provides=["downgrade_attempted"],
                ),
                CampaignStage(
                    name="TLS downgrade attempt",
                    description="Attempt a weaker TLS negotiation.",
                    test_id="TLS-DOWNGRADE", requires=["downgrade_attempted"],
                    provides=["tls_downgrade_attempted"],
                ),
                CampaignStage(
                    name="Wrong certificate",
                    description="Present an untrusted laboratory certificate.",
                    test_id="TLS-WRONG-CERT", requires=["tls_downgrade_attempted"],
                    provides=["untrusted_cert_presented"],
                ),
                CampaignStage(
                    name="Pinning behaviour",
                    description="Observe pinning enforcement.",
                    test_id="TLS-PINNING", requires=["untrusted_cert_presented"],
                    provides=["pinning_observed"],
                ),
                CampaignStage(
                    name="Objective: cookie protection verdict",
                    description="Determine whether a cookie value was observable at any point.",
                    test_id="COOKIE-HTTPS-ENCRYPTED", requires=["cleartext_control"],
                    is_objective=True,
                ),
            ],
        ),
    ]
