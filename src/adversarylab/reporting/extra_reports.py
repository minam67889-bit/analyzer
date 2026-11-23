"""Mandatory additional reports for the wireless adversary-emulation assessment.

Nine reports are produced from one assessment:

1. Cookie Exposure Report              6. Multi-Stage Attack Chain Report
2. Session Security Assessment         7. Longitudinal Traffic Analysis Report
3. HTTP Downgrade Resistance Report    8. Attacker-Visible Data Inventory
4. TLS and Certificate Security Report 9. Defender Detection and Prevention Report
5. Network Attacker Capability Report

Every finding references the evidence that produced it. Reports never convert missing
telemetry into a positive claim.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ..analysis.views import attacker_view, attacker_visible_inventory, defender_view
from ..cookies.model import CookieClassification, CookieObservation, redact_value
from ..core.results import TestResult
from ..logging_config import get_logger

logger = get_logger(__name__)

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; }
h1, h2, h3 { font-weight: 600; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.86rem; }
th, td { border: 1px solid #d0d0d0; padding: 0.35rem 0.55rem; text-align: left; vertical-align: top; }
th { background: #f4f4f6; }
.exposed { background: #fdeeee; }
.ok { background: #eef7ee; }
.muted { color: #666; }
.limitation { background: #fff8e6; border-left: 4px solid #e0b000; padding: 0.6rem 0.9rem; }
code { background: #f4f4f6; padding: 0.1rem 0.3rem; }
"""


class ReportBundle:
    """Writes the full report set for an assessment."""

    def __init__(self, result: Any, *, reveal_cookie_values: bool = False) -> None:
        self.result = result
        self._cookie_observations = _cookie_observations(result)
        self.reveal_cookie_values = reveal_cookie_values

    # ------------------------------------------------------------------
    def write(self, directory: str | Path) -> dict[str, Path]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        paths: dict[str, Path] = {}
        writers = {
            "cookie_exposure": self._cookie_exposure,
            "session_security": self._session_security,
            "http_downgrade_resistance": self._downgrade_report,
            "tls_certificate_security": self._tls_report,
            "network_attacker_capability": self._attacker_capability,
            "multi_stage_attack_chain": self._campaign_report,
            "longitudinal_traffic_analysis": self._longitudinal_report,
            "attacker_visible_data_inventory": self._inventory_report,
            "defender_detection_prevention": self._defender_report,
        }
        for name, writer in writers.items():
            payload, page = writer()
            json_path = out / f"{name}.json"
            html_path = out / f"{name}.html"
            json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str),
                                 encoding="utf-8")
            document = page if page.lstrip().lower().startswith("<!doctype") else _page(
                title=_TITLES[name], body=page,
            )
            html_path.write_text(document, encoding="utf-8")
            paths[name] = html_path
            logger.info("report written", extra={"lab_report": name, "lab_path": str(html_path)})
        return paths

    # ------------------------------------------------------------------
    def _results(self) -> list[TestResult]:
        return list(getattr(self.result, "results", []) or [])

    def _by_prefix(self, *prefixes: str) -> list[TestResult]:
        return [r for r in self._results() if r.test_id.startswith(prefixes)]

    # 1 -----------------------------------------------------------------
    def _cookie_exposure(self) -> tuple[dict[str, Any], str]:
        from ..cookies.report import CookieExposureReport

        report = CookieExposureReport(
            self._cookie_observations, reveal_values=self.reveal_cookie_values
        )
        return report.to_dict(), report.to_html()

    # 2 -----------------------------------------------------------------
    def _session_security(self) -> tuple[dict[str, Any], str]:
        longitudinal = _longitudinal(self.result)
        sessions = longitudinal.get("site_sessions", [])
        rows = "".join(
            f"<tr><td>{_e(s['domain'])}</td><td>{s['observations']}</td>"
            f"<td>{_e(s['first_seen'] or '')}</td><td>{_e(s['last_seen'] or '')}</td>"
            f"<td>{'yes' if s['tls'] else 'no'}</td>"
            f"<td>{'yes' if s['cleartext_http'] else 'no'}</td></tr>"
            for s in sessions
        )
        cookie_rows = "".join(_cookie_row(o) for o in self._cookie_observations)
        findings = longitudinal.get("findings", [])
        finding_rows = "".join(
            f"<tr><td>{_e(f['kind'])}</td><td>{_e(f['summary'])}</td>"
            f"<td>{_e(f['confidence'])}</td><td>{_e(f.get('caveat', ''))}</td></tr>"
            for f in findings
        )
        payload = {
            "report": "Session Security Assessment",
            "site_sessions": sessions,
            "cookie_outcomes": [o.to_dict() for o in self._cookie_observations],
            "findings": findings,
            "limitations": [
                "Session continuity describes repeated destination behaviour, not an authenticated identity.",
                "No user or session is asserted unless a plaintext identifier supports it.",
                "Encrypted sessions contribute metadata only.",
            ],
        }
        page = (
            "<h2>Site sessions</h2>"
            "<table><thead><tr><th>Domain</th><th>Observations</th><th>First seen</th>"
            "<th>Last seen</th><th>TLS</th><th>Cleartext HTTP</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=6>no sessions observed</td></tr>'}</tbody></table>"
            "<h2>Cookie outcomes</h2>"
            "<table><thead><tr><th>Site</th><th>Domain</th><th>Cookie</th><th>Classification</th>"
            "<th>Value</th><th>Verified</th><th>Notes</th></tr></thead>"
            f"<tbody>{cookie_rows or '<tr><td colspan=7>no cookie outcomes</td></tr>'}</tbody></table>"
            "<h2>Correlated findings</h2>"
            "<table><thead><tr><th>Kind</th><th>Summary</th><th>Confidence</th><th>Caveat</th></tr></thead>"
            f"<tbody>{finding_rows or '<tr><td colspan=4>no findings</td></tr>'}</tbody></table>"
            "<div class='limitation'><strong>Mandatory limitation:</strong> "
            "individually low-information observations are combined only to describe patterns. "
            "This report never identifies a specific authenticated user or session.</div>"
        )
        return payload, page

    # 3 -----------------------------------------------------------------
    def _downgrade_report(self) -> tuple[dict[str, Any], str]:
        relevant = self._by_prefix("HTTP-DOWNGRADE", "HTTP-CLEARTEXT", "HSTS", "TLS-DOWNGRADE")
        longitudinal = _longitudinal(self.result)
        chains = longitudinal.get("redirect_chains", [])
        rows = "".join(_result_row(r) for r in relevant)
        chain_rows = "".join(
            f"<tr class='{'exposed' if c['downgrade_risk'] else 'ok'}'>"
            f"<td>{_e(c['from'])}</td><td>{_e(c['to'])}</td><td>{c['status']}</td>"
            f"<td>{'downgrade risk' if c['downgrade_risk'] else 'https target'}</td>"
            f"<td>{_e(c['event_id'])}</td></tr>"
            for c in chains
        )
        payload = {
            "report": "HTTP Downgrade Resistance Report",
            "results": [r.to_dict() for r in relevant],
            "redirect_chains": chains,
            "limitations": [
                "A refused downgrade is one control; it does not by itself prove cookie safety.",
                "Redirect chains come from observed cleartext responses only.",
            ],
        }
        page = (
            "<h2>Downgrade-related test results</h2>"
            "<table><thead><tr><th>Test</th><th>Verdict</th><th>Confidence</th>"
            "<th>Block cause</th><th>Rationale</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=5>no downgrade tests executed</td></tr>'}</tbody></table>"
            "<h2>Observed redirect chains</h2>"
            "<table><thead><tr><th>From</th><th>To</th><th>Status</th><th>Assessment</th>"
            "<th>Evidence</th></tr></thead>"
            f"<tbody>{chain_rows or '<tr><td colspan=5>no redirects observed</td></tr>'}</tbody></table>"
            "<div class='limitation'>An HTTPS-to-HTTP redirect is reported as a downgrade risk. "
            "No claim is made about cookie exposure unless a cleartext cookie header was captured.</div>"
        )
        return payload, page

    # 4 -----------------------------------------------------------------
    def _tls_report(self) -> tuple[dict[str, Any], str]:
        relevant = self._by_prefix("TLS-", "COOKIE-HTTPS", "CERT-TRUST")
        rows = "".join(_result_row(r) for r in relevant)
        longitudinal = _longitudinal(self.result)
        tls_metadata = [
            {"sni": t.get("sni"), "version": t.get("version"), "cipher": t.get("cipher")}
            for t in _tls_flows(longitudinal)
        ]
        metadata_rows = "".join(
            f"<tr><td>{_e(t['sni'])}</td><td>{_e(t['version'])}</td><td>{_e(t['cipher'])}</td></tr>"
            for t in tls_metadata
        )
        payload = {
            "report": "TLS and Certificate Security Report",
            "results": [r.to_dict() for r in relevant],
            "observed_tls_metadata": tls_metadata,
            "certificate_install_opt_in": bool(
                (getattr(self.result, "environment", {}) or {}).get(
                    "certificate_install_opt_in", False
                )
            ),
            "limitations": [
                "A displayed certificate prompt is not evidence of interception.",
                "A TLS handshake proves encryption, not that the peer validated the certificate.",
                "No CA is installed unless the operator enabled the explicit opt-in experiment.",
            ],
        }
        page = (
            "<h2>TLS and certificate test results</h2>"
            "<table><thead><tr><th>Test</th><th>Verdict</th><th>Confidence</th>"
            "<th>Block cause</th><th>Rationale</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=5>no TLS tests executed</td></tr>'}</tbody></table>"
            "<h2>Observed TLS metadata</h2>"
            "<table><thead><tr><th>SNI</th><th>Version</th><th>Cipher</th></tr></thead>"
            f"<tbody>{metadata_rows or '<tr><td colspan=3>no TLS handshakes observed</td></tr>'}</tbody></table>"
            "<div class='limitation'>Metadata only. TLS content is not decrypted and no cookie "
            "value inside a TLS session is reported as attacker-observed.</div>"
        )
        return payload, page

    # 5 -----------------------------------------------------------------
    def _attacker_capability(self) -> tuple[dict[str, Any], str]:
        inventory = attacker_visible_inventory(self._results())
        rows = "".join(_result_row(r) for r in self._results())
        domain_rows = "".join(f"<li>{_e(d)}</li>" for d in inventory["domains_observed"])
        ip_rows = "".join(f"<li>{_e(i)}</li>" for i in inventory["destinations_observed"])
        payload = {
            "report": "Network Attacker Capability Report",
            "position": "same Wi-Fi segment; no device access, no CA, no custom application",
            "inventory": inventory,
            "results": [r.to_dict() for r in self._results()],
            "techniques_considered": [
                "passive reconnaissance and traffic observation",
                "DNS manipulation and resolution attacks",
                "gateway and routing manipulation",
                "DHCP and network configuration attacks",
                "ARP and local-network impersonation",
                "HTTP exposure and insecure redirects",
                "HTTPS downgrade resistance",
                "TLS interception feasibility",
                "certificate validation and trust manipulation",
                "captive portal and certificate-installation social engineering",
                "connection disruption and recovery",
                "IPv4/IPv6 differences and bypass possibilities",
                "browser and session information exposure",
            ],
            "limitations": [
                "Capabilities are host- and adapter-dependent; unsupported techniques are reported UNSUPPORTED.",
                "A technique being listed here does not mean it succeeded.",
            ],
        }
        page = (
            "<h2>What the attacker could observe</h2>"
            f"<p>Domains: <ul>{domain_rows or '<li>none</li>'}</ul></p>"
            f"<p>Destinations: <ul>{ip_rows or '<li>none</li>'}</ul></p>"
            "<h2>Techniques considered</h2><ul>"
            + "".join(f"<li>{_e(t)}</li>" for t in payload["techniques_considered"])
            + "</ul>"
            "<h2>Results by technique</h2>"
            "<table><thead><tr><th>Test</th><th>Verdict</th><th>Confidence</th>"
            "<th>Execution mode</th><th>Rationale</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=5>no tests executed</td></tr>'}</tbody></table>"
            "<div class='limitation'>Listing a technique is not a success claim. Every verdict "
            "above carries its execution mode and confidence.</div>"
        )
        return payload, page

    # 6 -----------------------------------------------------------------
    def _campaign_report(self) -> tuple[dict[str, Any], str]:
        campaigns = list(getattr(self.result, "campaigns", []) or [])
        blocks = []
        payload_runs = []
        for run in campaigns:
            stages = run.get("stages", [])
            rows = "".join(
                f"<tr><td>{_e(s['stage']['name'])}</td>"
                f"<td>{_e(', '.join(s['conditions_before']) or '-')}</td>"
                f"<td>{'yes' if s['feasible'] else 'no'}</td>"
                f"<td>{_e((s.get('result') or {}).get('verdict', ''))}</td>"
                f"<td>{_e(s.get('note', ''))}</td></tr>"
                for s in stages
            )
            blocks.append(
                f"<h3>{_e(run.get('campaign_id'))}: {_e(run.get('status'))}</h3>"
                f"<p>{_e(run.get('explanation', ''))}</p>"
                "<p>Objective reached: "
                f"<strong>{'yes' if run.get('objective_reached') else 'no'}</strong></p>"
                "<table><thead><tr><th>Stage</th><th>Conditions before</th><th>Feasible</th>"
                "<th>Verdict</th><th>Note</th></tr></thead>"
                f"<tbody>{rows or '<tr><td colspan=5>no stages</td></tr>'}</tbody></table>"
            )
            payload_runs.append(run)
        payload = {
            "report": "Multi-Stage Attack Chain Report",
            "campaigns": payload_runs,
            "limitations": [
                "A chain stage that produces no classifiable evidence does not establish its condition.",
                "A successful objective stage is not proof of a security failure; read the attacker and defender views separately.",
            ],
        }
        page = "".join(blocks) or "<p>No campaigns were assembled for this assessment.</p>"
        page += ("<div class='limitation'>Chains preserve observations between stages. "
                 "Where a chain stopped, the explanation names the unmet prerequisite or the "
                 "missing telemetry.</div>")
        return payload, page

    # 7 -----------------------------------------------------------------
    def _longitudinal_report(self) -> tuple[dict[str, Any], str]:
        longitudinal = _longitudinal(self.result)
        timeline = longitudinal.get("timeline", [])
        rows = "".join(
            f"<tr><td>{_e(e['timestamp'])}</td><td>{_e(e['category'])}</td>"
            f"<td>{_e(e['source'])}</td><td>{_e(e['severity'])}</td>"
            f"<td>{_e(e['test_id'] or '')}</td><td>{_e(e['summary'])}</td>"
            f"<td>{_e(e['dst_addr'] or '')}:{_e(e['dst_port'] or '')}</td>"
            f"<td>{_e(e['evidence_ref'] or '')}</td></tr>"
            for e in timeline[:500]
        )
        findings = longitudinal.get("findings", [])
        finding_rows = "".join(
            f"<tr><td>{_e(f['kind'])}</td><td>{_e(f['summary'])}</td>"
            f"<td>{_e(f['confidence'])}</td><td>{_e(f.get('caveat', ''))}</td>"
            f"<td>{_e(', '.join(f.get('evidence_refs', [])))}</td></tr>"
            for f in findings
        )
        graph = longitudinal.get("relationship_graph", {})
        payload = {"report": "Longitudinal Traffic Analysis Report", **longitudinal}
        page = (
            f"<p>{_e(longitudinal.get('summary', {}))}</p>"
            "<h2>Findings</h2>"
            "<table><thead><tr><th>Kind</th><th>Summary</th><th>Confidence</th>"
            "<th>Caveat</th><th>Evidence</th></tr></thead>"
            f"<tbody>{finding_rows or '<tr><td colspan=5>no findings</td></tr>'}</tbody></table>"
            "<h2>Relationship graph</h2>"
            f"<p>{len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges. "
            "JSON sidecar contains the machine-readable graph.</p>"
            "<h2>Unified timeline</h2>"
            "<table><thead><tr><th>Timestamp</th><th>Category</th><th>Source</th>"
            "<th>Severity</th><th>Test</th><th>Summary</th><th>Destination</th>"
            "<th>Evidence</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=8>no events</td></tr>'}</tbody></table>"
            "<div class='limitation'>Correlation describes patterns and sequencing. It never "
            "asserts an authenticated identity without a supporting plaintext identifier.</div>"
        )
        return payload, page

    # 8 -----------------------------------------------------------------
    def _inventory_report(self) -> tuple[dict[str, Any], str]:
        inventory = attacker_visible_inventory(self._results())
        cookie_rows = "".join(_cookie_row(o) for o in self._cookie_observations)
        per_test = "".join(
            f"<tr><td>{_e(r.test_id)}</td>"
            f"<td>{_e(', '.join(attacker_view(r)['observable_domains']) or '-')}</td>"
            f"<td>{_e(', '.join(attacker_view(r)['plaintext_cookie_names']) or '-')}</td>"
            f"<td>{_e(', '.join(attacker_view(r)['tls_domains_metadata_only']) or '-')}</td>"
            f"<td>{_e(r.verdict.value)}</td></tr>"
            for r in self._results()
        )
        payload = {
            "report": "Attacker-Visible Data Inventory",
            "inventory": inventory,
            "per_test": [
                {
                    "test_id": r.test_id,
                    "attacker_view": attacker_view(r),
                    "verdict": r.verdict.value,
                }
                for r in self._results()
            ],
            "limitations": [
                "Inventory lists visibility, not impact.",
                "Server-known values are listed separately and are never labelled as stolen.",
            ],
        }
        page = (
            "<h2>Aggregated visible data</h2>"
            f"<p>Domains: {_e(', '.join(inventory['domains_observed']) or 'none')}</p>"
            f"<p>Destinations: {_e(', '.join(inventory['destinations_observed']) or 'none')}</p>"
            f"<p>Plaintext cookie names: {_e(', '.join(inventory['plaintext_cookie_names']) or 'none')}</p>"
            f"<p>TLS domains (metadata only): {_e(', '.join(inventory['tls_domains_metadata_only']) or 'none')}</p>"
            "<h2>Cookie outcomes</h2>"
            "<table><thead><tr><th>Site</th><th>Domain</th><th>Cookie</th><th>Classification</th>"
            "<th>Value</th><th>Verified</th><th>Notes</th></tr></thead>"
            f"<tbody>{cookie_rows or '<tr><td colspan=7>none</td></tr>'}</tbody></table>"
            "<h2>Per test</h2>"
            "<table><thead><tr><th>Test</th><th>Domains</th><th>Plaintext cookie names</th>"
            "<th>TLS metadata</th><th>Verdict</th></tr></thead>"
            f"<tbody>{per_test or '<tr><td colspan=5>no tests</td></tr>'}</tbody></table>"
            "<div class='limitation'>Encrypted values are absent by design. Their absence is a "
            "property of the protection, not a gap in the report.</div>"
        )
        return payload, page

    # 9 -----------------------------------------------------------------
    def _defender_report(self) -> tuple[dict[str, Any], str]:
        views = [defender_view(r) for r in self._results()]
        rows = "".join(
            f"<tr><td>{_e(r.test_id)}</td>"
            f"<td>{view['detected_count']}</td><td>{view['blocked_count']}</td>"
            f"<td>{view['allowed_count']}</td>"
            f"<td>{'yes' if view['corroborated_by_independent_capture'] else 'no'}</td>"
            f"<td>{_e(r.block_cause.value)}</td>"
            f"<td>{_e(r.verdict.value)}</td></tr>"
            for r, view in zip(self._results(), views, strict=False)
        )
        missing = sorted({m for view in views for m in view["missing_telemetry"]})
        payload = {
            "report": "Defender Detection and Prevention Report",
            "views": [{"test_id": r.test_id, **defender_view(r)} for r in self._results()],
            "missing_telemetry": missing,
            "limitations": [
                "A firewall report is a claim by the firewall under test, not independent proof.",
                "A block claim is confirmed only when independent capture evidence agrees.",
                "Traffic disruption is not evidence of interception.",
                "Missing firewall telemetry is reported as missing and is not treated as a pass.",
            ],
        }
        page = (
            "<table><thead><tr><th>Test</th><th>Detected</th><th>Blocked</th><th>Allowed</th>"
            "<th>Corroborated by capture</th><th>Block cause</th><th>Verdict</th></tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=7>no tests</td></tr>'}</tbody></table>"
            "<h2>Missing defender telemetry</h2>"
            f"<ul>{''.join(f'<li>{_e(m)}</li>' for m in missing) or '<li>none reported</li>'}</ul>"
            "<div class='limitation'>The defender view never borrows conclusions from the "
            "attacker view. A block that the firewall reports but the capture does not "
            "corroborate remains an unconfirmed claim.</div>"
        )
        return payload, page


_TITLES = {
    "cookie_exposure": "Cookie Exposure Report",
    "session_security": "Session Security Assessment",
    "http_downgrade_resistance": "HTTP Downgrade Resistance Report",
    "tls_certificate_security": "TLS and Certificate Security Report",
    "network_attacker_capability": "Network Attacker Capability Report",
    "multi_stage_attack_chain": "Multi-Stage Attack Chain Report",
    "longitudinal_traffic_analysis": "Longitudinal Traffic Analysis Report",
    "attacker_visible_data_inventory": "Attacker-Visible Data Inventory",
    "defender_detection_prevention": "Defender Detection and Prevention Report",
}


def _page(*, title: str, body: str) -> str:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head><body>"
        f"<h1>{_e(title)}</h1>{body}</body></html>"
    )


def _cookie_observations(result: Any) -> list[CookieObservation]:
    payload = getattr(result, "cookie_exposure", {}) or {}
    observations: list[CookieObservation] = []
    for raw in payload.get("observations", []) or []:
        try:
            observations.append(CookieObservation(
                site_id=raw.get("site_id", ""),
                domain=raw.get("domain", ""),
                name=raw.get("name", ""),
                classification=CookieClassification(raw.get("classification", "server_only")),
                observed_value=raw.get("observed_value"),
                value_available=bool(raw.get("value_available")),
                observed_via=raw.get("observed_via", ""),
                connection=dict(raw.get("connection") or {}),
                evidence_ref=raw.get("evidence_ref"),
                attributes_known=dict(raw.get("attributes") or {}),
                verified_against_ground_truth=bool(raw.get("verified_against_ground_truth")),
                ground_truth_value_known=bool(raw.get("ground_truth_value_known")),
                notes=raw.get("notes", ""),
            ))
        except ValueError:
            continue
    return observations


def _longitudinal(result: Any) -> dict[str, Any]:
    return dict(getattr(result, "longitudinal", {}) or {})


def _tls_flows(longitudinal: dict[str, Any]) -> list[dict[str, Any]]:
    flows = []
    for edge in longitudinal.get("relationship_graph", {}).get("edges", []):
        if edge.get("kind") == "tls_sni":
            flows.append({"sni": edge.get("to", "").removeprefix("domain:"), "version": "", "cipher": ""})
    return flows


def _cookie_row(observation: CookieObservation) -> str:
    css = "exposed" if observation.value_available else ""
    # This table renders in the attacker-visible inventory: never print a raw value.
    value = redact_value(observation.observed_value) or ""
    return (
        f"<tr class='{css}'>"
        f"<td>{_e(observation.site_id)}</td><td>{_e(observation.domain)}</td>"
        f"<td>{_e(observation.name)}</td><td>{_e(observation.classification.value)}</td>"
        f"<td>{_e(value)}</td><td>{observation.verified_against_ground_truth}</td>"
        f"<td>{_e(observation.notes)}</td></tr>"
    )


def _result_row(result: TestResult) -> str:
    return (
        f"<tr><td>{_e(result.test_id)}</td><td>{_e(result.verdict.value)}</td>"
        f"<td>{_e(result.confidence.value)}</td><td>{_e(result.block_cause.value)}</td>"
        f"<td>{_e(result.rationale)}</td></tr>"
    )


def _e(value: Any) -> str:
    return html.escape(str(value))
