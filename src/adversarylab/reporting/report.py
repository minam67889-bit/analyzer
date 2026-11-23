"""Assessment report generation (HTML/JSON/CSV).

Reports are evidence-linked: every result references evidence ids and every evidence file
is hash-addressed. The HTML report is self-contained (no external assets) so it can be
archived with the session directory.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from ..adversary.orchestrator import AssessmentResult
from ..core.results import TestResult
from ..tests.registry import CoverageRow


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def render_coverage_table(rows: Iterable[CoverageRow]) -> str:
    out = [
        "<table class='coverage'><thead><tr>"
        "<th>Test</th><th>Category</th><th>Status</th><th>Verdict</th><th>Confidence</th><th>Reason</th>"
        "</tr></thead><tbody>"
    ]
    for row in rows:
        out.append(
            f"<tr class='status-{_escape(row.status.lower())}'>"
            f"<td>{_escape(row.test_id)}</td><td>{_escape(row.category)}</td>"
            f"<td>{_escape(row.status)}</td><td>{_escape(row.verdict)}</td>"
            f"<td>{_escape(row.confidence)}</td><td>{_escape(row.reason)}</td></tr>"
        )
    out.append("</tbody></table>")
    return "".join(out)


def render_results_table(results: Iterable[TestResult]) -> str:
    out = [
        "<table class='results'><thead><tr>"
        "<th>Test</th><th>Scenario</th><th>Verdict</th><th>Confidence</th><th>Block cause</th>"
        "<th>Execution mode</th><th>Rationale</th>"
        "</tr></thead><tbody>"
    ]
    for result in results:
        out.append(
            f"<tr class='verdict-{_escape(result.verdict.value.lower())}'>"
            f"<td>{_escape(result.test_id)}</td><td>{_escape(result.scenario_id or '')}</td>"
            f"<td>{_escape(result.verdict.value)}</td>"
            f"<td>{_escape(result.confidence.value)}</td>"
            f"<td>{_escape(result.block_cause.value)}</td>"
            f"<td>{_escape(result.execution_mode.value)}</td>"
            f"<td>{_escape(result.rationale)}</td></tr>"
        )
    out.append("</tbody></table>")
    return "".join(out)


def _iso(value: Any) -> str | None:
    """Accept a datetime or an already-serialized ISO string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class ReportGenerator:
    def __init__(self, result: AssessmentResult) -> None:
        self.result = result

    def summary(self) -> dict[str, Any]:
        verdicts: dict[str, int] = {}
        for result in self.result.results:
            verdicts[result.verdict.value] = verdicts.get(result.verdict.value, 0) + 1
        statuses: dict[str, int] = {}
        for row in self.result.coverage:
            statuses[row.status] = statuses.get(row.status, 0) + 1
        return {
            "session_id": self.result.session_id,
            "status": self.result.status,
            "started_at": _iso(self.result.started_at),
            "finished_at": _iso(self.result.finished_at),
            "tests_executed": len(self.result.results),
            "verdict_counts": verdicts,
            "coverage_status_counts": statuses,
        }

    def to_json(self) -> str:
        return json.dumps(self.result.to_dict(), indent=2, sort_keys=True, default=str)

    def to_csv_rows(self) -> list[dict[str, Any]]:
        rows = []
        for result in self.result.results:
            rows.append({
                "test_id": result.test_id,
                "scenario_id": result.scenario_id or "",
                "verdict": result.verdict.value,
                "confidence": result.confidence.value,
                "block_cause": result.block_cause.value,
                "execution_mode": result.execution_mode.value,
                "rationale": result.rationale,
            })
        return rows

    def to_html(self, *, evidence_records: Iterable[dict] | None = None) -> str:
        summary = self.summary()
        evidence = list(evidence_records or [])
        evidence_rows = "".join(
            f"<tr><td>{_escape(e.get('kind'))}</td><td>{_escape(e.get('path'))}</td>"
            f"<td>{_escape(e.get('sha256'))}</td><td>{_escape(e.get('bytes'))}</td></tr>"
            for e in evidence
        )
        limitations: list[str] = []
        for result in self.result.results:
            limitations.extend(result.limitations)
        limitations_html = "".join(f"<li>{_escape(item)}</li>" for item in sorted(set(limitations)))
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Adversary Lab Report — {_escape(summary['session_id'])}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; }}
h1, h2 {{ font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }}
th, td {{ border: 1px solid #d0d0d0; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f6; }}
.status-selected {{ background: #eef7ee; }}
.status-unsupported {{ background: #f7f0ee; }}
.status-skipped {{ background: #f5f5f5; }}
.verdict-pass, .verdict-blocked, .verdict-detected_and_blocked {{ background: #eef7ee; }}
.verdict-fail, .verdict-not_blocked, .verdict-not_detected {{ background: #fdeeee; }}
.verdict-inconclusive, .verdict-partially_verified {{ background: #fff7e6; }}
.banner {{ padding: 0.75rem 1rem; background: #1f2937; color: #fff; border-radius: 6px; }}
.small {{ color: #666; font-size: 0.85rem; }}
</style></head><body>
<div class="banner"><h1>Adversary Lab — Security Assessment Report</h1>
<div>Session {_escape(summary['session_id'])} · status {_escape(summary['status'])}</div></div>
<p class="small">Started {_escape(summary['started_at'])} · Finished {_escape(summary['finished_at'])}</p>
<h2>Summary</h2>
<pre>{_escape(json.dumps(summary, indent=2, sort_keys=True))}</pre>
<h2>Verdicts</h2>
{render_results_table(self.result.results)}
<h2>Coverage matrix</h2>
{render_coverage_table(self.result.coverage)}
<h2>Evidence manifest</h2>
<table><thead><tr><th>Kind</th><th>Path</th><th>SHA-256</th><th>Bytes</th></tr></thead>
<tbody>{evidence_rows or "<tr><td colspan='4'>No evidence records.</td></tr>"}</tbody></table>
<h2>Limitations</h2>
<ul>{limitations_html or "<li>None recorded.</li>"}</ul>
<h2>Environment</h2>
<pre>{_escape(json.dumps(self.result.environment, indent=2, sort_keys=True, default=str))}</pre>
<p class="small">Generated by Adversary Lab. Verdicts are evidence-linked; INCONCLUSIVE is an
explicit outcome and is never converted to PASS by omission of evidence.</p>
</body></html>"""

    def write(self, directory: str | Path, *, evidence_records: Iterable[dict] | None = None) -> dict[str, Path]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        paths = {
            "json": out / "report.json",
            "csv": out / "results.csv",
            "html": out / "report.html",
        }
        paths["json"].write_text(self.to_json(), encoding="utf-8")
        paths["html"].write_text(self.to_html(evidence_records=evidence_records), encoding="utf-8")
        from ..evidence.exporters import export_csv

        export_csv(self.to_csv_rows(), paths["csv"])
        return paths
