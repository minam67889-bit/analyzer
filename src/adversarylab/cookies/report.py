"""Cookie Exposure Report.

Self-contained HTML plus JSON/CSV forms. Values are redacted unless the caller explicitly
opts in, and the four outcome classes are always visually separated.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..logging_config import get_logger
from .model import CookieClassification, CookieObservation

logger = get_logger(__name__)

_CLASSIFICATION_LABELS = {
    CookieClassification.ATTACKER_OBSERVED_PLAINTEXT: "Attacker-observed (plaintext)",
    CookieClassification.ATTACKER_OBSERVED_INTERCEPTION: "Attacker-observed (lab interception, opt-in)",
    CookieClassification.SERVER_ONLY: "Server-known only",
    CookieClassification.ENCRYPTED_NOT_OBSERVABLE: "Not observable (encrypted)",
    CookieClassification.BROWSER_METADATA_ONLY: "Browser metadata only (no value)",
}


class CookieExposureReport:
    def __init__(self, observations: Iterable[CookieObservation], *, reveal_values: bool = False) -> None:
        self.observations = list(observations)
        self.reveal_values = reveal_values

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "reveal_values": self.reveal_values,
            "summary": self.summary(),
            "observations": [o.redacted_dict(reveal_values=self.reveal_values) for o in self.observations],
            "limitations": [
                "A packet capture showing an encrypted TLS connection is not evidence that "
                "its cookies were extracted.",
                "Cookie values are reported as attacker-observed only when the value was "
                "present in plaintext traffic visible to the laboratory attacker.",
                "Server-known ground-truth values are never labelled as attacker-stolen.",
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)

    def to_csv_rows(self) -> list[dict[str, Any]]:
        rows = []
        for observation in self.observations:
            payload = observation.redacted_dict(reveal_values=self.reveal_values)
            rows.append({
                "site_id": payload["site_id"],
                "domain": payload["domain"],
                "cookie_name": payload["name"],
                "classification": payload["classification"],
                "observed_value": payload["observed_value"] or "",
                "value_available": payload["value_available"],
                "verified_against_ground_truth": payload["verified_against_ground_truth"],
                "observed_via": payload["observed_via"],
                "timestamp": payload["timestamp"] or "",
                "evidence_ref": payload["evidence_ref"] or "",
                "secure": payload["attributes"].get("secure", ""),
                "httponly": payload["attributes"].get("httponly", ""),
                "samesite": payload["attributes"].get("samesite", ""),
                "notes": payload["notes"],
            })
        return rows

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for observation in self.observations:
            key = observation.classification.value
            counts[key] = counts.get(key, 0) + 1
        return {
            "outcomes": len(self.observations),
            "attacker_observed_values": sum(1 for o in self.observations if o.value_available),
            "verified_against_ground_truth": sum(
                1 for o in self.observations if o.verified_against_ground_truth
            ),
            "classifications": counts,
            "labels": {k.value: v for k, v in _CLASSIFICATION_LABELS.items()},
        }

    # ------------------------------------------------------------------
    def to_html(self) -> str:
        summary = self.summary()
        rows = "\n".join(self._row_html(o) for o in self.observations)
        counts = "".join(
            f"<tr><td>{_CLASSIFICATION_LABELS[classification]}</td><td>{count}</td></tr>"
            for classification, count in sorted(summary["classifications"].items())
        )
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Cookie Exposure Report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; }}
h1, h2 {{ font-weight: 600; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.88rem; }}
th, td {{ border: 1px solid #d0d0d0; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f6; }}
 tr.exposed {{ background: #fdeeee; }}
tr.encrypted {{ background: #eef2fb; }}
tr.server-only {{ background: #f6f6f4; }}
.limitation {{ background: #fff8e6; border-left: 4px solid #e0b000; padding: 0.6rem 0.9rem; }}
</style></head><body>
<h1>Cookie Exposure Report</h1>
<p>Attacker position: same Wi-Fi as an ordinary Android device with no device access,
no installed CA and no custom application. Values are redacted unless the report was
explicitly generated with value revelation enabled: <strong>{str(self.reveal_values).lower()}</strong>.</p>
<h2>Summary</h2>
<table class="summary"><thead><tr><th>Outcome class</th><th>Count</th></tr></thead>
<tbody>{counts}</tbody></table>
<p>Attacker-observed values: {summary['attacker_observed_values']} of {summary['outcomes']} outcomes.
Verified against laboratory ground truth: {summary['verified_against_ground_truth']}.</p>
<h2>Outcomes</h2>
<table class="cookies"><thead><tr>
<th>Site</th><th>Domain</th><th>Cookie</th><th>Classification</th><th>Value</th>
<th>Verified</th><th>Observed via</th><th>Evidence</th><th>Notes</th>
</tr></thead><tbody>
{rows}
</tbody></table>
<h2>Mandatory limitations</h2>
<div class="limitation"><ul>
<li>A packet capture showing an encrypted TLS connection is not evidence that its cookies were extracted.</li>
<li>Values are reported as attacker-observed only when present in plaintext traffic visible to the attacker.</li>
<li>Server-known ground-truth values are never labelled as attacker-stolen.</li>
</ul></div>
</body></html>"""

    def _row_html(self, observation: CookieObservation) -> str:
        payload = observation.redacted_dict(reveal_values=self.reveal_values)
        css = {
            CookieClassification.ATTACKER_OBSERVED_PLAINTEXT: "exposed",
            CookieClassification.ATTACKER_OBSERVED_INTERCEPTION: "exposed",
            CookieClassification.ENCRYPTED_NOT_OBSERVABLE: "encrypted",
            CookieClassification.SERVER_ONLY: "server-only",
            CookieClassification.BROWSER_METADATA_ONLY: "encrypted",
        }[observation.classification]
        value = payload["observed_value"] or ""
        return (
            f"<tr class='{css}'>"
            f"<td>{_escape(payload['site_id'])}</td>"
            f"<td>{_escape(payload['domain'])}</td>"
            f"<td>{_escape(payload['name'])}</td>"
            f"<td>{_escape(_CLASSIFICATION_LABELS[observation.classification])}</td>"
            f"<td>{_escape(value)}</td>"
            f"<td>{payload['verified_against_ground_truth']}</td>"
            f"<td>{_escape(payload['observed_via'])}</td>"
            f"<td>{_escape(payload['evidence_ref'] or '')}</td>"
            f"<td>{_escape(payload['notes'])}</td>"
            f"</tr>"
        )

    # ------------------------------------------------------------------
    def write(self, directory: str | Path) -> dict[str, Path]:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        paths = {
            "json": out / "cookie_exposure.json",
            "csv": out / "cookie_exposure.csv",
            "html": out / "cookie_exposure.html",
        }
        paths["json"].write_text(self.to_json(), encoding="utf-8")
        with paths["csv"].open("w", newline="", encoding="utf-8") as handle:
            rows = self.to_csv_rows()
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [])
            if rows:
                writer.writeheader()
                writer.writerows(rows)
        paths["html"].write_text(self.to_html(), encoding="utf-8")
        logger.info("cookie exposure report written", extra={"lab_report": str(out)})
        return paths


def _escape(value: Any) -> str:
    import html

    return html.escape(str(value))
