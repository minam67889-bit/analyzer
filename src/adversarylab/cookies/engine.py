"""Cookie exposure assessment engine.

The engine answers exactly one question per synthetic cookie: *did an attacker on this
Wi-Fi actually see the value?* It is deliberately conservative:

* Only plaintext HTTP ``Cookie``/``Set-Cookie`` headers count as attacker observation.
* A TLS session produces metadata (SNI, certificate, destination) and is reported as
  ``ENCRYPTED_NOT_OBSERVABLE`` — never as an extracted cookie.
* Ground-truth values are matched by exact comparison; a value that cannot be matched is
  reported as an unregistered observation rather than silently dropped.
* No value is ever reconstructed, guessed or copied from the server database into the
  attacker-observed column.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from ..core.events import EventCategory, NetworkEvent
from ..logging_config import get_logger
from ..protocols import http
from .ground_truth import CookieGroundTruth
from .model import (
    CookieClassification,
    CookieObservation,
)

logger = get_logger(__name__)


class CookieExposureEngine:
    def __init__(
        self,
        ground_truth: CookieGroundTruth,
        *,
        interception_enabled: bool = False,
        clock: Any | None = None,
    ) -> None:
        self.ground_truth = ground_truth
        # Interception is an explicit, separately documented opt-in. When it is off, an
        # HTTPS cookie is reported as not observable even if the lab holds a CA.
        self.interception_enabled = interception_enabled
        self.clock = clock
        self.observations: list[CookieObservation] = []
        self._observed: dict[str, list[CookieObservation]] = defaultdict(list)
        # domain -> set of cookie names seen in plaintext (registered or not)
        self._plaintext_names: dict[str, set[str]] = defaultdict(set)
        # domain -> metadata-only sightings (TLS, connections)
        self._metadata_domains: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._unknown_values: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def ingest_events(self, events: Iterable[NetworkEvent]) -> list[CookieObservation]:
        for event in events:
            self.ingest_event(event)
        return self.observations

    def ingest_event(self, event: NetworkEvent) -> CookieObservation | None:
        if event.category is EventCategory.HTTP:
            return self._ingest_http(event)
        if event.category is EventCategory.TLS:
            self._ingest_tls(event)
            return None
        if event.category is EventCategory.CONNECTION:
            self._ingest_connection(event)
            return None
        return None

    def _ingest_http(self, event: NetworkEvent) -> CookieObservation | None:
        details = dict(event.details or {})
        direction = details.get("direction")
        headers = {str(k).lower(): v for k, v in (details.get("headers") or {}).items()}
        host = (details.get("host") or headers.get("host") or "").split(":")[0].lower()
        if not direction:
            # Laboratory server events describe one side of an exchange without an
            # explicit direction: a request carries a Cookie header, a response carries
            # Set-Cookie values.
            direction = "request" if headers.get("cookie") else "response"
        if not host and direction == "request":
            # A request without a Host header cannot be attributed to a site.
            return None
        connection = _connection_from_event(event)
        if direction == "request":
            raw = headers.get("cookie")
            if not raw:
                return None
            produced = None
            for name, value in http.parse_cookie_header(raw):
                self._plaintext_names[host].add(name)
                produced = self._record_observation(
                    host=host, name=name, value=value, via="plaintext_http_request",
                    event=event, connection=connection, attributes={},
                ) or produced
            return produced
        if direction == "response":
            raw = headers.get("set-cookie")
            if not raw:
                set_cookies = details.get("set_cookies") or []
                raw = set_cookies[0] if set_cookies else None
            if not raw:
                return None
            try:
                name, value, attributes = http.parse_set_cookie_header(raw)
            except http.HttpError:
                return None
            self._plaintext_names[host].add(name)
            return self._record_observation(
                host=host, name=name, value=value, via="plaintext_http_response",
                event=event, connection=connection,
                attributes=_normalise_attributes(attributes),
            )
        return None

    def _ingest_tls(self, event: NetworkEvent) -> None:
        details = dict(event.details or {})
        sni = details.get("sni")
        if not sni:
            return
        domain = str(sni).lower().rstrip(".")
        self._metadata_domains[domain].append({
            "kind": "tls_handshake",
            "sni": domain,
            "version": details.get("version"),
            "cipher": details.get("cipher"),
            "timestamp": event.timestamp.isoformat(),
            "src_addr": event.src_addr,
            "dst_addr": event.dst_addr,
            "dst_port": event.dst_port,
            "evidence_ref": event.evidence_ref,
        })

    def _ingest_connection(self, event: NetworkEvent) -> None:
        details = dict(event.details or {})
        host = details.get("host") or details.get("sni")
        if not host:
            return
        domain = str(host).lower().rstrip(".")
        self._metadata_domains[domain].append({
            "kind": "connection",
            "dst_addr": event.dst_addr,
            "dst_port": event.dst_port,
            "timestamp": event.timestamp.isoformat(),
            "evidence_ref": event.evidence_ref,
        })

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------
    def _record_observation(
        self,
        *,
        host: str,
        name: str,
        value: str,
        via: str,
        event: NetworkEvent,
        connection: dict[str, Any],
        attributes: dict[str, Any],
    ) -> CookieObservation | None:
        row = self.ground_truth.lookup(domain=host, name=name)
        attribution_note = ""
        if not row and not host:
            # A plaintext response carries no Host header. If exactly one registered
            # cookie has this name, attribute it; otherwise record it as unregistered
            # rather than guessing.
            candidates = self.ground_truth.lookup(name=name)
            if len(candidates) == 1:
                row = candidates
                host = candidates[0]["domain"]
                attribution_note = "domain attributed from ground truth by unique cookie name"
        verified_row = self.ground_truth.verify(value, name=name)
        if row:
            site_id = row[0]["site_id"]
            domain = row[0]["domain"]
            classification = (
                CookieClassification.ATTACKER_OBSERVED_INTERCEPTION
                if via == "lab_tls_interception" else CookieClassification.ATTACKER_OBSERVED_PLAINTEXT
            )
            notes = attribution_note
            if verified_row is None:
                notes = "; ".join(filter(None, [
                    attribution_note,
                    "value observed in plaintext does not match the current ground-truth "
                    "value for this cookie (rotated, revoked or mismatched scope)",
                ]))
            observation = CookieObservation(
                site_id=site_id, domain=domain, name=name,
                classification=classification,
                observed_value=value, value_available=True,
                observed_via=via, connection=connection,
                evidence_ref=event.evidence_ref, timestamp=event.timestamp,
                attributes_known={**_merge_attributes(row[0]["attributes"], attributes)},
                verified_against_ground_truth=verified_row is not None,
                ground_truth_value_known=True,
                notes=notes,
            )
        else:
            # A plaintext cookie the laboratory did not register is still an exposure
            # finding: report it, but never claim it was verified.
            observation = CookieObservation(
                site_id="unregistered", domain=host, name=name,
                classification=CookieClassification.ATTACKER_OBSERVED_PLAINTEXT,
                observed_value=value, value_available=True,
                observed_via=via, connection=connection,
                evidence_ref=event.evidence_ref, timestamp=event.timestamp,
                attributes_known=dict(attributes),
                verified_against_ground_truth=False,
                ground_truth_value_known=False,
                notes="cookie value observed in plaintext but not present in the lab ground truth",
            )
            self._unknown_values.append({"domain": host, "name": name, "via": via})
        self.observations.append(observation)
        self._observed[f"{observation.site_id}:{observation.domain}:{name}"].append(observation)
        logger.info(
            "cookie observed in plaintext",
            extra={"lab_cookie": f"{observation.site_id}:{host}:{name}", "via": via},
        )
        return observation

    # ------------------------------------------------------------------
    # Finalisation
    # ------------------------------------------------------------------
    def finalize(self) -> list[CookieObservation]:
        """Produce one outcome per ground-truth cookie plus observed unknown cookies.

        Cookies that were never seen in plaintext are reported as server-known only, or as
        not observable because the site was contacted over TLS. The distinction is
        explicit so a reader never mistakes "the server knows it" for "the attacker got it".
        """
        results: list[CookieObservation] = list(self.observations)
        seen_keys = {f"{o.site_id}:{o.domain}:{o.name}" for o in results}
        for row in self.ground_truth.all():
            key = f"{row['site_id']}:{row['domain']}:{row['name']}"
            if key in seen_keys:
                continue
            domain = row["domain"].lower().rstrip(".")
            metadata = self._metadata_domains.get(domain) or self._metadata_domains.get(row["domain"])
            if metadata:
                classification = CookieClassification.ENCRYPTED_NOT_OBSERVABLE
                notes = (
                    "site was contacted over an encrypted tunnel; no cookie value was "
                    "accessible from the attacker's network position"
                )
                via = "tls_metadata_only"
            elif domain in self._plaintext_names:
                classification = CookieClassification.SERVER_ONLY
                notes = (
                    "site traffic was observable in plaintext but this cookie was not "
                    "present in any captured request or response"
                )
                via = "server_log_only"
            else:
                classification = CookieClassification.SERVER_ONLY
                notes = "cookie is known to the lab server but was not observed during this assessment"
                via = "server_log_only"
            results.append(CookieObservation(
                site_id=row["site_id"], domain=row["domain"], name=row["name"],
                classification=classification,
                observed_value=None, value_available=False,
                observed_via=via,
                timestamp=datetime.now(UTC),
                attributes_known=_merge_attributes(row["attributes"], {}),
                verified_against_ground_truth=False,
                ground_truth_value_known=True,
                notes=notes,
            ))
        # Metadata-only sightings with no ground-truth cookie: report as browser metadata.
        for domain, sightings in self._metadata_domains.items():
            if any(o.domain == domain for o in results):
                continue
            results.append(CookieObservation(
                site_id="unregistered", domain=domain, name="*",
                classification=CookieClassification.BROWSER_METADATA_ONLY,
                value_available=False, observed_via="tls_metadata_only",
                timestamp=datetime.now(UTC),
                notes=(
                    f"encrypted TLS metadata observed ({len(sightings)} sighting(s)); "
                    "no cookie value was accessible and none was inferred"
                ),
            ))
        return results

    def summary(self) -> dict[str, Any]:
        results = self.finalize()
        counts: dict[str, int] = {}
        for observation in results:
            counts[observation.classification.value] = counts.get(observation.classification.value, 0) + 1
        verified = [o for o in results if o.verified_against_ground_truth]
        return {
            "total_cookie_outcomes": len(results),
            "attacker_observed_values": sum(1 for o in results if o.value_available),
            "verified_against_ground_truth": len(verified),
            "unregistered_values_observed": len(self._unknown_values),
            "classifications": counts,
            "interception_enabled": self.interception_enabled,
        }


def _connection_from_event(event: NetworkEvent) -> dict[str, Any]:
    return {
        "src_addr": event.src_addr,
        "src_port": event.src_port,
        "dst_addr": event.dst_addr,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
    }


def _normalise_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    normalised: dict[str, Any] = {}
    for key, value in attributes.items():
        if isinstance(value, str):
            normalised[key] = value
        elif value is True:
            normalised[key] = True
    return normalised


def _merge_attributes(raw: str | None, observed: dict[str, Any]) -> dict[str, Any]:
    from .ground_truth import load_attributes

    merged = load_attributes(raw)
    merged.update({k: v for k, v in observed.items() if v not in (None, "")})
    return merged
