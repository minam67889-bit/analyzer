"""Cookie domain model shared by the ground-truth store and the exposure engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SameSite(str, Enum):
    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"
    UNSPECIFIED = "Unspecified"


class CookieClassification(str, Enum):
    """The only four honest answers to "did the attacker get the cookie?"."""

    ATTACKER_OBSERVED_PLAINTEXT = "attacker_observed_plaintext"
    ATTACKER_OBSERVED_INTERCEPTION = "attacker_observed_interception"
    SERVER_ONLY = "server_only"
    ENCRYPTED_NOT_OBSERVABLE = "encrypted_not_observable"
    BROWSER_METADATA_ONLY = "browser_metadata_only"


@dataclass
class CookieSpec:
    """A cookie the laboratory intends a test site to issue."""

    site_id: str
    domain: str
    name: str
    value: str
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: SameSite = SameSite.UNSPECIFIED
    persistent: bool = False
    session: bool = True
    set_cookie_header: str = ""
    purpose: str = "synthetic test cookie"
    notes: str = ""

    @property
    def fingerprint(self) -> str:
        return f"{self.site_id}:{self.domain}:{self.name}"

    def attributes_known(self) -> dict[str, Any]:
        return {
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite.value,
            "persistent": self.persistent,
            "session": self.session,
            "path": self.path,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "domain": self.domain,
            "name": self.name,
            "value": self.value,
            "purpose": self.purpose,
            "attributes": self.attributes_known(),
            "notes": self.notes,
        }


@dataclass
class CookieObservation:
    """One cookie's exposure outcome for one assessment."""

    site_id: str
    domain: str
    name: str
    classification: CookieClassification
    observed_value: str | None = None
    value_available: bool = False
    observed_via: str = ""
    connection: dict[str, Any] = field(default_factory=dict)
    evidence_ref: str | None = None
    timestamp: datetime | None = None
    attributes_known: dict[str, Any] = field(default_factory=dict)
    verified_against_ground_truth: bool = False
    ground_truth_value_known: bool = False
    notes: str = ""

    def redacted_dict(self, *, reveal_values: bool = False) -> dict[str, Any]:
        payload = self.to_dict()
        if not reveal_values:
            payload["observed_value"] = redact_value(self.observed_value)
            payload["ground_truth_value"] = (
                redact_value(self.attributes_known.get("ground_truth_value"))
                if self.ground_truth_value_known else None
            )
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "domain": self.domain,
            "name": self.name,
            "classification": self.classification.value,
            "observed_value": self.observed_value,
            "value_available": self.value_available,
            "observed_via": self.observed_via,
            "connection": dict(self.connection),
            "evidence_ref": self.evidence_ref,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "attributes": dict(self.attributes_known),
            "verified_against_ground_truth": self.verified_against_ground_truth,
            "ground_truth_value_known": self.ground_truth_value_known,
            "notes": self.notes,
        }


def redact_value(value: str | None) -> str | None:
    """Redact a synthetic value while keeping it recognisable for verification.

    Returns ``None`` for ``None``. The redacted form keeps a short prefix and a stable
    digest so a reader can confirm two references are the same cookie without learning it.
    """
    if value is None:
        return None
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]} sha256:{_short_digest(value)}"


def _short_digest(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
