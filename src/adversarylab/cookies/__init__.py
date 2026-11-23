"""Cookie exposure assessment.

Determines, strictly from what a same-Wi-Fi attacker could legitimately observe, whether
synthetic test cookies were exposed. The engine never infers a cookie value from encrypted
traffic: a TLS session yields browser metadata at most, and that is reported as such.
"""

from __future__ import annotations

from .engine import CookieExposureEngine
from .ground_truth import CookieGroundTruth
from .model import (
    CookieClassification,
    CookieObservation,
    CookieSpec,
    SameSite,
)
from .report import CookieExposureReport

__all__ = [
    "CookieClassification",
    "CookieExposureEngine",
    "CookieExposureReport",
    "CookieGroundTruth",
    "CookieObservation",
    "CookieSpec",
    "SameSite",
]
