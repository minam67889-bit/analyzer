from __future__ import annotations

from adversarylab.cookies.engine import CookieExposureEngine
from adversarylab.cookies.ground_truth import CookieGroundTruth
from adversarylab.cookies.model import (
    CookieClassification,
    CookieSpec,
    SameSite,
)
from adversarylab.core.events import EventCategory, EventSource, make_event
from adversarylab.protocols import http


def _http_event(direction: str, headers: dict[str, str], *, host: str = "plain.lab.test",
                src: str = "10.10.0.50", dst: str = "10.10.0.1", dst_port: int = 80):
    details: dict = {"direction": direction, "headers": headers}
    if direction == "request":
        details["host"] = host
    return make_event(
        session_id="s", category=EventCategory.HTTP, source=EventSource.PACKET_CAPTURE,
        summary="http", protocol="http", src_addr=src, dst_addr=dst, dst_port=dst_port,
        details=details,
    )


def _tls_event(sni: str):
    return make_event(
        session_id="s", category=EventCategory.TLS, source=EventSource.PACKET_CAPTURE,
        summary=f"TLS ClientHello sni={sni}", protocol="tls",
        src_addr="10.10.0.50", dst_addr="10.10.0.1", dst_port=443,
        details={"sni": sni, "version": "TLSv1.3"},
    )


def _ground_truth(tmp_path) -> CookieGroundTruth:
    store = CookieGroundTruth(tmp_path / "ground_truth.db")
    store.register(CookieSpec(
        site_id="plain", domain="plain.lab.test", name="session_id",
        value="plain-session-0001", secure=False, httponly=False,
        samesite=SameSite.LAX, session=True, purpose="plaintext session cookie",
    ))
    store.register(CookieSpec(
        site_id="secure", domain="secure.lab.test", name="secure_session",
        value="secure-session-0002", secure=True, httponly=True,
        samesite=SameSite.STRICT, session=True, purpose="secure session cookie",
    ))
    return store


def test_plaintext_cookie_is_attacker_observed_and_verified(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    engine.ingest_event(_http_event("request", {"cookie": "session_id=plain-session-0001"}))
    results = engine.finalize()
    observed = [o for o in results if o.site_id == "plain"]
    assert len(observed) == 1
    assert observed[0].classification is CookieClassification.ATTACKER_OBSERVED_PLAINTEXT
    assert observed[0].value_available is True
    assert observed[0].verified_against_ground_truth is True
    assert observed[0].observed_via == "plaintext_http_request"


def test_set_cookie_over_plaintext_is_attacker_observed(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    engine.ingest_event(_http_event(
        "response",
        {"set-cookie": "session_id=plain-session-0001; Path=/; HttpOnly; SameSite=Lax"},
    ))
    observed = [o for o in engine.finalize() if o.site_id == "plain"]
    assert observed[0].classification is CookieClassification.ATTACKER_OBSERVED_PLAINTEXT
    assert observed[0].attributes_known.get("httponly") is True


def test_https_cookie_is_reported_not_observable(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    engine.ingest_event(_tls_event("secure.lab.test"))
    results = engine.finalize()
    secure = [o for o in results if o.site_id == "secure"][0]
    assert secure.classification is CookieClassification.ENCRYPTED_NOT_OBSERVABLE
    assert secure.value_available is False
    assert secure.observed_value is None
    assert "encrypted" in secure.notes


def test_unvisited_cookie_is_server_known_only(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    results = engine.finalize()
    assert all(o.classification is CookieClassification.SERVER_ONLY for o in results)


def test_unknown_plaintext_value_is_reported_unregistered(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    engine.ingest_event(_http_event("request", {"cookie": "other=abc123"}))
    unknown = [o for o in engine.finalize() if o.site_id == "unregistered"]
    assert len(unknown) == 1
    assert unknown[0].value_available is True
    assert unknown[0].verified_against_ground_truth is False
    assert "not present in the lab ground truth" in unknown[0].notes


def test_mismatched_value_is_not_verified(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    engine.ingest_event(_http_event("request", {"cookie": "session_id=rotated-value"}))
    observed = [o for o in engine.finalize() if o.site_id == "plain"][0]
    assert observed.value_available is True
    assert observed.verified_against_ground_truth is False
    assert observed.notes


def test_interception_flag_does_not_invent_observations(tmp_path):
    """Enabling interception must not turn a TLS-only site into an observed cookie."""
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store, interception_enabled=True)
    engine.ingest_event(_tls_event("secure.lab.test"))
    secure = [o for o in engine.finalize() if o.site_id == "secure"][0]
    assert secure.value_available is False


def test_redaction_hides_value_but_keeps_digest(tmp_path):
    store = _ground_truth(tmp_path)
    engine = CookieExposureEngine(store)
    engine.ingest_event(_http_event("request", {"cookie": "session_id=plain-session-0001"}))
    observation = engine.finalize()[0]
    hidden = observation.redacted_dict(reveal_values=False)
    assert "plain-session-0001" not in str(hidden["observed_value"])
    assert "sha256:" in hidden["observed_value"]
    revealed = observation.redacted_dict(reveal_values=True)
    assert revealed["observed_value"] == "plain-session-0001"


def test_http_cookie_header_parsing():
    assert http.parse_cookie_header("a=1; b=2") == [("a", "1"), ("b", "2")]
    assert http.parse_cookie_header("") == []
    name, value, attrs = http.parse_set_cookie_header("n=v; Secure; HttpOnly; SameSite=Lax")
    assert (name, value) == ("n", "v")
    assert attrs["secure"] is True and attrs["httponly"] is True and attrs["samesite"] == "Lax"


def test_ground_truth_roundtrip_and_revoke(tmp_path):
    store = _ground_truth(tmp_path)
    assert store.verify("plain-session-0001", name="session_id") is not None
    assert store.verify("wrong", name="session_id") is None
    assert set(store.sites()) == {"plain", "secure"}
    store.revoke("plain", "plain.lab.test", "session_id")
    assert store.verify("plain-session-0001", name="session_id") is not None  # still known
