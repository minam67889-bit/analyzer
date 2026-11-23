"""Cookie exposure, downgrade and trust-manipulation tests.

These modules implement the same-Wi-Fi attacker model: the device needs no root, no
Shizuku, no ADB, no installed CA and no custom application. Every module records what the
attacker could actually observe and registers the corresponding synthetic cookie in the
laboratory ground truth so the exposure report can verify it.
"""

from __future__ import annotations

from ...core.capability import Capability
from ...core.events import EventCategory
from ...core.results import ExecutionMode, Observation
from ..spec import TestCategory, TestSpec
from .common import (
    BuiltinModule,
    bus_events,
    cookie_header_events,
    http_events,
    register_cookie,
)


def _spec(test_id: str, name: str, description: str, *, expect_block: bool = False,
          category: TestCategory = TestCategory.HTTP, techniques: list[str] | None = None,
          limitations: list[str] | None = None, requires_confirmation: bool = False,
          capabilities: list[Capability] | None = None, mode: ExecutionMode = ExecutionMode.REAL_NETWORK):
    return TestSpec(
        id=test_id,
        name=name,
        category=category,
        description=description,
        attack_techniques=techniques or ["T1557"],
        required_capabilities=capabilities or [Capability.IPV4, Capability.PACKET_CAPTURE],
        setup_procedure="start the laboratory endpoint that issues the synthetic cookie",
        execution_procedure="let the device browse the laboratory site over the lab Wi-Fi",
        expected_behavior=(
            "block or refuse the exposure" if expect_block
            else "the exposure path is demonstrated and recorded"
        ),
        observation_strategy=(
            "capture plaintext HTTP headers and compare against laboratory ground truth; "
            "TLS content is never treated as observable"
        ),
        evidence_requirements=["pcap", "lab http log", "cookie ground truth"],
        cleanup_procedure="stop the laboratory endpoint",
        recovery_procedure="revert action runner state",
        verdict_logic=(
            "PASS only when the exposure path was genuinely demonstrated; INCONCLUSIVE when "
            "no device traffic exists; never PASS from missing telemetry"
        ),
        known_limitations=limitations or [],
        execution_mode=mode,
        expect_block=expect_block,
        estimated_duration_seconds=15.0,
        requires_user_confirmation=requires_confirmation,
    )


class CookiePlaintextExposureTest(BuiltinModule):
    """A session cookie crossing the network in cleartext HTTP."""

    spec = _spec(
        "COOKIE-PLAINTEXT-EXPOSURE",
        "Plaintext cookie exposure",
        "Laboratory site issues a synthetic session cookie over HTTP; determine whether the "
        "cookie value is observable to a same-Wi-Fi attacker.",
        expect_block=False,
        techniques=["T1557", "T1539"],
        limitations=[
            "Only plaintext HTTP is treated as observable; a TLS capture is not evidence of cookie extraction.",
        ],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "cookies.lab.test")
        self.session_value = self.ctx.param("session_value", "syn-session-0001")
        self.cart_value = self.ctx.param("cart_value", "syn-cart-0002")
        register_cookie(self.ctx, "cookie-plaintext", self.host, "session_id", self.session_value,
                        httponly=False, samesite="Lax", session=True,
                        purpose="session cookie over plaintext HTTP")
        register_cookie(self.ctx, "cookie-plaintext", self.host, "cart_id", self.cart_value,
                        httponly=False, samesite="Lax", persistent=True, session=False,
                        purpose="persistent cart cookie over plaintext HTTP")
        self._run("start_http", host=self.host, path="/login",
                  body="<html><form action='/checkout'><input name='card'/></form></html>",
                  port=int(self.ctx.param("port", 8080)),
                  cookies=[
                      {"name": "session_id", "value": self.session_value, "samesite": "Lax"},
                      {"name": "cart_id", "value": self.cart_value, "samesite": "Lax"},
                  ])

    def collect(self):
        observations = super().collect()
        events = cookie_header_events(self.ctx)
        target = [e for e in events
                  if str((e.details or {}).get("host") or "").lower() == self.host.lower()]
        if target:
            observations.append(Observation(
                "packet_capture", "cookie_exposed", self.ctx.clock.now(),
                f"cookie header observed in cleartext for {self.host}",
                details={"host": self.host, "count": len(target),
                         "cookie_names": ["session_id", "cart_id"]},
            ))
        else:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no cleartext cookie header observed for the laboratory site",
                details={"host": self.host},
            ))
        return observations


class CookieSecureAttributesTest(BuiltinModule):
    """Whether Secure/HttpOnly/SameSite attributes are present and respected."""

    spec = _spec(
        "COOKIE-SECURE-ATTRS",
        "Cookie attribute assessment",
        "Issue cookies with Secure, HttpOnly and SameSite attributes and record which "
        "attributes were actually applied and whether a Secure cookie was sent over HTTP.",
        expect_block=False,
        techniques=["T1539", "T1557"],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "secure-attrs.lab.test")
        self.value = self.ctx.param("value", "syn-secure-0003")
        register_cookie(self.ctx, "cookie-attrs", self.host, "session_id", self.value,
                        secure=True, httponly=True, samesite="Strict", session=True,
                        purpose="cookie with full hardening attributes")
        self._run("start_http", host=self.host, path="/", port=int(self.ctx.param("port", 8081)),
                  cookies=[{"name": "session_id", "value": self.value,
                            "secure": True, "httponly": True, "samesite": "Strict"}])

    def collect(self):
        observations = super().collect()
        set_cookies = []
        for event in http_events(self.ctx):
            details = event.details or {}
            for raw in details.get("set_cookies") or []:
                set_cookies.append(str(raw))
            headers = {str(k).lower(): v for k, v in (details.get("headers") or {}).items()}
            if headers.get("set-cookie"):
                set_cookies.append(str(headers["set-cookie"]))
        if set_cookies:
            observations.append(Observation(
                "lab_server", "cookie_attributes", self.ctx.clock.now(),
                f"Set-Cookie observed over cleartext: {len(set_cookies)}",
                details={"set_cookies": set_cookies, "secure_present": any("Secure" in s for s in set_cookies),
                         "httponly_present": any("HttpOnly" in s for s in set_cookies)},
            ))
        else:
            observations.append(Observation(
                "lab_server", "no_observations", self.ctx.clock.now(),
                "no Set-Cookie header observed",
            ))
        return observations


class CookieRedirectExposureTest(BuiltinModule):
    """Cookie sent to an HTTP endpoint before an HTTP-to-HTTPS redirect."""

    spec = _spec(
        "COOKIE-REDIRECT-EXPOSURE",
        "Cookie exposure through insecure redirect",
        "An HTTP endpoint issues a cookie and redirects to HTTPS; determine whether the "
        "cookie value was already exposed before the redirect.",
        expect_block=False,
        techniques=["T1557", "T1185"],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "redirect.lab.test")
        self.value = self.ctx.param("value", "syn-redirect-0004")
        register_cookie(self.ctx, "cookie-redirect", self.host, "session_id", self.value,
                        httponly=False, samesite="Lax", session=True)
        self._run("start_http", host=self.host, path="/login", port=int(self.ctx.param("port", 8082)),
                  redirect_to="https://secure.lab.test/login",
                  cookies=[{"name": "session_id", "value": self.value, "samesite": "Lax"}])

    def collect(self):
        observations = super().collect()
        events = [e for e in cookie_header_events(self.ctx)
                  if str((e.details or {}).get("host") or "").lower() == self.host.lower()]
        redirects = [e for e in http_events(self.ctx, direction="response")
                     if (e.details or {}).get("status") in {301, 302, 303, 307, 308}]
        if events:
            observations.append(Observation(
                "packet_capture", "cookie_exposed", self.ctx.clock.now(),
                "cookie value exposed before/around an insecure redirect",
                details={"host": self.host, "count": len(events), "redirects": len(redirects)},
            ))
        else:
            observations.append(Observation(
                "packet_capture", "no_observations", self.ctx.clock.now(),
                "no cookie header observed at the redirecting endpoint",
                details={"host": self.host, "redirects": len(redirects)},
            ))
        return observations


class CookieHttpsEncryptedTest(BuiltinModule):
    """HTTPS-only cookie: prove the value was NOT attacker-observable."""

    spec = _spec(
        "COOKIE-HTTPS-ENCRYPTED",
        "Encrypted cookie non-exposure",
        "Serve the laboratory cookie only inside TLS and verify that no cookie value was "
        "present in attacker-observable traffic.",
        expect_block=False,
        techniques=["T1557"],
        limitations=[
            "A TLS handshake in the capture is metadata only and is never reported as a extracted cookie.",
        ],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "encrypted.lab.test")
        self.value = self.ctx.param("value", "syn-encrypted-0005")
        register_cookie(self.ctx, "cookie-encrypted", self.host, "session_id", self.value,
                        secure=True, httponly=True, samesite="Strict", session=True)
        self._run("start_tls", hostname=self.host, port=int(self.ctx.param("port", 8443)),
                  cert_mode="lab_ca")

    def collect(self):
        observations = super().collect()
        tls_events = [e for e in bus_events(self.ctx, categories={EventCategory.TLS})
                      if str((e.details or {}).get("sni") or "").lower() == self.host.lower()]
        plaintext = cookie_header_events(self.ctx)
        observations.append(Observation(
            "packet_capture",
            "detected" if tls_events else "no_observations",
            self.ctx.clock.now(),
            f"TLS handshakes for {self.host}: {len(tls_events)}; plaintext cookie headers: {len(plaintext)}",
            details={"tls_handshakes": len(tls_events), "plaintext_cookie_headers": len(plaintext),
                     "cookie_value_observable": bool(plaintext),
                     "sni": self.host},
        ))
        return observations


class CookieScopeMisconfigTest(BuiltinModule):
    """Cookie scoped too broadly is sent to sibling subdomains."""

    spec = _spec(
        "COOKIE-SCOPE-MISCONFIG",
        "Cookie scope misconfiguration",
        "Issue a cookie with a parent-domain scope and check whether it is sent to a "
        "sibling subdomain endpoint.",
        expect_block=False,
        techniques=["T1557", "T1539"],
    )

    def execute(self) -> None:
        self.parent = self.ctx.param("parent", "lab.test")
        self.host = self.ctx.param("host", "a.lab.test")
        self.sibling = self.ctx.param("sibling", "b.lab.test")
        self.value = self.ctx.param("value", "syn-scope-0006")
        register_cookie(self.ctx, "cookie-scope", self.host, "session_id", self.value,
                        httponly=False, samesite="Lax", session=True)
        self._run("start_http", host=self.host, path="/", port=int(self.ctx.param("port", 8083)),
                  cookies=[{"name": "session_id", "value": self.value, "path": "/"}],
                  headers={"Set-Cookie-Domain": self.parent})

    def collect(self):
        observations = super().collect()
        sibling_events = [
            e for e in cookie_header_events(self.ctx)
            if str((e.details or {}).get("host") or "").lower() == self.sibling.lower()
        ]
        observations.append(Observation(
            "packet_capture",
            "cookie_exposed" if sibling_events else "no_observations",
            self.ctx.clock.now(),
            f"cookie observed at sibling {self.sibling}: {len(sibling_events)}",
            details={"sibling": self.sibling, "count": len(sibling_events)},
        ))
        return observations


class HstsEnforcementTest(BuiltinModule):
    """HSTS header presence and plaintext follow-up behaviour."""

    spec = _spec(
        "HSTS-ENFORCEMENT",
        "HSTS and HTTPS enforcement",
        "Send Strict-Transport-Security from the laboratory endpoint and observe whether "
        "subsequent requests stay on HTTPS.",
        expect_block=False,
        techniques=["T1557"],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "hsts.lab.test")
        self._run("start_http", host=self.host, path="/", port=int(self.ctx.param("port", 8084)),
                  headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"})

    def collect(self):
        observations = super().collect()
        headers = []
        for event in http_events(self.ctx, direction="response"):
            headers.extend(
                str(v) for k, v in ((event.details or {}).get("headers") or {}).items()
                if str(k).lower() == "strict-transport-security"
            )
        observations.append(Observation(
            "lab_server", "detected" if headers else "no_observations", self.ctx.clock.now(),
            f"HSTS headers observed: {len(headers)}",
            details={"hsts": headers, "host": self.host},
        ))
        return observations


class HttpDowngradeResistanceTest(BuiltinModule):
    """Attempt to keep the device on HTTP instead of HTTPS."""

    spec = _spec(
        "HTTP-DOWNGRADE",
        "HTTP downgrade resistance",
        "Attempt to strip or bypass HTTPS so that the next request goes to the laboratory "
        "over cleartext, and observe whether the device or firewall refuses.",
        expect_block=True,
        techniques=["T1557", "T1656"],
        limitations=[
            "A failed downgrade is not proof of cookie safety; it is one control in the chain.",
        ],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "downgrade.lab.test")
        self._run("start_http", host=self.host, path="/", port=int(self.ctx.param("port", 8085)),
                  redirect_to=f"http://{self.host}/insecure",
                  body="<html>insecure</html>")

    def collect(self):
        observations = super().collect()
        cleartext = http_events(self.ctx, host=self.host)
        observations.append(Observation(
            "packet_capture", "detected" if cleartext else "no_observations",
            self.ctx.clock.now(),
            f"cleartext requests to {self.host}: {len(cleartext)}",
            details={"host": self.host, "cleartext_requests": len(cleartext)},
        ))
        return observations


class TlsInterceptionOptInTest(BuiltinModule):
    """Explicitly opt-in TLS interception experiment.

    Nothing is installed by default. The module only proceeds when the operator enabled
    ``tests.allow_certificate_install_opt_in`` *and* confirmed the test, and it records
    that the device was never modified by the default configuration.
    """

    spec = _spec(
        "TLS-INTERCEPT-OPTIN",
        "TLS interception (explicit opt-in)",
        "Controlled laboratory experiment for TLS interception feasibility. Requires an "
        "explicit operator opt-in; the default assessment installs nothing on the device.",
        expect_block=False,
        techniques=["T1557", "T1638"],
        requires_confirmation=True,
        limitations=[
            "Disabled unless tests.allow_certificate_install_opt_in is true.",
            "A displayed certificate prompt is not evidence of interception.",
        ],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "intercept.lab.test")
        config = self.ctx.config
        allowed = bool(getattr(getattr(config, "tests", None), "allow_certificate_install_opt_in", False))
        self.opted_in = allowed
        if not allowed:
            from ...core.results import Observation as _Observation

            self.ctx.collected.append(_Observation(
                "test_engine", "opt_in_required", self.ctx.clock.now(),
                "TLS interception experiment skipped: operator opt-in not enabled",
                details={"opt_in_enabled": False, "installed_certificate": False},
            ))
            return
        self._run("start_tls", hostname=self.host, port=int(self.ctx.param("port", 8444)),
                  cert_mode="lab_ca")

    def collect(self):
        observations = super().collect()
        if not self.opted_in:
            return observations
        observations.append(Observation(
            "lab_server", "no_observations", self.ctx.clock.now(),
            "interception endpoint started; device behaviour not observable in this environment",
            details={"opt_in_enabled": True, "installed_certificate": False},
        ))
        return observations


class CertTrustPromptTest(BuiltinModule):
    """Captive-portal style certificate prompt; records display vs. installation."""

    spec = _spec(
        "CERT-TRUST-PROMPT",
        "Certificate trust prompt",
        "Present a captive-portal style certificate prompt with a laboratory certificate "
        "and record whether it was displayed, whether any interaction occurred, and "
        "whether installation actually happened.",
        expect_block=False,
        category=TestCategory.HTTP,
        techniques=["T1185", "T1638"],
        limitations=[
            "No certificate is installed by default; installation requires the separate opt-in experiment.",
        ],
    )

    def execute(self) -> None:
        self.host = self.ctx.param("host", "portal.lab.test")
        self._run("start_http", host=self.host, path="/",
                  body=("<html><h1>Install laboratory certificate to continue</h1>"
                        "<p>This is a synthetic social-engineering scenario.</p></html>"),
                  port=int(self.ctx.param("port", 8086)))

    def collect(self):
        observations = super().collect()
        events = http_events(self.ctx, host=self.host)
        observations.append(Observation(
            "lab_server", "detected" if events else "no_observations", self.ctx.clock.now(),
            f"prompt endpoint requested {len(events)} time(s); installation not attempted",
            details={"host": self.host, "requests": len(events),
                     "prompt_displayed": bool(events),
                     "user_interaction_observed": False,
                     "certificate_installed": False},
        ))
        return observations
