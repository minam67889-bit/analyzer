"""Laboratory certificate authority and misconfiguration certificates.

Uses ``cryptography`` when available. If it is not installed, the lab falls back to
operator-supplied PEM files and reports ``LAB_CA`` as unavailable rather than fabricating a
certificate.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from ..errors import PlatformError


@dataclass
class CertificateBundle:
    cert_pem: bytes
    key_pem: bytes
    ca_cert_pem: bytes | None = None
    fingerprint_sha256: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None


def _require_crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise PlatformError(
            "certificate generation requires the optional 'cryptography' dependency"
        ) from exc
    return x509, hashes, serialization, rsa, NameOID


class CertificateAuthority:
    def __init__(self, cache_dir: str | Path | None = None) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cert: CertificateBundle | None = None

    @property
    def available(self) -> bool:
        try:
            _require_crypto()
            return True
        except PlatformError:
            return False

    def get_ca(self, *, common_name: str = "Adversary Lab Test CA") -> CertificateBundle:
        if self._cert is not None:
            return self._cert
        if self.cache_dir:
            cert_path = self.cache_dir / "lab-ca.crt"
            key_path = self.cache_dir / "lab-ca.key"
            if cert_path.exists() and key_path.exists():
                self._cert = CertificateBundle(
                    cert_pem=cert_path.read_bytes(),
                    key_pem=key_path.read_bytes(),
                    ca_cert_pem=cert_path.read_bytes(),
                )
                return self._cert
        x509, hashes, serialization, rsa, NameOID = _require_crypto()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._cert = CertificateBundle(
            cert_pem=cert_pem, key_pem=key_pem, ca_cert_pem=cert_pem,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc,
        )
        if self.cache_dir:
            (self.cache_dir / "lab-ca.crt").write_bytes(cert_pem)
            (self.cache_dir / "lab-ca.key").write_bytes(key_pem)
        return self._cert

    def issue(
        self,
        hostnames: list[str],
        *,
        ca: CertificateBundle | None = None,
        valid_days: int = 825,
        wrong_hostname: str | None = None,
        expired: bool = False,
    ) -> CertificateBundle:
        x509, hashes, serialization, rsa, NameOID = _require_crypto()
        ca = ca or self.get_ca()
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
        ca_key = serialization.load_pem_private_key(ca.key_pem, password=None)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cn = wrong_hostname or (hostnames[0] if hostnames else "lab.test")
        now = datetime.datetime.now(datetime.UTC)
        not_before = now - datetime.timedelta(days=2) if expired else now - datetime.timedelta(days=1)
        not_after = now - datetime.timedelta(days=1) if expired else now + datetime.timedelta(days=valid_days)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        san_entries = []
        for hostname in hostnames:
            try:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname)))
            except ValueError:
                san_entries.append(x509.DNSName(hostname))
        if san_entries:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return CertificateBundle(
            cert_pem=cert_pem,
            key_pem=key_pem,
            ca_cert_pem=ca.cert_pem,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
        )

    def self_signed(self, hostname: str) -> CertificateBundle:
        x509, hashes, serialization, rsa, NameOID = _require_crypto()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        )
        cert = builder.sign(key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return CertificateBundle(
            cert_pem=cert_pem, key_pem=key_pem,
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc,
        )

    def write_pair(self, bundle: CertificateBundle, cert_path: str | Path, key_path: str | Path) -> None:
        Path(cert_path).write_bytes(bundle.cert_pem)
        Path(key_path).write_bytes(bundle.key_pem)
