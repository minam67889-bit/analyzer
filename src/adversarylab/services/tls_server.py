"""TLS laboratory server.

Completes real TLS handshakes using Python ``ssl`` and records SNI via ``sni_callback``.
Handshake outcomes (success, certificate rejection, protocol mismatch) are logged as lab
server events and can be exported as evidence. No application data is decrypted or stored.
"""

from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass

from ..clock import Clock, SystemClock
from ..core.events import EventCategory, EventSeverity, EventSource, make_event
from ..logging_config import get_logger
from .certificates import CertificateBundle

logger = get_logger(__name__)


@dataclass
class TlsHandshakeRecord:
    timestamp: str
    client: str
    sni: str | None
    alpn: list[str]
    version: str | None
    cipher: str | None
    success: bool
    error: str | None = None
    cert_fingerprint: str | None = None


class TlsLabServer:
    def __init__(
        self,
        bundle: CertificateBundle,
        *,
        bind_addr: str = "0.0.0.0",
        port: int = 443,
        alpn: list[str] | None = None,
        minimum_version: ssl.TLSVersion | None = None,
        reject_sni: Callable[[str], bool] | None = None,
        bus: Callable[..., None] | None = None,
        clock: Clock | None = None,
        session_id: str = "",
        device_id: str | None = None,
    ) -> None:
        self.bundle = bundle
        self.bind_addr = bind_addr
        self.port = port
        self.alpn = alpn
        self.minimum_version = minimum_version
        self.reject_sni = reject_sni
        self.bus = bus
        self.clock = clock or SystemClock()
        self.session_id = session_id
        self.device_id = device_id
        self.handshakes: list[TlsHandshakeRecord] = []
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    def _build_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=_write_temp(self.bundle.cert_pem, "crt"),
            keyfile=_write_temp(self.bundle.key_pem, "key"),
        )
        if self.alpn:
            context.set_alpn_protocols(self.alpn)
        if self.minimum_version is not None:
            context.minimum_version = self.minimum_version
        server = self

        def sni_callback(sslobj, server_name, sslcontext):
            server._record_sni(server_name)
            if server.reject_sni and server_name and server.reject_sni(server_name):
                return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
            return None

        context.sni_callback = sni_callback
        return context

    def _record_sni(self, server_name: str | None) -> None:
        self._pending_sni = server_name

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread:
            return
        self._stop.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_addr, self.port))
        self._sock.listen(16)
        self._thread = threading.Thread(target=self._serve, daemon=True, name="lab-tls")
        self._thread.start()
        logger.info("lab TLS server started", extra={"lab_bind": f"{self.bind_addr}:{self.port}"})

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None

    # ------------------------------------------------------------------
    def _serve(self) -> None:
        context = self._build_context()
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(conn, addr, context), daemon=True
            ).start()

    def _handle(self, conn: socket.socket, addr: tuple[str, int], context: ssl.SSLContext) -> None:
        self._pending_sni = None
        record = TlsHandshakeRecord(
            timestamp=self.clock.now().isoformat(), client=addr[0], sni=None,
            alpn=[], version=None, cipher=None, success=False,
        )
        try:
            tls = context.wrap_socket(conn, server_side=True)
            record.sni = self._pending_sni
            record.alpn = [tls.selected_alpn_protocol()] if tls.selected_alpn_protocol() else []
            record.version = tls.version()
            record.cipher = tls.cipher()[0] if tls.cipher() else None
            record.success = True
            record.cert_fingerprint = self.bundle.fingerprint_sha256 or None
            try:
                tls.settimeout(0.5)
                tls.recv(4096)
            except (TimeoutError, ssl.SSLError, OSError):
                pass
            tls.close()
        except ssl.SSLError as exc:
            record.error = f"ssl:{exc.reason}" if getattr(exc, "reason", None) else str(exc)
        except OSError as exc:
            record.error = f"os:{exc}"
        except Exception as exc:  # pragma: no cover
            record.error = str(exc)
        self.handshakes.append(record)
        self._emit(record)

    def _emit(self, record: TlsHandshakeRecord) -> None:
        if self.bus is None:
            return
        self.bus(
            make_event(
                session_id=self.session_id,
                category=EventCategory.TLS,
                source=EventSource.LAB_SERVER,
                severity=EventSeverity.NOTICE if record.success else EventSeverity.WARNING,
                summary=(
                    f"lab TLS handshake sni={record.sni or '-'} "
                    f"version={record.version or '-'} success={record.success} "
                    f"error={record.error or '-'}"
                ),
                protocol="tls",
                dst_addr=record.client,
                dst_port=self.port,
                details={
                    "sni": record.sni,
                    "alpn": record.alpn,
                    "version": record.version,
                    "cipher": record.cipher,
                    "success": record.success,
                    "error": record.error,
                    "cert_fingerprint": record.cert_fingerprint,
                    "lab_server": True,
                },
                device_id=self.device_id,
            )
        )

    def export_log(self) -> list[dict]:
        return [
            {
                "timestamp": r.timestamp, "client": r.client, "sni": r.sni,
                "alpn": r.alpn, "version": r.version, "cipher": r.cipher,
                "success": r.success, "error": r.error,
                "cert_fingerprint": r.cert_fingerprint,
            }
            for r in self.handshakes
        ]


def _write_temp(data: bytes, suffix: str):
    import tempfile

    path = tempfile.NamedTemporaryFile(prefix="lab-tls-", suffix=f".{suffix}", delete=False)
    path.write(data)
    path.close()
    return path.name
