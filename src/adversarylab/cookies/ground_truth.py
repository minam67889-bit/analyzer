"""Laboratory ground-truth cookie database.

The laboratory knows which synthetic cookies each test site issues. That knowledge lives
here, separately from anything the attacker-side engine can observe, so a report can state
"server-known but never attacker-observed" without ambiguity.

Storage is SQLite (same engine as the event store) and the table is created lazily.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..logging_config import get_logger
from .model import CookieSpec

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cookie_ground_truth (
    site_id      TEXT NOT NULL,
    domain       TEXT NOT NULL,
    name         TEXT NOT NULL,
    value        TEXT NOT NULL,
    attributes   TEXT NOT NULL,
    purpose      TEXT NOT NULL DEFAULT '',
    issued_at    TEXT NOT NULL,
    revoked_at   TEXT,
    PRIMARY KEY (site_id, domain, name)
)
"""


class CookieGroundTruth:
    def __init__(self, path: str | Path, *, clock: Any | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------
    def register(self, spec: CookieSpec) -> None:
        """Record a cookie the laboratory expects a test site to issue."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO cookie_ground_truth
                    (site_id, domain, name, value, attributes, purpose, issued_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(site_id, domain, name) DO UPDATE SET
                    value = excluded.value,
                    attributes = excluded.attributes,
                    purpose = excluded.purpose,
                    issued_at = excluded.issued_at,
                    revoked_at = NULL
                """,
                (
                    spec.site_id, spec.domain, spec.name, spec.value,
                    _dump_attributes(spec.attributes_known()), spec.purpose,
                    datetime.now(UTC).isoformat(),
                ),
            )
            self._conn.commit()
        logger.info("ground-truth cookie registered", extra={"lab_cookie": spec.fingerprint})

    def revoke(self, site_id: str, domain: str, name: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE cookie_ground_truth SET revoked_at = ? WHERE site_id = ? AND domain = ? AND name = ?",
                (datetime.now(UTC).isoformat(), site_id, domain, name),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    def lookup(self, *, site_id: str | None = None, name: str | None = None,
               domain: str | None = None) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if site_id:
            clauses.append("site_id = ?")
            params.append(site_id)
        if name:
            clauses.append("name = ?")
            params.append(name)
        if domain:
            clauses.append("domain = ?")
            params.append(domain)
        query = "SELECT * FROM cookie_ground_truth"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        with self._lock:
            return list(self._conn.execute(query, params).fetchall())

    def verify(self, value: str, *, site_id: str | None = None,
               name: str | None = None) -> sqlite3.Row | None:
        """Return the ground-truth row whose value matches, if any.

        This is the only sanctioned way to confirm that an attacker-observed value is a
        genuine laboratory cookie rather than an arbitrary header the engine picked up.
        """
        rows = self.lookup(site_id=site_id, name=name)
        for row in rows:
            if row["value"] == value:
                return row
        return None

    def all(self) -> list[sqlite3.Row]:
        return self.lookup()

    def sites(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._conn.execute(
                "SELECT DISTINCT site_id FROM cookie_ground_truth ORDER BY site_id"
            ).fetchall()]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _dump_attributes(attributes: dict[str, Any]) -> str:
    import json

    return json.dumps(attributes, sort_keys=True, default=str)


def load_attributes(raw: str | None) -> dict[str, Any]:
    import json

    if not raw:
        return {}
    try:
        return dict(json.loads(raw))
    except ValueError:
        return {}
