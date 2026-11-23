"""SQLite persistence with explicit migrations.

The database is an index, not the system of record: raw evidence lives in the session
directory and is referenced by path + SHA-256. SQLite is used so the UI and reports can
query events/results without loading multi-gigabyte PCAP files.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .events import EventCategory, NetworkEvent

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  status TEXT NOT NULL,
  config_json TEXT,
  environment_json TEXT
);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  category TEXT NOT NULL,
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  test_id TEXT,
  scenario_id TEXT,
  device_id TEXT,
  protocol TEXT,
  src_addr TEXT,
  dst_addr TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  details_json TEXT NOT NULL DEFAULT '{}',
  evidence_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_test ON events(test_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE TABLE IF NOT EXISTS destinations (
  destination_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  host TEXT,
  ip TEXT,
  port INTEGER,
  protocol TEXT,
  family TEXT,
  ownership TEXT NOT NULL,
  ownership_reason TEXT NOT NULL,
  service_guess TEXT,
  discovered_by TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_dest_session ON destinations(session_id);
CREATE TABLE IF NOT EXISTS results (
  result_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  test_id TEXT NOT NULL,
  scenario_id TEXT,
  verdict TEXT NOT NULL,
  confidence TEXT NOT NULL,
  block_cause TEXT NOT NULL,
  execution_mode TEXT NOT NULL,
  rationale TEXT NOT NULL,
  started_at TEXT,
  ended_at TEXT,
  assertions_json TEXT NOT NULL DEFAULT '[]',
  observations_json TEXT NOT NULL DEFAULT '[]',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  limitations_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  test_id TEXT,
  scenario_id TEXT,
  kind TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
CREATE TABLE IF NOT EXISTS coverage (
  session_id TEXT NOT NULL,
  test_id TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (session_id, test_id)
);
"""


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone().isoformat() if dt else None


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent and str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    # ------------------------------------------------------------------
    def _migrate(self) -> None:
        with self._conn:
            self._conn.executescript(_DDL)
            row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            version = int(row["value"]) if row else 0
            if version < SCHEMA_VERSION:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(SCHEMA_VERSION),),
                )

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # meta
    # ------------------------------------------------------------------
    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    # ------------------------------------------------------------------
    # sessions
    # ------------------------------------------------------------------
    def insert_session(
        self,
        session_id: str,
        started_at: datetime,
        status: str,
        config: Mapping[str, Any] | None = None,
        environment: Mapping[str, Any] | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO sessions(session_id, started_at, status, config_json, environment_json) "
                "VALUES(?,?,?,?,?)",
                (
                    session_id,
                    _iso(started_at),
                    status,
                    json.dumps(config or {}, sort_keys=True),
                    json.dumps(environment or {}, sort_keys=True),
                ),
            )

    def update_session(self, session_id: str, **fields: Any) -> None:
        if not fields:
            return
        columns = []
        values: list[Any] = []
        for key, value in fields.items():
            columns.append(f"{key}=?")
            values.append(value)
        values.append(session_id)
        with self._conn:
            self._conn.execute(
                f"UPDATE sessions SET {', '.join(columns)} WHERE session_id=?", values
            )

    # ------------------------------------------------------------------
    # events
    # ------------------------------------------------------------------
    def insert_event(self, event: NetworkEvent) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO events("
                "event_id, session_id, timestamp, category, source, severity, summary, "
                "test_id, scenario_id, device_id, protocol, src_addr, dst_addr, "
                "src_port, dst_port, details_json, evidence_ref) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.event_id,
                    event.session_id,
                    _iso(event.timestamp),
                    event.category.value,
                    event.source.value,
                    event.severity.value,
                    event.summary,
                    event.test_id,
                    event.scenario_id,
                    event.device_id,
                    event.protocol,
                    event.src_addr,
                    event.dst_addr,
                    event.src_port,
                    event.dst_port,
                    json.dumps(dict(event.details), sort_keys=True),
                    event.evidence_ref,
                ),
            )

    def query_events(
        self,
        *,
        session_id: str | None = None,
        test_id: str | None = None,
        scenario_id: str | None = None,
        categories: Iterable[EventCategory] | None = None,
        limit: int | None = None,
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id=?")
            params.append(session_id)
        if test_id is not None:
            clauses.append("test_id=?")
            params.append(test_id)
        if scenario_id is not None:
            clauses.append("scenario_id=?")
            params.append(scenario_id)
        if categories is not None:
            cats = [c.value for c in categories]
            clauses.append(f"category IN ({','.join('?' for _ in cats)})")
            params.extend(cats)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY timestamp"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return list(self._conn.execute(sql, params).fetchall())

    # ------------------------------------------------------------------
    # destinations
    # ------------------------------------------------------------------
    def upsert_destination(self, dest: Mapping[str, Any]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO destinations("
                "destination_id, session_id, host, ip, port, protocol, family, ownership, "
                "ownership_reason, service_guess, discovered_by, first_seen, last_seen, active) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    dest["destination_id"],
                    dest["session_id"],
                    dest.get("host"),
                    dest.get("ip"),
                    dest.get("port"),
                    dest.get("protocol"),
                    dest.get("family"),
                    dest["ownership"],
                    dest["ownership_reason"],
                    dest.get("service_guess"),
                    dest.get("discovered_by"),
                    dest["first_seen"],
                    dest["last_seen"],
                    1 if dest.get("active", True) else 0,
                ),
            )

    def query_destinations(
        self, session_id: str, active_only: bool = True
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM destinations WHERE session_id=?"
        if active_only:
            sql += " AND active=1"
        sql += " ORDER BY last_seen"
        return list(self._conn.execute(sql, (session_id,)).fetchall())

    # ------------------------------------------------------------------
    # results
    # ------------------------------------------------------------------
    def insert_result(self, session_id: str, result: Mapping[str, Any]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO results("
                "result_id, session_id, test_id, scenario_id, verdict, confidence, block_cause, "
                "execution_mode, rationale, started_at, ended_at, assertions_json, "
                "observations_json, evidence_refs_json, limitations_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    result["result_id"],
                    session_id,
                    result["test_id"],
                    result.get("scenario_id"),
                    result["verdict"],
                    result["confidence"],
                    result["block_cause"],
                    result["execution_mode"],
                    result["rationale"],
                    result.get("started_at"),
                    result.get("ended_at"),
                    json.dumps(result.get("assertions", []), default=str),
                    json.dumps(result.get("observations", []), default=str),
                    json.dumps(result.get("evidence_refs", [])),
                    json.dumps(result.get("limitations", [])),
                ),
            )

    def query_results(self, session_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM results WHERE session_id=? ORDER BY ended_at", (session_id,)
            ).fetchall()
        )

    # ------------------------------------------------------------------
    # evidence
    # ------------------------------------------------------------------
    def insert_evidence(self, record: Mapping[str, Any]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO evidence("
                "evidence_id, session_id, test_id, scenario_id, kind, path, sha256, bytes, "
                "created_at, metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    record["evidence_id"],
                    record["session_id"],
                    record.get("test_id"),
                    record.get("scenario_id"),
                    record["kind"],
                    record["path"],
                    record["sha256"],
                    record["bytes"],
                    record["created_at"],
                    json.dumps(record.get("metadata", {}), sort_keys=True),
                ),
            )

    def query_evidence(
        self, session_id: str, test_id: str | None = None, scenario_id: str | None = None
    ) -> list[sqlite3.Row]:
        clauses = ["session_id=?"]
        params: list[Any] = [session_id]
        if test_id is not None:
            clauses.append("test_id=?")
            params.append(test_id)
        if scenario_id is not None:
            clauses.append("scenario_id=?")
            params.append(scenario_id)
        sql = f"SELECT * FROM evidence WHERE {' AND '.join(clauses)} ORDER BY created_at"
        return list(self._conn.execute(sql, params).fetchall())

    # ------------------------------------------------------------------
    # coverage
    # ------------------------------------------------------------------
    def upsert_coverage(self, session_id: str, test_id: str, status: str, reason: str = "") -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO coverage(session_id, test_id, status, reason) VALUES(?,?,?,?) "
                "ON CONFLICT(session_id, test_id) DO UPDATE SET status=excluded.status, "
                "reason=excluded.reason",
                (session_id, test_id, status, reason),
            )

    def coverage_rows(self, session_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM coverage WHERE session_id=? ORDER BY test_id", (session_id,)
            ).fetchall()
        )
