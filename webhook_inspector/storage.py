"""SQLite storage for received requests and replay attempts."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hook TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL DEFAULT '',
    headers TEXT NOT NULL,
    body BLOB NOT NULL,
    client_ip TEXT,
    received_at REAL NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS replays (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    resigned INTEGER NOT NULL,
    sent_at REAL NOT NULL,
    status_code INTEGER,
    error TEXT,
    elapsed_ms REAL
);
CREATE INDEX IF NOT EXISTS replays_request ON replays (request_id);
"""

_COLUMNS = "id, hook, method, path, query, headers, body, client_ip, received_at, status, reason"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class StoredRequest:
    id: int
    hook: str
    method: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: bytes
    client_ip: str | None
    received_at: float
    status: str
    reason: str

    @property
    def size(self) -> int:
        return len(self.body)

    @property
    def received_iso(self) -> str:
        return iso(self.received_at)

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_map(self) -> dict[str, str]:
        """Lower-case name -> first value."""
        out: dict[str, str] = {}
        for key, value in self.headers:
            out.setdefault(key.lower(), value)
        return out


@dataclass
class Replay:
    id: int
    request_id: int
    target: str
    resigned: bool
    sent_at: float
    status_code: int | None
    error: str | None
    elapsed_ms: float | None

    @property
    def sent_iso(self) -> str:
        return iso(self.sent_at)


class Store:
    def __init__(self, path: str | Path, retention: int = 1000) -> None:
        self.path = str(path)
        self.retention = retention
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def add(
        self,
        *,
        hook: str,
        method: str,
        path: str,
        query: str,
        headers: list[tuple[str, str]],
        body: bytes,
        client_ip: str | None,
        received_at: float,
        status: str,
        reason: str,
    ) -> int:
        """Insert a request and trim the table to the newest `retention` rows."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO requests (hook, method, path, query, headers, body, client_ip,"
                " received_at, status, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (hook, method, path, query, json.dumps([list(h) for h in headers]),
                 sqlite3.Binary(body), client_ip, received_at, status, reason),
            )
            new_id = int(cur.lastrowid)
            if self.retention > 0:
                conn.execute(
                    "DELETE FROM requests WHERE id <= (SELECT id FROM requests"
                    " ORDER BY id DESC LIMIT 1 OFFSET ?)",
                    (self.retention,),
                )
                conn.execute("DELETE FROM replays WHERE request_id NOT IN (SELECT id FROM requests)")
        return new_id

    def get(self, request_id: int) -> StoredRequest | None:
        with self._conn() as conn:
            row = conn.execute(f"SELECT {_COLUMNS} FROM requests WHERE id = ?", (request_id,)).fetchone()
        return _row(row) if row else None

    def list(self, limit: int = 200, hook: str | None = None) -> list[StoredRequest]:
        sql = f"SELECT {_COLUMNS} FROM requests"
        args: list[object] = []
        if hook:
            sql += " WHERE hook = ?"
            args.append(hook)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._conn() as conn:
            return [_row(r) for r in conn.execute(sql, args).fetchall()]

    def count(self) -> int:
        with self._conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0])

    def add_replay(self, request_id: int, target: str, resigned: bool, sent_at: float,
                   status_code: int | None, error: str | None, elapsed_ms: float | None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO replays (request_id, target, resigned, sent_at, status_code, error,"
                " elapsed_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (request_id, target, int(resigned), sent_at, status_code, error, elapsed_ms),
            )
            return int(cur.lastrowid)

    def replays(self, request_id: int) -> list[Replay]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, request_id, target, resigned, sent_at, status_code, error, elapsed_ms"
                " FROM replays WHERE request_id = ? ORDER BY id DESC",
                (request_id,),
            ).fetchall()
        return [Replay(r[0], r[1], r[2], bool(r[3]), r[4], r[5], r[6], r[7]) for r in rows]


def _row(row: tuple) -> StoredRequest:
    return StoredRequest(
        id=row[0], hook=row[1], method=row[2], path=row[3], query=row[4],
        headers=[(str(k), str(v)) for k, v in json.loads(row[5])],
        body=bytes(row[6]), client_ip=row[7], received_at=row[8], status=row[9], reason=row[10],
    )
