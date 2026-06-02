"""
database.py — Async SQLite database layer using aiosqlite.

Stores:
  - flows       (per-connection records)
  - block_rules (persisted blocking rules)
  - sessions    (summary per PCAP processing session)
"""

from __future__ import annotations

import json
import time
import aiosqlite
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "dpi.db"

CREATE_FLOWS = """
CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT,
    app          TEXT,
    sni          TEXT,
    bytes        INTEGER,
    packets      INTEGER,
    blocked      INTEGER,
    block_reason TEXT,
    created_at   REAL
)
"""

CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT UNIQUE,
    total_packets   INTEGER,
    total_bytes     INTEGER,
    dropped         INTEGER,
    app_breakdown   TEXT,
    started_at      REAL,
    ended_at        REAL
)
"""

CREATE_RULES = """
CREATE TABLE IF NOT EXISTS block_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT,
    value      TEXT,
    active     INTEGER DEFAULT 1,
    created_at REAL
)
"""


class Database:
    def __init__(self):
        self._db: aiosqlite.Connection | None = None

    async def connect(self):
        self._db = await aiosqlite.connect(DB_PATH)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(CREATE_FLOWS)
        await self._db.execute(CREATE_SESSIONS)
        await self._db.execute(CREATE_RULES)
        await self._db.commit()

    async def close(self):
        if self._db:
            await self._db.close()

    async def save_flow(self, session_id: str, flow):
        src_ip, dst_ip, src_port, dst_port, proto = flow.tuple_
        await self._db.execute(
            """INSERT INTO flows
               (session_id,src_ip,dst_ip,src_port,dst_port,protocol,
                app,sni,bytes,packets,blocked,block_reason,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (session_id, src_ip, dst_ip, src_port, dst_port, proto,
             flow.app, flow.sni, flow.bytes_, flow.packets,
             int(flow.blocked), flow.block_reason, time.time())
        )
        await self._db.commit()

    async def save_session(self, session):
        from .capture import flow_tracker
        breakdown = json.dumps(flow_tracker.app_breakdown())
        await self._db.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id,total_packets,total_bytes,dropped,
                app_breakdown,started_at,ended_at)
               VALUES (?,?,?,?,?,?,?)""",
            (session.session_id, session.total_packets, session.total_bytes,
             session.dropped, breakdown, session.start_time, time.time())
        )
        await self._db.commit()

    async def get_sessions(self, limit: int = 20) -> list[dict]:
        async with self._db.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_flows(self, session_id: str | None = None, limit: int = 500) -> list[dict]:
        if session_id:
            q = "SELECT * FROM flows WHERE session_id=? ORDER BY id DESC LIMIT ?"
            params = (session_id, limit)
        else:
            q = "SELECT * FROM flows ORDER BY id DESC LIMIT ?"
            params = (limit,)
        async with self._db.execute(q, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def get_app_history(self) -> list[dict]:
        """Return per-session app breakdown for the history chart."""
        async with self._db.execute(
            "SELECT session_id, app_breakdown, started_at FROM sessions ORDER BY started_at DESC LIMIT 10"
        ) as cur:
            rows = await cur.fetchall()
            result = []
            for r in rows:
                result.append({
                    "session_id":    r["session_id"],
                    "app_breakdown": json.loads(r["app_breakdown"]),
                    "started_at":    r["started_at"],
                })
            return result


db = Database()
