"""
main.py — FastAPI application entry point.

Routes:
  POST /api/capture/upload      — Upload a PCAP file and start processing
  POST /api/capture/stop        — Stop a running capture
  GET  /api/capture/status      — Current session status

  GET  /api/rules               — Get all blocking rules
  POST /api/rules               — Add a blocking rule
  DELETE /api/rules/{type}/{value} — Remove a blocking rule

  GET  /api/stats/summary       — Live session stats
  GET  /api/stats/flows         — Active flows list
  GET  /api/stats/history       — Historical sessions from DB
  GET  /api/stats/app-history   — Per-session app breakdown

  WS   /ws/live                 — Live packet event stream
"""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .capture import (
    flow_tracker, rule_manager, broadcaster, session,
    start_pcap_task, stop_capture,
)
from ..db.database import db


# ── Lifespan (DB connect/close) ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    await db.close()


app = FastAPI(title="DPI Packet Analyzer API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket endpoint ────────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await broadcaster.connect(websocket)
    try:
        while True:
            # Keep connection open; client can send pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        await broadcaster.disconnect(websocket)


# ── Capture endpoints ─────────────────────────────────────────────────────────
@app.post("/api/capture/upload")
async def upload_pcap(file: UploadFile = File(...)):
    if session.running:
        raise HTTPException(status_code=409, detail="A capture is already running. Stop it first.")

    # Save upload to a temp file
    suffix = ".pcap"
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    shutil.copyfileobj(file.file, tmp)
    tmp.close()

    start_pcap_task(tmp.name)
    return {"status": "started", "session_id": session.session_id, "filename": file.filename}


@app.post("/api/capture/stop")
async def stop_capture_route():
    stop_capture()
    return {"status": "stopped"}


@app.get("/api/capture/status")
async def capture_status():
    return {
        "running":       session.running,
        "session_id":    session.session_id,
        "total_packets": session.total_packets,
        "total_bytes":   session.total_bytes,
        "dropped":       session.dropped,
        "ws_clients":    broadcaster.client_count(),
    }


# ── Rules endpoints ───────────────────────────────────────────────────────────
class RuleIn(BaseModel):
    type:  str   # "ip" | "app" | "domain" | "port"
    value: str


@app.get("/api/rules")
async def get_rules():
    return rule_manager.get_all_rules()


@app.post("/api/rules")
async def add_rule(rule: RuleIn):
    t, v = rule.type.lower(), rule.value.strip()
    if t == "ip":
        rule_manager.block_ip(v)
    elif t == "app":
        rule_manager.block_app(v)
    elif t == "domain":
        rule_manager.block_domain(v)
    elif t == "port":
        rule_manager.block_port(int(v))
    else:
        raise HTTPException(400, "type must be ip | app | domain | port")

    # Persist to DB
    await db._db.execute(
        "INSERT INTO block_rules (type, value, active, created_at) VALUES (?,?,1,strftime('%s','now'))",
        (t, v)
    )
    await db._db.commit()

    await broadcaster.broadcast({"event": "rule_added", "type": t, "value": v})
    return {"status": "ok", "type": t, "value": v}


@app.delete("/api/rules/{rule_type}/{value}")
async def delete_rule(rule_type: str, value: str):
    t = rule_type.lower()
    if t == "ip":      rule_manager.unblock_ip(value)
    elif t == "app":   rule_manager.unblock_app(value)
    elif t == "domain": rule_manager.unblock_domain(value)
    elif t == "port":  rule_manager.unblock_port(int(value))
    else:
        raise HTTPException(400, "type must be ip | app | domain | port")

    await broadcaster.broadcast({"event": "rule_removed", "type": t, "value": value})
    return {"status": "ok"}


@app.delete("/api/rules")
async def clear_rules():
    rule_manager.clear_all()
    await broadcaster.broadcast({"event": "rules_cleared"})
    return {"status": "cleared"}


# ── Stats endpoints ───────────────────────────────────────────────────────────
@app.get("/api/stats/summary")
async def stats_summary():
    return {
        "total_packets":  session.total_packets,
        "total_bytes":    session.total_bytes,
        "dropped":        session.dropped,
        "active_flows":   flow_tracker.active_count(),
        "total_flows":    flow_tracker.total_count(),
        "app_breakdown":  flow_tracker.app_breakdown(),
        "running":        session.running,
    }


@app.get("/api/stats/flows")
async def stats_flows(limit: int = 200):
    return flow_tracker.get_all()[:limit]


@app.get("/api/stats/history")
async def stats_history(limit: int = 20):
    return await db.get_sessions(limit)


@app.get("/api/stats/app-history")
async def stats_app_history():
    return await db.get_app_history()


@app.get("/api/stats/db-flows")
async def stats_db_flows(session_id: Optional[str] = None, limit: int = 200):
    return await db.get_flows(session_id, limit)


@app.get("/")
async def root():
    return {"message": "DPI Packet Analyzer API v2.0 — connect your frontend to /ws/live"}
