"""
capture.py — The core packet processing pipeline.

Runs as a background asyncio task:
  1. Reads packets from a PCAP file
  2. Parses each packet (packet_parser.py)
  3. Extracts SNI / HTTP Host / DNS (sni_extractor.py)
  4. Classifies app (app_classifier.py)
  5. Checks blocking rules (rule_manager.py)
  6. Updates flow table (flow_tracker.py)
  7. Broadcasts a JSON event to all connected WebSocket clients

No database — everything runs in memory.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Optional

# Absolute imports — works whether run as a package or from backend/ root
try:
    from engine.packet_parser import PcapReader, PacketParser
    from engine.sni_extractor import extract_sni, extract_http_host, extract_dns_query, extract_quic_sni
    from engine.app_classifier import sni_to_app, port_to_app
    from engine.flow_tracker import FlowTracker
    from engine.rule_manager import RuleManager
    from api.broadcaster import Broadcaster
except ImportError:
    # Fallback for local development where backend is a package
    from ..engine.packet_parser import PcapReader, PacketParser  # type: ignore
    from ..engine.sni_extractor import extract_sni, extract_http_host, extract_dns_query, extract_quic_sni  # type: ignore
    from ..engine.app_classifier import sni_to_app, port_to_app  # type: ignore
    from ..engine.flow_tracker import FlowTracker  # type: ignore
    from ..engine.rule_manager import RuleManager  # type: ignore
    from .broadcaster import Broadcaster  # type: ignore

# ── Shared singletons (imported by FastAPI routes) ────────────────────────────
flow_tracker = FlowTracker()
rule_manager = RuleManager()
broadcaster  = Broadcaster()

# ── Session state ─────────────────────────────────────────────────────────────
class SessionState:
    def __init__(self):
        self.running:       bool = False
        self.session_id:    str  = ""
        self.total_packets: int  = 0
        self.total_bytes:   int  = 0
        self.dropped:       int  = 0
        self.start_time:  float  = 0.0
        self._task: Optional[asyncio.Task] = None

    def reset(self):
        self.total_packets = 0
        self.total_bytes   = 0
        self.dropped       = 0
        self.session_id    = str(uuid.uuid4())
        self.start_time    = time.time()

session = SessionState()


# ── PCAP Processing ───────────────────────────────────────────────────────────
async def process_pcap(pcap_path: str):
    """Process a PCAP file and stream results to WebSocket clients."""
    session.reset()
    session.running = True
    flow_tracker.clear()

    try:
        with PcapReader(pcap_path) as reader:
            for raw_pkt in reader:
                if not session.running:
                    break

                parsed = PacketParser.parse(raw_pkt)
                if parsed is None or not parsed.has_ip:
                    continue
                if not parsed.has_tcp and not parsed.has_udp:
                    continue

                # ── SNI / Host extraction ─────────────────────────────────────
                sni = ""
                payload = parsed.payload

                if parsed.has_tcp and parsed.dst_port == 443 and payload:
                    sni = extract_sni(payload) or ""
                    if not sni:
                        sni = extract_quic_sni(payload) or ""

                if parsed.has_tcp and parsed.dst_port == 80 and not sni and payload:
                    sni = extract_http_host(payload) or ""

                if (parsed.has_udp and (parsed.dst_port == 53 or parsed.src_port == 53)
                        and not sni and payload):
                    sni = extract_dns_query(payload) or ""

                # ── App classification ────────────────────────────────────────
                app = sni_to_app(sni) if sni else port_to_app(parsed.dst_port, parsed.protocol_name)

                # ── Flow tracking ─────────────────────────────────────────────
                tup = parsed.five_tuple
                flow = flow_tracker.update(tup, len(raw_pkt.data))
                if flow.sni == "" and sni:
                    flow.sni = sni
                if flow.app in ("Unknown", "HTTPS", "HTTP") and app not in ("Unknown",):
                    flow.app = app

                # ── Blocking ──────────────────────────────────────────────────
                reason = rule_manager.should_block(
                    parsed.src_ip, parsed.dst_port, flow.app, flow.sni
                )
                action = "DROP" if reason else "FORWARD"
                if reason and not flow.blocked:
                    flow.blocked = True
                    flow.block_reason = reason

                # ── Stats ─────────────────────────────────────────────────────
                session.total_packets += 1
                session.total_bytes   += len(raw_pkt.data)
                if action == "DROP":
                    session.dropped += 1

                # ── Build and broadcast event ─────────────────────────────────
                event = {
                    "event":    "block" if (reason and flow.packets == 1) else "packet",
                    "ts":       raw_pkt.ts_sec + raw_pkt.ts_usec / 1_000_000,
                    "src_ip":   parsed.src_ip,
                    "dst_ip":   parsed.dst_ip,
                    "src_port": parsed.src_port,
                    "dst_port": parsed.dst_port,
                    "protocol": parsed.protocol_name,
                    "app":      flow.app,
                    "sni":      flow.sni,
                    "bytes":    len(raw_pkt.data),
                    "action":   action,
                    "block_reason": reason or "",
                    "tcp_flags": parsed.tcp_flags if parsed.has_tcp else 0,
                }

                await broadcaster.broadcast(event)

                # Tiny yield to keep the event loop responsive
                await asyncio.sleep(0)

        # ── Session complete ──────────────────────────────────────────────────
        summary = {
            "event":         "done",
            "total_packets": session.total_packets,
            "total_bytes":   session.total_bytes,
            "dropped":       session.dropped,
            "active_flows":  flow_tracker.total_count(),
            "app_breakdown": flow_tracker.app_breakdown(),
            "duration_sec":  round(time.time() - session.start_time, 2),
        }
        await broadcaster.broadcast(summary)

    except Exception as exc:
        await broadcaster.broadcast({"event": "error", "message": str(exc)})
    finally:
        session.running = False


def start_pcap_task(pcap_path: str) -> asyncio.Task:
    """Launch process_pcap as a background asyncio task."""
    task = asyncio.create_task(process_pcap(pcap_path))
    session._task = task
    return task


def stop_capture():
    session.running = False
    if session._task and not session._task.done():
        session._task.cancel()
