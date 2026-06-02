"""
flow_tracker.py — Thread-safe 5-tuple flow state table.

Python port of connection_tracker.cpp logic from the DPI engine.
Tracks per-flow stats: packets, bytes, SNI, app classification, block state.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# 5-tuple type: (src_ip, dst_ip, src_port, dst_port, protocol)
FiveTuple = Tuple[str, str, int, int, str]


@dataclass
class Flow:
    tuple_: FiveTuple
    app:       str = "Unknown"
    sni:       str = ""
    packets:   int = 0
    bytes_:    int = 0
    blocked:   bool = False
    block_reason: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        src_ip, dst_ip, src_port, dst_port, proto = self.tuple_
        return {
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  proto,
            "app":       self.app,
            "sni":       self.sni,
            "packets":   self.packets,
            "bytes":     self.bytes_,
            "blocked":   self.blocked,
            "block_reason": self.block_reason,
            "first_seen":   self.first_seen,
            "last_seen":    self.last_seen,
        }


class FlowTracker:
    """Thread-safe flow table keyed by 5-tuple."""

    def __init__(self, timeout_sec: int = 120):
        self._flows: Dict[FiveTuple, Flow] = {}
        self._lock = threading.RLock()
        self._timeout = timeout_sec

    def get_or_create(self, tup: FiveTuple) -> Flow:
        with self._lock:
            if tup not in self._flows:
                self._flows[tup] = Flow(tuple_=tup)
            return self._flows[tup]

    def update(self, tup: FiveTuple, nbytes: int) -> Flow:
        with self._lock:
            flow = self.get_or_create(tup)
            flow.packets  += 1
            flow.bytes_   += nbytes
            flow.last_seen = time.time()
            return flow

    def get_all(self) -> list[dict]:
        with self._lock:
            return [f.to_dict() for f in self._flows.values()]

    def active_count(self) -> int:
        with self._lock:
            now = time.time()
            return sum(1 for f in self._flows.values()
                       if now - f.last_seen < self._timeout)

    def total_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def clear(self):
        with self._lock:
            self._flows.clear()

    def app_breakdown(self) -> dict[str, int]:
        """Return {app_name: packet_count} dict."""
        with self._lock:
            result: dict[str, int] = {}
            for f in self._flows.values():
                result[f.app] = result.get(f.app, 0) + f.packets
            return result
