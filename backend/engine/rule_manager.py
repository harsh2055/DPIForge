"""
rule_manager.py — Python port of rule_manager.cpp

Manages blocking rules:
  - IP addresses
  - Domains (exact + wildcard *.example.com)
  - Application names (e.g., "YouTube", "Netflix")
  - Port numbers

Thread-safe via RLock.
"""

from __future__ import annotations

import fnmatch
import threading
from typing import Optional


class RuleManager:

    def __init__(self):
        self._lock = threading.RLock()
        self._blocked_ips:     set[str] = set()
        self._blocked_apps:    set[str] = set()
        self._blocked_domains: set[str] = set()   # exact + wildcard patterns
        self._blocked_ports:   set[int] = set()

    # ── IP rules ──────────────────────────────────────────────────────────────
    def block_ip(self, ip: str):
        with self._lock:
            self._blocked_ips.add(ip.strip())

    def unblock_ip(self, ip: str):
        with self._lock:
            self._blocked_ips.discard(ip.strip())

    def is_ip_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips

    # ── App rules ─────────────────────────────────────────────────────────────
    def block_app(self, app: str):
        with self._lock:
            self._blocked_apps.add(app.strip().lower())

    def unblock_app(self, app: str):
        with self._lock:
            self._blocked_apps.discard(app.strip().lower())

    def is_app_blocked(self, app: str) -> bool:
        with self._lock:
            return app.strip().lower() in self._blocked_apps

    # ── Domain rules ──────────────────────────────────────────────────────────
    def block_domain(self, domain: str):
        with self._lock:
            self._blocked_domains.add(domain.strip().lower())

    def unblock_domain(self, domain: str):
        with self._lock:
            self._blocked_domains.discard(domain.strip().lower())

    def is_domain_blocked(self, domain: str) -> bool:
        """Supports exact match and wildcard patterns like *.example.com"""
        if not domain:
            return False
        lower = domain.lower()
        with self._lock:
            for pattern in self._blocked_domains:
                if pattern == lower:
                    return True
                if fnmatch.fnmatch(lower, pattern):
                    return True
        return False

    # ── Port rules ────────────────────────────────────────────────────────────
    def block_port(self, port: int):
        with self._lock:
            self._blocked_ports.add(port)

    def unblock_port(self, port: int):
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._lock:
            return port in self._blocked_ports

    # ── Combined check ────────────────────────────────────────────────────────
    def should_block(self, src_ip: str, dst_port: int, app: str, sni: str) -> Optional[str]:
        """
        Returns a block reason string, or None if traffic should be forwarded.
        Priority: IP → Port → App → Domain.
        """
        if self.is_ip_blocked(src_ip):
            return f"Blocked IP: {src_ip}"
        if self.is_port_blocked(dst_port):
            return f"Blocked Port: {dst_port}"
        if self.is_app_blocked(app):
            return f"Blocked App: {app}"
        if sni and self.is_domain_blocked(sni):
            return f"Blocked Domain: {sni}"
        return None

    # ── Serialisation ─────────────────────────────────────────────────────────
    def get_all_rules(self) -> dict:
        with self._lock:
            return {
                "ips":     sorted(self._blocked_ips),
                "apps":    sorted(self._blocked_apps),
                "domains": sorted(self._blocked_domains),
                "ports":   sorted(self._blocked_ports),
            }

    def clear_all(self):
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._blocked_ports.clear()
