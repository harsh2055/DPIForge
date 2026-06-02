"""
sni_extractor.py — Python port of sni_extractor.cpp

Extracts:
  - TLS SNI from ClientHello records
  - HTTP Host header from plaintext HTTP
  - DNS query name from UDP DNS packets
"""

from __future__ import annotations

from typing import Optional


# ── TLS constants ─────────────────────────────────────────────────────────────
TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXT_SNI = 0x0000
TLS_SNI_TYPE_HOSTNAME = 0x00


def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello and return the SNI hostname, or None.
    Direct port of SNIExtractor::extract() from sni_extractor.cpp.
    """
    try:
        if len(payload) < 9:
            return None

        # TLS record header
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return None
        version = (payload[1] << 8) | payload[2]
        if not (0x0300 <= version <= 0x0304):
            return None
        record_len = (payload[3] << 8) | payload[4]
        if record_len > len(payload) - 5:
            return None

        # Handshake header
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        offset = 9   # skip: 5-byte record header + 1-byte handshake type + 3-byte handshake length

        # Client version (2 bytes)
        offset += 2
        # Random (32 bytes)
        offset += 32

        if offset >= len(payload):
            return None

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(payload):
            return None
        cipher_len = (payload[offset] << 8) | payload[offset + 1]
        offset += 2 + cipher_len

        # Compression methods
        if offset >= len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(payload):
            return None
        ext_total = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        ext_end = min(offset + ext_total, len(payload))

        while offset + 4 <= ext_end:
            ext_type = (payload[offset] << 8) | payload[offset + 1]
            ext_len  = (payload[offset + 2] << 8) | payload[offset + 3]
            offset  += 4

            if offset + ext_len > ext_end:
                break

            if ext_type == TLS_EXT_SNI and ext_len >= 5:
                # SNI list length (2) + type (1) + SNI length (2) + value
                sni_type   = payload[offset + 2]
                sni_len    = (payload[offset + 3] << 8) | payload[offset + 4]
                if sni_type == TLS_SNI_TYPE_HOSTNAME and sni_len <= ext_len - 5:
                    return payload[offset + 5: offset + 5 + sni_len].decode("ascii", errors="replace")

            offset += ext_len

    except (IndexError, struct.error):
        pass

    return None


# ── HTTP Host extractor ───────────────────────────────────────────────────────
_HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def extract_http_host(payload: bytes) -> Optional[str]:
    """
    Extract the HTTP Host header value from a raw TCP payload.
    Port of HTTPHostExtractor::extract().
    """
    if len(payload) < 4:
        return None
    if not any(payload.startswith(m) for m in _HTTP_METHODS):
        return None

    # Search for 'host:' (case-insensitive)
    lower = payload.lower()
    idx = lower.find(b"host:")
    if idx == -1:
        return None
    start = idx + 5
    # Skip optional whitespace
    while start < len(payload) and payload[start] in (ord(' '), ord('\t')):
        start += 1
    end = start
    while end < len(payload) and payload[end] not in (ord('\r'), ord('\n')):
        end += 1
    host = payload[start:end].decode("ascii", errors="replace").strip()
    # Strip port if present
    if ':' in host:
        host = host.split(':', 1)[0]
    return host or None


# ── DNS query extractor ───────────────────────────────────────────────────────
def extract_dns_query(payload: bytes) -> Optional[str]:
    """
    Extract the first DNS query name from a UDP DNS payload.
    Port of DNSExtractor::extractQuery().
    """
    try:
        if len(payload) < 12:
            return None
        flags = payload[2]
        if flags & 0x80:    # QR bit set → response, not a query
            return None
        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return None

        offset = 12
        labels: list[str] = []
        while offset < len(payload):
            llen = payload[offset]
            if llen == 0:
                break
            if llen > 63:   # pointer or invalid
                break
            offset += 1
            labels.append(payload[offset: offset + llen].decode("ascii", errors="replace"))
            offset += llen
        return ".".join(labels) if labels else None
    except IndexError:
        return None


# ── QUIC heuristic SNI ────────────────────────────────────────────────────────
def extract_quic_sni(payload: bytes) -> Optional[str]:
    """
    Heuristic: scan QUIC Initial packet for embedded TLS ClientHello.
    Port of QUICSNIExtractor::extract().
    """
    if len(payload) < 5:
        return None
    if not (payload[0] & 0x80):   # must be long header
        return None
    # Scan for TLS ClientHello type byte
    for i in range(len(payload) - 50):
        if payload[i] == TLS_HANDSHAKE_CLIENT_HELLO:
            prefix_offset = max(0, i - 5)
            result = extract_sni(payload[prefix_offset:])
            if result:
                return result
    return None


import struct  # needed by extract_sni try/except
