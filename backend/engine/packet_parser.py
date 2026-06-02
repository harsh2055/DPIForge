"""
packet_parser.py — Python port of packet_parser.cpp + pcap_reader.cpp

Provides:
  - PcapReader : iterator over raw packets in a .pcap file
  - PacketParser.parse() : Ethernet → IPv4 → TCP/UDP → ParsedPacket
"""

from __future__ import annotations

import struct
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional


# ── PCAP file constants ───────────────────────────────────────────────────────
PCAP_GLOBAL_MAGIC = 0xA1B2C3D4
PCAP_GLOBAL_MAGIC_NS = 0xA1B23C4D   # nanosecond variant
PCAP_GLOBAL_HEADER_FMT = "=IHHiIII"  # 24 bytes
PCAP_PKT_HEADER_FMT = "=IIII"        # 16 bytes

ETHERTYPE_IPV4 = 0x0800
PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class RawPacket:
    ts_sec:  int
    ts_usec: int   # microseconds (or nanoseconds for ns variant)
    data:    bytes


@dataclass
class ParsedPacket:
    # Timing
    ts_sec:   int = 0
    ts_usec:  int = 0

    # Ethernet
    src_mac:    str = ""
    dst_mac:    str = ""
    ether_type: int = 0

    # IPv4
    has_ip:    bool = False
    ip_ver:    int  = 0
    ttl:       int  = 0
    protocol:  int  = 0
    src_ip:    str  = ""
    dst_ip:    str  = ""

    # TCP
    has_tcp:    bool = False
    src_port:   int  = 0
    dst_port:   int  = 0
    seq_num:    int  = 0
    ack_num:    int  = 0
    tcp_flags:  int  = 0

    # UDP
    has_udp: bool = False

    # Payload
    payload: bytes = field(default_factory=bytes)

    @property
    def protocol_name(self) -> str:
        if self.has_tcp: return "TCP"
        if self.has_udp: return "UDP"
        return {PROTO_ICMP: "ICMP"}.get(self.protocol, f"PROTO_{self.protocol}")

    @property
    def five_tuple(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol_name)


# ── PCAP Reader ────────────────────────────────────────────────────────────────
class PcapReader:
    """Iterate over packets in a .pcap file (classic format, little or big endian)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._f = open(self.path, "rb")
        self._swap = False
        self._read_global_header()

    def _read_global_header(self):
        raw = self._f.read(24)
        if len(raw) < 24:
            raise ValueError("File too small to be a valid PCAP")
        magic = struct.unpack_from("<I", raw)[0]
        if magic in (PCAP_GLOBAL_MAGIC, PCAP_GLOBAL_MAGIC_NS):
            self._fmt = "<IIII"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            self._fmt = ">IIII"
        else:
            raise ValueError(f"Not a valid PCAP file (magic={magic:#010x})")

    def __iter__(self) -> Generator[RawPacket, None, None]:
        return self._read_packets()

    def _read_packets(self) -> Generator[RawPacket, None, None]:
        hdr_size = struct.calcsize(self._fmt)
        while True:
            raw_hdr = self._f.read(hdr_size)
            if len(raw_hdr) < hdr_size:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(self._fmt, raw_hdr)
            data = self._f.read(incl_len)
            if len(data) < incl_len:
                break
            yield RawPacket(ts_sec=ts_sec, ts_usec=ts_usec, data=data)

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── Packet Parser ──────────────────────────────────────────────────────────────
class PacketParser:
    """Parse a RawPacket byte-by-byte, just like packet_parser.cpp."""

    ETH_HEADER_LEN = 14
    MIN_IP_HEADER  = 20
    MIN_TCP_HEADER = 20
    UDP_HEADER_LEN = 8

    @classmethod
    def parse(cls, pkt: RawPacket) -> Optional[ParsedPacket]:
        parsed = ParsedPacket(ts_sec=pkt.ts_sec, ts_usec=pkt.ts_usec)
        data = pkt.data
        offset = 0

        # ── Ethernet ─────────────────────────────────────────────────────────
        if len(data) < cls.ETH_HEADER_LEN:
            return None
        parsed.dst_mac = cls._mac(data[0:6])
        parsed.src_mac = cls._mac(data[6:12])
        parsed.ether_type = struct.unpack_from(">H", data, 12)[0]
        offset = cls.ETH_HEADER_LEN

        if parsed.ether_type != ETHERTYPE_IPV4:
            return None  # Only handle IPv4 for now

        # ── IPv4 ──────────────────────────────────────────────────────────────
        if len(data) < offset + cls.MIN_IP_HEADER:
            return None
        version_ihl = data[offset]
        parsed.ip_ver = (version_ihl >> 4) & 0x0F
        ihl = (version_ihl & 0x0F) * 4
        if parsed.ip_ver != 4 or ihl < cls.MIN_IP_HEADER:
            return None
        parsed.ttl      = data[offset + 8]
        parsed.protocol = data[offset + 9]
        parsed.src_ip   = socket.inet_ntoa(data[offset + 12: offset + 16])
        parsed.dst_ip   = socket.inet_ntoa(data[offset + 16: offset + 20])
        parsed.has_ip   = True
        offset += ihl

        # ── TCP ───────────────────────────────────────────────────────────────
        if parsed.protocol == PROTO_TCP:
            if len(data) < offset + cls.MIN_TCP_HEADER:
                return None
            parsed.src_port = struct.unpack_from(">H", data, offset)[0]
            parsed.dst_port = struct.unpack_from(">H", data, offset + 2)[0]
            parsed.seq_num  = struct.unpack_from(">I", data, offset + 4)[0]
            parsed.ack_num  = struct.unpack_from(">I", data, offset + 8)[0]
            data_offset     = (data[offset + 12] >> 4) * 4
            parsed.tcp_flags = data[offset + 13]
            parsed.has_tcp   = True
            offset += data_offset

        # ── UDP ───────────────────────────────────────────────────────────────
        elif parsed.protocol == PROTO_UDP:
            if len(data) < offset + cls.UDP_HEADER_LEN:
                return None
            parsed.src_port = struct.unpack_from(">H", data, offset)[0]
            parsed.dst_port = struct.unpack_from(">H", data, offset + 2)[0]
            parsed.has_udp  = True
            offset += cls.UDP_HEADER_LEN

        parsed.payload = data[offset:]
        return parsed

    @staticmethod
    def _mac(b: bytes) -> str:
        return ":".join(f"{x:02x}" for x in b)


# ── TCP flag helpers ───────────────────────────────────────────────────────────
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def tcp_flags_str(flags: int) -> str:
    names = []
    if flags & TCP_SYN: names.append("SYN")
    if flags & TCP_ACK: names.append("ACK")
    if flags & TCP_FIN: names.append("FIN")
    if flags & TCP_RST: names.append("RST")
    if flags & TCP_PSH: names.append("PSH")
    if flags & TCP_URG: names.append("URG")
    return "|".join(names) or "none"
