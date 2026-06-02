from backend.engine.packet_parser import PcapReader, PacketParser
from backend.engine.sni_extractor import extract_sni, extract_http_host, extract_dns_query
from backend.engine.app_classifier import sni_to_app
from backend.engine.flow_tracker import FlowTracker
from backend.engine.rule_manager import RuleManager

tracker = FlowTracker()
rm = RuleManager()
rm.block_app("YouTube")

with PcapReader("test_dpi.pcap") as r:
    for raw in r:
        p = PacketParser.parse(raw)
        if not p or not p.has_ip:
            continue
        if not p.has_tcp and not p.has_udp:
            continue

        sni = ""
        if p.has_tcp and p.dst_port == 443 and p.payload:
            sni = extract_sni(p.payload) or ""
        if p.has_tcp and p.dst_port == 80 and not sni and p.payload:
            sni = extract_http_host(p.payload) or ""
        if p.has_udp and (p.dst_port == 53 or p.src_port == 53) and not sni and p.payload:
            sni = extract_dns_query(p.payload) or ""

        app = sni_to_app(sni) if sni else ("HTTPS" if p.dst_port == 443 else "HTTP" if p.dst_port == 80 else "Unknown")
        flow = tracker.update(p.five_tuple, len(raw.data))
        if sni and not flow.sni:
            flow.sni = sni
        if app not in ("Unknown",):
            flow.app = app

        reason = rm.should_block(p.src_ip, p.dst_port, flow.app, flow.sni)
        if reason and not flow.blocked:
            flow.blocked = True
            flow.block_reason = reason

print()
print("=== RESULTS ===")
print(f"Total flows: {tracker.total_count()}")
print(f"App breakdown: {tracker.app_breakdown()}")
print()
print("Unique SNIs detected:")
seen = set()
for f in tracker.get_all():
    if f["sni"] and f["sni"] not in seen:
        seen.add(f["sni"])
        blocked_str = f" [BLOCKED: {f['block_reason']}]" if f["blocked"] else ""
        print(f"  {f['sni']} -> {f['app']}{blocked_str}")
