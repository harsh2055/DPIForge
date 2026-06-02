"""
app_classifier.py — Python port of types.cpp sniToAppType()
Maps SNI/domain strings to known application names.
"""

from __future__ import annotations

# ── Known application names ─────────────────────────────────────────────────
KNOWN_APPS = [
    "Unknown", "HTTP", "HTTPS", "DNS", "TLS", "QUIC",
    "Google", "Facebook", "YouTube", "Twitter/X", "Instagram",
    "Netflix", "Amazon", "Microsoft", "Apple", "WhatsApp",
    "Telegram", "TikTok", "Spotify", "Zoom", "Discord",
    "GitHub", "Cloudflare",
]

# ── SNI → App mapping rules (order matters — more specific first) ─────────────
_RULES: list[tuple[list[str], str]] = [
    # YouTube (check before Google — both share gstatic etc.)
    (["youtube", "ytimg", "youtu.be", "yt3.ggpht"], "YouTube"),
    # Google
    (["google", "gstatic", "googleapis", "ggpht", "gvt1"], "Google"),
    # Instagram (check before Facebook)
    (["instagram", "cdninstagram"], "Instagram"),
    # WhatsApp (check before Facebook)
    (["whatsapp", "wa.me"], "WhatsApp"),
    # Facebook / Meta
    (["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"], "Facebook"),
    # Twitter / X
    (["twitter", "twimg", "x.com", "t.co"], "Twitter/X"),
    # Netflix
    (["netflix", "nflxvideo", "nflximg"], "Netflix"),
    # Amazon / AWS
    (["amazon", "amazonaws", "cloudfront", "aws"], "Amazon"),
    # Microsoft
    (["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"], "Microsoft"),
    # Apple
    (["apple", "icloud", "mzstatic", "itunes"], "Apple"),
    # Telegram
    (["telegram", "t.me"], "Telegram"),
    # TikTok
    (["tiktok", "tiktokcdn", "musical.ly", "bytedance"], "TikTok"),
    # Spotify
    (["spotify", "scdn.co"], "Spotify"),
    # Zoom
    (["zoom.us", "zoomgov", "zoom"], "Zoom"),
    # Discord
    (["discord", "discordapp"], "Discord"),
    # GitHub
    (["github", "githubusercontent"], "GitHub"),
    # Cloudflare
    (["cloudflare", "cf-"], "Cloudflare"),
]


def sni_to_app(sni: str) -> str:
    """Map a Server Name Indication string to a known app name."""
    if not sni:
        return "Unknown"
    lower = sni.lower()
    for keywords, app in _RULES:
        if any(kw in lower for kw in keywords):
            return app
    return "HTTPS"  # SNI present but unrecognised → still TLS/HTTPS


def port_to_app(dst_port: int, protocol: str) -> str:
    """Fallback classification by port number."""
    if dst_port == 443:
        return "HTTPS"
    if dst_port == 80:
        return "HTTP"
    if dst_port in (53, 5353) or protocol == "UDP":
        return "DNS"
    return "Unknown"
