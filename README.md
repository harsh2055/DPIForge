# DPIForge — Deep Packet Inspector

> A full-stack network traffic analyzer with real-time TLS SNI extraction, application classification, live WebSocket streaming, and a dark cyberpunk dashboard.

![DPIForge Dashboard](https://img.shields.io/badge/Stack-Python%20%2B%20Next.js-00c8ff?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)
![Next.js](https://img.shields.io/badge/Frontend-Next.js%2016-000000?style=for-the-badge&logo=next.js)
![License](https://img.shields.io/badge/License-MIT-b06aff?style=for-the-badge)

---

## What is DPIForge?

**DPIForge** is a Deep Packet Inspection (DPI) system rewritten from C++ into a modern full-stack web application. It reads `.pcap` capture files, extracts 5-tuple network flows, identifies applications from TLS Server Name Indication (SNI) and HTTP Host headers, enforces live blocking rules, and streams everything in real-time to a live dashboard.

### Original C++ → New Python/Next.js Architecture

| Old (C++) | New (Python + Next.js) |
|---|---|
| `pcap_reader.cpp` + `packet_parser.cpp` | `backend/engine/packet_parser.py` |
| `sni_extractor.cpp` | `backend/engine/sni_extractor.py` |
| `types.cpp` (sniToAppType) | `backend/engine/app_classifier.py` |
| `connection_tracker.cpp` | `backend/engine/flow_tracker.py` |
| `rule_manager.cpp` | `backend/engine/rule_manager.py` |
| CLI output only | Full-stack React dashboard |
| No persistence | SQLite via aiosqlite |

---

## Architecture

```
┌──────────────────────────────────┐
│       Next.js Dashboard          │  ← Port 3000
│  Dark Cyberpunk UI / Vanilla CSS │
└────────────┬─────────────────────┘
             │ WebSocket  /ws/live
             │ REST API   /api/…
┌────────────▼─────────────────────┐
│     FastAPI Backend              │  ← Port 8000
│  ┌──────────────────────────────┐│
│  │  packet_parser.py            ││  Ethernet → IPv4 → TCP/UDP
│  │  sni_extractor.py            ││  TLS ClientHello → SNI
│  │  app_classifier.py           ││  SNI → App name (22 apps)
│  │  flow_tracker.py             ││  5-tuple flow state table
│  │  rule_manager.py             ││  Block IP/domain/app/port
│  └──────────────────────────────┘│
└────────────┬─────────────────────┘
             │ aiosqlite
┌────────────▼─────────────────────┐
│        SQLite (dpi.db)           │
│  flows · sessions · block_rules  │
└──────────────────────────────────┘
```

---

## Features

- **PCAP File Analysis** — drag-and-drop `.pcap` / `.pcapng` files in the browser
- **TLS SNI Extraction** — parses TLS ClientHello records byte-by-byte to pull Server Name Indication
- **HTTP Host Extraction** — reads plaintext HTTP `Host:` headers
- **DNS Query Extraction** — pulls domain names from UDP DNS packets
- **QUIC Heuristic** — scans QUIC Initial packets for embedded TLS ClientHello
- **22 App Classifications** — YouTube, Netflix, Discord, Spotify, Telegram, TikTok, GitHub, Zoom…
- **Live WebSocket Stream** — every packet event pushed to all connected browsers instantly
- **Live Block Rules** — add/remove IP, domain (wildcard `*.`), app, or port blocks at runtime
- **SQLite Persistence** — flows, sessions, and rules stored in `backend/dpi.db`
- **Dark Cyberpunk Dashboard** — JetBrains Mono data font, neon cyan/magenta accents, animated rows

---

## Project Structure

```
DPIForge/
├── backend/
│   ├── engine/
│   │   ├── packet_parser.py      # PCAP reading + Ethernet/IP/TCP/UDP parsing
│   │   ├── sni_extractor.py      # TLS SNI, HTTP Host, DNS, QUIC extraction
│   │   ├── app_classifier.py     # SNI → App name mapping (22 apps)
│   │   ├── flow_tracker.py       # Thread-safe 5-tuple flow state table
│   │   └── rule_manager.py       # In-memory block rules (IP/domain/app/port)
│   ├── api/
│   │   ├── main.py               # FastAPI app — all routes + WebSocket
│   │   ├── capture.py            # Core packet processing pipeline
│   │   └── broadcaster.py        # WebSocket fan-out to all clients
│   ├── db/
│   │   └── database.py           # aiosqlite DB layer
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── app/
│       │   ├── layout.tsx         # Root layout + SEO metadata
│       │   ├── page.tsx           # Main dashboard (3-column layout)
│       │   ├── globals.css        # Full design system (cyberpunk theme)
│       │   └── page.module.css
│       ├── components/
│       │   ├── Header.tsx         # Sticky header with live status
│       │   ├── PacketFeed.tsx     # Live scrolling packet table
│       │   ├── StatsPanel.tsx     # Counters + app breakdown bar charts
│       │   ├── BlockedFeed.tsx    # Magenta block alert cards
│       │   └── ControlPanel.tsx   # PCAP upload + block rule CRUD
│       └── hooks/
│           └── usePacketStream.ts # WebSocket client hook + API helpers
├── src/                           # Original C++ engine (preserved)
├── include/                       # Original C++ headers (preserved)
├── verify_engine.py               # Phase 1 test script
├── test_dpi.pcap                  # Sample capture file
├── start.bat                      # One-click launcher (Windows)
└── README.md
```

---

## Quick Start

### Prerequisites

- **Python 3.10+** — [python.org](https://python.org)
- **Node.js 18+** — [nodejs.org](https://nodejs.org)

### 1. Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the backend

```bash
# From the project root:
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:
- **REST API:** `http://localhost:8000`
- **Interactive Docs:** `http://localhost:8000/docs`
- **WebSocket:** `ws://localhost:8000/ws/live`

### 3. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000** in your browser.

### One-click Windows launch

```
Double-click start.bat
```

---

## Using the Dashboard

1. **Upload a PCAP file** — drag-and-drop into the upload zone, or click to browse
2. **Watch the live feed** — packets stream into the table in real time as they're parsed
3. **Check app breakdown** — the right panel shows which apps are generating traffic
4. **Add block rules** — use the control panel to block by domain, IP, app, or port
5. **Monitor blocks** — blocked flows appear in the red alert feed on the lower-left

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/capture/upload` | Upload and process a PCAP file |
| `POST` | `/api/capture/stop` | Stop a running capture |
| `GET` | `/api/capture/status` | Session status |
| `GET` | `/api/rules` | Get all active block rules |
| `POST` | `/api/rules` | Add a block rule `{ type, value }` |
| `DELETE` | `/api/rules/{type}/{value}` | Remove a specific block rule |
| `GET` | `/api/stats/summary` | Live session statistics |
| `GET` | `/api/stats/flows` | Active flow list |
| `GET` | `/api/stats/history` | Historical sessions from DB |
| `WS` | `/ws/live` | WebSocket — live packet event stream |

### Block rule types

| Type | Example value | Matches |
|------|---------------|---------|
| `ip` | `192.168.1.100` | Exact source IP |
| `domain` | `*.youtube.com` | Domain with wildcard |
| `app` | `YouTube` | Detected application name |
| `port` | `443` | Destination port |

### WebSocket event schema

```json
{
  "event": "packet",
  "ts": 1717300000.123,
  "src_ip": "192.168.1.5",
  "dst_ip": "142.250.80.46",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "app": "YouTube",
  "sni": "www.youtube.com",
  "bytes": 1460,
  "action": "FORWARD"
}
```

Event types: `packet`, `block`, `done`, `error`, `rule_added`, `rule_removed`

---

## How SNI Extraction Works

When your browser connects to `https://youtube.com`, it sends a **TLS ClientHello** packet before any encryption is established. This packet contains a plaintext extension called **Server Name Indication (SNI)** — the domain name the client wants to reach.

DPIForge parses the raw bytes of this handshake:

```
TLS Record Header (5 bytes)
  └── Content Type: 0x16 (Handshake)
  └── Version: 0x0303 (TLS 1.2)
  └── Length: ...

Handshake Header (4 bytes)
  └── Type: 0x01 (ClientHello)
  └── Length: ...

ClientHello Body
  └── Version (2) + Random (32) + Session ID (var)
  └── Cipher Suites (var)
  └── Compression Methods (var)
  └── Extensions (var)
       └── Extension Type 0x0000 (SNI) ← We extract this
            └── Hostname: "www.youtube.com"
```

The same approach is used for HTTP `Host:` headers (plaintext), DNS query names (UDP port 53), and QUIC Initial packets (which embed TLS ClientHello inside CRYPTO frames).

---

## Supported Application Detection

| App | Detection Method |
|-----|-----------------|
| YouTube | SNI contains `youtube`, `ytimg`, `youtu.be` |
| Google | SNI contains `google`, `gstatic`, `googleapis` |
| Netflix | SNI contains `netflix`, `nflxvideo` |
| Facebook | SNI contains `facebook`, `fbcdn`, `meta.com` |
| Instagram | SNI contains `instagram`, `cdninstagram` |
| WhatsApp | SNI contains `whatsapp`, `wa.me` |
| Twitter/X | SNI contains `twitter`, `twimg`, `x.com` |
| Discord | SNI contains `discord`, `discordapp` |
| Spotify | SNI contains `spotify`, `scdn.co` |
| Telegram | SNI contains `telegram`, `t.me` |
| TikTok | SNI contains `tiktok`, `bytedance` |
| Zoom | SNI contains `zoom.us`, `zoomgov` |
| GitHub | SNI contains `github`, `githubusercontent` |
| Amazon | SNI contains `amazon`, `amazonaws` |
| Microsoft | SNI contains `microsoft`, `azure`, `outlook` |
| Apple | SNI contains `apple`, `icloud` |
| Cloudflare | SNI contains `cloudflare` |
| HTTP | Port 80 traffic (plaintext) |
| HTTPS | Port 443, SNI not matched |
| DNS | Port 53 UDP |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet parsing | Pure Python `struct` / `socket` (no Scapy needed for PCAP) |
| Backend framework | FastAPI + uvicorn |
| Real-time transport | WebSockets (native FastAPI) |
| Database | SQLite via aiosqlite |
| Frontend framework | Next.js 16 (App Router, TypeScript) |
| Styling | Vanilla CSS with custom design system |
| Fonts | JetBrains Mono (data), Inter (UI) |

---

## Original C++ Engine

The original multi-threaded C++ DPI engine is preserved in `src/` and `include/`. It supports:
- PCAP file reading and writing
- Multi-threaded packet processing with a load balancer
- Fast-path packet forwarding
- Thread-safe connection tracking
- Blocking rule persistence

Build it with CMake (requires libpcap on Linux or Npcap on Windows):

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
