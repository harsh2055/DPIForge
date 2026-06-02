"use client";

import { useRef } from "react";
import { PacketEvent } from "@/hooks/usePacketStream";
import styles from "./PacketFeed.module.css";

const APP_COLORS: Record<string, string> = {
  YouTube:   "#ff0000", Netflix:  "#e50914", Spotify:  "#1db954",
  Discord:   "#5865f2", GitHub:   "#6e40c9", Zoom:     "#2d8cff",
  Google:    "#4285f4", Facebook: "#1877f2", Instagram:"#e1306c",
  WhatsApp:  "#25d366", Telegram: "#229ed9", TikTok:   "#ff0050",
  Twitter:   "#1da1f2", Amazon:   "#ff9900", Microsoft:"#00a4ef",
  Apple:     "#888888", HTTP:     "#ffb347", HTTPS:    "#00c8ff",
  DNS:       "#b06aff", QUIC:     "#00ff88",
};

function AppChip({ app }: { app: string }) {
  const color = APP_COLORS[app] || "#7a90b8";
  return (
    <span
      className="app-chip"
      style={{
        background: `${color}22`,
        color,
        border: `1px solid ${color}44`,
      }}
    >
      {app}
    </span>
  );
}

interface Props {
  packets: PacketEvent[];
}

export function PacketFeed({ packets }: Props) {
  const tbodyRef = useRef<HTMLTableSectionElement>(null);

  return (
    <div className={styles.wrapper}>
      <div className={styles.header}>
        <span className="section-title">
          <span className="accent">◈</span> Live Packet Feed
        </span>
        <span className={styles.count}>{packets.length} packets</span>
      </div>

      <div className={styles.tableWrap}>
        {packets.length === 0 ? (
          <div className={styles.empty}>
            <span className={styles.emptyIcon}>⬡</span>
            <span>Waiting for packets — upload a PCAP file to begin</span>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Src IP</th>
                <th>Dst IP</th>
                <th>Port</th>
                <th>Proto</th>
                <th>App</th>
                <th className="hide-mobile">SNI / Host</th>
                <th>Bytes</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody ref={tbodyRef}>
              {packets.map((p, i) => (
                <tr
                  key={`${p.ts}-${i}`}
                  className={`row-new ${p.action === "DROP" ? "row-blocked" : ""}`}
                >
                  <td>{new Date(p.ts * 1000).toISOString().substr(11, 12)}</td>
                  <td className={styles.ipCell}>{p.src_ip}</td>
                  <td className={styles.ipCell}>{p.dst_ip}</td>
                  <td className={styles.portCell}>
                    {p.src_port}→{p.dst_port}
                  </td>
                  <td>
                    <span className="badge badge-cyan">{p.protocol}</span>
                  </td>
                  <td>
                    <AppChip app={p.app ?? "Unknown"} />
                  </td>
                  <td className={`${styles.sniCell} hide-mobile`}>
                    {p.sni || "—"}
                  </td>
                  <td>{p.bytes?.toLocaleString()}</td>
                  <td>
                    <span className={p.action === "DROP" ? styles.drop : styles.forward}>
                      {p.action === "DROP" ? "▼ DROP" : "▲ FWD"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
