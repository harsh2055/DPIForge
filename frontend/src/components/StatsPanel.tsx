"use client";

import styles from "./StatsPanel.module.css";
import { SessionStats } from "@/hooks/usePacketStream";

function formatBytes(b: number): string {
  if (b >= 1_073_741_824) return (b / 1_073_741_824).toFixed(2) + " GB";
  if (b >= 1_048_576) return (b / 1_048_576).toFixed(2) + " MB";
  if (b >= 1024) return (b / 1024).toFixed(2) + " KB";
  return b + " B";
}

const APP_COLORS: Record<string, string> = {
  YouTube: "#ff0000", Netflix: "#e50914", Spotify: "#1db954",
  Discord: "#5865f2", GitHub: "#6e40c9", Zoom: "#2d8cff",
  Google: "#4285f4", Facebook: "#1877f2", Instagram: "#e1306c",
  WhatsApp: "#25d366", Telegram: "#229ed9", TikTok: "#ff0050",
  "Twitter/X": "#1da1f2", Amazon: "#ff9900", Microsoft: "#00a4ef",
  Apple: "#888888", HTTP: "#ffb347", HTTPS: "#00c8ff",
  DNS: "#b06aff", QUIC: "#00ff88", Unknown: "#3d5070",
};

function getColor(app: string) {
  return APP_COLORS[app] || "#7a90b8";
}

interface Props {
  stats: SessionStats;
}

export function StatsPanel({ stats }: Props) {
  const total = stats.totalPackets || 1;
  const entries = Object.entries(stats.appBreakdown)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 12);

  return (
    <div className={styles.wrapper}>
      {/* ── Counters ── */}
      <div className={styles.counters}>
        <div className={styles.counter}>
          <div className="stat-value">{stats.totalPackets.toLocaleString()}</div>
          <div className="stat-label">Total Packets</div>
        </div>
        <div className={styles.counter}>
          <div className="stat-value" style={{ color: "var(--green)" }}>
            {formatBytes(stats.totalBytes)}
          </div>
          <div className="stat-label">Total Bytes</div>
        </div>
        <div className={styles.counter}>
          <div className="stat-value" style={{ color: "var(--magenta)" }}>
            {stats.dropped.toLocaleString()}
          </div>
          <div className="stat-label">Dropped</div>
        </div>
        <div className={styles.counter}>
          <div className="stat-value" style={{ color: "var(--purple)" }}>
            {stats.activeFlows.toLocaleString()}
          </div>
          <div className="stat-label">Active Flows</div>
        </div>
      </div>

      <div className="glow-divider" />

      {/* ── App breakdown bars ── */}
      <div className={styles.breakdownHeader}>
        <span className="section-title">
          <span className="accent">◈</span> App Breakdown
        </span>
      </div>

      <div className={styles.bars}>
        {entries.length === 0 ? (
          <p className={styles.noData}>No data yet</p>
        ) : (
          entries.map(([app, count]) => {
            const pct = Math.round((count / total) * 100);
            const color = getColor(app);
            return (
              <div key={app} className={styles.barRow}>
                <div className={styles.barLabel}>
                  <span className={styles.appDot} style={{ background: color }} />
                  <span className={styles.appName}>{app}</span>
                  <span className={styles.barPct}>{pct}%</span>
                </div>
                <div className={styles.barTrack}>
                  <div
                    className={styles.barFill}
                    style={{
                      width: `${pct}%`,
                      background: `linear-gradient(90deg, ${color}99, ${color})`,
                      boxShadow: `0 0 8px ${color}55`,
                    }}
                  />
                </div>
                <span className={styles.barCount}>{count.toLocaleString()}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
