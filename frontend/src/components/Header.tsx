"use client";

import styles from "./Header.module.css";

interface Props {
  connected: boolean;
  running: boolean;
  totalPackets: number;
}

export function Header({ connected, running, totalPackets }: Props) {
  return (
    <header className={styles.header}>
      <div className="container">
        <div className={styles.inner}>
          {/* Logo */}
          <div className={styles.logo}>
            <span className={styles.logoIcon}>⬡</span>
            <div>
              <div className={styles.logoTitle}>DPI<span className={styles.logoAccent}>Forge</span></div>
              <div className={styles.logoSub}>Deep Packet Inspector v2.0</div>
            </div>
          </div>

          {/* Center status */}
          <div className={styles.status}>
            {running ? (
              <>
                <span className="pulse-dot pulse-dot-green" />
                <span className={styles.statusText}>Analyzing — {totalPackets.toLocaleString()} packets</span>
              </>
            ) : (
              <>
                <span className={`pulse-dot ${connected ? "pulse-dot-cyan" : "pulse-dot-amber"}`} />
                <span className={styles.statusText}>{connected ? "Idle — Ready" : "Connecting…"}</span>
              </>
            )}
          </div>

          {/* Right — quick info */}
          <div className={styles.right}>
            <div className={styles.pill}>
              <span className={styles.pillLabel}>Backend</span>
              <span className={styles.pillValue} style={{ color: connected ? "var(--green)" : "var(--magenta)" }}>
                {connected ? "Online" : "Offline"}
              </span>
            </div>
            <div className={styles.pill}>
              <span className={styles.pillLabel}>Engine</span>
              <span className={styles.pillValue} style={{ color: "var(--cyan)" }}>Python/FastAPI</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
