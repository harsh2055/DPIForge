"use client";

import { PacketEvent } from "@/hooks/usePacketStream";
import styles from "./BlockedFeed.module.css";

interface Props {
  blocked: PacketEvent[];
}

export function BlockedFeed({ blocked }: Props) {
  return (
    <div className={styles.wrapper}>
      <div className={styles.header}>
        <span className="section-title">
          <span style={{ color: "var(--magenta)" }}>◈</span> Block Alerts
        </span>
        <span className={styles.count} data-has={blocked.length > 0}>
          {blocked.length} blocked
        </span>
      </div>

      <div className={styles.feed}>
        {blocked.length === 0 ? (
          <div className={styles.empty}>
            <span>🛡</span>
            <span>No traffic blocked</span>
          </div>
        ) : (
          blocked.map((p, i) => (
            <div key={`${p.ts}-${i}`} className={`${styles.alert} row-new`}>
              <div className={styles.alertLeft}>
                <span className={styles.alertIcon}>⛔</span>
                <div>
                  <div className={styles.alertFlow}>
                    <span className={styles.alertIp}>{p.src_ip}</span>
                    <span className={styles.arrow}>→</span>
                    <span className={styles.alertIp}>{p.dst_ip}</span>
                    <span className={styles.alertPort}>:{p.dst_port}</span>
                  </div>
                  <div className={styles.alertReason}>{p.block_reason || `Blocked: ${p.app}`}</div>
                </div>
              </div>
              <div className={styles.alertRight}>
                <span className={styles.alertApp}>{p.app}</span>
                <span className={styles.alertTime}>
                  {new Date(p.ts * 1000).toISOString().substr(11, 8)}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
