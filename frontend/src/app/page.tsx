"use client";

import { usePacketStream } from "@/hooks/usePacketStream";
import { Header } from "@/components/Header";
import { PacketFeed } from "@/components/PacketFeed";
import { StatsPanel } from "@/components/StatsPanel";
import { BlockedFeed } from "@/components/BlockedFeed";
import { ControlPanel } from "@/components/ControlPanel";
import styles from "./page.module.css";

export default function DashboardPage() {
  const {
    connected, packets, blocked, stats, sessionDone,
    uploadPcap, startLiveCapture, fetchInterfaces, stopCapture, addRule, removeRule,
    fetchRules,
  } = usePacketStream();

  return (
    <div className={styles.app}>
      <Header
        connected={connected}
        running={stats.running}
        totalPackets={stats.totalPackets}
      />

      <main className={styles.main}>
        <div className="container" style={{ height: "100%" }}>
          <div className={styles.grid}>

            {/* ── Left column: Control + Block Alerts ── */}
            <div className={styles.leftCol}>
              <div className={`card ${styles.controlCard}`}>
                <ControlPanel
                  addRule={addRule}
                  removeRule={removeRule}
                  fetchRules={fetchRules}
                  uploadPcap={uploadPcap}
                  startLiveCapture={startLiveCapture}
                  fetchInterfaces={fetchInterfaces}
                  stopCapture={stopCapture}
                  running={stats.running}
                  connected={connected}
                />
              </div>
              <div className={`card ${styles.blockedCard}`}>
                <BlockedFeed blocked={blocked} />
              </div>
            </div>

            {/* ── Center column: Live packet feed ── */}
            <div className={styles.centerCol}>
              {sessionDone && (
                <div className={styles.doneBanner}>
                  ✓ Processing complete — {stats.totalPackets.toLocaleString()} packets analysed
                </div>
              )}
              <div className={`card ${styles.feedCard}`}>
                <PacketFeed packets={packets} />
              </div>
            </div>

            {/* ── Right column: Stats panel ── */}
            <div className={styles.rightCol}>
              <div className={`card ${styles.statsCard}`}>
                <StatsPanel stats={stats} />
              </div>
            </div>

          </div>
        </div>
      </main>
    </div>
  );
}
