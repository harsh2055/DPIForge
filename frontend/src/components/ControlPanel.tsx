"use client";

import { useState, useEffect, useCallback } from "react";
import styles from "./ControlPanel.module.css";

interface NetworkInterface {
  name: string;
  description: string;
  ip: string;
  mac: string;
}

interface Props {
  addRule: (type: string, value: string) => Promise<void>;
  removeRule: (type: string, value: string) => Promise<void>;
  fetchRules: () => Promise<{ ips: string[]; apps: string[]; domains: string[]; ports: number[] }>;
  uploadPcap: (file: File) => Promise<unknown>;
  startLiveCapture: (ifaceName: string) => Promise<unknown>;
  fetchInterfaces: () => Promise<NetworkInterface[]>;
  stopCapture: () => Promise<void>;
  running: boolean;
  connected: boolean;
}

const KNOWN_APPS = [
  "YouTube", "Netflix", "Spotify", "Discord", "GitHub", "Zoom",
  "Google", "Facebook", "Instagram", "WhatsApp", "Telegram",
  "TikTok", "Twitter/X", "Amazon", "Microsoft", "Apple",
];

export function ControlPanel({
  addRule,
  removeRule,
  fetchRules,
  uploadPcap,
  startLiveCapture,
  fetchInterfaces,
  stopCapture,
  running,
  connected,
}: Props) {
  const [activeTab, setActiveTab] = useState<"live" | "upload">("live");
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>("");
  const [loadingIfaces, setLoadingIfaces] = useState<boolean>(false);

  const [ruleType, setRuleType]   = useState("domain");
  const [ruleValue, setRuleValue] = useState("");
  const [rules, setRules] = useState<{ ips: string[]; apps: string[]; domains: string[]; ports: number[] }>({
    ips: [], apps: [], domains: [], ports: [],
  });
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [filename, setFilename] = useState("");
  const [actionLoading, setActionLoading] = useState(false);

  const refreshRules = useCallback(async () => {
    try {
      const r = await fetchRules();
      setRules(r);
    } catch {}
  }, [fetchRules]);

  useEffect(() => {
    refreshRules();
  }, [refreshRules]);

  // Fetch available network interfaces
  useEffect(() => {
    if (activeTab === "live") {
      setLoadingIfaces(true);
      fetchInterfaces()
        .then((ifaces) => {
          setInterfaces(ifaces);
          if (ifaces.length > 0) {
            setSelectedIface(ifaces[0].name);
          }
        })
        .catch(() => {})
        .finally(() => setLoadingIfaces(false));
    }
  }, [activeTab, fetchInterfaces]);

  async function handleAddRule(e: React.FormEvent) {
    e.preventDefault();
    const val = ruleValue.trim();
    if (!val) return;

    if (ruleType === "ip") {
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipPattern.test(val)) {
        alert("Please enter a valid IPv4 address (e.g., 192.168.1.1)");
        return;
      }
      const octets = val.split(".").map(Number);
      if (octets.some((o) => o < 0 || o > 255)) {
        alert("Each octet in the IP address must be between 0 and 255.");
        return;
      }
    } else if (ruleType === "port") {
      const portVal = parseInt(val, 10);
      if (isNaN(portVal) || portVal < 1 || portVal > 65535 || String(portVal) !== val) {
        alert("Please enter a valid port number between 1 and 65535.");
        return;
      }
    }

    await addRule(ruleType, val);
    setRuleValue("");
    await refreshRules();
  }

  async function handleRemove(type: string, value: string) {
    await removeRule(type, value);
    await refreshRules();
  }

  async function handleFile(file: File) {
    setFilename(file.name);
    setUploading(true);
    try {
      await uploadPcap(file);
    } finally {
      setUploading(false);
    }
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }

  async function handleStartSniff() {
    if (!selectedIface || actionLoading) return;
    setActionLoading(true);
    try {
      await startLiveCapture(selectedIface);
    } catch {
    } finally {
      setActionLoading(false);
    }
  }

  async function handleStopSniff() {
    if (actionLoading) return;
    setActionLoading(true);
    try {
      await stopCapture();
    } catch {
    } finally {
      setActionLoading(false);
    }
  }

  const activeIfaceDetails = interfaces.find((i) => i.name === selectedIface);

  return (
    <div className={styles.wrapper}>
      {/* ── Capture Section ── */}
      <div className={styles.section}>
        <div className="section-title">
          <span className="accent">◈</span> Capture
        </div>

        {/* Tab switcher */}
        <div className={styles.tabs}>
          <button
            type="button"
            className={`${styles.tab} ${activeTab === "live" ? styles.tabActive : ""}`}
            onClick={() => !running && setActiveTab("live")}
            disabled={running}
            style={{ opacity: running && activeTab !== "live" ? 0.5 : 1 }}
          >
            Live Sniff
          </button>
          <button
            type="button"
            className={`${styles.tab} ${activeTab === "upload" ? styles.tabActive : ""}`}
            onClick={() => !running && setActiveTab("upload")}
            disabled={running}
            style={{ opacity: running && activeTab !== "upload" ? 0.5 : 1 }}
          >
            PCAP Upload
          </button>
        </div>

        {activeTab === "live" ? (
          <div className={styles.interfaceSelectWrapper}>
            <label style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
              Select Interface Card (NIC)
            </label>
            {loadingIfaces ? (
              <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", padding: "0.5rem" }}>
                Scanning adapters...
              </div>
            ) : (
              <select
                className="input"
                value={selectedIface}
                onChange={(e) => setSelectedIface(e.target.value)}
                disabled={running}
                style={{ width: "100%" }}
              >
                {interfaces.length === 0 ? (
                  <option value="">No adapters found</option>
                ) : (
                  interfaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.description} {i.ip ? `(${i.ip})` : ""}
                    </option>
                  ))
                )}
              </select>
            )}

            {activeIfaceDetails && (
              <div className={styles.ifaceDetails}>
                <div className={styles.ifaceDetailRow}>
                  <span className={styles.ifaceDetailLabel}>Adapter IP:</span>
                  <span className={styles.ifaceDetailValue}>{activeIfaceDetails.ip || "N/A"}</span>
                </div>
                <div className={styles.ifaceDetailRow}>
                  <span className={styles.ifaceDetailLabel}>MAC Address:</span>
                  <span className={styles.ifaceDetailValue}>{activeIfaceDetails.mac || "N/A"}</span>
                </div>
              </div>
            )}

            <div className={styles.liveActions}>
              {!running ? (
                <button
                  className="btn btn-primary"
                  onClick={handleStartSniff}
                  disabled={!selectedIface || !connected || actionLoading}
                  style={{ width: "100%" }}
                >
                  {actionLoading ? "Starting..." : "▶ Start Live Sniffing"}
                </button>
              ) : (
                <button
                  className="btn btn-danger"
                  onClick={handleStopSniff}
                  disabled={actionLoading}
                  style={{ width: "100%" }}
                >
                  {actionLoading ? "Stopping..." : "⏹ Stop Sniffing"}
                </button>
              )}
            </div>
          </div>
        ) : (
          /* PCAP Upload Mode */
          <>
            <div
              className={`dropzone ${dragging ? "drag-over" : ""}`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              onClick={() => document.getElementById("pcap-file-input")?.click()}
              role="button"
              aria-label="Upload PCAP file"
            >
              <input
                id="pcap-file-input"
                type="file"
                accept=".pcap,.pcapng"
                style={{ display: "none" }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                }}
              />
              <div className={styles.dropIcon}>⬆</div>
              <div className={styles.dropText}>
                {uploading ? "Processing…" : filename ? filename : "Drop .pcap file here or click to browse"}
              </div>
              <div className={styles.dropSub}>.pcap / .pcapng supported</div>
            </div>

            <div className={styles.captureActions}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span className={`pulse-dot ${connected ? "pulse-dot-green" : "pulse-dot-magenta"}`} />
                <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                  {connected ? "WS Connected" : "WS Disconnected"}
                </span>
              </div>
              {running && (
                <button className="btn btn-danger" onClick={stopCapture} id="stop-capture-btn">
                  ⏹ Stop
                </button>
              )}
            </div>
          </>
        )}
      </div>

      <div className="glow-divider" />

      {/* ── Add Rule ── */}
      <div className={styles.section}>
        <div className="section-title">
          <span style={{ color: "var(--magenta)" }}>◈</span> Block Rules
        </div>
        <form onSubmit={handleAddRule} className={styles.ruleForm} id="add-rule-form">
          <select
            className="input"
            value={ruleType}
            onChange={(e) => setRuleType(e.target.value)}
            id="rule-type-select"
          >
            <option value="domain">Domain</option>
            <option value="ip">IP Address</option>
            <option value="app">Application</option>
            <option value="port">Port</option>
          </select>

          {ruleType === "app" ? (
            <select
              className="input"
              value={ruleValue}
              onChange={(e) => setRuleValue(e.target.value)}
              id="rule-app-select"
            >
              <option value="">Select app…</option>
              {KNOWN_APPS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          ) : (
            <input
              className="input"
              placeholder={
                ruleType === "ip" ? "192.168.1.100" : ruleType === "domain" ? "*.youtube.com" : "443"
              }
              value={ruleValue}
              onChange={(e) => setRuleValue(e.target.value)}
              id="rule-value-input"
            />
          )}

          <button type="submit" className="btn btn-primary" id="add-rule-btn">
            + Block
          </button>
        </form>

        {/* Active rules list */}
        <div className={styles.rulesList}>
          {[
            ...rules.ips.map((v) => ({ type: "ip", value: v })),
            ...rules.domains.map((v) => ({ type: "domain", value: v })),
            ...rules.apps.map((v) => ({ type: "app", value: v })),
            ...rules.ports.map((v) => ({ type: "port", value: String(v) })),
          ].map(({ type, value }) => (
            <div key={`${type}:${value}`} className={styles.ruleTag}>
              <span className={styles.ruleTypeLabel}>{type}</span>
              <span className={styles.ruleValue}>{value}</span>
              <button
                className={styles.ruleRemove}
                onClick={() => handleRemove(type, value)}
                aria-label={`Remove ${type} rule ${value}`}
              >
                ×
              </button>
            </div>
          ))}
          {rules.ips.length + rules.apps.length + rules.domains.length + rules.ports.length === 0 && (
            <p className={styles.noRules}>No active block rules</p>
          )}
        </div>
      </div>
    </div>
  );
}
