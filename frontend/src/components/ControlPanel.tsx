"use client";

import { useState, useEffect, useCallback } from "react";
import styles from "./ControlPanel.module.css";

interface Props {
  addRule: (type: string, value: string) => Promise<void>;
  removeRule: (type: string, value: string) => Promise<void>;
  fetchRules: () => Promise<{ ips: string[]; apps: string[]; domains: string[]; ports: number[] }>;
  uploadPcap: (file: File) => Promise<unknown>;
  stopCapture: () => Promise<void>;
  running: boolean;
  connected: boolean;
}

const KNOWN_APPS = [
  "YouTube", "Netflix", "Spotify", "Discord", "GitHub", "Zoom",
  "Google", "Facebook", "Instagram", "WhatsApp", "Telegram",
  "TikTok", "Twitter/X", "Amazon", "Microsoft", "Apple",
];

export function ControlPanel({ addRule, removeRule, fetchRules, uploadPcap, stopCapture, running, connected }: Props) {
  const [ruleType, setRuleType]   = useState("domain");
  const [ruleValue, setRuleValue] = useState("");
  const [rules, setRules] = useState<{ ips: string[]; apps: string[]; domains: string[]; ports: number[] }>({
    ips: [], apps: [], domains: [], ports: [],
  });
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [filename, setFilename] = useState("");

  const refreshRules = useCallback(async () => {
    try {
      const r = await fetchRules();
      setRules(r);
    } catch {}
  }, [fetchRules]);

  useEffect(() => { refreshRules(); }, [refreshRules]);

  async function handleAddRule(e: React.FormEvent) {
    e.preventDefault();
    if (!ruleValue.trim()) return;
    await addRule(ruleType, ruleValue.trim());
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
    try { await uploadPcap(file); }
    finally { setUploading(false); }
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }

  return (
    <div className={styles.wrapper}>
      {/* ── PCAP Upload ── */}
      <div className={styles.section}>
        <div className="section-title"><span className="accent">◈</span> Capture</div>
        <div
          className={`dropzone ${dragging ? "drag-over" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
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
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
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
      </div>

      <div className="glow-divider" />

      {/* ── Add Rule ── */}
      <div className={styles.section}>
        <div className="section-title"><span style={{ color: "var(--magenta)" }}>◈</span> Block Rules</div>
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
              {KNOWN_APPS.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
          ) : (
            <input
              className="input"
              placeholder={
                ruleType === "ip" ? "192.168.1.100" :
                ruleType === "domain" ? "*.youtube.com" : "443"
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
