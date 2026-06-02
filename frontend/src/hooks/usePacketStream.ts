/**
 * usePacketStream.ts
 * Custom React hook that manages the WebSocket connection to the backend
 * and maintains live packet feed + stats state.
 */

import { useCallback, useEffect, useRef, useState } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/live";
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface PacketEvent {
  event: "packet" | "block" | "done" | "error" | "rule_added" | "rule_removed" | "stats";
  ts: number;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  app?: string;
  sni?: string;
  bytes?: number;
  action?: "FORWARD" | "DROP";
  block_reason?: string;
  tcp_flags?: number;
  // done event
  total_packets?: number;
  total_bytes?: number;
  dropped?: number;
  active_flows?: number;
  app_breakdown?: Record<string, number>;
  duration_sec?: number;
  message?: string;
}

export interface SessionStats {
  totalPackets: number;
  totalBytes: number;
  dropped: number;
  activeFlows: number;
  appBreakdown: Record<string, number>;
  running: boolean;
}

const MAX_FEED_SIZE = 200;

export function usePacketStream() {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [packets, setPackets] = useState<PacketEvent[]>([]);
  const [blocked, setBlocked] = useState<PacketEvent[]>([]);
  const [stats, setStats] = useState<SessionStats>({
    totalPackets: 0,
    totalBytes: 0,
    dropped: 0,
    activeFlows: 0,
    appBreakdown: {},
    running: false,
  });
  const [sessionDone, setSessionDone] = useState(false);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 2s
      setTimeout(connect, 2000);
    };
    ws.onerror = () => ws.close();

    ws.onmessage = (e) => {
      const data: PacketEvent = JSON.parse(e.data);

      if (data.event === "done") {
        setStats((prev) => ({
          ...prev,
          totalPackets: data.total_packets ?? prev.totalPackets,
          totalBytes: data.total_bytes ?? prev.totalBytes,
          dropped: data.dropped ?? prev.dropped,
          activeFlows: data.active_flows ?? prev.activeFlows,
          appBreakdown: data.app_breakdown ?? prev.appBreakdown,
          running: false,
        }));
        setSessionDone(true);
        return;
      }

      if (data.event === "packet" || data.event === "block") {
        setPackets((prev) => [data, ...prev].slice(0, MAX_FEED_SIZE));
        if (data.event === "block" || data.action === "DROP") {
          setBlocked((prev) => [data, ...prev].slice(0, MAX_FEED_SIZE));
        }
        setStats((prev) => ({
          ...prev,
          totalPackets: prev.totalPackets + 1,
          totalBytes: prev.totalBytes + (data.bytes ?? 0),
          dropped: data.action === "DROP" ? prev.dropped + 1 : prev.dropped,
          running: true,
          appBreakdown: data.app
            ? {
                ...prev.appBreakdown,
                [data.app]: (prev.appBreakdown[data.app] ?? 0) + 1,
              }
            : prev.appBreakdown,
        }));
      }
    };
  }, []);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  const uploadPcap = useCallback(async (file: File) => {
    setSessionDone(false);
    setPackets([]);
    setBlocked([]);
    setStats({ totalPackets: 0, totalBytes: 0, dropped: 0, activeFlows: 0, appBreakdown: {}, running: true });

    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${API_URL}/api/capture/upload`, { method: "POST", body: fd });
    return res.json();
  }, []);

  const stopCapture = useCallback(async () => {
    await fetch(`${API_URL}/api/capture/stop`, { method: "POST" });
    setStats((s) => ({ ...s, running: false }));
  }, []);

  const addRule = useCallback(async (type: string, value: string) => {
    await fetch(`${API_URL}/api/rules`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, value }),
    });
  }, []);

  const removeRule = useCallback(async (type: string, value: string) => {
    await fetch(`${API_URL}/api/rules/${type}/${encodeURIComponent(value)}`, { method: "DELETE" });
  }, []);

  const fetchRules = useCallback(async () => {
    const res = await fetch(`${API_URL}/api/rules`);
    return res.json();
  }, []);

  const fetchHistory = useCallback(async () => {
    const res = await fetch(`${API_URL}/api/stats/history`);
    return res.json();
  }, []);

  const fetchAppHistory = useCallback(async () => {
    const res = await fetch(`${API_URL}/api/stats/app-history`);
    return res.json();
  }, []);

  return {
    connected, packets, blocked, stats, sessionDone,
    uploadPcap, stopCapture, addRule, removeRule,
    fetchRules, fetchHistory, fetchAppHistory,
    API_URL,
  };
}
