import { useEffect, useRef, useState } from "react";
import { triggerCriticalNotification } from "../utils/notifications";
import { useAppStore, type DashboardPayload } from "../store/useAppStore";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "../utils/AuthContext";

export function useAIOpsWebSocket() {
  const queryClient = useQueryClient();
  const { token } = useAuth();
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [connected, setConnected] = useState(false);
  
  const setStoreDashboard = useAppStore((s) => s.setDashboard);
  const setStoreConnected = useAppStore((s) => s.setConnected);
  const setInvestigatingSite = useAppStore((s) => s.setInvestigatingSite);
  const setSendMessage = useAppStore((s) => s.setSendMessage);
  
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const knownAlertIds = useRef(new Set<string>());

  useEffect(() => {
    // Expose the send method globally so pages can broadcast
    const sendMessage = (msg: any) => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify(msg));
      }
    };
    setSendMessage(sendMessage);

    let stopped = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (stopped || !token) return;
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const host = window.location.host;
      const ws = new WebSocket(`${protocol}//${host}/ws?token=${encodeURIComponent(token)}`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setStoreConnected(true);
        retryRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as DashboardPayload;

          // Catch UI State Echoes
          if (payload.type === "INVESTIGATING_UPDATE" && payload.site) {
            setInvestigatingSite(payload.site, payload.is_investigating ?? false);
            return;
          }

          // Catch Database Resync Requests
          if (payload.type === "RCA_UPDATE") {
            queryClient.invalidateQueries({ queryKey: ["rca-dashboard"] });
            queryClient.invalidateQueries({ queryKey: ["rca-analyze"] });
            return;
          }
            
          setData(payload);
          setStoreDashboard(payload);

          for (const alert of payload.alerts ?? []) {
            const a = alert as Record<string, unknown>;
            const id = String(a.id ?? "");
            if (id && !knownAlertIds.current.has(id)) {
              knownAlertIds.current.add(id);
              if (a.severity === "CRITICAL" || a.severity === "HIGH") {
                triggerCriticalNotification(
                  id,
                  `Critical Alert: ${a.node_name ?? "Unknown"}`,
                  `${a.severity} — ${a.mapped_location ?? "Unknown location"}`,
                );
              }
            }
          }
        } catch {
          // ignore malformed messages
        }
      };

      ws.onclose = () => {
        setConnected(false);
        setStoreConnected(false);
        wsRef.current = null;
        const delay = Math.min(1000 * Math.pow(2, retryRef.current), 30000);
        retryRef.current++;
        if (!stopped) retryTimer = setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      stopped = true;
      if (retryTimer) clearTimeout(retryTimer);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [token, setStoreDashboard, setStoreConnected, setSendMessage, setInvestigatingSite, queryClient]);

  return { data, connected };
}
