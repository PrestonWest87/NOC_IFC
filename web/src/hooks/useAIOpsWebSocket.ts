import { useEffect, useRef, useState, useCallback } from "react";
import { triggerCriticalNotification } from "../utils/notifications";
import { useAppStore, type DashboardPayload } from "../store/useAppStore";
import { useQueryClient } from "@tanstack/react-query";

export function useAIOpsWebSocket() {
  const queryClient = useQueryClient();
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [connected, setConnected] = useState(false);
  const setStoreDashboard = useAppStore((s) => s.setDashboard);
  const setStoreConnected = useAppStore((s) => s.setConnected);
  const setInvestigatingSite = useAppStore((s) => s.setInvestigatingSite);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const knownAlertIds = useRef(new Set<string>());

  const sendMessage = useCallback((msg: unknown) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  useEffect(() => {
    function connect() {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const host = window.location.host;
      const ws = new WebSocket(`${protocol}//${host}/ws`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setStoreConnected(true);
        retryRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as DashboardPayload;

          if (payload.type === "INVESTIGATING_UPDATE") {
            if (payload.site !== undefined && payload.is_investigating !== undefined) {
              setInvestigatingSite(payload.site, payload.is_investigating);
            }
            return;
          }

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
        setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [setStoreDashboard, setStoreConnected, setInvestigatingSite, queryClient]);

  return { data, connected, sendMessage };
}
