import { create } from "zustand";

/** Minimal SolarWinds fields used by realtime map and alert notifications. */
export interface AlertItem {
  id?: number | string;
  node_name?: string;
  severity?: string;
  status?: string;
  mapped_location?: string;
}

/** Server push or workflow-echo payload shared between the WebSocket hook and pages. */
export interface DashboardPayload {
  type?: string;
  alerts?: AlertItem[];
  events?: unknown[];
  grid?: unknown[];
  alert_count?: number;
  active_issue_counts?: Record<string, number>;
  site?: string;
  is_investigating?: boolean;
}

/** Shared in-memory WebSocket/dashboard state and command sender. */
interface AppState {
  dashboard: DashboardPayload | null;
  connected: boolean;
  investigatingSites: string[];
  sendMessage: (msg: any) => void;
  setDashboard: (data: DashboardPayload) => void;
  setConnected: (connected: boolean) => void;
  setInvestigatingSite: (site: string, isInvestigating: boolean) => void;
  setSendMessage: (fn: (msg: any) => void) => void;
}

/** In-memory Zustand state for realtime dashboard data and outbound socket commands. */
export const useAppStore = create<AppState>((set) => ({
  dashboard: null,
  connected: false,
  investigatingSites: [],
  sendMessage: () => {}, // Default empty function
  
  setDashboard: (data) => set({ dashboard: data }),
  setConnected: (connected) => set({ connected }),
  
  setInvestigatingSite: (site, isInvestigating) => set((state) => ({
    investigatingSites: isInvestigating 
      ? [...new Set([...state.investigatingSites, site])]
      : state.investigatingSites.filter(s => s !== site)
  })),
  
  setSendMessage: (fn) => set({ sendMessage: fn }),
}));
