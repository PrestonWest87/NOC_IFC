import { create } from "zustand";

export interface AlertItem {
  id?: number | string;
  node_name?: string;
  severity?: string;
  status?: string;
  mapped_location?: string;
}

export interface DashboardPayload {
  type?: string;
  alerts?: AlertItem[];
  events?: unknown[];
  grid?: unknown[];
  alert_count?: number;
  site?: string; // Used for investigation updates
  is_investigating?: boolean; // Used for investigation updates
}

interface AppState {
  dashboard: DashboardPayload | null;
  connected: boolean;
  investigatingSites: string[];
  setDashboard: (data: DashboardPayload) => void;
  setConnected: (connected: boolean) => void;
  setInvestigatingSite: (site: string, isInvestigating: boolean) => void;
}

export const useAppStore = create<AppState>((set) => ({
  dashboard: null,
  connected: false,
  investigatingSites: [],
  setDashboard: (data) => set({ dashboard: data }),
  setConnected: (connected) => set({ connected }),
  setInvestigatingSite: (site, isInvestigating) => set((state) => {
    const current = new Set(state.investigatingSites);
    if (isInvestigating) {
      current.add(site);
    } else {
      current.delete(site);
    }
    return { investigatingSites: Array.from(current) };
  }),
}));
