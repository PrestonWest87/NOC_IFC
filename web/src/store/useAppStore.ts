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
}

interface AppState {
  dashboard: DashboardPayload | null;
  connected: boolean;
  setDashboard: (data: DashboardPayload) => void;
  setConnected: (connected: boolean) => void;
}

export const useAppStore = create<AppState>((set) => ({
  dashboard: null,
  connected: false,
  setDashboard: (data) => set({ dashboard: data }),
  setConnected: (connected) => set({ connected }),
}));