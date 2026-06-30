export const PAGE_PERMISSION_MAP: Record<string, string> = {
  "/": "Global Dashboards",
  "/threat-telemetry": "Threat Telemetry",
  "/regional-grid": "Regional Grid",
  "/threat-hunting": "Threat Hunting & IOCs",
  "/aiops-rca": "AIOps RCA",
  "/shift-logbook": "Shift Logbook",
  "/reporting": "Reporting & Briefings",
  "/settings": "Settings & Admin",
};

export const PAGE_ROUTE_MAP: Record<string, string> = Object.fromEntries(
  Object.entries(PAGE_PERMISSION_MAP).map(([k, v]) => [v, k])
);
