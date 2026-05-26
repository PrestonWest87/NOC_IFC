export const TAB_PERMISSION_MAP: Record<string, Record<string, string>> = {
  dashboard: {
    "Tab: Dashboards -> Operational": "0",
    "Tab: Dashboards -> Global Risk": "1",
    "Tab: Dashboards -> Internal Risk": "2",
    "Tab: Dashboards -> Unified Brief": "3",
  },
  threatTelemetry: {
    "Tab: Threat Telemetry -> RSS Triage": "0",
    "Tab: Threat Telemetry -> CISA KEV": "1",
    "Tab: Threat Telemetry -> Cloud Services": "2",
    "Tab: Threat Telemetry -> Perimeter Crime": "3",
  },
  regionalGrid: {
    "Tab: Regional Grid -> Geospatial Map": "geospatial",
    "Tab: Regional Grid -> Executive Dash": "executive",
    "Tab: Regional Grid -> Hazard Analytics": "hazard",
    "Tab: Regional Grid -> Location Matrix": "matrix",
    "Tab: Regional Grid -> Weather Alerts Log": "alerts",
    "Tab: Regional Grid -> Atmos Weather": "atmos",
  },
  threatHunting: {
    "Tab: Threat Hunting -> Global IOC Matrix": "ioc",
    "Tab: Threat Hunting -> Deep Hunt Builder": "hunt",
    "Tab: Reporting -> Elastic SIEM Report": "siem",
  },
  aiopsRca: {
    "Tab: AIOps RCA -> Active Board": "0",
    "Tab: AIOps RCA -> Predictive Analytics": "1",
    "Tab: AIOps RCA -> Global Correlation": "2",
  },
  reporting: {
    "Tab: Reporting -> Daily Fusion": "0",
    "Tab: Reporting -> Report Builder": "1",
    "Tab: Reporting -> Shared Library": "2",
  },
  settings: {
    "Tab: Settings -> Facility Locations": "facilities",
    "Tab: Settings -> Internal Assets": "assets",
    "Tab: Settings -> RSS Sources": "rss",
    "Tab: Settings -> ML Training": "ml",
    "Tab: Settings -> AI & SMTP": "ai-smtp",
    "Tab: Settings -> Users & Roles": "users",
    "Tab: Settings -> Backup & Restore": "backup",
    "Tab: Settings -> Danger Zone": "danger",
  },
};

export function getAllowedTabs(
  allowedActions: string[] | undefined,
  pageKey: keyof typeof TAB_PERMISSION_MAP
): string[] {
  const map = TAB_PERMISSION_MAP[pageKey];
  if (!allowedActions || allowedActions.length === 0) return [];
  return Object.entries(map)
    .filter(([action]) => allowedActions.includes(action))
    .map(([_, tabKey]) => tabKey);
}
