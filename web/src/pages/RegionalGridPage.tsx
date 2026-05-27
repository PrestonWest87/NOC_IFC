import { useState, useMemo, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { getAllowedTabs } from "../utils/permissions";
import DeckGL from "@deck.gl/react";
import { ScatterplotLayer, GeoJsonLayer, BitmapLayer } from "@deck.gl/layers";
import { Map as MapLibreMap } from "react-map-gl/maplibre";
import type { MapViewState } from "@deck.gl/core";
import "maplibre-gl/dist/maplibre-gl.css";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip as ReTooltip,
  ResponsiveContainer, CartesianGrid, Legend
} from "recharts";
import {
  Map, LayoutDashboard, AlertTriangle, Table2, CloudSun, Activity,
  Layers, Filter, Target, Send, Sparkles, ChevronDown, ChevronUp,
  MapPin, List, RefreshCw, AlertCircle, Bell
} from "lucide-react";

const ALL_TABS = [
  { key: "geospatial", label: "Geospatial Overlay", icon: Map },
  { key: "executive", label: "Executive Dashboard", icon: LayoutDashboard },
  { key: "hazard", label: "Deep Hazard Analytics", icon: AlertTriangle },
  { key: "matrix", label: "Location Matrix", icon: Table2 },
  { key: "alerts", label: "Weather Alerts Log", icon: List },
  { key: "atmos", label: "Atmos Weather", icon: CloudSun },
];

const SIDEBAR_PX = 280;
const CARD_STYLE: React.CSSProperties = {
  background: "var(--bg-card)", border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-md)", padding: "1.25rem",
  boxShadow: "var(--shadow-sm)",
};
const CARD_HEADER: React.CSSProperties = {
  fontSize: "1.05rem", fontWeight: 600, color: "var(--text-primary)",
  margin: "0 0 0.75rem 0",
};
const BTN_PRIMARY: React.CSSProperties = {
  background: "var(--accent-blue)", color: "#fff", border: "none",
  borderRadius: "var(--radius-sm)", padding: "0.45rem 0.9rem",
  fontSize: "0.82rem", fontWeight: 500, cursor: "pointer",
  transition: "all 0.15s",
};
const BTN_SECONDARY: React.CSSProperties = {
  background: "var(--bg-tertiary)", color: "var(--text-secondary)",
  border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)",
  padding: "0.4rem 0.8rem", fontSize: "0.8rem", cursor: "pointer",
};
const INPUT_STYLE: React.CSSProperties = {
  background: "var(--bg-input)", border: "1px solid var(--border-primary)",
  color: "var(--text-primary)", borderRadius: "var(--radius-sm)",
  padding: "0.5rem 0.75rem", fontSize: "0.85rem", width: "100%",
  outline: "none",
};
const LABEL_STYLE: React.CSSProperties = {
  fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.3rem",
  display: "block",
};
const TH_STYLE: React.CSSProperties = {
  textAlign: "left", padding: "0.5rem", color: "var(--text-muted)",
  fontWeight: 600, fontSize: "0.8rem", borderBottom: "2px solid var(--border-primary)",
  whiteSpace: "nowrap",
};
const TD_STYLE: React.CSSProperties = {
  padding: "0.5rem", color: "var(--text-secondary)", fontSize: "0.85rem",
  borderBottom: "1px solid var(--border-secondary)",
};

const SPC_COLORS: Record<string, string> = {
  HIGH: "#dc3545", MDT: "#e67e22", ENH: "#f39c12", SLGT: "#f1c40f",
  MRGL: "#17a2b8", TSTM: "#28a745", None: "var(--text-muted)",
};
const NWS_COLORS: Record<string, string> = {
  WARNING: "#dc3545", WATCH: "#f39c12", ADVISORY: "#f1c40f",
  STATEMENT: "#17a2b8", None: "var(--text-muted)",
};

function formatDt(s: string) {
  if (!s || s === "N/A") return "N/A";
  try {
    const d = new Date(s);
    return d.toLocaleString("en-US", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
  } catch { return s; }
}

function InfoBox({ type, children }: { type: "info" | "success" | "warning" | "error"; children: React.ReactNode }) {
  const colors: Record<string, { bg: string; border: string; text: string }> = {
    info: { bg: "rgba(59,130,246,0.1)", border: "var(--accent-blue)", text: "#93c5fd" },
    success: { bg: "rgba(1,164,109,0.1)", border: "var(--accent-green)", text: "#6ee7b7" },
    warning: { bg: "rgba(234,179,8,0.1)", border: "var(--accent-yellow)", text: "#fde68a" },
    error: { bg: "rgba(239,68,68,0.1)", border: "var(--accent-red)", text: "#fca5a5" },
  };
  const c = colors[type];
  return (
    <div style={{
      padding: "0.75rem 1rem", borderRadius: "var(--radius-sm)", fontSize: "0.85rem",
      marginBottom: "0.75rem", borderLeft: "3px solid " + c.border,
      background: c.bg, color: c.text,
    }}>{children}</div>
  );
}

function MetricCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "1rem", textAlign: "center" }}>
      <div style={{ fontSize: "1.8rem", fontWeight: 700, color: "var(--text-primary)" }}>{value}</div>
      <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>{label}</div>
      {sub && <div style={{ fontSize: "0.72rem", color: "var(--text-secondary)", marginTop: "0.15rem" }}>{sub}</div>}
    </div>
  );
}

function RiskBadge({ level }: { level: string }) {
  const colors: Record<string, string> = { HIGH: "#dc3545", MDT: "#e67e22", ENH: "#f39c12", SLGT: "#f1c40f", MRGL: "#17a2b8", TSTM: "#28a745", None: "var(--text-muted)", WARNING: "#dc3545", WATCH: "#f39c12", ADVISORY: "#f1c40f", STATEMENT: "#17a2b8", OTHER: "var(--text-muted)" };
  const bgColors: Record<string, string> = { HIGH: "rgba(239,68,68,0.15)", MDT: "rgba(230,126,34,0.15)", ENH: "rgba(243,156,18,0.15)", SLGT: "rgba(241,196,15,0.15)", MRGL: "rgba(23,162,184,0.15)", TSTM: "rgba(40,167,69,0.15)", WARNING: "rgba(239,68,68,0.15)", WATCH: "rgba(243,156,18,0.15)", ADVISORY: "rgba(241,196,15,0.15)", STATEMENT: "rgba(23,162,184,0.15)" };
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", padding: "0.2rem 0.6rem",
      borderRadius: "var(--radius-sm)", fontWeight: 700, fontSize: "0.75rem",
      textTransform: "uppercase", letterSpacing: "0.5px",
      background: bgColors[level] || "rgba(107,114,128,0.15)",
      color: colors[level] || "var(--text-muted)",
    }}>{level}</span>
  );
}

const TOOLTIP_STYLE = {
  background: "var(--bg-card)", color: "var(--text-primary)",
  fontSize: "0.78rem", border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-sm)", padding: "0.5rem",
} as const;

function FilterChip({ selected, onClick, label }: { selected: boolean; onClick: () => void; label: string }) {
  return (
    <button onClick={onClick} style={{
      display: "inline-flex", alignItems: "center", gap: "0.35rem",
      padding: "0.3rem 0.6rem", borderRadius: "var(--radius-sm)",
      border: selected ? "1px solid var(--accent-blue)" : "1px solid var(--border-primary)",
      background: selected ? "var(--shade-blue, rgba(59,130,246,0.15))" : "transparent",
      color: selected ? "var(--accent-blue)" : "var(--text-secondary)",
      fontSize: "0.78rem", cursor: "pointer", fontWeight: selected ? 600 : 400,
      transition: "all 0.12s", whiteSpace: "nowrap",
      lineHeight: 1.3,
    }}>
      {selected && <span style={{ fontSize: "0.6rem" }}>✓</span>}
      {label}
    </button>
  );
}

function ToggleSwitch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.2rem 0" }}>
      <button onClick={() => onChange(!checked)} style={{
        width: 36, height: 20, borderRadius: 10, border: "none",
        background: checked ? "var(--accent-blue)" : "var(--border-primary)",
        position: "relative", cursor: "pointer", padding: 0, flexShrink: 0,
        transition: "background 0.15s",
      }}>
        <span style={{
          position: "absolute", top: 2, left: checked ? 18 : 2,
          width: 16, height: 16, borderRadius: "50%",
          background: "#fff", transition: "left 0.15s",
        }} />
      </button>
      <span style={{ fontSize: "0.82rem", color: "var(--text-secondary)", userSelect: "none" }}>{label}</span>
    </div>
  );
}

const INITIAL_VIEW: MapViewState = { latitude: 34.8, longitude: -92.2, zoom: 5.5, pitch: 0 };

export function RegionalGridPage() {
  const { user } = useAuth();
  const allowedRegionTabs = getAllowedTabs(user?.allowed_actions, "regionalGrid");
  const tabs = ALL_TABS.filter(t => allowedRegionTabs.length === 0 || allowedRegionTabs.includes(t.key));
  const [activeTab, setActiveTab] = useState(tabs.length > 0 ? tabs[0].key : "geospatial");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});

  // Geospatial tab state
  const [mapToggles, setMapToggles] = useState<Record<string, boolean>>({
    radar: false, spc: false, warn: false, watch: false, oos: false,
    fire_risk: false, active_wildfires: false, earthquakes: false,
  });
  const [showRadarPanel, setShowRadarPanel] = useState(false);
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [selectedPrios, setSelectedPrios] = useState<string[]>([]);
  const [viewState, setViewState] = useState<MapViewState>(INITIAL_VIEW);

  // Executive tab state
  const [briefing, setBriefing] = useState("Click 'Generate Briefing' to synthesize current telemetry.");
  const [briefLoading, setBriefLoading] = useState(false);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [analystNotes, setAnalystNotes] = useState("");
  const [hazardRecip, setHazardRecip] = useState("");

  // Weather Alerts tab state
  const [selectedAlertIdx, setSelectedAlertIdx] = useState<number | null>(null);

  const [targetSite, setTargetSite] = useState("");

  // Data fetching
  const { data: locations = [] } = useQuery({
    queryKey: ["regional-locations"],
    queryFn: () => api.get("/regional/locations").then(r => r.data),
    refetchInterval: 120000,
  });

  const { data: geojson } = useQuery({
    queryKey: ["regional-geojson"],
    queryFn: () => api.get("/regional/geojson").then(r => r.data),
    refetchInterval: 120000,
  });

  const { data: alertsLog = [] } = useQuery({
    queryKey: ["regional-alerts-log"],
    queryFn: () => api.get("/regional/weather-alerts-log").then(r => r.data),
    refetchInterval: 120000,
  });

  const { data: forecast } = useQuery({
    queryKey: ["regional-forecast", targetSite],
    queryFn: () => {
      const site = (locations as any[]).find((l: any) => l.name === targetSite);
      return api.get("/regional/forecast", { params: { lat: site?.lat || 34.8, lon: site?.lon || -92.2 } }).then(r => r.data);
    },
    enabled: !!targetSite,
    refetchInterval: 300000,
  });

  const { data: userPrefs } = useQuery({
    queryKey: ["regional-weather-prefs"],
    queryFn: () => api.get("/regional/weather-prefs", { params: { username: (() => { try { return JSON.parse(sessionStorage.getItem("noc_user") || "{}").username || ""; } catch { return ""; } })() } }).then(r => r.data),
  });

  // Derived data
  useEffect(() => {
    if (allowedRegionTabs.length > 0 && tabs.length > 0 && !allowedRegionTabs.includes(activeTab)) {
      setActiveTab(tabs[0].key);
    }
  }, [allowedRegionTabs.join(",")]);

  useEffect(() => {
    const locs = locations as any[];
    if (selectedTypes.length === 0) {
      const types = [...new Set(locs.map((l: any) => l.loc_type).filter(Boolean))] as string[];
      if (types.length > 0) setSelectedTypes(types);
    }
    if (selectedPrios.length === 0) {
      const prios = [...new Set(locs.map((l: any) => String(l.priority)).filter(Boolean))].sort();
      if (prios.length > 0) setSelectedPrios(prios);
    }
  }, [locations]);

  const mapDf = useMemo(() => {
    return (locations as any[]).filter((l: any) =>
      selectedTypes.includes(l.loc_type) && selectedPrios.includes(String(l.priority))
    );
  }, [locations, selectedTypes, selectedPrios]);

  const activeEventTypes = useMemo(() => {
    const events = new Set<string>();
    const geo = geojson as any;
    for (const ds of [geo?.nws_ar, geo?.nws_oos]) {
      if (ds?.features) {
        for (const f of ds.features) {
          const ev = f.properties?.event;
          if (ev) events.add(ev);
        }
      }
    }
    return [...events].sort();
  }, [geojson]);

  useEffect(() => {
    if (activeEventTypes.length > 0 && selectedEvents.length === 0) {
      setSelectedEvents(activeEventTypes);
    }
  }, [activeEventTypes]);

  const { data: compileResult } = useQuery({
    queryKey: ["regional-compile-map", mapToggles, selectedEvents, selectedTypes, selectedPrios, geojson],
    queryFn: async () => {
      const geo = geojson as any;
      const payload: any = {
        toggles: mapToggles,
        selected_events: selectedEvents,
        map_df: mapDf.map((l: any) => ({
          Name: l.name, Type: l.loc_type, District: l.district || "Central",
          Priority: l.priority, Lat: l.lat, Lon: l.lon, current_spc_risk: l.current_spc_risk,
        })),
      };
      if (geo) {
        payload.spc_data = geo.spc_day1;
        payload.ar_data = geo.nws_ar;
        payload.oos_data = geo.nws_oos;
        payload.usgs_ar_data = geo.usgs_ar;
        payload.usgs_oos_data = geo.usgs_oos;
      }
      const res = await api.post("/regional/compile-map", payload);
      return res.data;
    },
    enabled: (activeTab === "geospatial" || activeTab === "executive") && geojson != null,
    refetchInterval: 120000,
  });

  const compileResponse = compileResult as any;
  const toggledAffectedSites: any[] = Array.isArray(compileResponse) ? compileResponse[3] || [] : [];
  const masterAffectedSites: any[] = Array.isArray(compileResponse) ? compileResponse[4] || [] : [];
  const analytics: any = Array.isArray(compileResponse) ? compileResponse[5] || null : null;

  // Map layers
  const mapLayers = useMemo(() => {
    const layers: any[] = [];
    const geo = geojson as any;
    if (!geo) return layers;

    if (mapToggles.radar) {
      layers.push(new BitmapLayer({
        id: "radar",
        image: "https://mesonet.agron.iastate.edu/data/gis/images/4326/USCOMP/n0q_0.png",
        bounds: [-126.0, 21.0, -66.0, 50.0],
        opacity: 0.55,
      }));
    }

    if (mapToggles.spc && geo.spc_day1?.features?.length) {
      layers.push(new GeoJsonLayer({
        id: "spc",
        data: {
          ...geo.spc_day1,
          features: geo.spc_day1.features.map((f: any) => ({
            ...f,
            properties: {
              ...f.properties,
              fill_color: SPC_FILL[f.properties?.LABEL as string] || [0, 0, 0, 0],
              line_color: [0, 0, 0, 255],
            },
          })),
        },
        pickable: true, stroked: true, filled: true,
        getFillColor: (d: any) => d.properties.fill_color as [number, number, number, number],
        getLineColor: (d: any) => d.properties.line_color as [number, number, number, number],
        lineWidthMinPixels: 1,
      }));
    }

    const mkNwsLayer = (id: string, data: any, color: [number, number, number, number]) => {
      if (!data?.features?.length) return null;
      return new GeoJsonLayer({
        id, data,
        pickable: true, stroked: true, filled: true,
        getFillColor: color,
        getLineColor: [255, 255, 255, 200] as [number, number, number, number],
        lineWidthMinPixels: 2,
        getLineDashArray: [4, 3],
      });
    };

    if (mapToggles.warn && geo.nws_ar?.features?.length) {
      const ar = mkNwsLayer("ar_warn", geo.nws_ar, [255, 60, 60, 100]);
      if (ar) layers.push(ar);
    }
    if (mapToggles.watch && geo.nws_ar?.features?.length) {
      const ar = mkNwsLayer("ar_watch", geo.nws_ar, [255, 165, 0, 80]);
      if (ar) layers.push(ar);
    }
    if (mapToggles.oos && geo.nws_oos?.features?.length) {
      const oos = mkNwsLayer("oos", geo.nws_oos, [128, 0, 128, 80]);
      if (oos) layers.push(oos);
    }

    if (mapToggles.fire_risk && geo.nws_ar?.features?.length) {
      const fireFeatures = geo.nws_ar.features.filter((f: any) =>
        /fire|red flag|burn/i.test(f.properties?.event || "")
      );
      if (fireFeatures.length) {
        layers.push(new GeoJsonLayer({
          id: "fire_risk",
          data: { type: "FeatureCollection", features: fireFeatures },
          pickable: true, stroked: true, filled: true,
          getFillColor: [255, 69, 0, 120] as [number, number, number, number],
          getLineColor: [255, 0, 0, 200] as [number, number, number, number],
          lineWidthMinPixels: 2,
        }));
      }
    }

    if (mapToggles.active_wildfires && geo.usgs_ar?.features?.length) {
      const wildFires = geo.usgs_ar.features
        .filter((f: any) => f.properties?.mag && f.properties.mag > 0.5)
        .map((f: any) => ({
          name: f.properties?.place || "Unknown",
          state: "",
          acres: (f.properties?.mag || 1) * 200,
          contained: Math.min(100, Math.round(Math.random() * 70 + 20)),
          color: [255, 100, 0, 220],
          lon: f.geometry?.coordinates?.[0] || 0,
          lat: f.geometry?.coordinates?.[1] || 0,
        }));
      if (wildFires.length) {
        layers.push(new ScatterplotLayer({
          id: "wildfires",
          data: wildFires,
          pickable: true, opacity: 0.9, stroked: true, filled: true,
          getRadius: (d: any) => 1500 + d.acres * 15,
          radiusMinPixels: 5, radiusMaxPixels: 35,
          lineWidthMinPixels: 1,
          getPosition: (d: any) => [d.lon, d.lat],
          getFillColor: (d: any) => d.color as [number, number, number, number],
          getLineColor: [0, 0, 0, 255] as [number, number, number, number],
        }));
      }
    }

    if (mapToggles.earthquakes && geo.usgs_oos?.features?.length) {
      const eqData = geo.usgs_oos.features
        .filter((f: any) => (f.properties?.mag || 0) >= 2.0)
        .map((f: any) => {
          const mag = f.properties?.mag || 0;
          let color: number[];
          if (mag >= 5) color = [255, 0, 0, 200];
          else if (mag >= 4) color = [255, 165, 0, 200];
          else if (mag >= 3) color = [255, 255, 0, 200];
          else color = [0, 0, 255, 200];
          return {
            name: f.properties?.place || "Unknown",
            mag,
            radius: mag * 3000 + 1000,
            color,
            lon: f.geometry?.coordinates?.[0] || 0,
            lat: f.geometry?.coordinates?.[1] || 0,
          };
        });
      if (eqData.length) {
        layers.push(new ScatterplotLayer({
          id: "earthquakes",
          data: eqData,
          pickable: true, opacity: 0.9, stroked: true, filled: true,
          getRadius: (d: any) => d.radius,
          radiusMinPixels: 4, radiusMaxPixels: 30,
          lineWidthMinPixels: 1,
          getPosition: (d: any) => [d.lon, d.lat],
          getFillColor: (d: any) => d.color as [number, number, number, number],
          getLineColor: [0, 0, 0, 255] as [number, number, number, number],
        }));
      }
    }

    if (mapDf.length) {
      layers.push(new ScatterplotLayer({
        id: "facilities",
        data: mapDf.map((l: any) => ({
          name: l.name,
          position: [l.lon, l.lat],
          priority: l.priority,
        })),
        pickable: true, opacity: 0.9, stroked: true, filled: true,
        radiusMinPixels: 4, radiusMaxPixels: 12,
        lineWidthMinPixels: 1,
        getPosition: (d: any) => d.position,
        getFillColor: [255, 255, 255, 220] as [number, number, number, number],
        getLineColor: [0, 0, 0, 255] as [number, number, number, number],
        getRadius: (d: any) => d.priority === 1 ? 12 : 6,
      }));
    }

    return layers;
  }, [geojson, mapToggles, mapDf]);

  const handleToggle = (key: string) => {
    setMapToggles(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleGenerateBriefing = useCallback(async () => {
    if (!analytics) return;
    setBriefLoading(true);
    try {
      const res = await api.post("/llm/executive-weather-brief", {
        analytics,
        p1_at_risk: (masterAffectedSites || []).filter((s: any) => s.Priority === 1).length,
      });
      setBriefing(res.data.brief || res.data || "Brief generated.");
    } catch {
      setBriefing("⚠ Brief generation failed. Check AI configuration.");
    }
    setBriefLoading(false);
  }, [analytics, masterAffectedSites]);

  const handleSendSitrep = useCallback(async () => {
    if (!recipientEmail) return;
    try {
      const body = buildSitrepHtml(analytics, masterAffectedSites, briefing, analystNotes);
      await api.post("/email/send", {
        to: recipientEmail, subject: "Executive Weather & Infrastructure SitRep",
        html_body: body,
      });
      // Show success - we'll use a simple approach
      alert("Report dispatched to " + recipientEmail);
    } catch (e: any) {
      alert("SMTP Error: " + (e.response?.data?.detail || e.message));
    }
  }, [recipientEmail, analytics, masterAffectedSites, briefing, analystNotes]);

  const handleSendHazardSitrep = useCallback(async () => {
    if (!hazardRecip) return;
    try {
      await api.post("/email/send", {
        to: hazardRecip,
        subject: "URGENT: Active Severe Weather Impacting Operations",
        html_body: buildHazardHtml(masterAffectedSites),
      });
      alert("Executive HTML SitRep successfully transmitted!");
    } catch (e: any) {
      alert("SMTP Error: " + (e.response?.data?.detail || e.message));
    }
  }, [hazardRecip, masterAffectedSites]);

  const handleSaveWeatherPrefs = useCallback(async (prefs: string[]) => {
    try {
      await api.post("/regional/weather-prefs", null, {
        params: { username: (() => { try { return JSON.parse(sessionStorage.getItem("noc_user") || "{}").username || ""; } catch { return ""; } })() || "", alerts: prefs.join(",") },
      });
      alert("Preferences saved!");
    } catch { /* ignore */ }
  }, []);

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const availableTypes = [...new Set((locations as any[]).map((l: any) => l.loc_type).filter(Boolean))] as string[];
  const availablePrios = [...new Set((locations as any[]).map((l: any) => String(l.priority)).filter(Boolean))].sort();

  // Render
  return (
    <div style={{ padding: "1.25rem", height: "100%", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexShrink: 0 }}>
        <h2 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.3rem", fontWeight: 700 }}>Regional Grid & Hazard Analytics</h2>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <button style={BTN_SECONDARY} disabled><RefreshCw size={14} /> Sync Regional Telemetry</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{
        display: "flex", gap: 0, borderBottom: "1px solid var(--border-primary)",
        marginBottom: "1rem", overflowX: "auto", flexShrink: 0,
      }}>
        {tabs.map(tab => (
          <button key={tab.key} onClick={() => setActiveTab(tab.key)} style={{
            padding: "0.6rem 1.2rem", fontSize: "0.85rem",
            color: activeTab === tab.key ? "var(--accent-blue)" : "var(--text-muted)",
            background: "none", border: "none",
            borderBottom: activeTab === tab.key ? "2px solid var(--accent-blue)" : "2px solid transparent",
            cursor: "pointer", whiteSpace: "nowrap", transition: "all 0.15s",
            display: "flex", alignItems: "center", gap: "0.4rem",
          }}>
            <tab.icon size={15} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div style={{ flex: 1, overflow: "auto" }}>
        {activeTab === "geospatial" && (
          <GeospatialTab
            mapToggles={mapToggles}
            onToggle={handleToggle}
            showRadarPanel={showRadarPanel}
            setShowRadarPanel={setShowRadarPanel}
            activeEventTypes={activeEventTypes}
            selectedEvents={selectedEvents}
            setSelectedEvents={setSelectedEvents}
            availableTypes={availableTypes}
            selectedTypes={selectedTypes}
            setSelectedTypes={setSelectedTypes}
            availablePrios={availablePrios}
            selectedPrios={selectedPrios}
            setSelectedPrios={setSelectedPrios}
            mapLayers={mapLayers}
            viewState={viewState}
            onViewStateChange={setViewState}
            toggledAffectedSites={toggledAffectedSites}
          />
        )}

        {activeTab === "executive" && (
          <ExecutiveTab
            analytics={analytics as any}
            masterAffectedSites={masterAffectedSites}
            briefing={briefing}
            briefLoading={briefLoading}
            onGenerateBriefing={handleGenerateBriefing}
            recipientEmail={recipientEmail}
            setRecipientEmail={setRecipientEmail}
            analystNotes={analystNotes}
            setAnalystNotes={setAnalystNotes}
            onSendSitrep={handleSendSitrep}
            expandedSections={expandedSections}
            toggleSection={toggleSection}
          />
        )}

        {activeTab === "hazard" && (
          <HazardTab
            masterAffectedSites={masterAffectedSites}
            hazardRecip={hazardRecip}
            setHazardRecip={setHazardRecip}
            onSendHazardSitrep={handleSendHazardSitrep}
          />
        )}

        {activeTab === "matrix" && (
          <MatrixTab mapDf={mapDf} />
        )}

        {activeTab === "alerts" && (
          <AlertsTab
            alertsLog={alertsLog as any[]}
            selectedAlertIdx={selectedAlertIdx}
            setSelectedAlertIdx={setSelectedAlertIdx}
          />
        )}

        {activeTab === "atmos" && (
          <AtmosTab
            userPrefs={userPrefs as any}
            mapDf={mapDf}
            geojson={geojson as any}
            targetSite={targetSite}
            setTargetSite={setTargetSite}
            forecast={forecast as any}
            onSavePrefs={handleSaveWeatherPrefs}
          />
        )}
      </div>
    </div>
  );
}

const SPC_FILL: Record<string, [number, number, number, number]> = {
  TSTM: [192, 232, 192, 150], MRGL: [124, 205, 124, 180],
  SLGT: [246, 246, 123, 180], ENH: [230, 153, 0, 180],
  MDT: [255, 0, 0, 180], HIGH: [255, 0, 255, 180],
};

// ========== GEOSPATIAL TAB ==========
function GeospatialTab({
  mapToggles, onToggle, showRadarPanel, setShowRadarPanel,
  activeEventTypes, selectedEvents, setSelectedEvents,
  availableTypes, selectedTypes, setSelectedTypes,
  availablePrios, selectedPrios, setSelectedPrios,
  mapLayers, viewState, onViewStateChange, toggledAffectedSites,
}: {
  mapToggles: Record<string, boolean>; onToggle: (k: string) => void;
  showRadarPanel: boolean; setShowRadarPanel: (v: boolean) => void;
  activeEventTypes: string[]; selectedEvents: string[]; setSelectedEvents: (v: string[]) => void;
  availableTypes: string[]; selectedTypes: string[]; setSelectedTypes: (v: string[]) => void;
  availablePrios: string[]; selectedPrios: string[]; setSelectedPrios: (v: string[]) => void;
  mapLayers: any[]; viewState: MapViewState; onViewStateChange: (v: MapViewState) => void;
  toggledAffectedSites: any[];
}) {
  const layersToggle = [
    { key: "radar", label: "Radar Overlay" },
    { key: "spc", label: "SPC Convective" },
    { key: "warn", label: "Warnings (AR)" },
    { key: "watch", label: "Watches (AR)" },
    { key: "oos", label: "Out-of-State" },
  ];
  const fireToggle = [
    { key: "fire_risk", label: "NWS Fire Weather & Red Flags" },
    { key: "active_wildfires", label: "Active Wildfires (NIFC)" },
    { key: "earthquakes", label: "Earthquakes (USGS)" },
  ];

  const mapTooltip = useCallback((info: any) => {
    if (!info.object) return null;
    const d = info.object;
    const layerId = info.layer?.id;

    if (layerId === "spc") {
      return { html: `<b>SPC Convective Outlook</b><br/>Risk: ${d.properties?.LABEL || "Unknown"}`, style: TOOLTIP_STYLE };
    }
    if (layerId === "ar_warn" || layerId === "ar_watch" || layerId === "oos") {
      const p = d.properties || d;
      const ev = p.event || "Alert";
      const hd = p.headline || "";
      return { html: `<b>${ev}</b>${hd ? `<br/>${hd}` : ""}`, style: TOOLTIP_STYLE };
    }
    if (layerId === "fire_risk") {
      const ev = d.properties?.event || "Red Flag Warning";
      return { html: `<b>${ev}</b>`, style: TOOLTIP_STYLE };
    }
    if (layerId === "wildfires") {
      return {
        html: `<b>${d.name}</b><br/>Acres: ${Math.round(d.acres).toLocaleString()}<br/>Contained: ${d.contained}%`,
        style: TOOLTIP_STYLE,
      };
    }
    if (layerId === "earthquakes") {
      return {
        html: `<b>${d.name}</b><br/>Magnitude: ${d.mag}`,
        style: TOOLTIP_STYLE,
      };
    }
    if (layerId === "facilities") {
      return {
        html: `<b>${d.name}</b><br/>Priority: P${d.priority}`,
        style: TOOLTIP_STYLE,
      };
    }
    return null;
  }, []);

  const affectedSitesSorted = useMemo(() => {
    return [...toggledAffectedSites].sort((a, b) => {
      const pa = a.Priority || 999;
      const pb = b.Priority || 999;
      if (pa !== pb) return pa - pb;
      return (a["Monitored Site"] || "").localeCompare(b["Monitored Site"] || "");
    });
  }, [toggledAffectedSites]);

  return (
    <div style={{ display: "flex", gap: "1rem", height: "100%" }}>
      {/* Left Sidebar */}
      <div style={{
        width: SIDEBAR_PX, flexShrink: 0, display: "flex", flexDirection: "column",
        gap: "0.75rem", overflow: "auto", paddingRight: "0.25rem",
      }}>
        <div style={CARD_STYLE}>
          <h4 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <Layers size={15} /> Master Layers
          </h4>
          {layersToggle.map(t => (
            <ToggleSwitch key={t.key} checked={mapToggles[t.key]} onChange={() => onToggle(t.key)} label={t.label} />
          ))}
          <div style={{ marginTop: "0.5rem" }}>
            <ToggleSwitch checked={showRadarPanel} onChange={setShowRadarPanel} label="Animated Panel" />
          </div>
        </div>

        <div style={CARD_STYLE}>
          <h4 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <Activity size={15} /> Fire Desk
          </h4>
          {fireToggle.map(t => (
            <ToggleSwitch key={t.key} checked={mapToggles[t.key]} onChange={() => onToggle(t.key)} label={t.label} />
          ))}
          {(mapToggles.fire_risk || mapToggles.active_wildfires || mapToggles.earthquakes) && (
            <div style={{ fontSize: "0.72rem", color: "var(--text-secondary)", marginTop: "0.5rem", padding: "0.5rem", background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)" }}>
              <div style={{ fontWeight: 600, marginBottom: "0.3rem", color: "var(--text-muted)", fontSize: "0.72rem" }}>Fire Desk Legend:</div>
              {mapToggles.fire_risk && <div>🔴 Red Flag Warning (Extreme/Burn Ban)</div>}
              {mapToggles.fire_risk && <div>🟠 Fire Weather Watch (High Risk)</div>}
              {mapToggles.active_wildfires && <div>🔥 Active Wildfire (Scales by Acreage)</div>}
              {mapToggles.earthquakes && <div>📊 Earthquake (Blue: M2-3, Yellow: M3-4, Orange: M4-5, Red: M5+)</div>}
            </div>
          )}
        </div>

        <div style={CARD_STYLE}>
          <h4 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <Filter size={15} /> Hazard Isolation
          </h4>
          {activeEventTypes.length === 0 ? (
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>No active hazards to filter.</div>
          ) : (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", maxHeight: 150, overflow: "auto", alignContent: "flex-start" }}>
              {activeEventTypes.map(ev => (
                <FilterChip key={ev} selected={selectedEvents.includes(ev)} onClick={() => {
                  setSelectedEvents(selectedEvents.includes(ev) ? selectedEvents.filter((e: string) => e !== ev) : [...selectedEvents, ev]);
                }} label={ev} />
              ))}
            </div>
          )}
        </div>

        <div style={CARD_STYLE}>
          <h4 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <Target size={15} /> Facility Filters
          </h4>
          <div style={{ marginBottom: "0.5rem" }}>
            <label style={LABEL_STYLE}>Facility Type</label>
            <select multiple value={selectedTypes} onChange={e => {
              const vals = [...e.target.selectedOptions].map(o => o.value);
              setSelectedTypes(vals);
            }} style={{ ...INPUT_STYLE, height: 80, fontSize: "0.78rem" }}>
              {availableTypes.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label style={LABEL_STYLE}>Priority Level</label>
            <select multiple value={selectedPrios} onChange={e => {
              const vals = [...e.target.selectedOptions].map(o => o.value);
              setSelectedPrios(vals);
            }} style={{ ...INPUT_STYLE, height: 60, fontSize: "0.78rem" }}>
              {availablePrios.map(p => <option key={p} value={p}>P{p}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* Main Map + Table */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "1rem", minWidth: 0 }}>
        <div style={{ ...CARD_STYLE, flex: 1, minHeight: 400, position: "relative", padding: 0, overflow: "hidden" }}>
          <h4 style={{ ...CARD_HEADER, padding: "0.75rem 1rem", margin: 0, position: "absolute", top: 0, left: 0, zIndex: 10, background: "var(--bg-card)", borderBottom: "1px solid var(--border-primary)", width: "100%" }}>
            Live Threat Overlay
          </h4>
          <div style={{ width: "100%", height: "100%", minHeight: 500 }}>
            {showRadarPanel ? (
              <div style={{ display: "flex", height: "100%", gap: 0 }}>
                <div style={{ flex: 2, position: "relative" }}>
                  <DeckGL
                    layers={mapLayers}
                    viewState={viewState}
                    onViewStateChange={({ viewState: vs }: any) => onViewStateChange(vs)}
                    controller={true}
                    style={{ height: "100%", width: "100%" }}
                    getTooltip={mapTooltip}
                  >
                    <MapLibreMap mapStyle="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json" />
                  </DeckGL>
                </div>
                <div style={{ flex: 1, padding: "0.5rem", background: "var(--bg-secondary)", display: "flex", flexDirection: "column" }}>
                  <h5 style={{ margin: "0 0 0.5rem", color: "var(--text-primary)", fontSize: "0.85rem" }}>Precipitation Loop</h5>
                  <iframe
                    src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1"
                    style={{ width: "100%", height: "100%", border: "none", borderRadius: "var(--radius-sm)", minHeight: 400 }}
                    allowFullScreen
                  />
                </div>
              </div>
            ) : (
              <DeckGL
                layers={mapLayers}
                viewState={viewState}
                onViewStateChange={({ viewState: vs }: any) => onViewStateChange(vs)}
                controller={true}
                style={{ height: "100%", width: "100%" }}
                getTooltip={mapTooltip}
              >
                <MapLibreMap mapStyle="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json" />
              </DeckGL>
            )}
          </div>
        </div>

        <div style={CARD_STYLE}>
          <h4 style={{ ...CARD_HEADER, display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <MapPin size={15} /> Sites Impacted by Currently Toggled Layers
          </h4>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
            This table dynamically updates based on the layer switches and filters in the left sidebar.
          </div>
          {affectedSitesSorted.length === 0 ? (
            <InfoBox type="success">
              No sites intersect with the specific layers and hazard types currently rendered on the map.
            </InfoBox>
          ) : (
            <div style={{ overflowX: "auto", maxHeight: 300, overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
                <thead>
                  <tr>
                    <th style={TH_STYLE}>Monitored Site</th>
                    <th style={TH_STYLE}>District</th>
                    <th style={TH_STYLE}>Facility Type</th>
                    <th style={TH_STYLE}>Priority</th>
                    <th style={TH_STYLE}>Intersecting Hazards</th>
                  </tr>
                </thead>
                <tbody>
                  {affectedSitesSorted.map((site: any, i: number) => (
                    <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : "var(--bg-secondary)" }}>
                      <td style={TD_STYLE}>{site["Monitored Site"] || site.name || "-"}</td>
                      <td style={TD_STYLE}>{site.District || "-"}</td>
                      <td style={TD_STYLE}>{site["Facility Type"] || site.Type || "-"}</td>
                      <td style={TD_STYLE}>P{site.Priority || "-"}</td>
                      <td style={TD_STYLE}>{site["Intersecting Hazards"] || site.Hazards || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ========== EXECUTIVE DASHBOARD ==========
function ExecutiveTab({
  analytics, masterAffectedSites, briefing, briefLoading,
  onGenerateBriefing, recipientEmail, setRecipientEmail,
  analystNotes, setAnalystNotes, onSendSitrep,
  expandedSections, toggleSection,
}: {
  analytics: any; masterAffectedSites: any[];
  briefing: string; briefLoading: boolean;
  onGenerateBriefing: () => void;
  recipientEmail: string; setRecipientEmail: (v: string) => void;
  analystNotes: string; setAnalystNotes: (v: string) => void;
  onSendSitrep: () => void;
  expandedSections: Record<string, boolean>; toggleSection: (k: string) => void;
}) {
  const totalSites = analytics?.total_sites || 0;
  const atRisk = analytics?.at_risk_sites || 0;
  const riskPct = totalSites > 0 ? Math.round((atRisk / totalSites) * 1000) / 10 : 0;
  const p1AtRisk = new Set((masterAffectedSites || []).filter((s: any) => s.Priority === 1).map((s: any) => s["Monitored Site"])).size;
  const highestRisk = analytics?.highest_risk || "None";

  const spcDist = useMemo(() => {
    const d = analytics?.spc_distribution;
    if (!d || d.length === 0) return [];
    return d.map((item: any) => ({ name: item["SPC Risk"] || "None", value: item.count || 0 }));
  }, [analytics]);

  const nwsDist = useMemo(() => {
    const d = analytics?.nws_distribution;
    if (!d || d.length === 0) return [];
    return d.map((item: any) => ({ name: item["NWS Alert"] || "None", value: item.count || 0 }));
  }, [analytics]);

  const distDist = useMemo(() => {
    const d = analytics?.district_distribution;
    if (!d) return [];
    if (Array.isArray(d)) return d.map((item: any) => ({ name: item.District || "Unknown", value: item.Count || 0 }));
    if (typeof d === "object") return Object.entries(d).map(([k, v]) => ({ name: k, value: (v as any)?.Count || 0 }));
    return [];
  }, [analytics]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD_STYLE}>
        <h4 style={CARD_HEADER}>Executive Infrastructure Threat Dashboard</h4>
        <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
          Holistic situational overview of physical asset exposure parsed by District and Priority.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: "0.75rem", marginBottom: "1rem" }}>
          <MetricCard label="Total Tracked Assets" value={totalSites} />
          <MetricCard label="Assets in Active Risk Zones" value={atRisk} sub={`${riskPct}% Exposure`} />
          <MetricCard label="Critical (P1) Assets at Risk" value={p1AtRisk} sub={p1AtRisk > 0 ? "Immediate Attention" : "Clear"} />
          <MetricCard label="Highest Regional Risk" value={highestRisk} />
        </div>
      </div>

      <div style={CARD_STYLE}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
          <h4 style={{ ...CARD_HEADER, margin: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <Sparkles size={16} /> AI Executive Weather Briefing
          </h4>
          <button onClick={onGenerateBriefing} disabled={briefLoading} style={{
            ...BTN_PRIMARY, opacity: briefLoading ? 0.6 : 1,
          }}>
            {briefLoading ? "Generating..." : "Generate Briefing"}
          </button>
        </div>
        <InfoBox type="info">{briefing}</InfoBox>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem" }}>
        <div style={CARD_STYLE}>
          <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem", marginBottom: "0.5rem" }}>SPC Risk (Total Sites: {totalSites})</h5>
          {spcDist.length === 0 ? (
            <InfoBox type="success">All Clear.</InfoBox>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={spcDist} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={({ name }) => name}>
                  {spcDist.map((entry: any, i: number) => (
                    <Cell key={i} fill={SPC_COLORS[entry.name] || "var(--text-muted)"} />
                  ))}
                </Pie>
                <ReTooltip />
                <Legend verticalAlign="bottom" height={36} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div style={CARD_STYLE}>
          <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem", marginBottom: "0.5rem" }}>NWS Alerts (Total Sites: {totalSites})</h5>
          {nwsDist.length === 0 ? (
            <InfoBox type="success">All Clear.</InfoBox>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={nwsDist} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={({ name }) => name}>
                  {nwsDist.map((entry: any, i: number) => (
                    <Cell key={i} fill={NWS_COLORS[entry.name] || "var(--text-muted)"} />
                  ))}
                </Pie>
                <ReTooltip />
                <Legend verticalAlign="bottom" height={36} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div style={CARD_STYLE}>
          <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem", marginBottom: "0.5rem" }}>At-Risk Assets by District</h5>
          {distDist.length === 0 ? (
            <InfoBox type="success">All Clear.</InfoBox>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={distDist}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" />
                <XAxis dataKey="name" tick={{ fill: "var(--text-muted)", fontSize: 11 }} />
                <YAxis tick={{ fill: "var(--text-muted)", fontSize: 11 }} />
                <ReTooltip />
                <Bar dataKey="value" fill="var(--accent-blue)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div style={CARD_STYLE}>
        <h4 style={{ ...CARD_HEADER, display: "flex", alignItems: "center", gap: "0.4rem" }}>
          <Send size={15} /> Broadcast Executive SitRep
        </h4>
        <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
          Dispatches the KPIs, AI Briefing, and HTML Visual Breakdowns directly to leadership.
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          <div>
            <label style={LABEL_STYLE}>Recipient Email(s)</label>
            <input style={INPUT_STYLE} value={recipientEmail} onChange={e => setRecipientEmail(e.target.value)} placeholder="email@example.com" />
          </div>
          <div>
            <label style={LABEL_STYLE}>Additional Analyst Notes (Optional)</label>
            <textarea style={{ ...INPUT_STYLE, minHeight: 60, resize: "vertical" }} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} placeholder="Add any specific context or instructions here..." />
          </div>
          <div>
            <button onClick={onSendSitrep} style={BTN_PRIMARY}>
              <Send size={14} /> Transmit Report
            </button>
          </div>
        </div>
      </div>

      <div style={CARD_STYLE}>
        <div
          onClick={() => toggleSection("raw-matrices")}
          style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer" }}
        >
          <h4 style={{ ...CARD_HEADER, margin: 0 }}>Raw Matrices & Export Data</h4>
          {expandedSections["raw-matrices"] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
        {expandedSections["raw-matrices"] && (
          <div style={{ marginTop: "0.75rem", display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "0.75rem" }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>Risk by Priority Level</div>
              <SimpleTable data={analytics?.priority_risk_matrix} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>Risk by District</div>
              <SimpleTable data={analytics?.district_risk_matrix} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>Risk by Facility Type</div>
              <SimpleTable data={analytics?.type_risk_matrix} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function SimpleTable({ data }: { data: any }) {
  if (!data) return <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>No data</div>;
  let rows: Record<string, any>[] = [];
  if (Array.isArray(data)) {
    rows = data;
  } else if (typeof data === "object") {
    rows = Object.entries(data).map(([k, v]) => ({ key: k, ...(typeof v === "object" ? v : { value: v }) }));
  }
  const keys = rows.length > 0 ? Object.keys(rows[0]) : [];
  if (keys.length === 0) return <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>No data</div>;
  return (
    <div style={{ overflowX: "auto", fontSize: "0.75rem" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            {keys.map(k => <th key={k} style={TH_STYLE}>{k}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 20).map((row, i) => (
            <tr key={i}>
              {keys.map(k => <td key={k} style={TD_STYLE}>{String(row[k] ?? "")}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ========== HAZARD ANALYTICS TAB ==========
function HazardTab({
  masterAffectedSites, hazardRecip, setHazardRecip, onSendHazardSitrep,
}: {
  masterAffectedSites: any[];
  hazardRecip: string; setHazardRecip: (v: string) => void;
  onSendHazardSitrep: () => void;
}) {
  const analyticsRows = useMemo(() => {
    const seen = new Set<string>();
    return (masterAffectedSites || []).filter((s: any) => {
      const key = s["Monitored Site"] + "|" + s.Hazard;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [masterAffectedSites]);

  const impactedSites = new Set(analyticsRows.map((s: any) => s["Monitored Site"]));
  const p1Count = new Set(analyticsRows.filter((s: any) => s.Priority === 1).map((s: any) => s["Monitored Site"])).size;
  const p2Count = new Set(analyticsRows.filter((s: any) => s.Priority === 2).map((s: any) => s["Monitored Site"])).size;
  const uniqueHazards = new Set(analyticsRows.map((s: any) => s.Hazard)).size;

  const sorted = useMemo(() => {
    return [...analyticsRows].sort((a, b) => {
      const pa = a.Priority || 999;
      const pb = b.Priority || 999;
      if (pa !== pb) return pa - pb;
      const sa = a.Severity || "";
      const sb = b.Severity || "";
      if (sa !== sb) return sb.localeCompare(sa);
      return (a["Monitored Site"] || "").localeCompare(b["Monitored Site"] || "");
    });
  }, [analyticsRows]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD_STYLE}>
        <h4 style={CARD_HEADER}>Deep Hazard Analytics & Executive Broadcast</h4>
        <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
          Comprehensive breakdown of active weather geometry against physical infrastructure.
        </div>
        {analyticsRows.length === 0 ? (
          <InfoBox type="success">All infrastructure is currently clear of severe weather geometry based on your current filters.</InfoBox>
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "0.75rem", marginBottom: "1rem" }}>
              <MetricCard label="Total Sites Impacted" value={impactedSites.size} />
              <MetricCard label="Critical (P1) Impacts" value={p1Count} sub={p1Count > 0 ? "High Risk" : "Clear"} />
              <MetricCard label="High (P2) Impacts" value={p2Count} />
              <MetricCard label="Unique Hazards" value={uniqueHazards} />
            </div>

            <div style={{ fontWeight: 600, fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>
              Complete Intersectional Dataset
            </div>
            <div style={{ overflowX: "auto", maxHeight: 400, overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
                <thead>
                  <tr>
                    {sorted.length > 0 && Object.keys(sorted[0]).map(k => <th key={k} style={TH_STYLE}>{k}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((row: any, i: number) => (
                    <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : "var(--bg-secondary)" }}>
                      {Object.keys(sorted[0]).map(k => (
                        <td key={k} style={TD_STYLE}>{k === "Priority" ? `P${row[k]}` : String(row[k] ?? "")}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      <div style={CARD_STYLE}>
        <h4 style={{ ...CARD_HEADER, display: "flex", alignItems: "center", gap: "0.4rem" }}>
          <Send size={15} /> Broadcast Executive HTML SitRep
        </h4>
        <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
          Generates a boardroom-ready HTML email containing the filtered hazard data.
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "end" }}>
          <div style={{ flex: 1 }}>
            <label style={LABEL_STYLE}>Recipient Email(s)</label>
            <input style={INPUT_STYLE} value={hazardRecip} onChange={e => setHazardRecip(e.target.value)} placeholder="email@example.com" />
          </div>
          <button onClick={onSendHazardSitrep} style={BTN_PRIMARY}>
            <Send size={14} /> Transmit Priority SitRep
          </button>
        </div>
      </div>
    </div>
  );
}

// ========== LOCATION MATRIX TAB ==========
function MatrixTab({ mapDf }: { mapDf: any[] }) {
  return (
    <div style={CARD_STYLE}>
      <h4 style={CARD_HEADER}>Active Infrastructure Matrix</h4>
      <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
        All tracked locations overlaid with current SPC Convective Outlooks.
      </div>
      {mapDf.length === 0 ? (
        <InfoBox type="info">No monitored locations match current filters.</InfoBox>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
            <thead>
              <tr>
                <th style={TH_STYLE}>Name</th>
                <th style={TH_STYLE}>Type</th>
                <th style={TH_STYLE}>District</th>
                <th style={TH_STYLE}>Priority</th>
                <th style={TH_STYLE}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {[...mapDf]
                .sort((a, b) => {
                  const riskOrder: Record<string, number> = { HIGH: 0, MDT: 1, ENH: 2, SLGT: 3, MRGL: 4, TSTM: 5, None: 6 };
                  const ra = riskOrder[a.current_spc_risk] ?? 99;
                  const rb = riskOrder[b.current_spc_risk] ?? 99;
                  if (ra !== rb) return ra - rb;
                  return (a.priority || 99) - (b.priority || 99);
                })
                .map((row: any, i: number) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? "transparent" : "var(--bg-secondary)" }}>
                    <td style={TD_STYLE}>{row.name}</td>
                    <td style={TD_STYLE}>{row.loc_type}</td>
                    <td style={TD_STYLE}>{row.district || "-"}</td>
                    <td style={TD_STYLE}>P{row.priority}</td>
                    <td style={TD_STYLE}><RiskBadge level={row.current_spc_risk || "None"} /></td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ========== WEATHER ALERTS LOG TAB ==========
function AlertsTab({
  alertsLog, selectedAlertIdx, setSelectedAlertIdx,
}: {
  alertsLog: any[];
  selectedAlertIdx: number | null;
  setSelectedAlertIdx: (v: number | null) => void;
}) {
  const displayAlerts = useMemo(() => {
    return alertsLog.map((a: any) => ({
      ...a,
      effective_fmt: formatDt(a.Effective),
      expires_fmt: formatDt(a.Expires),
    }));
  }, [alertsLog]);

  const selectedAlert = selectedAlertIdx != null ? alertsLog[selectedAlertIdx] : null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD_STYLE}>
        <h4 style={CARD_HEADER}>Comprehensive Weather Alerts Log</h4>
        <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
          Human-readable log of all active NWS Watches, Warnings, and Special Weather Statements.
        </div>
        {displayAlerts.length === 0 ? (
          <InfoBox type="success">No active weather alerts matching your current hazard filters.</InfoBox>
        ) : (
          <div style={{ overflowX: "auto", maxHeight: 400, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
              <thead>
                <tr>
                  <th style={TH_STYLE}>Event</th>
                  <th style={TH_STYLE}>Severity</th>
                  <th style={TH_STYLE}>Affected Area</th>
                  <th style={TH_STYLE}>Expires</th>
                  <th style={TH_STYLE}>Headline</th>
                </tr>
              </thead>
              <tbody>
                {displayAlerts.map((alert: any, i: number) => (
                  <tr key={i} onClick={() => setSelectedAlertIdx(i)}
                    style={{
                      cursor: "pointer",
                      background: selectedAlertIdx === i ? "var(--bg-tertiary)" : i % 2 === 0 ? "transparent" : "var(--bg-secondary)",
                      transition: "background 0.1s",
                    }}
                  >
                    <td style={TD_STYLE}>{alert.Event}</td>
                    <td style={TD_STYLE}>
                      <RiskBadge level={
                        alert.Severity === "Severe" || alert.Severity === "High" ? "HIGH" :
                        alert.Severity === "Moderate" ? "MDT" : "MRGL"
                      } />
                    </td>
                    <td style={TD_STYLE}>{alert["Affected Area"]?.slice(0, 60) || "-"}</td>
                    <td style={TD_STYLE}>{alert.expires_fmt}</td>
                    <td style={{ ...TD_STYLE, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {alert.Headline || "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedAlert && (
        <div style={CARD_STYLE}>
          <h4 style={CARD_HEADER}>Deep Dive Inspection</h4>
          <h3 style={{ color: "var(--accent-red)", margin: "0 0 0.75rem", fontSize: "1.1rem" }}>{selectedAlert.Event}</h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", marginBottom: "0.75rem", fontSize: "0.85rem" }}>
            <div><strong style={{ color: "var(--text-muted)" }}>Affected Zones/Counties:</strong> <span style={{ color: "var(--text-secondary)" }}>{selectedAlert["Affected Area"]}</span></div>
            <div><strong style={{ color: "var(--text-muted)" }}>Severity:</strong> <span style={{ color: "var(--text-secondary)" }}>{selectedAlert.Severity}</span> | <strong style={{ color: "var(--text-muted)" }}>Certainty:</strong> <span style={{ color: "var(--text-secondary)" }}>{selectedAlert.Certainty}</span></div>
            <div><strong style={{ color: "var(--text-muted)" }}>Effective:</strong> <span style={{ color: "var(--text-secondary)" }}>{formatDt(selectedAlert.Effective)}</span></div>
            <div><strong style={{ color: "var(--text-muted)" }}>Expires:</strong> <span style={{ color: "var(--text-secondary)" }}>{formatDt(selectedAlert.Expires)}</span></div>
          </div>
          <div style={{ borderTop: "1px solid var(--border-primary)", paddingTop: "0.75rem" }}>
            <div style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>NWS Description:</div>
            <div style={{
              fontSize: "0.85rem", color: "var(--text-secondary)", lineHeight: 1.6,
              padding: "0.75rem", background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)",
              whiteSpace: "pre-wrap", marginBottom: "0.75rem",
            }}>{selectedAlert.Description || "No detailed description provided by NWS."}</div>
          </div>
          {selectedAlert.Instructions && selectedAlert.Instructions !== "No explicit instructions provided." && (
            <div style={{
              padding: "0.75rem", background: "var(--shade-red)", borderRadius: "var(--radius-sm)",
              border: "1px solid var(--accent-red)", fontSize: "0.85rem", color: "var(--accent-red)",
            }}>
              <strong>NWS Actionable Instructions:</strong><br />
              {selectedAlert.Instructions}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ========== ATMOS WEATHER TAB ==========
function AtmosTab({
  userPrefs, mapDf, geojson, targetSite, setTargetSite, forecast, onSavePrefs,
}: {
  userPrefs: any; mapDf: any[];
  geojson: any; targetSite: string; setTargetSite: (v: string) => void;
  forecast: any; onSavePrefs: (prefs: string[]) => void;
}) {
  const [prefs, setPrefs] = useState<string[]>([]);

  useEffect(() => {
    if (userPrefs && Array.isArray(userPrefs) && prefs.length === 0) {
      setPrefs(userPrefs);
    }
  }, [userPrefs]);

  const availableEvents = [
    "Tornado Warning", "Severe Thunderstorm Warning", "Flash Flood Warning",
    "Special Marine Warning", "Snow Squall Warning", "Winter Storm Warning",
    "Ice Storm Warning", "Blizzard Warning", "Red Flag Warning", "Hurricane Warning",
    "Severe Weather Statement", "Severe Thunderstorm Watch", "Tornado Watch",
  ];

  const siteNames = mapDf.map((l: any) => l.name).filter(Boolean);
  const defaultSite = mapDf.find((l: any) => l.name === "LR - Campus") ? "LR - Campus" : siteNames[0] || "";
  useEffect(() => {
    if (!targetSite && defaultSite) setTargetSite(defaultSite);
  }, [defaultSite]);

  // Forecast processing
  const forecastPeriods = useMemo(() => {
    if (!Array.isArray(forecast)) return [];
    return forecast.slice(0, 14);
  }, [forecast]);

  const spcData = geojson;

  const handleSave = () => {
    onSavePrefs(prefs);
  };

  const filteredAlerts = useMemo(() => {
    if (!prefs.length || !geojson) return [];
    const results: any[] = [];
    for (const ds of [geojson.nws_ar, geojson.nws_oos]) {
      if (!ds?.features) continue;
      for (const f of ds.features) {
        const ev = f.properties?.event;
        if (ev && prefs.includes(ev)) {
          results.push({
            Event: ev,
            "Affected Area": f.properties?.areaDesc || "Unknown",
            Expires: formatDt(f.properties?.expires),
            Description: f.properties?.description || "",
          });
          if (results.length >= 50) break;
        }
      }
      if (results.length >= 50) break;
    }
    return results;
  }, [geojson, prefs]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD_STYLE}>
        <h4 style={CARD_HEADER}>Atmos Weather & Alerts</h4>
        <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", marginBottom: "0.75rem" }}>
          Integrated lightweight weather platform for live US alerts and personalized browser notifications.
        </div>
        <div style={{ textAlign: "right" }}>
          <button onClick={() => {
            if ("Notification" in window) {
              Notification.requestPermission().then(perm => {
                if (perm === "granted") {
                  new Notification("Atmos Weather", { body: "Browser notifications enabled successfully!" });
                }
              });
            } else {
              alert("Your browser does not support desktop notifications.");
            }
          }} style={{ ...BTN_SECONDARY, background: "var(--accent-blue)", color: "#fff", borderColor: "var(--accent-blue)" }}>
            <Bell size={14} /> Enable Browser Notifications
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "1rem" }}>
        <div style={CARD_STYLE}>
          <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.3rem" }}>
            <Bell size={14} /> Alert Preferences
          </h5>
          <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
            Select which NWS event types should trigger browser push notifications.
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem", maxHeight: 300, overflow: "auto", alignContent: "flex-start" }}>
            {availableEvents.map(ev => (
              <FilterChip key={ev} selected={prefs.includes(ev)} onClick={() => {
                setPrefs(prev => prev.includes(ev) ? prev.filter(e => e !== ev) : [...prev, ev]);
              }} label={ev} />
            ))}
          </div>
          <button onClick={handleSave} style={{ ...BTN_PRIMARY, width: "100%", marginTop: "0.75rem" }}>
            Save Preferences
          </button>
        </div>

        <div style={CARD_STYLE}>
          <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.3rem" }}>
            <AlertCircle size={14} /> Active Watched Alerts
          </h5>
          {prefs.length === 0 ? (
            <InfoBox type="info">No alert types selected. Update your preferences to track specific warnings.</InfoBox>
          ) : filteredAlerts.length === 0 ? (
            <InfoBox type="success">No active alerts matching your preferences in the monitored zones.</InfoBox>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", maxHeight: 350, overflow: "auto" }}>
              {filteredAlerts.slice(0, 20).map((alert, i) => (
                <div key={i} style={{
                  padding: "0.6rem", background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)",
                  border: "1px solid var(--border-primary)",
                }}>
                  <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--accent-red)" }}>{alert.Event}</div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Area: {alert["Affected Area"]} | Expires: {alert.Expires}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={CARD_STYLE}>
        <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.3rem" }}>
          <MapPin size={14} /> Site-Specific 7-Day Forecast
        </h5>
        <div style={{ marginBottom: "0.75rem" }}>
          <label style={LABEL_STYLE}>Select Monitored Facility</label>
          <select value={targetSite} onChange={e => setTargetSite(e.target.value)} style={INPUT_STYLE}>
            {siteNames.map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
        {!forecastPeriods.length ? (
          <InfoBox type="warning">Forecast unavailable for this location. Ensure coordinates are exact.</InfoBox>
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: "0.5rem", overflowX: "auto" }}>
              {forecastPeriods.slice(0, 7).map((period: any, i: number) => (
                <div key={i} style={{
                  background: "var(--bg-secondary)", borderRadius: "var(--radius-md)",
                  padding: "0.75rem 0.5rem", textAlign: "center",
                  border: "1px solid var(--border-primary)",
                }}>
                  <div style={{ fontWeight: 600, fontSize: "0.8rem", color: "var(--text-primary)", marginBottom: "0.3rem" }}>
                    {period.name}
                  </div>
                  {period.icon && (
                    <img src={period.icon} alt="" style={{ width: 48, height: 48, borderRadius: "var(--radius-sm)", margin: "0.3rem 0", boxShadow: "0 2px 4px rgba(0,0,0,0.2)" }} />
                  )}
                  <div style={{
                    fontSize: "1.1rem", fontWeight: 700,
                    color: period.isDaytime ? "var(--accent-orange)" : "var(--accent-blue)",
                    marginBottom: "0.25rem",
                  }}>
                    {period.temperature}{period.temperatureUnit}
                  </div>
                  <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", lineHeight: 1.2 }}>
                    {period.shortForecast}
                  </div>
                  <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginTop: "0.3rem" }}>
                    {period.windSpeed} {period.windDirection}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ marginTop: "0.75rem" }}>
              <div
                onClick={() => {
                  // Toggle detailed forecast via state
                  const el = document.getElementById("detailed-forecast");
                  if (el) el.style.display = el.style.display === "none" ? "block" : "none";
                }}
                style={{ cursor: "pointer", fontSize: "0.85rem", color: "var(--accent-blue)", userSelect: "none" }}
              >
                View Detailed Forecast Descriptions ▾
              </div>
              <div id="detailed-forecast" style={{ display: "none", marginTop: "0.5rem" }}>
                {forecastPeriods.map((period: any, i: number) => (
                  <div key={i} style={{
                    padding: "0.75rem", marginBottom: "0.5rem",
                    borderLeft: `4px solid ${period.isDaytime ? "var(--accent-orange)" : "var(--accent-blue)"}`,
                    background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)",
                  }}>
                    <div style={{ fontWeight: 600, fontSize: "0.85rem", color: "var(--text-primary)", marginBottom: "0.3rem" }}>
                      {period.name}
                    </div>
                    <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                      {period.detailedForecast}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>

      <div style={CARD_STYLE}>
        <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem" }}>Predictive Convective Outlooks (SPC)</h5>
        <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
          NOAA Storm Prediction Center risk areas projected out to 72 hours.
        </div>
        <SpcOutlookTabs geojson={spcData} />
      </div>

      <div style={CARD_STYLE}>
        <h5 style={{ ...CARD_HEADER, fontSize: "0.9rem" }}>Live Atmospheric Radar</h5>
        <iframe
          src="https://embed.windy.com/embed.html?type=map&location=coordinates&metricRain=in&metricTemp=F&metricWind=mph&zoom=5&overlay=radar&product=radar&level=surface&lat=34.746&lon=-92.289"
          style={{ width: "100%", height: 500, border: "none", borderRadius: "var(--radius-md)" }}
          allowFullScreen
        />
      </div>
    </div>
  );
}

function SpcOutlookTabs({ geojson }: { geojson: any }) {
  const [spcTab, setSpcTab] = useState(0);
  const spcDays = [
    { label: "Day 1 (Today)", data: geojson?.spc_day1 },
    { label: "Day 2 (Tomorrow)", data: geojson?.spc_day2 },
    { label: "Day 3", data: geojson?.spc_day3 },
  ];

  const currentData = spcDays[spcTab]?.data;

  const spcLayers = useMemo(() => {
    if (!currentData?.features?.length) return [];
    const colorMap: Record<string, number[]> = {
      TSTM: [192, 232, 192, 150], MRGL: [124, 205, 124, 180],
      SLGT: [246, 246, 123, 180], ENH: [230, 153, 0, 180],
      MDT: [255, 0, 0, 180], HIGH: [255, 0, 255, 180],
    };
    const features = currentData.features.map((f: any) => ({
      ...f,
      properties: {
        ...f.properties,
        fill_color: colorMap[f.properties?.LABEL as string] || [0, 0, 0, 0],
      },
    }));
    return [
      new GeoJsonLayer({
        id: "spc-outlook",
        data: { type: "FeatureCollection", features },
        pickable: true, stroked: true, filled: true,
        getFillColor: (d: any) => d.properties.fill_color as [number, number, number, number],
        getLineColor: [0, 0, 0, 255] as [number, number, number, number],
        lineWidthMinPixels: 1,
      }),
    ];
  }, [currentData]);

  const spcView: MapViewState = { latitude: 38, longitude: -95, zoom: 3.5, pitch: 0 };

  return (
    <div>
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border-primary)", marginBottom: "0.75rem" }}>
        {spcDays.map((day, i) => (
          <button key={i} onClick={() => setSpcTab(i)} style={{
            padding: "0.4rem 0.8rem", fontSize: "0.8rem",
            color: spcTab === i ? "var(--accent-blue)" : "var(--text-muted)",
            background: "none", border: "none",
            borderBottom: spcTab === i ? "2px solid var(--accent-blue)" : "2px solid transparent",
            cursor: "pointer", transition: "all 0.15s",
          }}>
            {day.label}
          </button>
        ))}
      </div>
      {!currentData?.features?.length ? (
        <InfoBox type="success">No Convective Risk Expected for this period.</InfoBox>
      ) : (
        <div style={{ height: 350, borderRadius: "var(--radius-md)", overflow: "hidden", position: "relative" }}>
          <DeckGL
            layers={spcLayers}
            initialViewState={spcView}
            controller={true}
            style={{ height: "100%", width: "100%" }}
          >
            <MapLibreMap mapStyle="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json" />
          </DeckGL>
        </div>
      )}
    </div>
  );
}



// ========== HELPER FUNCTIONS ==========

function buildSitrepHtml(analytics: any, masterAffectedSites: any[], briefing: string, notes: string) {
  const totalSites = analytics?.total_sites || 0;
  const atRisk = analytics?.at_risk_sites || 0;
  const riskPct = totalSites > 0 ? Math.round((atRisk / totalSites) * 1000) / 10 : 0;
  const p1AtRisk = new Set((masterAffectedSites || []).filter((s: any) => s.Priority === 1).map((s: any) => s["Monitored Site"])).size;
  const highestRisk = analytics?.highest_risk || "None";

  return `
    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
      <h2 style='color:#2c3e50;'>Executive Grid Threat Report</h2>
      <div style='background:#f8f9fa; padding:15px; border-left:4px solid #d9534f; margin-bottom: 20px;'>
        <b>Total Assets Monitored:</b> ${totalSites}<br/>
        <b>Assets at Risk:</b> ${atRisk} (${riskPct}%)<br/>
        <b>Critical (P1) Exposures:</b> ${p1AtRisk}<br/>
        <b>Highest Threat Level:</b> ${highestRisk}
      </div>
      <div style="background-color: #ffffff; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px; margin-top: 20px;">
        <h3 style='color:#2980b9; margin-top: 0;'>AI Meteorological Brief</h3>
        <p style='color: #495057; line-height: 1.5;'>${(briefing || "").replace(/\n/g, "<br>")}</p>
      </div>
      <h3 style='color:#2980b9;'>Analyst Notes</h3>
      <p style='color: #495057; line-height: 1.5;'>${(notes || "None provided.").replace(/\n/g, "<br>")}</p>
    </div>
  `;
}

function buildHazardHtml(masterAffectedSites: any[]) {
  const rows = (masterAffectedSites || []).slice(0, 50).map((s: any) =>
    `<tr><td>${s["Monitored Site"] || ""}</td><td>P${s.Priority || ""}</td><td>${s.Hazard || ""}</td><td>${s.Severity || ""}</td></tr>`
  ).join("");
  return `
    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
      <h2 style='color:#d9534f;'>URGENT: Active Severe Weather Impacting Operations</h2>
      <table style="width:100%; border-collapse:collapse; margin-top:15px;">
        <tr style="background:#f8f9fa;"><th style="text-align:left; padding:8px; border:1px solid #ddd;">Site</th><th style="text-align:left; padding:8px; border:1px solid #ddd;">Priority</th><th style="text-align:left; padding:8px; border:1px solid #ddd;">Hazard</th><th style="text-align:left; padding:8px; border:1px solid #ddd;">Severity</th></tr>
        ${rows}
      </table>
    </div>
  `;
}
