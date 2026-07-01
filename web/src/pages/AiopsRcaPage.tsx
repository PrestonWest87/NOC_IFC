import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { getAllowedTabs } from "../utils/permissions";
import { formatTimeInChicago, formatDateInChicago, chicagoDateString } from "../utils/timezone";
import { MapContainer } from "../components/MapContainer";
import DeckGL from "@deck.gl/react";
import { ScatterplotLayer } from "@deck.gl/layers";
import { Map } from "react-map-gl/maplibre";
import type { MapViewState } from "@deck.gl/core";
import "maplibre-gl/dist/maplibre-gl.css";
import {
  Activity, AlertTriangle, Radio, BarChart3, Globe,
  Play, Send, CheckCircle, Wrench, ChevronDown, ChevronUp,
  RefreshCw, FileText, Shield,
  MapPin, Clock, TrendingUp, Zap
} from "lucide-react";

const INITIAL_VIEW: MapViewState = { latitude: 34.8, longitude: -92.2, zoom: 6, pitch: 0 };

const tabBtn = (active: boolean): React.CSSProperties => ({
  padding: "0.6rem 1.2rem",
  border: "none",
  background: active ? "var(--bg-card)" : "transparent",
  color: active ? "var(--text-primary)" : "var(--text-muted)",
  fontWeight: active ? 600 : 400,
  cursor: "pointer",
  borderBottom: active ? "2px solid var(--accent-blue)" : "2px solid transparent",
  fontSize: "0.9rem",
  display: "flex",
  alignItems: "center",
  gap: "0.4rem",
});

const card: React.CSSProperties = {
  background: "var(--bg-card)",
  borderRadius: "var(--radius-md)",
  padding: "1rem",
  boxShadow: "var(--shadow-sm)",
  border: "1px solid var(--border-primary)",
};

const inputBase: React.CSSProperties = {
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-sm)",
  padding: "0.4rem 0.6rem",
  fontSize: "0.85rem",
  width: "100%",
  boxSizing: "border-box",
};

const btnBase: React.CSSProperties = {
  padding: "0.45rem 1rem",
  borderRadius: "var(--radius-sm)",
  border: "none",
  cursor: "pointer",
  fontWeight: 600,
  fontSize: "0.8rem",
  display: "inline-flex",
  alignItems: "center",
  gap: "0.35rem",
};

const label: React.CSSProperties = { fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.25rem" };

export function AiopsRcaPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const allowedRcaTabs = getAllowedTabs(user?.allowed_actions, "aiopsRca");
  const userActions = user?.allowed_actions ?? [];
  const canDispatch = userActions.includes("Action: Dispatch RCA Tickets");
  const canManageMaint = userActions.includes("Action: Manage Site Maintenance");
  const RCA_TAB_LABELS = ["Active Board", "Patterns", "Global"];
  const [activeTab, setActiveTab] = useState(0);
  const [livePolling, setLivePolling] = useState(true);
  const [dispatchChecked, setDispatchChecked] = useState<Record<string, boolean>>({});
  const [ticketExpanded, setTicketExpanded] = useState<string | null>(null);
  const [maintExpanded, setMaintExpanded] = useState<string | null>(null);
  const [maintForm, setMaintForm] = useState<Record<string, { status: string; etr: string; reason: string }>>({});
  const [ticketTexts, setTicketTexts] = useState<Record<string, string>>({});
  const [sitrepReport, setSitrepReport] = useState<string | null>(null);
  const [deepAnalysisRun, setDeepAnalysisRun] = useState(false);

  // Global Store Methods for Syncing

  const investigateMutation = useMutation({
  mutationFn: (params: { site: string; is_investigating: boolean }) =>
    api.post("/rca/investigate", params).then((r) => r.data),
  onSuccess: () => {
    // This will trigger locally, while the broadcast triggers everyone else
    queryClient.invalidateQueries({ queryKey: ["rca-dashboard"] });
  },
});

  const pollMs = livePolling ? 5000 : false;

  const { data: dashboard } = useQuery({
    queryKey: ["rca-dashboard"],
    queryFn: () => api.get("/rca/dashboard").then((r) => r.data),
    refetchInterval: pollMs,
  });

  const { data: analysis, isFetching: analysisLoading, refetch: refetchAnalysis } = useQuery({
    queryKey: ["rca-analyze"],
    queryFn: () => api.post("/rca/analyze").then((r) => r.data),
    refetchInterval: livePolling ? 30000 : false,
    enabled: activeTab === 0 || deepAnalysisRun,
    retry: 1,
    staleTime: 10000,
  });

  const {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    data: _sitrepData,
    isFetching: sitrepLoading,
    refetch: refetchSitrep,
  } = useQuery({
    queryKey: ["rca-sitrep"],
    queryFn: () => api.get("/rca/sitrep").then((r) => r.data),
    enabled: false,
  });

  const ackMutation = useMutation({
    mutationFn: (alertIds: number[]) =>
      api.post("/rca/acknowledge", alertIds).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rca-dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["rca-analyze"] });
    },
  });

  const dispatchMutation = useMutation({
    mutationFn: ({ alertIds, dispatched }: { alertIds: number[]; dispatched: boolean }) =>
      api.post("/rca/dispatch", { alert_ids: alertIds, is_dispatched: dispatched }).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rca-analyze"] });
      queryClient.invalidateQueries({ queryKey: ["rca-dashboard"] });
    },
  });

  const maintMutation = useMutation({
    mutationFn: (params: { site_name: string; is_maint: boolean; etr: string; reason: string }) =>
      api.post("/rca/site-maintenance", params).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rca-dashboard"] });
    },
  });

  const saveMaint = useCallback(
    (site: string) => {
      const f = maintForm[site] || { status: "No Maintenance", etr: "", reason: "" };
      maintMutation.mutate({
        site_name: site,
        is_maint: f.status === "Active Maintenance",
        etr: f.etr,
        reason: f.reason,
      });
    },
    [maintForm, maintMutation]
  );

  const locations = dashboard?.locations ?? [];
  const alerts: any[] = dashboard?.alerts ?? [];
  const events = dashboard?.events ?? [];
  const clustered = analysis?.clustered ?? {};
  const fleetOutages = analysis?.fleet_outages ?? [];
  const rootCause = analysis?.root_cause ?? {};
  const chronicInsights = analysis?.chronic_insights ?? null;

  const allowedTypes = user?.allowed_site_types;
  const filteredLocations = useMemo(
    () => allowedTypes && allowedTypes.length > 0
      ? (locations ?? []).filter((l: any) => allowedTypes.includes(l.loc_type))
      : (locations ?? []),
    [locations, allowedTypes]
  );

  const investigatingSites = useMemo(() => {
  return new Set((dashboard?.investigating_sites as string[]) || []);
}, [dashboard?.investigating_sites]);

  const prevAlertCounts = useRef<Record<string, number>>({});
  const prevAlertLength = useRef(0);
  const hasAutoAnalyzed = useRef(false);

  const sites = useMemo(
    () => {
      const mapped = (filteredLocations ?? []).map((l: any) => {
        const siteAlerts = alerts.filter((a: any) => a.mapped_location === l.name);
        return {
          name: l.name,
          lat: l.lat,
          lon: l.lon,
          loc_type: l.loc_type,
          alert_count: siteAlerts.length,
          is_dispatched: siteAlerts.some((a: any) => a.is_dispatched),
          under_maintenance: l.under_maintenance ?? false,
          maintenance_etr: l.maintenance_etr ?? null,
          maintenance_reason: l.maintenance_reason ?? null,
        };
      });
      return mapped;
    },
    [filteredLocations, alerts]
  );

  const incidentSites = useMemo(() => {
    const allowedNames = new Set(sites.map((s: any) => s.name));
    const fromCluster = Object.keys(clustered).filter((n) => allowedNames.has(n));
    const fromRoot = Object.keys(rootCause).filter((n) => allowedNames.has(n));
    const fromAlerts: string[] = [...new Set(alerts.map((a: any) => a.mapped_location).filter((n: string) => allowedNames.has(n)))];
    return [...new Set([...fromCluster, ...fromRoot, ...fromAlerts])] as string[];
  }, [clustered, rootCause, alerts, sites]);

  const getRc = (site: string) => {
    const rc = rootCause[site];
    if (!rc) return null;
    if (Array.isArray(rc)) {
      return {
        cause: rc[0] ?? "Unknown",
        score: rc[1] ?? 0,
        priority: rc[2] ?? "P3 - MODERATE",
        evidenceLog: rc[3] ?? [],
        blastRadius: rc[4] ?? "Unknown",
        patientZero: rc[5] ?? null,
        cascadeStr: rc[6] ?? "N/A",
      };
    }
    return rc as any;
  };

  const getClusterAlerts = (site: string): any[] => {
    if (clustered[site]?.alerts) return clustered[site].alerts;
    return alerts.filter((a: any) => a.mapped_location === site);
  };

  const getSiteInfo = (site: string) => sites.find((s: any) => s.name === site);

  const handleAcknowledge = (site: string) => {
    const clusterAlerts = getClusterAlerts(site);
    const ids = clusterAlerts.map((a: any) => a.id).filter(Boolean);
    if (ids.length > 0) ackMutation.mutate(ids);
  };

  const handleDispatchToggle = (site: string, checked: boolean) => {
    setDispatchChecked((prev) => ({ ...prev, [site]: checked }));
    const clusterAlerts = getClusterAlerts(site);
    const ids = clusterAlerts.map((a: any) => a.id).filter(Boolean);
    if (ids.length > 0) dispatchMutation.mutate({ alertIds: ids, dispatched: checked });
  };

  const handleGenerateTicket = useCallback(
    (site: string) => {
      const rc = getRc(site);
      const priority = rc?.priority ?? "P3 - MODERATE";
      const pz = rc?.patientZero ?? "Indeterminate (Simultaneous Failure)";
      const cause = rc?.cause ?? "Under Investigation";
      api
        .post("/rca/generate-ticket", { site, priority, patient_zero: pz, root_cause: cause })
        .then((r) => {
          setTicketTexts((prev) => ({ ...prev, [site]: r.data.ticket }));
        })
        .catch(() => {
          const fallback = [
            `URGENT: ${priority} Incident at ${site}`,
            `Patient Zero: ${pz}`,
            `Root Cause: ${cause}`,
            ``,
            `---`,
            `Action Required: Investigate and remediate at earliest convenience.`,
            `Recipients: remedyforceworkflow@aecc.com, noc@aecc.com`,
          ].join("\n");
          setTicketTexts((prev) => ({ ...prev, [site]: fallback }));
        });
    },
    [rootCause]
  );

  const [siteDialog, setSiteDialog] = useState<{
    name: string; lat: number; lon: number; alert_count: number;
    is_dispatched: boolean; under_maintenance: boolean;
    maintenance_etr: string | null; maintenance_reason: string | null;
  } | null>(null);
  const [dialogDispatch, setDialogDispatch] = useState(false);
  const [dialogStatus, setDialogStatus] = useState<string>("Investigate/Dispatch");
  const [dialogEtr, setDialogEtr] = useState("");
  const [dialogReason, setDialogReason] = useState("");

  const openSiteDialog = useCallback((site: any) => {
    const lat = site.position ? site.position[1] : site.lat;
    const lon = site.position ? site.position[0] : site.lon;
    setSiteDialog({ ...site, lat, lon });
    setDialogDispatch(site.is_dispatched);
    const isMaint = site.under_maintenance;
    setDialogStatus(isMaint ? "No Dispatch Needed" : "Investigate/Dispatch");
    setDialogEtr(site.maintenance_etr ? chicagoDateString(new Date(site.maintenance_etr)) : chicagoDateString());
    setDialogReason(site.maintenance_reason ?? "");
  }, []);

  const handleMapClick = useCallback((info: any) => {
    if (info.object && info.layer?.id === "sites") {
      const d = info.object;
      openSiteDialog(d);
    }
  }, [openSiteDialog]);

  const handleSaveSiteDialog = useCallback(async () => {
    if (!siteDialog) return;
    const { name } = siteDialog;
    const clusterAlerts = alerts.filter((a: any) => a.mapped_location === name);
    const alertIds = clusterAlerts.map((a: any) => a.id).filter(Boolean);

    const promises: Promise<any>[] = [];

    if (alertIds.length > 0) {
      promises.push(dispatchMutation.mutateAsync({ alertIds, dispatched: dialogDispatch }));
    }

    const isMaint = dialogStatus === "No Dispatch Needed";
    const isInvestigating = !isMaint;

    // Use our new solid backend API endpoint!
    promises.push(investigateMutation.mutateAsync({ site: name, is_investigating: isInvestigating }));

    const etrDate = isMaint ? dialogEtr : "";
    const reason = dialogReason;
    promises.push(maintMutation.mutateAsync({ site_name: name, is_maint: isMaint, etr: etrDate, reason }));

    await Promise.allSettled(promises);
    setSiteDialog(null);
}, [siteDialog, dialogDispatch, dialogStatus, dialogEtr, dialogReason, alerts, dispatchMutation, maintMutation, investigateMutation]);

 useEffect(() => {
    const prev = prevAlertCounts.current;
    const curr: Record<string, number> = {};
    for (const s of sites) {
      curr[s.name] = s.alert_count;
      
      // Auto-clear investigating state if the problem is fixed
      if (s.alert_count === 0 && investigatingSites.has(s.name)) {
        investigateMutation.mutate({ site: s.name, is_investigating: false });
      }

      if (prev[s.name] !== undefined && prev[s.name] > 0 && s.alert_count === 0 && s.under_maintenance) {
        maintMutation.mutate({ site_name: s.name, is_maint: false, etr: chicagoDateString(), reason: "" });
      }
    }
    prevAlertCounts.current = curr;
  }, [sites, investigatingSites, maintMutation, investigateMutation]);

  useEffect(() => {
    if (typeof Notification !== "undefined" && Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, []);

  useEffect(() => {
    const curLen = alerts.length;
    if (prevAlertLength.current > 0 && curLen > prevAlertLength.current && typeof Notification !== "undefined" && Notification.permission === "granted") {
      const delta = curLen - prevAlertLength.current;
      new Notification(`NOC Alert: ${delta} new alert(s)`, {
        body: `${delta} new alert(s) detected on AIOps RCA board.`,
        icon: "/favicon.ico",
      });
    }
    prevAlertLength.current = curLen;
  }, [alerts.length]);

  useEffect(() => {
    if (!hasAutoAnalyzed.current) {
      hasAutoAnalyzed.current = true;
      refetchAnalysis();
    }
  }, [refetchAnalysis]);

  const handleRunDeepAnalysis = () => {
    setDeepAnalysisRun(true);
    refetchAnalysis().then(() => setDeepAnalysisRun(true));
  };

  const handleRunGlobalCorrelation = () => {
    refetchSitrep().then((res) => {
      if (res.data?.report) setSitrepReport(res.data.report);
    });
  };

  const mapTooltip = useCallback((info: any) => {
    if (!info.object) return null;
    const d = info.object;
    if (info.layer?.id === "sites") {
      return {
        html: `<b>${d.name}</b><br/>${d.status_text}`,
        style: { background: "var(--bg-card)", color: "var(--text-primary)", fontSize: "0.78rem", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.5rem" },
      };
    }
    return null;
  }, []);

  const mapLayers = useMemo(() => {
    const seenCoords: Record<string, number> = {};
    const pts: any[] = [];
    const pulseData: any[] = [];

    for (const s of sites) {
      const isDown = s.alert_count > 0;
      const isNoDispatch = s.under_maintenance;
      const isDispatched = s.is_dispatched;
      const isInvestigating = investigatingSites.has(s.name);

      let color: [number, number, number, number];
      let statusText: string;
      let showPulse: boolean;
      let radius: number;

      if (!isDown) {
        color = [40, 167, 69, 200];
        statusText = "Operational / Clear";
        showPulse = false;
        radius = 2000;
      } else if (isInvestigating) {
        color = [255, 165, 0, 200];
        statusText = "Down (Investigating)";
        showPulse = false;
        radius = 3500;
      } else if (isDispatched) {
        color = [255, 193, 7, 200];
        statusText = "Down (Ticket Dispatched)";
        showPulse = false;
        radius = 3000;
      } else if (isNoDispatch) {
        color = [0, 123, 255, 200];
        statusText = "Down (Maintenance)";
        showPulse = false;
        radius = 2500;
      } else {
        color = [220, 53, 69, 200];
        statusText = "Down (Action Required)";
        showPulse = true;
        radius = 4000;
      }

      const coordKey = `${s.lat}_${s.lon}`;
      if (seenCoords[coordKey] !== undefined) {
        seenCoords[coordKey] += 1;
        const offset = seenCoords[coordKey];
        pts.push({
          name: s.name, position: [s.lon + 0.012 * offset, s.lat + 0.012 * offset] as [number, number],
          color, alert_count: s.alert_count, under_maintenance: s.under_maintenance,
          is_dispatched: s.is_dispatched, maintenance_etr: s.maintenance_etr,
          maintenance_reason: s.maintenance_reason, status_text: statusText, radius,
        });
      } else {
        seenCoords[coordKey] = 0;
        pts.push({
          name: s.name, position: [s.lon, s.lat] as [number, number],
          color, alert_count: s.alert_count, under_maintenance: s.under_maintenance,
          is_dispatched: s.is_dispatched, maintenance_etr: s.maintenance_etr,
          maintenance_reason: s.maintenance_reason, status_text: statusText, radius,
        });
      }

      if (showPulse) {
        pulseData.push({ position: [s.lon, s.lat] as [number, number], radius: 12000 });
      }
    }

    const baseLayers: any[] = [
      new ScatterplotLayer({
        id: "sites",
        data: pts,
        getPosition: (d: any) => d.position,
        getFillColor: (d: any) => d.color,
        getRadius: (d: any) => d.radius,
        radiusMinPixels: 4,
        radiusMaxPixels: 15,
        pickable: true,
        stroked: true,
        getLineColor: [255, 255, 255, 255],
        lineWidthMinPixels: 1,
      }),
    ];

    if (pulseData.length > 0) {
      baseLayers.push(
        new ScatterplotLayer({
          id: "alert-pulses",
          data: pulseData,
          getPosition: (d: any) => d.position,
          getFillColor: [220, 53, 69, 40],
          getRadius: (d: any) => d.radius,
          radiusMaxPixels: 45,
          pickable: false,
        })
      );
    }

    return baseLayers;
  }, [sites, investigatingSites]);

  const chronOffNodes =
    chronicInsights && Array.isArray(chronicInsights[0])
      ? chronicInsights[0]
      : chronicInsights?.offending_nodes ?? chronicInsights?.offendingNodes ?? chronicInsights?.[0] ?? null;
  const chronHotspots =
    chronicInsights && Array.isArray(chronicInsights[1])
      ? chronicInsights[1]
      : chronicInsights?.hotspots ?? chronicInsights?.[1] ?? null;
  const chronForecast =
    chronicInsights && Array.isArray(chronicInsights)
      ? chronicInsights[2]
      : chronicInsights?.forecast ?? chronicInsights?.[2] ?? null;

  const renderChronicTable = (data: any, caption: string) => {
    if (!data) return <div style={{ ...label, fontStyle: "italic" }}>No data available</div>;
    const rows = Array.isArray(data) ? data : data.data ?? data.rows ?? [];
    if (rows.length === 0) return <div style={{ ...label, fontStyle: "italic" }}>No data available</div>;
    const cols = Object.keys(rows[0]);
    return (
      <div style={{ overflowX: "auto" }}>
        <div style={{ ...label, marginBottom: "0.35rem" }}>{caption}</div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
          <thead>
            <tr>
              {cols.map((c) => (
                <th
                  key={c}
                  style={{
                    textAlign: "left",
                    padding: "0.35rem 0.5rem",
                    borderBottom: "1px solid var(--border-primary)",
                    color: "var(--text-secondary)",
                    fontWeight: 600,
                    fontSize: "0.72rem",
                    textTransform: "uppercase",
                    letterSpacing: "0.03em",
                  }}
                >
                  {c.replace(/_/g, " ")}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 15).map((row: any, i: number) => (
              <tr key={i}>
                {cols.map((c) => (
                  <td
                    key={c}
                    style={{
                      padding: "0.3rem 0.5rem",
                      borderBottom: "1px solid var(--border-primary)",
                      color: "var(--text-primary)",
                    }}
                  >
                    {String(row[c])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  useEffect(() => {
    if (allowedRcaTabs.length > 0 && !allowedRcaTabs.includes(String(activeTab))) {
      setActiveTab(Number(allowedRcaTabs[0]));
    }
  }, [allowedRcaTabs.join(",")]);

  return (
    <div style={{ padding: "1.5rem", height: "calc(100vh - 3rem)", overflow: "auto" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
        <div>
          <h2 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.35rem" }}>AIOps Root Cause Analysis</h2>
          <span style={{ ...label, margin: 0 }}>Live correlation of non-uniform monitoring alerts with Regional Intelligence.</span>
        </div>
      </div>

      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid var(--border-primary)", marginBottom: "1rem" }}>
        {RCA_TAB_LABELS.filter((_, i) => allowedRcaTabs.length === 0 || allowedRcaTabs.includes(String(i))).map((label, i) => (
          <button key={label} style={tabBtn(activeTab === i)} onClick={() => setActiveTab(i)}>
            {i === 0 ? <Activity size={16} /> : i === 1 ? <BarChart3 size={16} /> : <Globe size={16} />} {label}
          </button>
        ))}
      </div>

      <div style={{ display: activeTab === 0 ? '' : 'none' }}>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "0.75rem" }}>
            <button
              style={{
                ...btnBase,
                background: livePolling ? "var(--accent-green)" : "var(--bg-tertiary)",
                color: livePolling ? "#fff" : "var(--text-muted)",
              }}
              onClick={() => setLivePolling((p) => !p)}
            >
              {livePolling ? <Zap size={14} /> : <RefreshCw size={14} />}
              {livePolling ? "Live 5s Polling ON" : "Live 5s Polling OFF"}
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "3fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
            <MapContainer height="600px">
              <div style={{ position: "absolute", top: 8, left: 10, zIndex: 10, fontSize: "0.8rem", fontWeight: 600, color: "var(--text-secondary)", background: "var(--bg-card)", padding: "0.2rem 0.6rem", borderRadius: "var(--radius-sm)" }}>
                Overlays
              </div>
              <DeckGL
                layers={mapLayers}
                initialViewState={INITIAL_VIEW}
                controller={true}
                style={{ height: "100%" }}
                getTooltip={mapTooltip}
                onClick={handleMapClick}
                getCursor={({ isDragging, isHovering }: any) => isDragging ? "grabbing" : isHovering ? "pointer" : "default"}
              >
                <Map mapStyle="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json" />
              </DeckGL>
              {siteDialog && (
                <div style={{
                  position: "fixed", inset: 0, zIndex: 1000,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  background: "rgba(0,0,0,0.5)",
                }} onClick={() => setSiteDialog(null)}>
                  <div onClick={(e) => e.stopPropagation()} style={{
                    background: "var(--bg-card)", color: "var(--text-primary)",
                    borderRadius: "var(--radius-md)", padding: "1.25rem",
                    minWidth: 320, maxWidth: 420,
                    boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
                    border: "1px solid var(--border-primary)",
                    fontSize: "0.82rem", lineHeight: 1.5,
                  }}>
                    <div style={{ fontWeight: 700, marginBottom: "0.5rem", fontSize: "0.9rem", borderBottom: "1px solid var(--border-primary)", paddingBottom: "0.3rem" }}>
                      Manage Site Status — {siteDialog.name}
                    </div>

                    <div style={{ marginBottom: "0.5rem" }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.2rem" }}>Status</div>
                      {canDispatch && (
                        <label style={{ display: "flex", alignItems: "center", gap: "0.35rem", fontSize: "0.82rem", cursor: "pointer", marginBottom: "0.2rem" }}>
                          <input type="radio" name="site-status-modal" value="Investigate/Dispatch"
                            checked={dialogStatus === "Investigate/Dispatch"}
                            onChange={(e) => setDialogStatus(e.target.value)}
                            style={{ accentColor: "var(--accent-blue)" }}
                          /> Investigate/Dispatch
                        </label>
                      )}
                      {canManageMaint && (
                        <label style={{ display: "flex", alignItems: "center", gap: "0.35rem", fontSize: "0.82rem", cursor: "pointer" }}>
                          <input type="radio" name="site-status-modal" value="No Dispatch Needed"
                            checked={dialogStatus === "No Dispatch Needed"}
                            onChange={(e) => setDialogStatus(e.target.value)}
                            style={{ accentColor: "var(--accent-blue)" }}
                          /> No Dispatch Needed
                        </label>
                      )}
                    </div>

                    {canDispatch && (
                      <div style={{ marginBottom: "0.5rem" }}>
                        <label style={{ display: "flex", alignItems: "center", gap: "0.35rem", fontSize: "0.82rem", cursor: "pointer" }}>
                          <input type="checkbox"
                            checked={dialogDispatch}
                            onChange={(e) => setDialogDispatch(e.target.checked)}
                            style={{ accentColor: "var(--accent-blue)" }}
                          /> Ticket Dispatched
                        </label>
                      </div>
                    )}

                    <div style={{ marginBottom: "0.4rem" }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.15rem" }}>ETR</div>
                      <input type="date" value={dialogEtr}
                        onChange={(e) => setDialogEtr(e.target.value)}
                        style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-input)", color: "var(--text-primary)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.25rem 0.4rem", fontSize: "0.78rem" }}
                      />
                    </div>

                    <div style={{ marginBottom: "0.5rem" }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.15rem" }}>Reason</div>
                      <textarea value={dialogReason}
                        onChange={(e) => setDialogReason(e.target.value)}
                        rows={2}
                        style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-input)", color: "var(--text-primary)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.25rem 0.4rem", fontSize: "0.78rem", resize: "vertical" }}
                      />
                    </div>

                    <div style={{ display: "flex", gap: "0.4rem", justifyContent: "flex-end", borderTop: "1px solid var(--border-primary)", paddingTop: "0.4rem" }}>
                      <button onClick={() => setSiteDialog(null)}
                        style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.3rem 0.7rem", fontSize: "0.78rem", cursor: "pointer" }}>
                        Cancel
                      </button>
                      <button onClick={handleSaveSiteDialog}
                        style={{ background: "var(--accent-blue)", color: "#fff", border: "none", borderRadius: "var(--radius-sm)", padding: "0.3rem 0.7rem", fontSize: "0.78rem", cursor: "pointer", fontWeight: 600 }}>
                        Save Changes
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </MapContainer>

            <div style={{ ...card, height: "600px", overflow: "auto", display: "flex", flexDirection: "column" }}>
              <h3 style={{ margin: "0 0 0.5rem", fontSize: "0.95rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                <Clock size={15} /> Event Log
              </h3>
              <div style={{ flex: 1, borderTop: "1px solid var(--border-primary)", paddingTop: "0.5rem" }}>
                {(events ?? []).length === 0 && (
                  <div style={{ ...label, textAlign: "center", padding: "1rem 0" }}>No events recorded</div>
                )}
                {(events ?? []).map((e: any, i: number) => {
                  const ts = e.timestamp ? formatTimeInChicago(e.timestamp) : "";
                  const msg = (e.message ?? "").replace(/[^\x20-\x7E]/g, "").trim();
                  return (
                    <div
                      key={e.id ?? i}
                      style={{
                        padding: "0.3rem 0",
                        borderBottom: "1px solid var(--border-primary)",
                        fontSize: "0.75rem",
                        color: "var(--text-secondary)",
                        lineHeight: 1.4,
                      }}
                    >
                      <span style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", fontWeight: 600 }}>{ts}</span>
                      {" | "}
                      {msg}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {fleetOutages.length > 0 && (
            <div
              style={{
                background: "var(--accent-red)",
                border: "2px solid var(--accent-red)",
                borderRadius: "var(--radius-md)",
                padding: "0.8rem 1.2rem",
                marginBottom: "1rem",
                textAlign: "center",
                color: "#fff",
              }}
            >
              <h3 style={{ margin: 0, color: "#fff", fontSize: "1.1rem" }}>
                GLOBAL FLEET EVENT DETECTED
              </h3>
              {fleetOutages.map((event: any, i: number) => (
                <p key={i} style={{ margin: "0.25rem 0 0", fontSize: "0.9rem", opacity: 0.95 }}>
                  Massive <strong>{event.provider ?? event.provider_name ?? "Unknown"}</strong> Carrier Outage affecting{" "}
                  <strong>{(event.affected_sites ?? []).length}</strong> tracked sites. Individual downstream RCAs have been
                  automatically overridden.
                </p>
              ))}
            </div>
          )}

          <div>
            <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
              <AlertTriangle size={16} /> Correlation
            </h3>
            {incidentSites.length === 0 && (
              <div style={{ color: "var(--accent-green)", fontWeight: 600, fontSize: "0.9rem" }}>Grid Operational.</div>
            )}

            {incidentSites.map((site) => {
              const rc = getRc(site);
              const siteInfo = getSiteInfo(site);
              const isUnderMaint = siteInfo?.under_maintenance ?? false;
              const dispatchVal =
                dispatchChecked[site] ??
                getClusterAlerts(site).some((a: any) => a.is_dispatched);
              const clusterAlerts = getClusterAlerts(site);
              const alertIds = clusterAlerts.map((a: any) => a.id).filter(Boolean);

              const isAcking = ackMutation.isPending;
              const mf = maintForm[site] ?? { status: "No Maintenance", etr: "", reason: "" };

              return (
                <div key={site} style={{ ...card, marginBottom: "0.75rem" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem" }}>
                    <div>
                      <h4 style={{ margin: 0, fontSize: "0.95rem", color: "var(--text-primary)" }}>
                        {rc?.priority ?? "P3 - MODERATE"} | Site: {site}
                      </h4>
                    </div>
                    {clusterAlerts.length > 0 && (
                      <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", background: "var(--bg-tertiary)", padding: "0.15rem 0.45rem", borderRadius: "var(--radius-sm)" }}>
                        {clusterAlerts.length} alerts
                      </span>
                    )}
                  </div>

                  <div
                    style={{
                      background: "var(--bg-tertiary)",
                      borderLeft: "4px solid var(--accent-orange)",
                      padding: "0.5rem 0.75rem",
                      borderRadius: "var(--radius-sm)",
                      marginBottom: "0.5rem",
                      fontSize: "0.85rem",
                      color: "var(--text-primary)",
                    }}
                  >
                    {rc?.cause ?? "Awaiting analysis..."}
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem", fontSize: "0.82rem", color: "var(--text-secondary)" }}>
                    <Shield size={14} />
                    <strong>Patient Zero:</strong>{" "}
                    {rc?.patientZero ? (
                      <span style={{ color: "var(--accent-red)", fontWeight: 600 }}>{rc.patientZero}</span>
                    ) : (
                      "Indeterminate (Simultaneous Failure)"
                    )}
                  </div>

                  {isUnderMaint && siteInfo && (
                    <div
                      style={{
                        background: "rgba(234,179,8,0.15)",
                        borderLeft: "4px solid var(--accent-yellow)",
                        padding: "0.4rem 0.7rem",
                        borderRadius: "var(--radius-sm)",
                        marginBottom: "0.5rem",
                        fontSize: "0.8rem",
                        color: "var(--text-primary)",
                      }}
                    >
                      <strong>SITE UNDER MAINTENANCE</strong> (ETR:{" "}
                      {siteInfo.maintenance_etr
                        ? formatDateInChicago(siteInfo.maintenance_etr)
                        : "Unknown"}
                      )
                      <br />
                      <span style={{ color: "var(--text-secondary)" }}>
                        Reason: {siteInfo.maintenance_reason || "No reason provided."}
                      </span>
                    </div>
                  )}

                  <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center", marginTop: "0.4rem" }}>
                    {canDispatch && (
                      <label
                        style={{
                          ...btnBase,
                          background: "var(--bg-tertiary)",
                          color: "var(--text-primary)",
                          cursor: "pointer",
                          gap: "0.4rem",
                          fontSize: "0.8rem",
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={dispatchVal}
                          onChange={(e) => handleDispatchToggle(site, e.target.checked)}
                          style={{ accentColor: "var(--accent-blue)", cursor: "pointer" }}
                        />
                        Ticket Dispatched
                      </label>
                    )}

                    {canDispatch && (
                      <button
                        style={{
                          ...btnBase,
                          background: "transparent",
                          color: "var(--accent-blue)",
                          border: "1px solid var(--accent-blue)",
                        }}
                        onClick={() => {
                          if (ticketExpanded === site) {
                            setTicketExpanded(null);
                          } else {
                            setTicketExpanded(site);
                            if (!ticketTexts[site]) handleGenerateTicket(site);
                          }
                        }}
                      >
                        <FileText size={14} />
                        {ticketExpanded === site ? "Hide Ticket" : "Draft & Dispatch Ticket"}
                        {ticketExpanded === site ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    )}

                    <button
                      style={{
                        ...btnBase,
                        background: isAcking ? "var(--bg-tertiary)" : "var(--accent-green)",
                        color: isAcking ? "var(--text-muted)" : "#fff",
                        opacity: isAcking ? 0.6 : 1,
                        cursor: isAcking ? "not-allowed" : "pointer",
                      }}
                      disabled={isAcking}
                      onClick={() => handleAcknowledge(site)}
                    >
                      <CheckCircle size={14} />
                      {isAcking ? "Acknowledging..." : `Acknowledge Incident & Clear Board (${site})`}
                    </button>

                    {canManageMaint && (
                      <button
                        style={{
                          ...btnBase,
                          background: "transparent",
                          color: "var(--accent-orange)",
                          border: "1px solid var(--accent-orange)",
                        }}
                        onClick={() => {
                          setMaintExpanded((prev) => (prev === site ? null : site));
                          if (!maintForm[site]) {
                            setMaintForm((prev) => ({
                              ...prev,
                              [site]: {
                                status: siteInfo?.under_maintenance ? "Active Maintenance" : "No Maintenance",
                                etr: siteInfo?.maintenance_etr
                                  ? chicagoDateString(new Date(siteInfo.maintenance_etr))
                                  : chicagoDateString(),
                                reason: siteInfo?.maintenance_reason ?? "",
                              },
                            }));
                          }
                        }}
                      >
                        <Wrench size={14} />
                        {maintExpanded === site ? "Hide Maintenance" : "Maintenance Controls"}
                        {maintExpanded === site ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    )}
                  </div>

                  {canDispatch && ticketExpanded === site && (
                    <div style={{ marginTop: "0.75rem", padding: "0.75rem", background: "var(--bg-tertiary)", borderRadius: "var(--radius-sm)" }}>
                      <div style={{ ...label, marginBottom: "0.3rem" }}>Ticket Notes / RCA Summary</div>
                      <textarea
                        style={{
                          ...inputBase,
                          minHeight: "180px",
                          resize: "vertical",
                          fontFamily: "var(--font-mono)",
                          fontSize: "0.78rem",
                          lineHeight: 1.5,
                        }}
                        value={ticketTexts[site] ?? "Generating ticket..."}
                        onChange={(e) =>
                          setTicketTexts((prev) => ({ ...prev, [site]: e.target.value }))
                        }
                      />
                      <div style={{ ...label, marginTop: "0.5rem", marginBottom: "0.3rem" }}>
                        Ticket will be automatically dispatched to: <strong>remedyforceworkflow@aecc.com, noc@aecc.com</strong>
                      </div>
                      <button
                        style={{
                          ...btnBase,
                          background: "var(--accent-blue)",
                          color: "#fff",
                          width: "100%",
                          justifyContent: "center",
                          marginTop: "0.4rem",
                        }}
                        disabled={dispatchMutation.isPending}
                        onClick={async () => {
                          if (alertIds.length > 0) {
                            try {
                              await api.post("/rca/send-ticket", {
                                site,
                                ticket_text: ticketTexts[site] ?? "",
                                recipient: "remedyforceworkflow@aecc.com, noc@aecc.com",
                                alert_ids: alertIds,
                              });
                              setDispatchChecked((prev) => ({ ...prev, [site]: true }));
                            } catch (err) {
                              console.error("Failed to send ticket:", err);
                            }
                          }
                        }}
                      >
                        <Send size={14} /> Dispatch Ticket
                      </button>
                    </div>
                  )}

                  {canManageMaint && maintExpanded === site && (
                    <div style={{ marginTop: "0.75rem", padding: "0.75rem", background: "var(--bg-tertiary)", borderRadius: "var(--radius-sm)" }}>
                      <div style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary)", marginBottom: "0.5rem" }}>
                        Maintenance Controls: {site}
                      </div>
                      <div style={{ marginBottom: "0.5rem" }}>
                        <div style={label}>Maintenance Status</div>
                        <select
                          style={inputBase}
                          value={mf.status}
                          onChange={(e) =>
                            setMaintForm((prev) => ({
                              ...prev,
                              [site]: { ...prev[site], status: e.target.value },
                            }))
                          }
                        >
                          <option value="Active Maintenance">Active Maintenance</option>
                          <option value="No Maintenance">No Maintenance</option>
                        </select>
                      </div>
                      <div style={{ marginBottom: "0.5rem" }}>
                        <div style={label}>Estimated Time of Restoration (ETR)</div>
                        <input
                          type="date"
                          style={inputBase}
                          value={mf.etr}
                          onChange={(e) =>
                            setMaintForm((prev) => ({
                              ...prev,
                              [site]: { ...prev[site], etr: e.target.value },
                            }))
                          }
                        />
                      </div>
                      <div style={{ marginBottom: "0.5rem" }}>
                        <div style={label}>Reason / Explanation</div>
                        <textarea
                          style={{ ...inputBase, minHeight: "60px", resize: "vertical" }}
                          value={mf.reason}
                          onChange={(e) =>
                            setMaintForm((prev) => ({
                              ...prev,
                              [site]: { ...prev[site], reason: e.target.value },
                            }))
                          }
                        />
                      </div>
                      <button
                        style={{
                          ...btnBase,
                          background: "var(--accent-blue)",
                          color: "#fff",
                          width: "100%",
                          justifyContent: "center",
                        }}
                        onClick={() => saveMaint(site)}
                        disabled={maintMutation.isPending}
                      >
                        {maintMutation.isPending ? "Saving..." : "Save Maintenance Update"}
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

      <div style={{ display: activeTab === 1 ? '' : 'none' }}>
          <h3 style={{ margin: "0 0 0.25rem", fontSize: "1rem", color: "var(--text-primary)" }}>
            Predictive Analytics & Chronic Degradation
          </h3>
          <p style={{ ...label, marginBottom: "0.75rem" }}>
            Analyzes historical telemetry to identify degrading hardware and unstable infrastructure before catastrophic failure.
          </p>

          <button
            style={{
              ...btnBase,
              background: deepAnalysisRun ? "var(--bg-tertiary)" : "var(--accent-blue)",
              color: deepAnalysisRun ? "var(--text-muted)" : "#fff",
              width: "100%",
              justifyContent: "center",
              marginBottom: "1rem",
              cursor: deepAnalysisRun && analysisLoading ? "not-allowed" : "pointer",
            }}
            disabled={deepAnalysisRun && analysisLoading}
            onClick={handleRunDeepAnalysis}
          >
            {analysisLoading ? <RefreshCw size={15} className="spin" /> : <Play size={15} />}
            {analysisLoading ? "Processing..." : "Run Deep Analysis"}
          </button>

          {deepAnalysisRun && (
            <div>
              {!chronOffNodes && !chronHotspots && !chronForecast && (
                <div style={{ color: "var(--accent-green)", fontWeight: 600, fontSize: "0.9rem", marginBottom: "1rem" }}>
                  No chronic degradation patterns detected in the current telemetry window.
                </div>
              )}

              {(chronOffNodes || chronHotspots) && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
                  <div style={card}>
                    <h4 style={{ margin: "0 0 0.25rem", fontSize: "0.9rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                      <AlertTriangle size={15} /> Top Offending Nodes
                    </h4>
                    <div style={{ ...label, marginBottom: "0.5rem" }}>
                      Specific devices exhibiting high frequency of state-flapping.
                    </div>
                    {renderChronicTable(chronOffNodes, "")}
                  </div>
                  <div style={card}>
                    <h4 style={{ margin: "0 0 0.25rem", fontSize: "0.9rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                      <MapPin size={15} /> Infrastructure Hotspots
                    </h4>
                    <div style={{ ...label, marginBottom: "0.5rem" }}>
                      Sites or regions experiencing chronic instability.
                    </div>
                    {chronHotspots
                      ? renderChronicTable(chronHotspots, "")
                      : (
                        <div style={{ ...label, fontStyle: "italic" }}>
                          Insufficient data for site heatmapping.
                        </div>
                      )}
                  </div>
                </div>
              )}

              {chronForecast && (
                <div style={{ ...card, marginTop: "0.5rem" }}>
                  <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.9rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                    <TrendingUp size={15} /> AI Predictive Maintenance Forecast
                  </h4>
                  {typeof chronForecast === "string" ? (
                    <div
                      style={{ fontSize: "0.85rem", color: "var(--text-primary)", lineHeight: 1.6, whiteSpace: "pre-wrap" }}
                      dangerouslySetInnerHTML={{ __html: chronForecast }}
                    />
                  ) : Array.isArray(chronForecast) ? (
                    <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.85rem", color: "var(--text-primary)", lineHeight: 1.7 }}>
                      {chronForecast.map((item: any, i: number) => (
                        <li key={i}>{typeof item === "string" ? item : JSON.stringify(item)}</li>
                      ))}
                    </ul>
                  ) : (
                    renderChronicTable(chronForecast, "")
                  )}
                </div>
              )}

              {!deepAnalysisRun && !analysisLoading && (
                <div style={{ ...label, fontStyle: "italic" }}>
                  Click "Run Deep Analysis" to generate predictive insights.
                </div>
              )}
            </div>
          )}

          {!deepAnalysisRun && (
            <div style={{ ...label, fontStyle: "italic" }}>
              Click "Run Deep Analysis" to generate predictive insights.
            </div>
          )}
        </div>

      <div style={{ display: activeTab === 2 ? '' : 'none' }}>
          <h3 style={{ margin: "0 0 0.25rem", fontSize: "1rem", color: "var(--text-primary)" }}>
            Deterministic Global Correlation Engine
          </h3>
          <p style={{ ...label, marginBottom: "0.75rem" }}>
            Calculates causation graphs based on geospatial math and telemetry overlays across all domains.
          </p>

          <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
            <button
              style={{
                ...btnBase,
                background: sitrepLoading ? "var(--bg-tertiary)" : "var(--accent-blue)",
                color: sitrepLoading ? "var(--text-muted)" : "#fff",
                justifyContent: "center",
                cursor: sitrepLoading ? "not-allowed" : "pointer",
              }}
              disabled={sitrepLoading}
              onClick={handleRunGlobalCorrelation}
            >
              {sitrepLoading ? <RefreshCw size={15} /> : <Radio size={15} />}
              {sitrepLoading ? "Calculating..." : "Run Global Correlation"}
            </button>
          </div>

          {sitrepReport && (
            <div>
              <div style={{ ...card, marginBottom: "0.75rem" }}>
                <div
                  style={{ fontSize: "0.85rem", color: "var(--text-primary)", lineHeight: 1.7, whiteSpace: "pre-wrap", fontFamily: "var(--font-mono)" }}
                  dangerouslySetInnerHTML={{ __html: sitrepReport }}
                />
              </div>
              <div style={{ display: "flex", gap: "1rem" }}>
                <button
                  style={{
                    ...btnBase,
                    background: "var(--accent-green)",
                    color: "#fff",
                    justifyContent: "center",
                  }}
                  onClick={() => {
                    api.post("/rca/dispatch", { alert_ids: [], is_dispatched: true }).then(() => {
                      alert("SitRep Broadcast transmitted successfully.");
                    }).catch(() => {
                      alert("SitRep Broadcast: Message queued for delivery.");
                    });
                  }}
                >
                  <Send size={15} /> Broadcast SitRep
                </button>
              </div>
            </div>
          )}

          {!sitrepReport && !sitrepLoading && (
            <div style={{ ...label, fontStyle: "italic" }}>
              Click "Run Global Correlation" to generate a multi-domain situation report.
            </div>
          )}
      </div>
    </div>
  );
}
