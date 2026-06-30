import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import {
  Activity, AlertTriangle, Cloud, Globe, Shield, Cpu, HardDrive,
  RefreshCw, FileText, TrendingUp, Award, BarChart3,
  ExternalLink, ChevronDown, ChevronRight, Info, RotateCw, Send,
  X, Check, Clock, MapPin, Server, Mail, Zap, Loader2,
} from "lucide-react";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { formatInChicago, chicagoDateString } from "../utils/timezone";
import { getAllowedTabs } from "../utils/permissions";

const RISK_COLORS: Record<string, string> = {
  GREEN: "#28a745", BLUE: "#007bff", YELLOW: "#ffc107",
  ORANGE: "#fd7e14", RED: "#dc3545",
};
const RISK_NAMES: Record<string, string> = {
  GREEN: "GREEN (LOW)", BLUE: "BLUE (GUARDED)", YELLOW: "YELLOW (ELEVATED)",
  ORANGE: "ORANGE (HIGH)", RED: "RED (SEVERE)",
};

function RiskBadge({ level, size = "sm" }: { level: string; size?: "sm" | "lg" }) {
  const bg = RISK_COLORS[level] || "#6b7280";
  const fs = size === "lg" ? "1.2rem" : "0.75rem";
  const px = size === "lg" ? "0.8rem 1.5rem" : "0.2rem 0.6rem";
  return (
    <span
      style={{
        background: bg, color: "#fff", padding: px, borderRadius: "var(--radius-sm, 4px)",
        fontWeight: 700, fontSize: fs, display: "inline-block",
      }}
    >
      {level}
    </span>
  );
}

function MetricCard({ label, value, icon }: { label: string; value: number; icon?: React.ReactNode }) {
  return (
    <div
      style={{
        background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)",
        padding: "1.25rem", textAlign: "center",
        boxShadow: "0 1px 3px rgba(0,0,0,0.1)", border: "1px solid var(--border-primary, #e2e8f0)",
      }}
    >
      {icon && <div style={{ marginBottom: "0.5rem", color: "var(--accent-blue, #3b82f6)" }}>{icon}</div>}
      <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--text-primary, #1e293b)" }}>{value}</div>
      <div style={{ fontSize: "0.8rem", color: "var(--text-secondary, #64748b)" }}>{label}</div>
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const color = score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 40 ? "#eab308" : "#6b7280";
  return (
    <span
      style={{
        background: color, color: "#fff", padding: "0.1rem 0.4rem", borderRadius: "var(--radius-sm, 3px)",
        fontWeight: 700, fontSize: "0.7rem", whiteSpace: "nowrap",
      }}
    >
      {score.toFixed(0)}
    </span>
  );
}

function TabButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "0.6rem 1.2rem", border: "none", cursor: "pointer", borderRadius: "var(--radius-sm, 4px)",
        fontWeight: 600, fontSize: "0.85rem", transition: "all 0.2s",
        background: active ? "var(--accent-blue, #3b82f6)" : "var(--bg-tertiary, #f1f5f9)",
        color: active ? "#fff" : "var(--text-primary, #1e293b)",
      }}
    >
      {label}
    </button>
  );
}

function SubTabButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "0.4rem 1rem", border: active ? "2px solid var(--accent-blue, #3b82f6)" : "2px solid transparent",
        cursor: "pointer", borderRadius: "var(--radius-sm, 4px)", fontWeight: 600, fontSize: "0.8rem",
        background: active ? "var(--bg-secondary, #f8fafc)" : "transparent",
        color: active ? "var(--accent-blue, #3b82f6)" : "var(--text-secondary, #64748b)",
      }}
    >
      {label}
    </button>
  );
}

const articleStyle: React.CSSProperties = {
  padding: "0.6rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem",
};
const articleTitleStyle: React.CSSProperties = {
  fontWeight: 600, color: "var(--text-primary, #1e293b)", textDecoration: "none", margin: "0 0 0.2rem",
};

function ArticleItem({ article }: { article: any }) {
  return (
    <div style={articleStyle}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "0.2rem" }}>
        <ScoreBadge score={article.score ?? 0} />
        <a href={article.link} target="_blank" rel="noopener noreferrer" style={articleTitleStyle}>
          {article.title}
        </a>
        <ExternalLink size={12} style={{ color: "var(--text-muted, #94a3b8)", flexShrink: 0 }} />
      </div>
      <div style={{ color: "var(--text-secondary, #64748b)", fontSize: "0.73rem" }}>
        {article.source} &middot; {article.category}
      </div>
      {article.summary && (
        <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.75rem", marginTop: "0.15rem" }}>
          {article.summary.slice(0, 120)}{article.summary.length > 120 ? "..." : ""}
        </div>
      )}
      {article.ai_bluf && (
        <div style={{ color: "#059669", fontSize: "0.75rem", marginTop: "0.15rem", fontStyle: "italic" }}>
          BLUF: {article.ai_bluf.slice(0, 100)}
        </div>
      )}
    </div>
  );
}

const SUB_PANELS = ["Threat Triage", "Infrastructure Status", "AI Analysis"];

export function DashboardPage() {
  const { user } = useAuth();
  const allowedDashboardTabs = getAllowedTabs(user?.allowed_actions, "dashboard");
  const DASHBOARD_TABS = ["Operational Dashboard", "Global Risk", "Internal Risk", "Unified Brief"];
  const [tab, setTab] = useState(0);
  const [subPanel, setSubPanel] = useState(0);
  const [autoRotate, setAutoRotate] = useState(true);
  const [cisLegendOpen, setCisLegendOpen] = useState(false);
  const [scoringOverview, setScoringOverview] = useState<string | null>(null);
  const [scoringOverviewRisk, setScoringOverviewRisk] = useState<string | null>(null);
  const [dispatchEmail, setDispatchEmail] = useState("");
  const [ubEmail, setUbEmail] = useState("");
  const [forceRefreshKey, setForceRefreshKey] = useState(0);

  const [globalOverrideForm, setGlobalOverrideForm] = useState<any>(null);
  const [internalOverrideForm, setInternalOverrideForm] = useState<any>(null);
  const rotateRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const queryClient = useQueryClient();

  const refreshBriefingMut = useMutation({
    mutationFn: () => api.post("/rca/sitrep", { action: "refresh_briefing" }),
    onSuccess: () => {
      setForceRefreshKey((k) => k + 1);
      queryClient.invalidateQueries({ queryKey: ["sys-config"] });
    },
  });
  const securityAuditMut = useMutation({ mutationFn: () => api.post("/rca/sitrep", { action: "security_audit" }) });
  const generateScoringMut = useMutation({
    mutationFn: (intel: any) => api.post("/dashboard/generate-scoring-rationale", { intel }),
    onSuccess: (res) => {
      const d = res.data;
      if (d.status === "ok") { setScoringOverview(d.report); setScoringOverviewRisk(executiveIntel?.unified_risk); }
    },
  });
  const generateUnifiedBriefMut = useMutation({
    mutationFn: () => api.post("/dashboard/generate-unified-brief"),
    onSuccess: () => {
      setForceRefreshKey((k) => k + 1);
      queryClient.invalidateQueries({ queryKey: ["sys-config"] });
    },
  });
  const generateInternalMut = useMutation({
    mutationFn: () => api.post("/dashboard/generate-internal-risk"),
    onSuccess: () => { refetchInternal(); },
  });

  const saveOverrideConfigMut = useMutation({
    mutationFn: (data: any) => api.post("/admin/config", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sys-config"] });
      queryClient.invalidateQueries({ queryKey: ["executive-intel"] });
    },
  });

  useEffect(() => {
    if (autoRotate && tab === 0) {
      rotateRef.current = setInterval(() => {
        setSubPanel((p) => (p + 1) % SUB_PANELS.length);
      }, 10000);
    }
    return () => {
      if (rotateRef.current) clearInterval(rotateRef.current);
    };
  }, [autoRotate, tab]);

  useEffect(() => {
    if (allowedDashboardTabs.length > 0 && !allowedDashboardTabs.includes(String(tab))) {
      setTab(Number(allowedDashboardTabs[0]));
    }
  }, [allowedDashboardTabs.join(",")]);

  const { data: metrics } = useQuery({
    queryKey: ["dashboard-metrics"], queryFn: () => api.get("/dashboard/metrics").then((r) => r.data), refetchInterval: 30000,
  });
  const { data: pinnedArticles } = useQuery({
    queryKey: ["pinned-articles"], queryFn: () => api.get("/dashboard/pinned-articles").then((r) => r.data), refetchInterval: 30000,
  });
  const { data: liveArticles } = useQuery({
    queryKey: ["live-articles"], queryFn: () => api.get("/dashboard/live-articles").then((r) => r.data), refetchInterval: 15000,
  });
  const { data: cves } = useQuery({
    queryKey: ["cves-dash"], queryFn: () => api.get("/threat/cves", { params: { limit: 15 } }).then((r) => r.data), refetchInterval: 300000,
  });
  const { data: outages } = useQuery({
    queryKey: ["outages-dash"], queryFn: () => api.get("/threat/cloud-outages", { params: { active_only: true } }).then((r) => r.data), refetchInterval: 120000,
  });
  const { data: hazards } = useQuery({
    queryKey: ["hazards-dash"], queryFn: () => api.get("/dashboard/hazards", { params: { limit: 15 } }).then((r) => r.data), refetchInterval: 120000,
  });
  const { data: sitrep } = useQuery({
    queryKey: ["sitrep-dash", forceRefreshKey], queryFn: () => api.get("/rca/sitrep").then((r) => r.data), refetchInterval: 60000,
  });
  const { data: executiveIntel } = useQuery({
    queryKey: ["executive-intel"], queryFn: () => api.get("/dashboard/executive-intel").then((r) => r.data), refetchInterval: 60000,
  });
  const { data: threatTrends } = useQuery({
    queryKey: ["threat-trends"], queryFn: () => api.get("/dashboard/threat-trends", { params: { days: 14 } }).then((r) => r.data), refetchInterval: 120000,
  });
  const { data: internalRisk, refetch: refetchInternal } = useQuery({
    queryKey: ["internal-risk"], queryFn: () => api.get("/dashboard/internal-risk").then((r) => r.data), refetchInterval: 300000,
  });
  const { data: internalRiskHistory } = useQuery({
    queryKey: ["internal-risk-history"], queryFn: () => api.get("/dashboard/internal-risk/history", { params: { days: 28 } }).then((r) => r.data), refetchInterval: 300000,
  });
  const { data: sysConfig } = useQuery({
    queryKey: ["sys-config"], queryFn: () => api.get("/settings/config").then((r) => r.data), refetchInterval: 120000,
  });

  useEffect(() => {
    if (sysConfig) {
      setGlobalOverrideForm({
        scoring_mode: sysConfig.scoring_mode || "auto",
        cyber_criticality_override: sysConfig.cyber_criticality_override || 0,
        cyber_lethality_override: sysConfig.cyber_lethality_override || 0,
        physical_criticality_override: sysConfig.physical_criticality_override || 0,
        physical_lethality_override: sysConfig.physical_lethality_override || 0,
        global_risk_offset: sysConfig.global_risk_offset || 0,
      });
      setInternalOverrideForm({
        scoring_mode: sysConfig.scoring_mode || "auto",
        internal_criticality_override: sysConfig.internal_criticality_override || 0,
        internal_lethality_override: sysConfig.internal_lethality_override || 0,
        internal_risk_offset: sysConfig.internal_risk_offset || 0,
      });
    }
  }, [sysConfig]);

  const hasAutoGeneratedInternal = useRef(false);
  useEffect(() => {
    if (!hasAutoGeneratedInternal.current && internalRisk !== undefined) {
      hasAutoGeneratedInternal.current = true;
      if (internalRisk?.status === "empty") {
        generateInternalMut.mutate();
      }
    }
  }, [internalRisk]);

  const handleForceRefreshBriefing = () => {
    refreshBriefingMut.mutate();
  };

  const handleSecurityAudit = () => {
    securityAuditMut.mutate();
  };

  const handleGenerateScoring = () => {
    if (!executiveIntel) return;
    generateScoringMut.mutate(executiveIntel);
  };

  const mdToHtml = (md: string) => {
    let html = md
      .replace(/### (.*?)$/gm, '<h3 style="color:#e2e8f0; margin:15px 0 5px;">$1</h3>')
      .replace(/## (.*?)$/gm, '<h2 style="color:#e2e8f0; border-bottom:1px solid #334155; padding-bottom:5px; margin:20px 0 10px;">$1</h2>')
      .replace(/# (.*?)$/gm, '<h1 style="color:#e2e8f0; margin:20px 0 10px;">$1</h1>')
      .replace(/\*\*(.*?)\*\*/g, '<strong style="color:#f1f5f9;">$1</strong>')
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" style="color:#38bdf8;">$1</a>')
      .replace(/^- (.*?)$/gm, '<li style="margin:4px 0; color:#cbd5e1;">$1</li>')
      .replace(/^\* (.*?)$/gm, '<li style="margin:4px 0; color:#cbd5e1;">$1</li>')
      .replace(/\n/g, '<br>');
    if (html.includes('<li')) html = '<ul style="padding-left:20px; margin:8px 0;">' + html.replace(/(<li.*?<\/li>)/g, '$1') + '</ul>';
    return html;
  };

  const handleDispatchReport = async () => {
    if (!dispatchEmail || !executiveIntel) return;
    try {
      const body = scoringOverview
        ? mdToHtml(scoringOverview)
        : `<p style="color:#94a3b8;">No AI scoring report available.</p>`;
      const colorMap: Record<string, string> = { GREEN: "#22c55e", BLUE: "#3b82f6", YELLOW: "#eab308", ORANGE: "#f97316", RED: "#ef4444" };
      const uc = colorMap[executiveIntel.unified_risk?.toUpperCase()] || "#64748b";
      const cc = colorMap[executiveIntel.cyber_score?.toUpperCase()] || "#64748b";
      const pc = colorMap[executiveIntel.physical_score?.toUpperCase()] || "#64748b";
      const htmlBody = `
        <div style="font-family:Arial,sans-serif; max-width:800px; margin:0 auto; background:#0f172a; color:#e2e8f0; padding:20px;">
          <table width="100%" cellpadding="15" style="margin-bottom:20px; text-align:center; background:#1e293b; border:1px solid #334155; border-radius:8px;">
            <tr><th colspan="2" style="background:${uc}; color:#fff; border-radius:8px 8px 0 0; padding:15px; font-size:20px;">
              UNIFIED THREAT POSTURE: ${executiveIntel.unified_risk || "UNKNOWN"}
            </th></tr>
            <tr>
              <td style="border-right:1px solid #334155;"><span style="font-size:11px; text-transform:uppercase; color:#94a3b8;">Cyber & SCADA</span><br><strong style="font-size:20px; color:${cc};">${executiveIntel.cyber_score || "N/A"}</strong></td>
              <td><span style="font-size:11px; text-transform:uppercase; color:#94a3b8;">Physical & Perimeter</span><br><strong style="font-size:20px; color:${pc};">${executiveIntel.physical_score || "N/A"}</strong></td>
            </tr>
          </table>
          <div style="background:#1e293b; padding:20px; border-radius:8px; border-left:4px solid ${uc};">
            ${body}
          </div>
          <p style="text-align:center; color:#64748b; font-size:12px; margin-top:20px;">Generated by NOC Intelligence Fusion Center</p>
        </div>`;
      await api.post("/email/send", {
        to: dispatchEmail,
        subject: `Executive Threat Posture: ${executiveIntel.unified_risk || "UNKNOWN"}`,
        html_body: htmlBody,
      });
      alert("Report dispatched to " + dispatchEmail);
    } catch { alert("Failed to dispatch report. Check SMTP settings."); }
  };

  const handleGenerateInternal = () => {
    generateInternalMut.mutate();
  };

  const handleGenerateUnifiedBrief = () => {
    generateUnifiedBriefMut.mutate();
  };

  const handleBroadcastBrief = async () => {
    if (!ubEmail) return;
    try {
      const { data } = await api.post("/email/broadcast-brief", { email: ubEmail });
      if (data.status === "ok") alert("Brief transmitted to " + ubEmail);
      else alert("Broadcast error: " + (data.message || "Unknown error"));
    } catch (e: any) { alert("Failed to transmit brief: " + (e.response?.data?.detail || e.message)); }
  };

  const getScoreForLevel = (level: string) => {
    const m: Record<string, string> = {
      GREEN: "-8 to -5", BLUE: "-4 to -2", YELLOW: "-1 to +2",
      ORANGE: "+3 to +5", RED: "+6 to +8",
    };
    return m[level] || "";
  };

  return (
    <div style={{ padding: "1.5rem", color: "var(--text-primary, #1e293b)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <h2 style={{ margin: 0, fontSize: "1.5rem" }}>Global NOC Dashboards</h2>
      </div>

      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.5rem", flexWrap: "wrap" }}>
        {DASHBOARD_TABS.filter((_v, idx) => allowedDashboardTabs.length === 0 || allowedDashboardTabs.includes(String(idx))).map(l => {
          const originalIndex = DASHBOARD_TABS.indexOf(l);
          return <TabButton key={l} active={tab === originalIndex} label={l} onClick={() => { setTab(originalIndex); setSubPanel(0); }} />;
        })}
      </div>

      {/* ==================== TAB 1: Operational Dashboard ==================== */}
      {tab === 0 && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
            <MetricCard label="High-Threat RSS (24h)" value={metrics?.rss_count ?? 0} icon={<Activity size={24} />} />
            <MetricCard label="Active KEVs (24h)" value={metrics?.cve_count ?? 0} icon={<Shield size={24} />} />
            <MetricCard label="Hazards (24h)" value={metrics?.hazard_count ?? 0} icon={<AlertTriangle size={24} />} />
            <MetricCard label="Cloud Outages (24h)" value={metrics?.cloud_count ?? 0} icon={<Cloud size={24} />} />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "1rem" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.85rem", cursor: "pointer" }}>
              <input
                type="checkbox" checked={autoRotate}
                onChange={(e) => setAutoRotate(e.target.checked)}
                style={{ accentColor: "var(--accent-blue, #3b82f6)" }}
              />
              Auto-Rotate
            </label>
            <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
              {SUB_PANELS.map((l, i) => (
                <SubTabButton key={l} active={subPanel === i} label={l} onClick={() => setSubPanel(i)} />
              ))}
            </div>
          </div>

          {/* Sub Panel: Threat Triage */}
          {subPanel === 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Award size={16} /> Pinned Intel
                </h3>
                <div style={{ maxHeight: 500, overflowY: "auto" }}>
                  {(!pinnedArticles || pinnedArticles.length === 0) ? (
                    <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", padding: "1rem 0" }}>No pinned articles.</div>
                  ) : (
                    pinnedArticles.map((a: any) => <ArticleItem key={a.id} article={a} />)
                  )}
                </div>
              </div>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Activity size={16} /> Live Feed (Top 15)
                </h3>
                <div style={{ maxHeight: 500, overflowY: "auto" }}>
                  {(!liveArticles || liveArticles.length === 0) ? (
                    <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", padding: "1rem 0" }}>No live articles.</div>
                  ) : (
                    liveArticles.map((a: any) => <ArticleItem key={a.id} article={a} />)
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Sub Panel: Infrastructure Status */}
          {subPanel === 1 && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "1.5rem" }}>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Shield size={16} /> CISA KEVs (Top 15)
                </h3>
                <div style={{ maxHeight: 450, overflowY: "auto" }}>
                  {(!cves || cves.length === 0) ? (
                    <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", padding: "1rem 0" }}>No CVEs.</div>
                  ) : (
                    cves.map((c: any) => (
                      <div key={c.cve_id || c.id} style={{ padding: "0.4rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem" }}>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                          target="_blank" rel="noopener noreferrer"
                          style={{ fontWeight: 600, color: "var(--accent-blue, #3b82f6)", textDecoration: "none" }}
                        >
                          {c.cve_id}
                        </a>
                        <div style={{ color: "var(--text-secondary, #64748b)", fontSize: "0.75rem" }}>
                          {c.vendor} {c.product} &middot; {c.vulnerability_name?.slice(0, 60)}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Cloud size={16} /> Active Cloud Outages
                </h3>
                <div style={{ maxHeight: 450, overflowY: "auto" }}>
                  {(!outages || outages.length === 0) ? (
                    <div style={{ color: "#059669", fontSize: "0.85rem", padding: "1rem 0", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                      <Check size={16} /> Clear.
                    </div>
                  ) : (
                    outages.map((o: any) => (
                      <div key={o.id} style={{ padding: "0.4rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem" }}>
                        <div style={{ fontWeight: 600, color: "var(--text-primary, #1e293b)" }}>{o.provider}</div>
                        <div style={{ color: "var(--text-secondary, #64748b)", fontSize: "0.75rem" }}>
                          {o.title && o.link ? <a href={o.link} target="_blank" rel="noopener noreferrer" style={{ color: "inherit" }}>{o.title}</a> : o.title || o.description?.slice(0, 80)}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <MapPin size={16} /> Regional Hazards
                </h3>
                <div style={{ maxHeight: 450, overflowY: "auto" }}>
                  {(!hazards || hazards.length === 0) ? (
                    <div style={{ color: "#059669", fontSize: "0.85rem", padding: "1rem 0", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                      <Check size={16} /> Clear.
                    </div>
                  ) : (
                    hazards.map((h: any) => (
                      <div key={h.id} style={{ padding: "0.4rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                          <SeverityIcon severity={h.severity} />
                          <strong>{h.severity}</strong>
                        </div>
                        <div style={{ color: "var(--text-secondary, #64748b)", fontSize: "0.75rem" }}>
                          {h.title} ({h.location})
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Sub Panel: AI Analysis */}
          {subPanel === 2 && (
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "1.5rem" }}>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <FileText size={16} /> AI Shift Briefing
                </h3>
                <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "0.75rem", flexWrap: "wrap" }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted, #94a3b8)" }}>
                    <Clock size={12} style={{ verticalAlign: "middle", marginRight: "0.25rem" }} />
                    Last Sync: {sitrep?.rolling_summary_time ? formatInChicago(sitrep.rolling_summary_time) : "N/A"}
                  </span>
                  <button
                    onClick={handleForceRefreshBriefing}
                    disabled={refreshBriefingMut.isPending}
                    style={{
                      padding: "0.35rem 0.75rem", border: "1px solid var(--accent-blue, #3b82f6)", borderRadius: "var(--radius-sm, 4px)",
                      background: "transparent", color: "var(--accent-blue, #3b82f6)", cursor: refreshBriefingMut.isPending ? "not-allowed" : "pointer", fontSize: "0.8rem",
                      fontWeight: 500, display: "flex", alignItems: "center", gap: "0.3rem", opacity: refreshBriefingMut.isPending ? 0.6 : 1,
                    }}
                  >
                    {refreshBriefingMut.isPending ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />} Force Refresh Briefing
                  </button>
                </div>
                <div
                  style={{
                    background: "var(--bg-secondary, #f8fafc)", borderRadius: "var(--radius-sm, 4px)",
                    padding: "1rem", fontSize: "0.85rem", color: "var(--text-primary, #1e293b)",
                    lineHeight: 1.6, whiteSpace: "pre-wrap",
                  }}
                >
                  {sysConfig?.rolling_summary || (sitrep?.report ? typeof sitrep.report === "string" ? sitrep.report : JSON.stringify(sitrep.report) : "Initializing...")}
                </div>
              </div>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Shield size={16} /> Security Auditor
                </h3>
                <p style={{ fontSize: "0.82rem", color: "var(--text-secondary, #64748b)", margin: "0 0 1rem" }}>
                  Cross-reference internal stack against 30-day KEV inventory.
                </p>
                <button
                  onClick={handleSecurityAudit}
                  disabled={securityAuditMut.isPending}
                  style={{
                    padding: "0.5rem 1rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                    background: "var(--accent-blue, #3b82f6)", color: "#fff", cursor: securityAuditMut.isPending ? "not-allowed" : "pointer",
                    fontWeight: 600, fontSize: "0.85rem", width: "100%",
                    display: "flex", alignItems: "center", justifyContent: "center", gap: "0.4rem",
                    opacity: securityAuditMut.isPending ? 0.6 : 1,
                  }}
                >
                  {securityAuditMut.isPending ? <Loader2 size={16} className="spin" /> : <Zap size={16} />} Scan Stack Against 30-Day KEVs
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==================== TAB 2: Global Risk ==================== */}
      {tab === 1 && (
        <div>
          {/* CIS Threat Legend Modal */}
          {cisLegendOpen && (
            <div style={{
              position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
              background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center", justifyContent: "center",
              zIndex: 1000,
            }}>
              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)",
                padding: "2rem", maxWidth: 600, width: "90%", maxHeight: "80vh", overflowY: "auto",
                border: "1px solid var(--border-primary, #e2e8f0)",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                  <h3 style={{ margin: 0, fontSize: "1.1rem" }}>CIS Threat Level Legend</h3>
                  <button onClick={() => setCisLegendOpen(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-secondary, #64748b)" }}>
                    <X size={20} />
                  </button>
                </div>
                <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.9rem", color: "var(--text-secondary, #64748b)" }}>
                  Official MS-ISAC / CIS Alert Levels
                </h4>
                <p style={{ fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)", marginBottom: "1rem" }}>
                  Formula: <code>Severity = (Criticality + Lethality) - (System + Network Countermeasures)</code>
                </p>
                {["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"].map((lvl) => (
                  <div key={lvl} style={{ display: "flex", gap: "0.75rem", marginBottom: "0.75rem", alignItems: "flex-start" }}>
                    <div style={{
                      background: RISK_COLORS[lvl], color: "#fff", padding: "0.2rem 0.6rem",
                      borderRadius: "var(--radius-sm, 3px)", fontWeight: 700, fontSize: "0.75rem",
                      whiteSpace: "nowrap", minWidth: 60, textAlign: "center",
                    }}>{lvl}</div>
                    <div style={{ fontSize: "0.8rem", color: "var(--text-primary, #1e293b)" }}>
                      <strong>{RISK_NAMES[lvl]}</strong> &mdash; Range: {getScoreForLevel(lvl)}
                    </div>
                  </div>
                ))}
                <div style={{ marginTop: "1rem" }}>
                  {["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"].map((lvl) => (
                    <div key={lvl + "desc"} style={{ fontSize: "0.78rem", color: "var(--text-secondary, #64748b)", padding: "0.25rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)" }}>
                      <strong style={{ color: RISK_COLORS[lvl] }}>{RISK_NAMES[lvl]}</strong>:&nbsp;
                      {lvl === "GREEN" && "Low risk. Normal probing, low-risk viruses. Continue routine monitoring and patching."}
                      {lvl === "BLUE" && "General risk of increased hacking/malicious activity. No known severe exploits or significant impacts yet."}
                      {lvl === "YELLOW" && "Significant risk. Known vulnerabilities being exploited with moderate damage, or high potential for disruption."}
                      {lvl === "ORANGE" && "High risk targeting core infrastructure. Multiple service outages, critical vulnerabilities actively exploited with significant impact."}
                      {lvl === "RED" && "Severe risk. Widespread outages, destructive compromises to SCADA/critical systems. Potential for actual loss of life or economic security."}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem", flexWrap: "wrap", gap: "0.5rem" }}>
            <h3 style={{ margin: 0, fontSize: "1.1rem" }}>Executive Grid Threat Matrix</h3>
            <button
              onClick={() => setCisLegendOpen(true)}
              style={{
                padding: "0.35rem 0.75rem", border: "1px solid var(--border-primary, #e2e8f0)",
                borderRadius: "var(--radius-sm, 4px)", background: "var(--bg-card, #fff)", cursor: "pointer",
                fontSize: "0.8rem", fontWeight: 500, color: "var(--text-primary, #1e293b)",
                display: "flex", alignItems: "center", gap: "0.3rem",
              }}
            >
              <Info size={14} /> View CIS Threat Legend
            </button>
          </div>
          <p style={{ fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)", margin: "0 0 1rem" }}>
            Strategic synthesis of Physical and Cyber telemetry measured against a 14-day operational baseline.
          </p>

          {/* Unified Risk Banner */}
          {executiveIntel && (
            <div style={{
              textAlign: "center", padding: "1.5rem", background: "var(--bg-tertiary, #1e1e1e)",
              borderRadius: "var(--radius-md, 8px)", border: `2px solid ${RISK_COLORS[executiveIntel.unified_risk] || "#28a745"}`,
              marginBottom: "1.5rem",
            }}>
              <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", fontWeight: 600, letterSpacing: "1px", marginBottom: "0.5rem" }}>
                GLOBAL THREAT POSTURE (CIS STANDARD)
              </div>
              <div style={{ fontSize: "2.5rem", fontWeight: 800, color: RISK_COLORS[executiveIntel.unified_risk] || "#28a745", marginBottom: "0.25rem" }}>
                {RISK_NAMES[executiveIntel.unified_risk] || executiveIntel.unified_risk}
              </div>
              <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.82rem" }}>
                Last Updated: {formatInChicago(executiveIntel.timestamp)}
              </div>
            </div>
          )}

          {/* 14-Day Trend */}
          <div style={{
            background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
            border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
          }}>
            <h3 style={{ margin: "0 0 1rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <TrendingUp size={16} /> 14-Day CIS Alert Level Trend
            </h3>
            {(!threatTrends || threatTrends.length === 0) ? (
              <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", padding: "2rem 0", textAlign: "center" }}>
                Gathering baseline telemetry. Graph will populate tomorrow.
              </div>
            ) : (
              <div style={{ width: "100%", height: 250 }}>
                <ResponsiveContainer>
                  <LineChart data={threatTrends.map((d: any) => ({
                    date: d.record_date ? chicagoDateString(new Date(d.record_date)) : "",
                    cyber: d.cyber_points ?? 0,
                    physical: d.physical_points ?? 0,
                  }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                    <XAxis dataKey="date" tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                    <YAxis tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                    <Tooltip
                      contentStyle={{
                        background: "var(--bg-card, #fff)", border: "1px solid var(--border-primary, #e2e8f0)",
                        borderRadius: "var(--radius-sm, 4px)", fontSize: "0.8rem",
                      }}
                    />
                    <Line type="monotone" dataKey="cyber" stroke="#00b4d8" strokeWidth={2} dot={{ r: 3 }} name="Cyber CIS Score" />
                    <Line type="monotone" dataKey="physical" stroke="#ff9f1c" strokeWidth={2} dot={{ r: 3 }} name="Physical CIS Score" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
            {executiveIntel && (
              <div style={{ display: "flex", justifyContent: "center", gap: "1.5rem", marginTop: "0.75rem", fontSize: "0.85rem", color: "var(--text-secondary, #64748b)", flexWrap: "wrap" }}>
                <span><strong>Cyber:</strong> {executiveIntel.current_cyber_pts} ({executiveIntel.cyber_score})</span>
                <span><strong>Physical:</strong> {executiveIntel.current_phys_pts} ({executiveIntel.physical_score})</span>
                <span><strong>Unified:</strong> <RiskBadge level={executiveIntel.unified_risk} /></span>
              </div>
            )}
            <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem", justifyContent: "center", flexWrap: "wrap" }}>
              {["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"].map((lvl) => (
                <div key={lvl} style={{
                  background: RISK_COLORS[lvl], padding: "0.3rem 0.6rem", borderRadius: "var(--radius-sm, 3px)",
                  textAlign: "center", color: lvl === "YELLOW" ? "#000" : "#fff", fontSize: "0.7rem", fontWeight: 600, minWidth: 60,
                }}>
                  {lvl}<br />{getScoreForLevel(lvl)}
                </div>
              ))}
            </div>
          </div>

          {/* Physical & Cyber Columns */}
          {executiveIntel && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", marginBottom: "1.5rem" }}>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Globe size={16} /> Physical &amp; Perimeter (1 Mile)
                </h3>
                <div style={{ marginBottom: "0.5rem" }}>
                  <RiskBadge level={executiveIntel.physical_score} />
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-primary, #1e293b)", marginBottom: "0.75rem", lineHeight: 1.5 }}>
                  {executiveIntel.physical_brief}
                </div>
                {executiveIntel.recent_crimes && executiveIntel.recent_crimes.length > 0 && (
                  <div>
                    <strong style={{ fontSize: "0.82rem" }}>Grid-Relevant Perimeter Incidents:</strong>
                    {executiveIntel.recent_crimes.slice(0, 5).map((c: any, i: number) => (
                      <div key={i} style={{ fontSize: "0.78rem", color: "var(--text-secondary, #64748b)", padding: "0.25rem 0" }}>
                        <strong>{c.fbi_category || c.category}:</strong> {c.raw_title} ({c.distance_miles?.toFixed(1)} mi) &middot; {c.timestamp}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Server size={16} /> Cyber &amp; SCADA (48 Hours)
                </h3>
                <div style={{ marginBottom: "0.5rem" }}>
                  <RiskBadge level={executiveIntel.cyber_score} />
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-primary, #1e293b)", marginBottom: "0.75rem", lineHeight: 1.5 }}>
                  {executiveIntel.cyber_brief}
                </div>
                {executiveIntel.evidence_log && executiveIntel.evidence_log.length > 0 && (
                  <div>
                    <strong style={{ fontSize: "0.82rem" }}>Evidence Log:</strong>
                    {executiveIntel.evidence_log.map((log: string, i: number) => (
                      <div key={i} style={{ fontSize: "0.78rem", color: "var(--text-secondary, #64748b)", padding: "0.25rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)" }} dangerouslySetInnerHTML={{ __html: log }} />
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Dynamic Scoring Overview */}
          <div style={{
            background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
            border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
          }}>
            <h3 style={{ margin: "0 0 0.5rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <BarChart3 size={16} /> Dynamic Scoring Overview
            </h3>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)", margin: "0 0 0.75rem" }}>
              AI-generated synthesis of all live telemetry detailing the exact reasoning behind the current threat score.
            </p>
            <button
              onClick={handleGenerateScoring}
              disabled={!executiveIntel || generateScoringMut.isPending}
              style={{
                padding: "0.5rem 1rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                background: "var(--accent-blue, #3b82f6)", color: "#fff", cursor: executiveIntel && !generateScoringMut.isPending ? "pointer" : "not-allowed",
                fontWeight: 600, fontSize: "0.85rem", opacity: executiveIntel && !generateScoringMut.isPending ? 1 : 0.5,
                display: "flex", alignItems: "center", gap: "0.4rem",
              }}
            >
              {generateScoringMut.isPending ? <Loader2 size={16} className="spin" /> : <RotateCw size={16} />} Generate Scoring Rationale
            </button>
            {scoringOverview && (
              <div style={{ marginTop: "1rem" }}>
                {scoringOverviewRisk && executiveIntel && scoringOverviewRisk !== executiveIntel.unified_risk && (
                  <div style={{
                    background: "#fef3c7", border: "1px solid #f59e0b", borderRadius: "var(--radius-sm, 4px)",
                    padding: "0.5rem 0.75rem", fontSize: "0.8rem", color: "#92400e", marginBottom: "0.75rem",
                  }}>
                    The Executive Threat Matrix posture has shifted to <strong>{executiveIntel.unified_risk}</strong> since this rationale was generated. Please regenerate.
                  </div>
                )}
                <div style={{
                  background: "var(--bg-secondary, #f8fafc)", borderRadius: "var(--radius-sm, 4px)",
                  padding: "1rem", fontSize: "0.85rem", lineHeight: 1.6, whiteSpace: "pre-wrap",
                  border: "1px solid var(--border-primary, #e2e8f0)",
                }}>
                  {scoringOverview}
                </div>
              </div>
            )}
          </div>

          {/* Dispatch Intelligence Report */}
          <div style={{
            background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
            border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
          }}>
            <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <Send size={16} /> Dispatch Intelligence Report
            </h3>
            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
              <input
                type="email" placeholder="Recipient Email Address"
                value={dispatchEmail}
                onChange={(e) => setDispatchEmail(e.target.value)}
                style={{
                  flex: 1, minWidth: 200, padding: "0.5rem 0.75rem", borderRadius: "var(--radius-sm, 4px)",
                  border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-input, #fff)",
                  color: "var(--text-primary, #1e293b)", fontSize: "0.85rem",
                }}
              />
              <button
                onClick={handleDispatchReport}
                disabled={!executiveIntel || !dispatchEmail}
                style={{
                  padding: "0.5rem 1rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                  background: "#2563eb", color: "#fff", cursor: "pointer", fontWeight: 600, fontSize: "0.85rem",
                  opacity: executiveIntel && dispatchEmail ? 1 : 0.5,
                  display: "flex", alignItems: "center", gap: "0.4rem",
                }}
              >
                <Mail size={16} /> Send AI Scoring Report
              </button>
            </div>
          </div>

          {/* Global Risk Scoring Overrides */}
          <div style={{
            background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
            border: "1px solid var(--border-primary, #e2e8f0)",
          }}>
            <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <BarChart3 size={16} /> Global Risk Scoring Overrides
            </h3>
            <p style={{ fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)", margin: "0 0 0.75rem" }}>
              Override the automatic CIS scoring. Changes take effect immediately on save.
            </p>
            {globalOverrideForm && (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                  <label style={{ fontSize: "0.82rem", fontWeight: 600, minWidth: 120 }}>Scoring Mode:</label>
                  <select
                    value={globalOverrideForm.scoring_mode}
                    onChange={(e) => setGlobalOverrideForm((f: any) => ({ ...f, scoring_mode: e.target.value }))}
                    style={{
                      padding: "0.35rem 0.5rem", borderRadius: "var(--radius-sm, 4px)",
                      border: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem",
                    }}
                  >
                    <option value="auto">Auto (Full Algorithmic)</option>
                    <option value="manual">Manual (Override All)</option>
                    <option value="hybrid">Hybrid (Auto + Offset)</option>
                  </select>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted, #94a3b8)" }}>
                    Current: {executiveIntel?.scoring_mode || "auto"}
                  </span>
                </div>

                {globalOverrideForm.scoring_mode === "manual" && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", maxWidth: 500 }}>
                    <div>
                      <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>Cyber Criticality (1-5):</label>
                      <input type="range" min={1} max={5} step={1}
                        value={globalOverrideForm.cyber_criticality_override}
                        onChange={(e) => setGlobalOverrideForm((f: any) => ({ ...f, cyber_criticality_override: Number(e.target.value) }))}
                        style={{ width: "100%" }} />
                      <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", textAlign: "center" }}>
                        {globalOverrideForm.cyber_criticality_override}/5
                      </div>
                    </div>
                    <div>
                      <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>Cyber Lethality (1-5):</label>
                      <input type="range" min={1} max={5} step={1}
                        value={globalOverrideForm.cyber_lethality_override}
                        onChange={(e) => setGlobalOverrideForm((f: any) => ({ ...f, cyber_lethality_override: Number(e.target.value) }))}
                        style={{ width: "100%" }} />
                      <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", textAlign: "center" }}>
                        {globalOverrideForm.cyber_lethality_override}/5
                      </div>
                    </div>
                    <div>
                      <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>Physical Criticality (1-5):</label>
                      <input type="range" min={1} max={5} step={1}
                        value={globalOverrideForm.physical_criticality_override}
                        onChange={(e) => setGlobalOverrideForm((f: any) => ({ ...f, physical_criticality_override: Number(e.target.value) }))}
                        style={{ width: "100%" }} />
                      <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", textAlign: "center" }}>
                        {globalOverrideForm.physical_criticality_override}/5
                      </div>
                    </div>
                    <div>
                      <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>Physical Lethality (1-5):</label>
                      <input type="range" min={1} max={5} step={1}
                        value={globalOverrideForm.physical_lethality_override}
                        onChange={(e) => setGlobalOverrideForm((f: any) => ({ ...f, physical_lethality_override: Number(e.target.value) }))}
                        style={{ width: "100%" }} />
                      <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", textAlign: "center" }}>
                        {globalOverrideForm.physical_lethality_override}/5
                      </div>
                    </div>
                  </div>
                )}

                {globalOverrideForm.scoring_mode === "hybrid" && (
                  <div style={{ maxWidth: 300 }}>
                    <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>
                      Global Offset ({globalOverrideForm.global_risk_offset >= 0 ? "+" : ""}{globalOverrideForm.global_risk_offset}):
                    </label>
                    <input type="range" min={-3} max={3} step={1}
                      value={globalOverrideForm.global_risk_offset}
                      onChange={(e) => setGlobalOverrideForm((f: any) => ({ ...f, global_risk_offset: Number(e.target.value) }))}
                      style={{ width: "100%" }} />
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)" }}>
                      <span>-3</span><span>0</span><span>+3</span>
                    </div>
                  </div>
                )}

                <button
                  onClick={() => saveOverrideConfigMut.mutate(globalOverrideForm)}
                  disabled={saveOverrideConfigMut.isPending}
                  style={{
                    padding: "0.4rem 0.75rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                    background: "var(--accent-blue, #3b82f6)", color: "#fff", cursor: "pointer",
                    fontWeight: 600, fontSize: "0.82rem", alignSelf: "flex-start",
                    display: "flex", alignItems: "center", gap: "0.3rem",
                    opacity: saveOverrideConfigMut.isPending ? 0.6 : 1,
                  }}
                >
                  {saveOverrideConfigMut.isPending ? <Loader2 size={14} className="spin" /> : null} Save Global Overrides
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================== TAB 3: Internal Risk ==================== */}
      {tab === 2 && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem", flexWrap: "wrap", gap: "0.5rem" }}>
            <div>
              <h3 style={{ margin: 0, fontSize: "1.1rem" }}>Internal Asset Risk Dashboard</h3>
              <p style={{ margin: "0.2rem 0 0", fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)" }}>
                Active correlation of internal assets against OSINT telemetry (Auto-updates every 6 hours).
              </p>
            </div>
            <button
              onClick={handleGenerateInternal}
              disabled={generateInternalMut.isPending}
              style={{
                padding: "0.4rem 0.75rem", border: "1px solid var(--accent-blue, #3b82f6)",
                borderRadius: "var(--radius-sm, 4px)", background: "transparent",
                color: "var(--accent-blue, #3b82f6)", cursor: generateInternalMut.isPending ? "not-allowed" : "pointer", fontSize: "0.8rem",
                fontWeight: 500, display: "flex", alignItems: "center", gap: "0.3rem",
                opacity: generateInternalMut.isPending ? 0.6 : 1,
              }}
            >
              {generateInternalMut.isPending ? <Loader2 size={14} className="spin" /> : <RotateCw size={14} />} Force Generate
            </button>
          </div>

          {!internalRisk || internalRisk.status === "empty" ? (
            <div style={{
              background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)",
              padding: "2rem", textAlign: "center", border: "1px solid var(--border-primary, #e2e8f0)",
            }}>
              <p style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.9rem" }}>
                Internal Risk matrices are currently calculating. Please check back in a few minutes.
              </p>
              <button
                onClick={handleGenerateInternal}
                disabled={generateInternalMut.isPending}
                style={{
                  marginTop: "0.5rem", padding: "0.5rem 1rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                  background: "var(--accent-blue, #3b82f6)", color: "#fff", cursor: generateInternalMut.isPending ? "not-allowed" : "pointer", fontWeight: 600,
                  opacity: generateInternalMut.isPending ? 0.6 : 1,
                }}
              >
                {generateInternalMut.isPending ? <Loader2 size={14} className="spin" /> : null} Trigger Manual Calculation
              </button>
            </div>
          ) : (
            <>
              {/* Internal Risk Banner */}
              <div style={{
                textAlign: "center", padding: "1.5rem", background: "var(--bg-tertiary, #1e1e1e)",
                borderRadius: "var(--radius-md, 8px)", border: `2px solid ${RISK_COLORS[internalRisk.risk_level] || "#6c757d"}`,
                marginBottom: "1.5rem",
              }}>
                <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", fontWeight: 600, letterSpacing: "1px", marginBottom: "0.5rem" }}>
                  INTERNAL ASSET POSTURE (CIS STANDARD)
                </div>
                <div style={{ fontSize: "2.5rem", fontWeight: 800, color: RISK_COLORS[internalRisk.risk_level] || "#6c757d", marginBottom: "0.25rem" }}>
                  {RISK_NAMES[internalRisk.risk_level] || internalRisk.risk_level} [{internalRisk.score}]
                </div>
                <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.82rem" }}>
                  Analyzed {internalRisk.total_assets} total assets against OSINT feeds.
                </div>
                <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.78rem", marginTop: "0.5rem" }}>
                  <Clock size={12} style={{ verticalAlign: "middle", marginRight: "0.25rem" }} />
                   Last Updated: {formatInChicago(internalRisk.timestamp)}
                </div>
              </div>

              {/* Metric Cards */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
                <div style={{
                  background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                  textAlign: "center", border: "1px solid var(--border-primary, #e2e8f0)",
                }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted, #94a3b8)", marginBottom: "0.25rem" }}>Total Asset Footprint</div>
                  <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--text-primary, #1e293b)" }}>{internalRisk.total_assets ?? 0}</div>
                </div>
                <div style={{
                  background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                  textAlign: "center", border: "1px solid var(--border-primary, #e2e8f0)",
                }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted, #94a3b8)", marginBottom: "0.25rem" }}>Total OSINT Correlations</div>
                  <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--text-primary, #1e293b)" }}>{internalRisk.total_osint_hits ?? 0}</div>
                </div>
                <div style={{
                  background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                  textAlign: "center", border: "1px solid var(--border-primary, #e2e8f0)",
                }}>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted, #94a3b8)", marginBottom: "0.25rem" }}>Critical OSINT Hits</div>
                  <div style={{ fontSize: "2rem", fontWeight: 700, color: "#ef4444" }}>{internalRisk.critical_osint_hits ?? 0}</div>
                </div>
              </div>

              {/* Historical Trend */}
              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
              }}>
                <h3 style={{ margin: "0 0 1rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <TrendingUp size={16} /> Historical Threat Trend
                </h3>
                {(!internalRiskHistory || internalRiskHistory.length === 0) ? (
                  <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", padding: "2rem 0", textAlign: "center" }}>
                    No historical data yet.
                  </div>
                ) : (
                  <div style={{ width: "100%", height: 250 }}>
                    <ResponsiveContainer>
                      <LineChart data={internalRiskHistory.map((d: any) => ({
                        time: d.timestamp ? chicagoDateString(new Date(d.timestamp)) : "",
                        score: d.score ?? 0,
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                        <XAxis dataKey="time" tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                        <YAxis tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                        <Tooltip
                          contentStyle={{
                            background: "var(--bg-card, #fff)", border: "1px solid var(--border-primary, #e2e8f0)",
                            borderRadius: "var(--radius-sm, 4px)", fontSize: "0.8rem",
                          }}
                        />
                        <Line type="monotone" dataKey="score" stroke="#dc3545" strokeWidth={2} dot={{ r: 3 }} name="CIS Risk Score" />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>

              {/* Hardware Assets */}
              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
              }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Cpu size={16} /> Hardware Assets
                </h3>
                <HardwareSoftwareTable
                  data={internalRisk.hw_data}
                  type="hardware"
                  emptyMessage="No hardware assets loaded. Go to Settings to import your inventory."
                />
              </div>

              {/* Software Assets */}
              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
              }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <HardDrive size={16} /> Software Assets
                </h3>
                <HardwareSoftwareTable
                  data={internalRisk.sw_data}
                  type="software"
                  emptyMessage="All tracked software assets are currently clear of recent OSINT correlations."
                />
              </div>

              {/* Internal Risk Scoring Overrides */}
              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                border: "1px solid var(--border-primary, #e2e8f0)",
              }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <BarChart3 size={16} /> Internal Risk Scoring Overrides
                </h3>
                <p style={{ fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)", margin: "0 0 0.75rem" }}>
                  Override the internal asset risk scoring. Changes take effect on next calculation.
                </p>
                {internalOverrideForm && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                    <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                      <label style={{ fontSize: "0.82rem", fontWeight: 600, minWidth: 120 }}>Scoring Mode:</label>
                      <select
                        value={internalOverrideForm.scoring_mode}
                        onChange={(e) => setInternalOverrideForm((f: any) => ({ ...f, scoring_mode: e.target.value }))}
                        style={{
                          padding: "0.35rem 0.5rem", borderRadius: "var(--radius-sm, 4px)",
                          border: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem",
                        }}
                      >
                        <option value="auto">Auto (Full Algorithmic)</option>
                        <option value="manual">Manual (Override All)</option>
                        <option value="hybrid">Hybrid (Auto + Offset)</option>
                      </select>
                    </div>

                    {internalOverrideForm.scoring_mode === "manual" && (
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", maxWidth: 400 }}>
                        <div>
                          <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>Criticality Override (1-5):</label>
                          <input type="range" min={1} max={5} step={1}
                            value={internalOverrideForm.internal_criticality_override}
                            onChange={(e) => setInternalOverrideForm((f: any) => ({ ...f, internal_criticality_override: Number(e.target.value) }))}
                            style={{ width: "100%" }} />
                          <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", textAlign: "center" }}>
                            {internalOverrideForm.internal_criticality_override}/5
                          </div>
                        </div>
                        <div>
                          <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>Lethality Override (1-5):</label>
                          <input type="range" min={1} max={5} step={1}
                            value={internalOverrideForm.internal_lethality_override}
                            onChange={(e) => setInternalOverrideForm((f: any) => ({ ...f, internal_lethality_override: Number(e.target.value) }))}
                            style={{ width: "100%" }} />
                          <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", textAlign: "center" }}>
                            {internalOverrideForm.internal_lethality_override}/5
                          </div>
                        </div>
                      </div>
                    )}

                    {internalOverrideForm.scoring_mode === "hybrid" && (
                      <div style={{ maxWidth: 300 }}>
                        <label style={{ fontSize: "0.78rem", fontWeight: 600 }}>
                          Internal Offset ({internalOverrideForm.internal_risk_offset >= 0 ? "+" : ""}{internalOverrideForm.internal_risk_offset}):
                        </label>
                        <input type="range" min={-3} max={3} step={1}
                          value={internalOverrideForm.internal_risk_offset}
                          onChange={(e) => setInternalOverrideForm((f: any) => ({ ...f, internal_risk_offset: Number(e.target.value) }))}
                          style={{ width: "100%" }} />
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)" }}>
                          <span>-3</span><span>0</span><span>+3</span>
                        </div>
                      </div>
                    )}

                    <button
                      onClick={() => saveOverrideConfigMut.mutate(internalOverrideForm)}
                      disabled={saveOverrideConfigMut.isPending}
                      style={{
                        padding: "0.4rem 0.75rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                        background: "var(--accent-blue, #3b82f6)", color: "#fff", cursor: "pointer",
                        fontWeight: 600, fontSize: "0.82rem", alignSelf: "flex-start",
                        display: "flex", alignItems: "center", gap: "0.3rem",
                        opacity: saveOverrideConfigMut.isPending ? 0.6 : 1,
                      }}
                    >
                      {saveOverrideConfigMut.isPending ? <Loader2 size={14} className="spin" /> : null} Save Internal Overrides
                    </button>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* ==================== TAB 4: Unified Brief ==================== */}
      {tab === 3 && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem", flexWrap: "wrap", gap: "0.5rem" }}>
            <div>
              <h3 style={{ margin: 0, fontSize: "1.1rem" }}>Executive Unified Risk Brief</h3>
              <p style={{ margin: "0.2rem 0 0", fontSize: "0.82rem", color: "var(--text-muted, #94a3b8)" }}>
                AI-generated synthesis of Global OSINT Threats and Internal Asset Vulnerabilities. Auto-updates every 2 hours.
              </p>
            </div>
            <button
              onClick={handleGenerateUnifiedBrief}
              disabled={generateUnifiedBriefMut.isPending}
              style={{
                padding: "0.4rem 0.75rem", border: "1px solid var(--accent-blue, #3b82f6)",
                borderRadius: "var(--radius-sm, 4px)", background: "transparent",
                color: "var(--accent-blue, #3b82f6)", cursor: generateUnifiedBriefMut.isPending ? "not-allowed" : "pointer", fontSize: "0.8rem",
                fontWeight: 500, display: "flex", alignItems: "center", gap: "0.3rem",
                opacity: generateUnifiedBriefMut.isPending ? 0.6 : 1,
              }}
            >
              {generateUnifiedBriefMut.isPending ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />} Force Refresh Brief
            </button>
          </div>

          {!sysConfig?.unified_brief ? (
            <div style={{
              background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)",
              padding: "2rem", textAlign: "center", border: "1px solid var(--border-primary, #e2e8f0)",
            }}>
              <p style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.9rem" }}>
                Brief is currently being generated by the background scheduler. Please check back shortly or click Force Refresh.
              </p>
            </div>
          ) : (
            <>
              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                border: "1px solid var(--border-primary, #e2e8f0)", marginBottom: "1.5rem",
              }}>
                <div style={{ fontSize: "0.78rem", color: "var(--text-muted, #94a3b8)", marginBottom: "0.75rem" }}>
                  <Clock size={12} style={{ verticalAlign: "middle", marginRight: "0.25rem" }} />
                  Last Auto-Generated: {sysConfig.unified_brief_time ? formatInChicago(sysConfig.unified_brief_time) : "Unknown"}
                </div>
                <div style={{
                  fontSize: "0.85rem", lineHeight: 1.7, whiteSpace: "pre-wrap",
                  color: "var(--text-primary, #1e293b)",
                }}>
                  {sysConfig.unified_brief}
                </div>
              </div>

              <div style={{
                background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem",
                border: "1px solid var(--border-primary, #e2e8f0)",
              }}>
                <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <Send size={16} /> Broadcast Executive Brief
                </h3>
                <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
                  <input
                    type="email" placeholder="Recipient Email(s)"
                    value={ubEmail}
                    onChange={(e) => setUbEmail(e.target.value)}
                    style={{
                      flex: 1, minWidth: 200, padding: "0.5rem 0.75rem", borderRadius: "var(--radius-sm, 4px)",
                      border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-input, #fff)",
                      color: "var(--text-primary, #1e293b)", fontSize: "0.85rem",
                    }}
                  />
                  <button
                    onClick={handleBroadcastBrief}
                    disabled={!ubEmail}
                    style={{
                      padding: "0.5rem 1rem", border: "none", borderRadius: "var(--radius-sm, 4px)",
                      background: "#2563eb", color: "#fff", cursor: "pointer", fontWeight: 600, fontSize: "0.85rem",
                      opacity: ubEmail ? 1 : 0.5, display: "flex", alignItems: "center", gap: "0.4rem",
                    }}
                  >
                    <Mail size={16} /> Transmit Brief
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function SeverityIcon({ severity }: { severity: string }) {
  const s = (severity || "").toLowerCase();
  const color = s === "extreme" || s === "severe" ? "#ef4444" : s === "moderate" ? "#f97316" : "#6b7280";
  return <AlertTriangle size={14} color={color} />;
}

function HardwareSoftwareTable({ data, type, emptyMessage }: { data: any; type: "hardware" | "software"; emptyMessage: string }) {
  const [expanded, setExpanded] = useState(true);

  let items: any[] = [];
  if (Array.isArray(data)) items = data;
  else if (data && typeof data === "object") items = Object.values(data);
  if (!Array.isArray(items)) items = [];

  const atRisk = items.filter((h: any) => (h["OSINT Threat Matches"] ?? 0) > 0 || (h.osint_count ?? 0) > 0);

  return (
    <div>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          background: "none", border: "none", cursor: "pointer", padding: 0,
          display: "flex", alignItems: "center", gap: "0.3rem",
          fontSize: "0.85rem", fontWeight: 600, color: "var(--text-primary, #1e293b)", marginBottom: "0.5rem",
        }}
      >
        {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        View {type === "hardware" ? "Hardware Inventory" : "At-Risk Software"} &amp; OSINT Correlations
        {atRisk.length > 0 && (
          <span style={{
            background: "#fef3c7", color: "#92400e", padding: "0.1rem 0.4rem",
            borderRadius: "var(--radius-sm, 3px)", fontSize: "0.7rem", fontWeight: 700, marginLeft: "0.3rem",
          }}>
            {atRisk.length} at risk
          </span>
        )}
      </button>

      {expanded && (
        <div>
          {items.length === 0 ? (
            <div style={{ color: "var(--text-muted, #94a3b8)", fontSize: "0.85rem", padding: "1rem 0" }}>
              {type === "hardware" && items.length === 0
                ? "No hardware assets loaded. Go to Settings -> Internal Assets to import your inventory."
                : emptyMessage}
            </div>
          ) : (
            <>
              {atRisk.length > 0 && (
                <div style={{
                  background: "#fef3c7", border: "1px solid #f59e0b", borderRadius: "var(--radius-sm, 4px)",
                  padding: "0.5rem 0.75rem", fontSize: "0.8rem", color: "#92400e", marginBottom: "0.75rem",
                }}>
                  Detected {atRisk.length} {type} assets actively exposed to recent OSINT intelligence.
                </div>
              )}
              {atRisk.length === 0 && items.length > 0 && (
                <div style={{
                  background: "#ecfdf5", border: "1px solid #10b981", borderRadius: "var(--radius-sm, 4px)",
                  padding: "0.5rem 0.75rem", fontSize: "0.8rem", color: "#065f46", marginBottom: "0.75rem",
                }}>
                  All tracked {type} assets are currently clear of recent OSINT correlations.
                </div>
              )}
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
                  <thead>
                    <tr style={{ background: "var(--bg-secondary, #f8fafc)" }}>
                      {type === "hardware" ? (
                        <>
                          <th style={thStyle}>IP Address</th>
                          <th style={thStyle}>Asset Name</th>
                          <th style={thStyle}>Type</th>
                          <th style={thStyle}>OS</th>
                          <th style={thStyle}>OSINT Matches</th>
                          <th style={thStyle}>Risk Score</th>
                        </>
                      ) : (
                        <>
                          <th style={thStyle}>Name</th>
                          <th style={thStyle}>OSINT Matches</th>
                          <th style={thStyle}>Risk Level</th>
                        </>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item: any, idx: number) => {
                      const rowRisk = (item["OSINT Threat Matches"] ?? 0) > 0 || (item.osint_count ?? 0) > 0;
                      return (
                        <tr
                          key={item.id || item.ip_address || item.name || idx}
                          style={{
                            borderBottom: "1px solid var(--border-primary, #e2e8f0)",
                            background: rowRisk ? "rgba(239, 68, 68, 0.05)" : "transparent",
                          }}
                        >
                          {type === "hardware" ? (
                            <>
                              <td style={{ ...tdStyle, fontFamily: "var(--font-mono, monospace)" }}>{item.ip_address || item.ip || "-"}</td>
                              <td style={tdStyle}>{item.asset_name || item.name || "-"}</td>
                              <td style={tdStyle}>{item.host_type || item.type || "-"}</td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem" }}>{item.operating_system || item.os || "-"}</td>
                              <td style={tdStyle}>
                                <span style={{
                                  background: rowRisk ? "#fef2f2" : "var(--bg-tertiary, #f1f5f9)",
                                  color: rowRisk ? "#dc2626" : "var(--text-secondary, #64748b)",
                                  padding: "0.1rem 0.4rem", borderRadius: "var(--radius-sm, 3px)",
                                  fontWeight: 700, fontSize: "0.75rem",
                                }}>
                                  {item["OSINT Threat Matches"] ?? item.osint_count ?? 0}
                                </span>
                              </td>
                              <td style={tdStyle}>{(item.risk_score ?? item.raw_risk_score ?? 0).toFixed(1)}</td>
                            </>
                          ) : (
                            <>
                              <td style={tdStyle}>{item.name || "-"}</td>
                              <td style={tdStyle}>
                                <span style={{
                                  background: rowRisk ? "#fef2f2" : "var(--bg-tertiary, #f1f5f9)",
                                  color: rowRisk ? "#dc2626" : "var(--text-secondary, #64748b)",
                                  padding: "0.1rem 0.4rem", borderRadius: "var(--radius-sm, 3px)",
                                  fontWeight: 700, fontSize: "0.75rem",
                                }}>
                                  {item["OSINT Threat Matches"] ?? item.osint_count ?? 0}
                                </span>
                              </td>
                              <td style={tdStyle}>
                                {item.risk_level ? <RiskBadge level={item.risk_level} /> : "-"}
                              </td>
                            </>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left", padding: "0.5rem", color: "var(--text-secondary, #64748b)",
  fontWeight: 600, borderBottom: "2px solid var(--border-primary, #e2e8f0)", fontSize: "0.75rem",
  whiteSpace: "nowrap",
};
const tdStyle: React.CSSProperties = {
  padding: "0.5rem", color: "var(--text-primary, #1e293b)", fontSize: "0.78rem",
};
