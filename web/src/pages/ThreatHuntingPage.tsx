import { useState, useMemo, useCallback, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { getAllowedTabs } from "../utils/permissions";
import { formatDateInChicago, chicagoDateString } from "../utils/timezone";
import {
  Shield, Search, AlertTriangle, FileDown, SlidersHorizontal,
  Target, Clock, ExternalLink, Filter,
  Activity, ChevronRight, Loader2,
  RefreshCw, FileText, Globe, Bug, Network,
  Link2, Hash, Mail, FileCode, Brain,
} from "lucide-react";

const ALL_HUNT_TABS = [
  { key: "ioc", label: "Live Global IOC Matrix", icon: Shield },
  { key: "hunt", label: "Deep Hunt & Detection Builder", icon: Search },
  { key: "siem", label: "Elastic SIEM Report", icon: Activity },
];

const IOC_TYPE_OPTIONS = [
  "IPv4", "SHA256", "Domain", "CVE", "MITRE ATT&CK", "URL", "MD5", "Email", "SHA1",
];

const IOC_TYPE_COLORS: Record<string, { bg: string; text: string; icon: any }> = {
  IPv4: { bg: "rgba(59,130,246,0.15)", text: "#60a5fa", icon: Globe },
  SHA256: { bg: "rgba(139,92,246,0.15)", text: "#a78bfa", icon: Hash },
  Domain: { bg: "rgba(16,185,129,0.15)", text: "#34d399", icon: Network },
  CVE: { bg: "rgba(239,68,68,0.15)", text: "#f87171", icon: Bug },
  "MITRE ATT&CK": { bg: "rgba(245,158,11,0.15)", text: "#fbbf24", icon: Target },
  URL: { bg: "rgba(99,102,241,0.15)", text: "#818cf8", icon: Link2 },
  MD5: { bg: "rgba(236,72,153,0.15)", text: "#f472b6", icon: FileCode },
  Email: { bg: "rgba(34,211,238,0.15)", text: "#22d3ee", icon: Mail },
  SHA1: { bg: "rgba(168,85,247,0.15)", text: "#c084fc", icon: FileCode },
};

function osintPivotLink(iocType: string, value: string): string | null {
  switch (iocType) {
    case "SHA256": case "MD5": case "SHA1": return `https://www.virustotal.com/gui/file/${value}`;
    case "IPv4": return `https://www.shodan.io/host/${value}`;
    case "Domain": return `https://www.virustotal.com/gui/domain/${value}`;
    case "CVE": return `https://nvd.nist.gov/vuln/detail/${value}`;
    case "MITRE ATT&CK": return `https://attack.mitre.org/techniques/${value.replace(/\./g, "/")}`;
    default: return null;
  }
}

function formatDt(s: string | null | undefined): string {
  if (!s) return "—";
  return formatDateInChicago(s);
}

function csvEscape(v: string): string {
  if (/[",\n\r]/.test(v)) return `"${v.replace(/"/g, '""')}"`;
  return v;
}

function downloadCsv(filename: string, headers: string[], rows: any[], mapFn: (r: any) => string[]) {
  const bom = "\uFEFF";
  const header = headers.map(csvEscape).join(",");
  const body = rows.map(r => mapFn(r).map(csvEscape).join(",")).join("\n");
  const blob = new Blob([bom + header + "\n" + body], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const CARD: React.CSSProperties = {
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
  borderRadius: "var(--radius-sm)", padding: "0.5rem 1rem",
  fontSize: "0.85rem", fontWeight: 600, cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: "0.4rem",
  transition: "all 0.15s",
};
const BTN_SECONDARY: React.CSSProperties = {
  background: "var(--bg-tertiary)", color: "var(--text-secondary)",
  border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)",
  padding: "0.45rem 0.9rem", fontSize: "0.82rem", cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: "0.35rem",
  transition: "all 0.15s",
};
const INPUT_STYLE: React.CSSProperties = {
  background: "var(--bg-input)", border: "1px solid var(--border-primary)",
  color: "var(--text-primary)", borderRadius: "var(--radius-sm)",
  padding: "0.5rem 0.75rem", fontSize: "0.85rem", width: "100%",
  outline: "none", boxSizing: "border-box",
};
const LABEL: React.CSSProperties = {
  fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.3rem",
  display: "block", fontWeight: 500,
};
const TH: React.CSSProperties = {
  textAlign: "left", padding: "0.55rem 0.65rem", color: "var(--text-muted)",
  fontWeight: 600, fontSize: "0.78rem", borderBottom: "2px solid var(--border-primary)",
  whiteSpace: "nowrap", textTransform: "uppercase", letterSpacing: "0.3px",
};
const TD: React.CSSProperties = {
  padding: "0.55rem 0.65rem", color: "var(--text-secondary)", fontSize: "0.82rem",
  borderBottom: "1px solid var(--border-secondary)", verticalAlign: "middle",
};

function InfoBox({ type, children }: { type: "info" | "success" | "warning" | "error"; children: React.ReactNode }) {
  const m: Record<string, { bg: string; border: string; text: string }> = {
    info: { bg: "rgba(59,130,246,0.1)", border: "var(--accent-blue)", text: "#93c5fd" },
    success: { bg: "rgba(1,164,109,0.1)", border: "var(--accent-green)", text: "#6ee7b7" },
    warning: { bg: "rgba(234,179,8,0.1)", border: "var(--accent-yellow)", text: "#fde68a" },
    error: { bg: "rgba(239,68,68,0.1)", border: "var(--accent-red)", text: "#fca5a5" },
  };
  const c = m[type];
  return (
    <div style={{
      padding: "0.75rem 1rem", borderRadius: "var(--radius-sm)", fontSize: "0.85rem",
      marginBottom: "0.75rem", borderLeft: "3px solid " + c.border,
      background: c.bg, color: c.text, lineHeight: 1.5,
    }}>{children}</div>
  );
}

function Badge({ label }: { label: string }) {
  const def = { bg: "rgba(107,114,128,0.15)", text: "var(--text-muted)", icon: Shield };
  const { bg, text, icon: Icon } = IOC_TYPE_COLORS[label] || def;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "0.25rem",
      padding: "0.2rem 0.5rem", borderRadius: "var(--radius-sm)",
      fontSize: "0.72rem", fontWeight: 600, letterSpacing: "0.3px",
      background: bg, color: text, whiteSpace: "nowrap",
    }}>
      <Icon size={11} />
      {label}
    </span>
  );
}

export function ThreatHuntingPage() {
  const { user } = useAuth();
  const allowedHuntTabs = getAllowedTabs(user?.allowed_actions, "threatHunting");
  const tabs = ALL_HUNT_TABS.filter(t => allowedHuntTabs.length === 0 || allowedHuntTabs.includes(t.key));
  const [activeTab, setActiveTab] = useState(tabs.length > 0 ? tabs[0].key : "ioc");

  useEffect(() => {
    if (allowedHuntTabs.length > 0 && tabs.length > 0 && !allowedHuntTabs.includes(activeTab)) {
      setActiveTab(tabs[0].key);
    }
  }, [allowedHuntTabs.join(",")]);

  return (
    <div style={{ padding: "1.25rem", height: "100%", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexShrink: 0 }}>
        <h2 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.3rem", fontWeight: 700 }}>
          <Shield size={22} style={{ verticalAlign: "middle", marginRight: "0.5rem" }} />
          Active Threat Hunting & Detection Engineering
        </h2>
      </div>

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

      <div style={{ flex: 1, overflow: "auto" }}>
        {activeTab === "ioc" && <IocMatrixTab />}
        {activeTab === "hunt" && <DeepHuntTab />}
        {activeTab === "siem" && <ElasticSiemTab />}
      </div>
    </div>
  );
}

function IocMatrixTab() {
  const [typeFilter, setTypeFilter] = useState<string[]>(["IPv4", "SHA256", "Domain", "CVE", "MITRE ATT&CK"]);
  const [expandedFilter, setExpandedFilter] = useState(false);

  const { data: iocs = [], isLoading } = useQuery({
    queryKey: ["hunting-iocs"],
    queryFn: () => api.get("/hunting/iocs", { params: { days_back: 3 } }).then(r => r.data),
    refetchInterval: 120000,
  });

  const data = iocs as any[];

  const filtered = useMemo(() => {
    if (!data || data.length === 0) return [];
    return data.filter((i: any) => typeFilter.includes(i.Type || i.indicator_type));
  }, [data, typeFilter]);

  const allTypes = useMemo(() => {
    if (!data || data.length === 0) return IOC_TYPE_OPTIONS;
    const types = new Set<string>();
    data.forEach((i: any) => types.add(i.Type || i.indicator_type));
    const sorted = [...types].sort();
    return sorted.length > 0 ? sorted : IOC_TYPE_OPTIONS;
  }, [data]);

  const handleExport = useCallback(() => {
    const ts = chicagoDateString().replace(/-/g, "");
    downloadCsv(
      `Hunt_Targets_${ts}.csv`,
      ["Type", "Indicator", "Context", "Detected", "Source Article"],
      filtered,
      (r: any) => [
        r.Type || r.indicator_type || "",
        r.Indicator || r.indicator_value || "",
        r.Context || r.context || "",
        r.Detected || r.detected_at || "",
        r["Source Article"] || r.source_article || r.source_link || "",
      ],
    );
  }, [filtered]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1rem" }}>
          <div>
            <h4 style={{ ...CARD_HEADER, margin: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <Globe size={16} /> Global Indicators of Compromise (Last 72 Hours)
            </h4>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
              Automated IOC extraction from ingested threat intelligence — {filtered.length} matching
            </div>
          </div>
          <button onClick={handleExport} disabled={filtered.length === 0} style={{
            ...BTN_SECONDARY, opacity: filtered.length === 0 ? 0.5 : 1,
          }}>
            <FileDown size={14} /> Export CSV
          </button>
        </div>

        <div style={{
          background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)",
          padding: "0.75rem 1rem", marginBottom: "1rem",
        }}>
          <div
            onClick={() => setExpandedFilter(!expandedFilter)}
            style={{ display: "flex", alignItems: "center", gap: "0.4rem", cursor: "pointer", fontSize: "0.82rem", color: "var(--text-secondary)", fontWeight: 500 }}
          >
            <Filter size={14} />
            Filter by Threat Type ({typeFilter.length} selected)
            <ChevronRight size={14} style={{ transform: expandedFilter ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.15s" }} />
          </div>
          {expandedFilter && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem", marginTop: "0.5rem" }}>
              {allTypes.map(t => {
                const checked = typeFilter.includes(t);
                const col = IOC_TYPE_COLORS[t];
                return (
                  <button key={t} onClick={() => setTypeFilter(prev => checked ? prev.filter(x => x !== t) : [...prev, t])} style={{
                    padding: "0.3rem 0.6rem", borderRadius: "var(--radius-sm)", border: checked ? "1px solid " + (col?.text || "var(--accent-blue)") : "1px solid var(--border-primary)",
                    background: checked ? (col?.bg || "rgba(59,130,246,0.1)") : "transparent",
                    color: checked ? (col?.text || "var(--accent-blue)") : "var(--text-muted)",
                    fontSize: "0.75rem", cursor: "pointer", fontWeight: checked ? 600 : 400,
                    display: "inline-flex", alignItems: "center", gap: "0.25rem",
                    transition: "all 0.1s",
                  }}>
                    {checked && <span style={{ fontSize: "0.65rem" }}>✓</span>}
                    {t}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {isLoading ? (
          <div style={{ textAlign: "center", padding: "3rem 0", color: "var(--text-muted)" }}>
            <Loader2 size={24} style={{ animation: "spin 1s linear infinite", margin: "0 auto 0.5rem" }} />
            Loading IOCs...
          </div>
        ) : filtered.length === 0 ? (
          <InfoBox type="info">No IOCs extracted in the last 72 hours matching the selected filters.</InfoBox>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
              <thead>
                <tr>
                  <th style={TH}>Type</th>
                  <th style={TH}>Indicator</th>
                  <th style={TH}>Context</th>
                  <th style={TH}>Detected</th>
                  <th style={TH}>Source Intel</th>
                  <th style={TH}>Investigate</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((i: any, idx: number) => {
                  const type = i.Type || i.indicator_type || "";
                  const value = i.Indicator || i.indicator_value || "";
                  const context = i.Context || i.context || "";
                  const detected = i.Detected || i.detected_at || "";
                  const sourceLink = i["Source Article"] || i.source_article || i.source_link || "";
                  const pivotLink = osintPivotLink(type, value);
                  return (
                    <tr key={i.id || idx} style={{ background: idx % 2 === 0 ? "transparent" : "var(--bg-secondary)" }}>
                      <td style={TD}><Badge label={type} /></td>
                      <td style={{ ...TD, fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace", fontSize: "0.78rem", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis" }}>
                        {value}
                      </td>
                      <td style={{ ...TD, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", fontSize: "0.78rem" }}>
                        {typeof context === "string" ? context.slice(0, 120) : JSON.stringify(context).slice(0, 120)}
                        {typeof context === "string" && context.length > 120 ? "…" : ""}
                      </td>
                      <td style={{ ...TD, whiteSpace: "nowrap", fontSize: "0.78rem" }}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                          <Clock size={11} style={{ color: "var(--text-muted)" }} />
                          {formatDt(detected)}
                        </span>
                      </td>
                      <td style={TD}>
                        {sourceLink ? (
                          <a href={sourceLink} target="_blank" rel="noopener noreferrer" style={{
                            color: "var(--accent-blue)", textDecoration: "none", fontSize: "0.78rem",
                            display: "inline-flex", alignItems: "center", gap: "0.25rem",
                          }}>
                            <ExternalLink size={11} /> Article
                          </a>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>—</span>
                        )}
                      </td>
                      <td style={TD}>
                        {pivotLink ? (
                          <a href={pivotLink} target="_blank" rel="noopener noreferrer" style={{
                            color: "var(--accent-green)", textDecoration: "none", fontSize: "0.78rem",
                            display: "inline-flex", alignItems: "center", gap: "0.25rem",
                          }}>
                            <ExternalLink size={11} /> Open Tool
                          </a>
                        ) : (
                          <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function DeepHuntTab() {
  const [huntTarget, setHuntTarget] = useState("");
  const [huntDepth, setHuntDepth] = useState(30);
  const [huntResult, setHuntResult] = useState<any[] | null>(null);
  const [detectionPackage, setDetectionPackage] = useState<string | null>(null);
  const [huntError, setHuntError] = useState<string | null>(null);
  const [isCompiling, setIsCompiling] = useState(false);

  const { mutate: compileHunt, isPending } = useMutation({
    mutationFn: async () => {
      if (!huntTarget.trim()) throw new Error("Please enter a target entity.");
      const res = await api.get("/hunting/search-articles", {
        params: { target: huntTarget.trim(), days_back: huntDepth },
      });
      return res.data;
    },
    onSuccess: async (data) => {
      const arts = Array.isArray(data) ? data : data?.items || data?.articles || [];
      setHuntResult(arts);
      setHuntError(null);
      setIsCompiling(true);
      try {
        const pkg = buildDetectionPackage(huntTarget.trim(), arts);
        setDetectionPackage(pkg);
      } catch {
        setDetectionPackage("Failed to generate detection package from search results.");
      }
      setIsCompiling(false);
    },
    onError: (err: any) => {
      setHuntError(err?.response?.data?.detail || err.message || "Search failed.");
      setHuntResult(null);
      setDetectionPackage(null);
      setIsCompiling(false);
    },
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD}>
        <h4 style={{ ...CARD_HEADER, display: "flex", alignItems: "center", gap: "0.4rem" }}>
          <Brain size={16} /> Targeted LLM Deep Hunt & Detection Engine
        </h4>
        <div style={{ fontSize: "0.82rem", color: "var(--text-secondary)", marginBottom: "1rem" }}>
          Search intelligence articles for a target entity and auto-generate a structured detection package.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div>
            <label style={LABEL}>Target Entity</label>
            <div style={{ position: "relative" }}>
              <Target size={15} style={{ position: "absolute", left: "0.65rem", top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", pointerEvents: "none" }} />
              <input
                style={{ ...INPUT_STYLE, paddingLeft: "2rem" }}
                value={huntTarget}
                onChange={e => setHuntTarget(e.target.value)}
                placeholder="e.g., Volt Typhoon, Ivanti Connect Secure, LockBit 3.0"
                onKeyDown={e => { if (e.key === "Enter") compileHunt(); }}
              />
            </div>
          </div>

          <div>
            <label style={LABEL}>
              <SlidersHorizontal size={12} style={{ verticalAlign: "middle", marginRight: "0.25rem" }} />
              Historical Depth: {huntDepth} days
            </label>
            <input
              type="range" min={7} max={90} value={huntDepth}
              onChange={e => setHuntDepth(Number(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-blue)", cursor: "pointer" }}
            />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)" }}>
              <span>7 days</span>
              <span>90 days</span>
            </div>
          </div>

          <button
            onClick={() => compileHunt()}
            disabled={isPending || !huntTarget.trim()}
            style={{
              ...BTN_PRIMARY, alignSelf: "flex-start",
              opacity: isPending || !huntTarget.trim() ? 0.6 : 1,
            }}
          >
            {isPending ? (
              <><Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> Scanning telemetry...</>
            ) : (
              <><Search size={14} /> Compile Detection Package</>
            )}
          </button>
        </div>
      </div>

      {huntError && <InfoBox type="error">{huntError}</InfoBox>}

      {huntResult !== null && (
        <div style={CARD}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
            <AlertTriangle size={16} style={{ color: "var(--accent-yellow)" }} />
            <span style={{ fontSize: "0.9rem", fontWeight: 600, color: "var(--text-primary)" }}>
              Found {huntResult.length} report{huntResult.length !== 1 ? "s" : ""} matching "{huntTarget}"
            </span>
          </div>
          {(huntResult as any[]).length > 0 && (
            <div style={{ maxHeight: 200, overflow: "auto", marginBottom: "0.75rem" }}>
              {(huntResult as any[]).slice(0, 15).map((a: any, i: number) => (
                <div key={a.id || i} style={{
                  padding: "0.4rem 0", borderBottom: "1px solid var(--border-secondary)",
                  fontSize: "0.82rem",
                }}>
                  <div style={{ color: "var(--text-primary)", fontWeight: 500 }}>
                    {a.link ? (
                      <a href={a.link} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent-blue)", textDecoration: "none" }}>
                        {a.title || a.source || "Article " + (i + 1)}
                      </a>
                    ) : (a.title || a.source || "Article " + (i + 1))}
                  </div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", marginTop: "0.15rem" }}>
                    {a.source && <span>{a.source} · </span>}
                    {a.published_date && <span>{formatDt(a.published_date)}</span>}
                    {a.score != null && <span> · Score: {typeof a.score === "number" ? a.score.toFixed(0) : a.score}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {(isCompiling) && (
        <div style={{ ...CARD, textAlign: "center", padding: "2rem" }}>
          <Loader2 size={28} style={{ animation: "spin 1s linear infinite", color: "var(--accent-blue)" }} />
          <div style={{ marginTop: "0.75rem", color: "var(--text-secondary)", fontSize: "0.9rem" }}>
            Synthesizing detection package from {huntResult?.length || 0} intelligence reports...
          </div>
        </div>
      )}

      {detectionPackage && !isCompiling && (
        <div style={CARD}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
            <FileText size={18} style={{ color: "var(--accent-blue)" }} />
            <h4 style={{ margin: 0, fontSize: "1rem", color: "var(--text-primary)", fontWeight: 700 }}>
              Detection Package: {huntTarget.toUpperCase()}
            </h4>
          </div>
          <div style={{
            background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)",
            padding: "1.25rem", fontSize: "0.85rem", lineHeight: 1.7,
            color: "var(--text-primary)", whiteSpace: "pre-wrap",
            fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
            maxHeight: 600, overflow: "auto",
          }}>
            {detectionPackage}
          </div>
        </div>
      )}
    </div>
  );
}

function buildDetectionPackage(target: string, articles: any[]): string {
  if (!articles || articles.length === 0) {
    return `No intelligence reports found for "${target}". Unable to generate detection package.`;
  }

  const sections: string[] = [];

  sections.push("=".repeat(72));
  sections.push(`  DETECTION PACKAGE: ${target.toUpperCase()}`);
  sections.push("=".repeat(72));
  sections.push(`  Generated from ${articles.length} intelligence reports`);
  sections.push("=".repeat(72));
  sections.push("");

  sections.push("### 1. THREAT OVERVIEW & MITRE TTPs");
  sections.push("");
  const overviewParts = articles.slice(0, 8).map((a, i) => {
    const src = a.source || "Unknown source";
    const title = a.title || `Report ${i + 1}`;
    const summary = a.summary || a.description || a.content || "";
    const snippet = typeof summary === "string" ? summary.slice(0, 300) : JSON.stringify(summary).slice(0, 300);
    return `[${i + 1}] ${title} (${src})\n    ${snippet}${summary && typeof summary === "string" && summary.length > 300 ? "..." : ""}`;
  });
  sections.push(overviewParts.join("\n\n"));
  sections.push("");

  sections.push("---");
  sections.push("### 2. KNOWN VULNERABILITIES & INFRASTRUCTURE");
  sections.push("");
  const cves = new Set<string>();
  articles.forEach(a => {
    const text = JSON.stringify(a).toLowerCase();
    const foundCves = text.match(/cve-\d{4}-\d{4,7}/gi);
    if (foundCves) foundCves.forEach(c => cves.add(c.toUpperCase()));
  });
  if (cves.size > 0) {
    sections.push("  Associated CVEs:");
    [...cves].slice(0, 15).forEach(c => sections.push(`    - ${c}`));
  } else {
    sections.push("  No specific CVEs identified in the source reports.");
  }
  sections.push("");
  sections.push("  Key intelligence sources:");
  const uniqueSources = [...new Set(articles.map(a => a.source).filter(Boolean))];
  uniqueSources.slice(0, 8).forEach(s => sections.push(`    - ${s}`));
  sections.push("");

  sections.push("---");
  sections.push("### 3. SIEM HUNT QUERIES");
  sections.push("");
  sections.push("  Splunk / Elastic Search:");
  sections.push("");
  sections.push(`  # Hunt for indicators related to: ${target}`);
  sections.push(`  index=* "${target}"`);
  sections.push("  | stats count by src_ip, dest_ip, user");
  sections.push("  | where count > 0");
  sections.push("  | sort -count");
  sections.push("");
  sections.push("  Alternative query patterns:");
  sections.push(`  event.dataset:("winlog" OR "syslog") AND message:*${target.replace(/\s+/g, "* AND message:*")}*`);
  sections.push("  | within 7d");
  sections.push("  | top 20 source.ip, destination.ip");
  sections.push("");

  sections.push("---");
  sections.push("### 4. YARA DETECTION STUB");
  sections.push("");
  sections.push("```yara");
  sections.push(`rule hunt_${target.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase()}_iocs {`);
  sections.push("  meta:");
  sections.push(`    description = "Detection rule for ${target} indicators"`);
  sections.push(`    author = "NOC Intelligence Fusion Center"`);
  sections.push(`    date = "${chicagoDateString()}"`);
  sections.push("    hash = \"auto-generated\"");
  sections.push("  strings:");
  const keywords = target.split(/\s+/).filter(Boolean);
  keywords.forEach((kw, i) => {
    sections.push(`    $s${i + 1} = "${kw}" nocase`);
  });
  if (articles.length > 0) {
    const sampleTitle = (articles[0].title || articles[0].source || "").slice(0, 40).replace(/[^a-zA-Z0-9 ]/g, "");
    if (sampleTitle) sections.push(`    $ref = "${sampleTitle}" ascii wide`);
  }
  sections.push("  condition:");
  sections.push("    any of them");
  sections.push("}");
  sections.push("```");
  sections.push("");
  sections.push("=".repeat(72));
  sections.push("  END OF DETECTION PACKAGE");
  sections.push("=".repeat(72));

  return sections.join("\n");
}

function ElasticSiemTab() {
  const [syncing, setSyncing] = useState(false);

  const { data: events = [], isLoading, refetch } = useQuery({
    queryKey: ["elastic-events"],
    queryFn: () => api.get("/threat/elastic-events", { params: { hours_back: 24 } }).then(r => r.data).catch(() => {
      return [];
    }),
    refetchInterval: 120000,
    retry: 1,
  });

  const eventsList = (Array.isArray(events) ? events : events?.items || events?.events || []) as any[];

  const [triageResult, setTriageResult] = useState<string | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);

  const handleSync = async () => {
    setSyncing(true);
    try {
      await api.post("/threat/sync-elastic-cache", { hours_back: 24 });
      refetch();
    } catch { /* ignore */ }
    setSyncing(false);
  };

  const handleTriage = async () => {
    if (eventsList.length === 0) return;
    setTriageLoading(true);
    try {
      const res = await api.post("/threat/generate-siem-triage", { events: eventsList.slice(0, 50) });
      setTriageResult(res.data.summary || res.data.triage || res.data.result || JSON.stringify(res.data));
    } catch {
      const ctx = eventsList.slice(0, 30).map((e: any) =>
        `[${e.timestamp || e["@timestamp"] || ""}] ${e.severity || e.event?.severity || "INFO"}: ${(e.message || e.event?.original || "")}`,
      ).join("\n");
      setTriageResult(`=== SIEM TRIAGE SUMMARY (Client-Side) ===\n\nEvents Analyzed: ${eventsList.length}\n\n${ctx.slice(0, 2000)}`);
    }
    setTriageLoading(false);
  };

  const severityColor = (sev: string) => {
    const s = (sev || "").toUpperCase();
    if (s === "CRITICAL") return "#dc3545";
    if (s === "HIGH" || s === "ERROR") return "#f97316";
    if (s === "MEDIUM" || s === "WARN" || s === "WARNING") return "#eab308";
    if (s === "LOW" || s === "INFO") return "#22d3ee";
    return "var(--text-muted)";
  };

  const uniqueIps = useMemo(() => {
    const ips = new Set<string>();
    eventsList.forEach((e: any) => {
      const ip = e.source_ip || e["source.ip"] || e.source?.ip || e.ip;
      if (ip) ips.add(ip);
    });
    return ips.size;
  }, [eventsList]);

  const criticalCount = useMemo(() => {
    return eventsList.filter((e: any) => {
      const s = (e.severity || e.event?.severity || "").toUpperCase();
      return s === "CRITICAL" || s === "HIGH";
    }).length;
  }, [eventsList]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={CARD}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <div>
            <h4 style={{ ...CARD_HEADER, margin: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <Activity size={16} /> Advanced SIEM Fusion & Hunt
            </h4>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.2rem" }}>
              Live telemetry triage with AI-assisted event analysis
            </div>
          </div>
          <button onClick={handleSync} disabled={syncing} style={{
            ...BTN_SECONDARY, opacity: syncing ? 0.6 : 1,
          }}>
            <RefreshCw size={14} style={{ animation: syncing ? "spin 1s linear infinite" : "none" }} />
            {syncing ? "Syncing..." : "Sync Local Cache"}
          </button>
        </div>

        {eventsList.length > 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "0.75rem", marginBottom: "1rem" }}>
            <div style={{ background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)", padding: "0.75rem 1rem", textAlign: "center" }}>
              <div style={{ fontSize: "1.6rem", fontWeight: 700, color: "var(--text-primary)" }}>{eventsList.length}</div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "0.15rem" }}>Local Events (24h)</div>
            </div>
            <div style={{ background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)", padding: "0.75rem 1rem", textAlign: "center" }}>
              <div style={{ fontSize: "1.6rem", fontWeight: 700, color: criticalCount > 0 ? "#f97316" : "var(--text-primary)" }}>{uniqueIps}</div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "0.15rem" }}>Unique Threat IPs</div>
            </div>
            <div style={{ background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)", padding: "0.75rem 1rem", textAlign: "center" }}>
              <div style={{ fontSize: "1.6rem", fontWeight: 700, color: criticalCount > 0 ? "#dc3545" : "var(--text-primary)" }}>
                {eventsList.length > 0 ? Math.round((criticalCount / eventsList.length) * 100) : 0}%
              </div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "0.15rem" }}>Critical Density</div>
            </div>
          </div>
        )}

        {isLoading ? (
          <div style={{ textAlign: "center", padding: "2rem 0", color: "var(--text-muted)" }}>
            <Loader2 size={20} style={{ animation: "spin 1s linear infinite" }} />
            <div style={{ marginTop: "0.5rem" }}>Loading Elastic events...</div>
          </div>
        ) : eventsList.length === 0 ? (
          <InfoBox type="info">
            No high-severity SIEM alerts logged locally in the last 24 hours. Click "Sync Local Cache" to pull from Elastic, or verify the Elastic worker is running.
          </InfoBox>
        ) : (
          <>
            <div style={{ overflowX: "auto", maxHeight: 350, overflowY: "auto", marginBottom: "1rem" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
                <thead>
                  <tr>
                    <th style={TH}>Timestamp</th>
                    <th style={TH}>Severity</th>
                    <th style={TH}>Category</th>
                    <th style={TH}>Source IP</th>
                    <th style={TH}>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {eventsList.slice(0, 100).map((e: any, i: number) => {
                    const ts = e.timestamp || e["@timestamp"] || e.Time || "";
                    const sev = e.severity || e.event?.severity || e.Severity || "INFO";
                    const cat = e.event_category || e.event?.category || e.Category || "—";
                    const ip = e.source_ip || e["source.ip"] || e.source?.ip || e.IP || e.ip || "—";
                    const msg = e.message || e.event?.original || e.Message || "—";
                    return (
                      <tr key={e.id || i} style={{ background: i % 2 === 0 ? "transparent" : "var(--bg-secondary)" }}>
                        <td style={{ ...TD, whiteSpace: "nowrap", fontSize: "0.75rem" }}>{formatDt(ts)}</td>
                        <td style={TD}>
                          <span style={{
                            display: "inline-block", padding: "0.15rem 0.4rem", borderRadius: "var(--radius-sm)",
                            fontSize: "0.7rem", fontWeight: 700, color: "#fff",
                            background: severityColor(sev),
                          }}>{sev}</span>
                        </td>
                        <td style={{ ...TD, fontSize: "0.75rem" }}>{cat}</td>
                        <td style={{ ...TD, fontFamily: "monospace", fontSize: "0.75rem" }}>{ip}</td>
                        <td style={{ ...TD, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", fontSize: "0.75rem" }}>
                          {typeof msg === "string" ? msg.slice(0, 120) : JSON.stringify(msg).slice(0, 120)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <button onClick={handleTriage} disabled={triageLoading} style={{
              ...BTN_PRIMARY, opacity: triageLoading ? 0.6 : 1,
            }}>
              {triageLoading ? (
                <><Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> Analyzing...</>
              ) : (
                <><Brain size={14} /> AI Triage & Summarize Results</>
              )}
            </button>
          </>
        )}
      </div>

      {triageResult && (
        <div style={CARD}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
            <FileText size={16} style={{ color: "var(--accent-blue)" }} />
            <h4 style={{ margin: 0, fontSize: "0.95rem", color: "var(--text-primary)" }}>SIEM Triage Summary</h4>
          </div>
          <div style={{
            background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)",
            padding: "1rem", fontSize: "0.85rem", lineHeight: 1.6,
            color: "var(--text-primary)", whiteSpace: "pre-wrap",
            fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
            maxHeight: 500, overflow: "auto",
          }}>
            {triageResult}
          </div>
        </div>
      )}
    </div>
  );
}
