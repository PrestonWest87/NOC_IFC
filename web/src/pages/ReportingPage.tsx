import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { getAllowedTabs } from "../utils/permissions";
import { formatDateInChicago, chicagoDateString, formatInChicago } from "../utils/timezone";
import {
  FileText, Calendar, Mail, Send, BookOpen, Search, Plus, Eye,
  Trash2, Loader2, AlertCircle, CheckCircle, Target, Layers, Save,
  User, ChevronDown, ChevronRight, Clock
} from "lucide-react";

const btn = (color: string): React.CSSProperties => ({
  background: color,
  color: "#fff",
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: "0.5rem 1rem",
  cursor: "pointer",
  fontWeight: 600,
  fontSize: "0.8rem",
  display: "inline-flex",
  alignItems: "center",
  gap: "0.35rem",
  transition: "opacity 0.15s",
});

const inputStyle: React.CSSProperties = {
  background: "var(--bg-input)",
  color: "var(--text-primary)",
  border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-sm)",
  padding: "0.45rem 0.6rem",
  fontSize: "0.8rem",
  width: "100%",
  boxSizing: "border-box",
};

const textareaStyle: React.CSSProperties = {
  ...inputStyle,
  resize: "vertical",
  minHeight: 70,
  fontFamily: "var(--font-mono)",
  fontSize: "0.75rem",
};

const selectStyle: React.CSSProperties = {
  ...inputStyle,
  cursor: "pointer",
};

const cardStyle: React.CSSProperties = {
  background: "var(--bg-card)",
  borderRadius: "var(--radius-md)",
  padding: "1rem",
  border: "1px solid var(--border-primary)",
};

const sectionTitle: React.CSSProperties = {
  margin: "0 0 0.5rem",
  fontSize: "0.85rem",
  color: "var(--text-secondary)",
};

function formatDate(d: string | null | undefined) {
  if (!d) return "";
  return formatDateInChicago(d);
}

function Spinner() {
  return <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} />;
}

export function ReportingPage() {
  const { user } = useAuth();
  const allowedReportTabs = getAllowedTabs(user?.allowed_actions, "reporting");
  const ALL_REPORT_TABS = [
    { label: "Daily Fusion Briefing", icon: Calendar },
    { label: "Custom Report Builder", icon: FileText },
    { label: "Shared Library", icon: BookOpen },
  ];
  const [tab, setTab] = useState(0);

  useEffect(() => {
    if (allowedReportTabs.length > 0 && !allowedReportTabs.includes(String(tab))) {
      setTab(Number(allowedReportTabs[0]));
    }
  }, [allowedReportTabs.join(",")]);

  const tabs = ALL_REPORT_TABS.filter((_, i) => allowedReportTabs.length === 0 || allowedReportTabs.includes(String(i)));

  return (
    <div style={{ padding: "1.5rem" }}>
      <h2 style={{ margin: "0 0 1rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <FileText size={22} />
        Reporting & Briefings
      </h2>

      <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap", marginBottom: "1.25rem" }}>
        {tabs.map((t, i) => (
          <button
            key={i}
            onClick={() => setTab(i)}
            style={{
              background: tab === i ? "var(--accent-blue)" : "transparent",
              color: tab === i ? "#fff" : "var(--text-secondary)",
              border: `1px solid ${tab === i ? "var(--accent-blue)" : "var(--border-primary)"}`,
              borderRadius: "var(--radius-sm)",
              padding: "0.45rem 0.75rem",
              cursor: "pointer",
              fontWeight: tab === i ? 700 : 500,
              fontSize: "0.78rem",
              display: "inline-flex",
              alignItems: "center",
              gap: "0.35rem",
              whiteSpace: "nowrap",
            }}
          >
            <t.icon size={14} />
            {t.label}
          </button>
        ))}
      </div>
      {tab === 0 && <DailyFusionBriefing />}
      {tab === 1 && <CustomReportBuilder />}
      {tab === 2 && <SharedLibrary />}
    </div>
  );
}

/* ==============================
   TAB 1: DAILY FUSION BRIEFING
   ============================== */
function DailyFusionBriefing() {
  const queryClient = useQueryClient();
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [recipients, setRecipients] = useState("");

  const { data: briefings, isLoading: briefingsLoading } = useQuery({
    queryKey: ["daily-briefings"],
    queryFn: () => api.get("/reporting/daily-briefings").then(r => r.data),
    refetchInterval: 60000,
  });

  const { data: config } = useQuery({
    queryKey: ["settings-config"],
    queryFn: () => api.get("/settings/config").then(r => r.data),
    refetchInterval: 60000,
  });

  const briefs: any[] = Array.isArray(briefings) ? briefings : [];

  const selected = briefs.length > 0 ? briefs[selectedIdx] : null;

  const genMutation = useMutation({
    mutationFn: () => api.post("/reporting/generate-daily"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["daily-briefings"] });
    },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const broadcastMutation = useMutation({
    mutationFn: (data: { report_date: string; content: string; recipients: string }) =>
      api.post("/reporting/broadcast", data),
    onSuccess: (r: any) => {
      if (r.data.status === "ok") alert("Report transmitted successfully!");
      else alert("Broadcast error: " + (r.data.message || "Unknown error"));
    },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <div style={cardStyle}>
        <h3 style={{ margin: "0 0 0.5rem", fontSize: "1rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.4rem" }}>
          <Calendar size={16} />
          Daily Master Fusion Report
        </h3>
        <p style={{ margin: "0 0 1rem", fontSize: "0.8rem", color: "var(--text-muted)" }}>
          AI-synthesized situational report covering Cyber, Vulnerabilities, Physical Hazards, and Cloud Infrastructure.
        </p>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <button
            onClick={() => genMutation.mutate()}
            disabled={genMutation.isPending}
            style={btn("var(--accent-blue)")}
          >
            {genMutation.isPending ? <Spinner /> : <Plus size={14} />}
            {genMutation.isPending ? "Generating..." : "Generate Yesterday's Report"}
          </button>
          {genMutation.data && (
            <span style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem", fontSize: "0.8rem", color: "var(--accent-green)" }}>
              <CheckCircle size={14} />
              Report generated!
            </span>
          )}
          {genMutation.isError && (
            <span style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem", fontSize: "0.8rem", color: "var(--accent-red)" }}>
              <AlertCircle size={14} />
              {(genMutation.error as any)?.response?.data?.detail || "Generation failed"}
            </span>
          )}
        </div>
      </div>

      {briefingsLoading ? (
        <div style={{ ...cardStyle, textAlign: "center", padding: "2rem" }}>
          <Spinner />
          <span style={{ marginLeft: "0.5rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>Loading briefings...</span>
        </div>
      ) : briefs.length === 0 ? (
        <div style={cardStyle}>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
            No historical reports found. Click the generation button above to synthesize your first shift briefing.
          </p>
        </div>
      ) : (
        <>
          <div style={cardStyle}>
            <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", flexWrap: "wrap", marginBottom: "1rem" }}>
              <div style={{ flex: 1, minWidth: 220 }}>
                <div style={sectionTitle}>Select Historical Briefing</div>
                <select
                  style={selectStyle}
                  value={selectedIdx}
                  onChange={e => setSelectedIdx(Number(e.target.value))}
                >
                  {briefs.map((b: any, i: number) => (
                    <option key={b.id || i} value={i}>
                      {b.report_date?.slice ? formatDateInChicago(b.report_date) : String(b.report_date)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            {selected && (
              <div style={{
                background: "var(--bg-secondary)",
                borderRadius: "var(--radius-sm)",
                padding: "1rem",
                fontSize: "0.82rem",
                lineHeight: 1.6,
                color: "var(--text-primary)",
                whiteSpace: "pre-wrap",
                fontFamily: "var(--font-mono)",
                maxHeight: 500,
                overflow: "auto",
              }}>
                {selected.content as string}
              </div>
            )}
          </div>

          {selected && (
            <div style={cardStyle}>
              <h4 style={{ margin: "0 0 0.75rem", fontSize: "0.9rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                <Mail size={15} />
                Broadcast Report
              </h4>
              <p style={{ margin: "0 0 0.75rem", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                Send this report via email. Markdown formatting will be converted to HTML.
              </p>
              <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 250 }}>
                  <div style={sectionTitle}>Recipient Email(s)</div>
                  <input
                    style={inputStyle}
                    placeholder="admin@example.com, operator@example.com"
                    value={recipients || config?.smtp_recipient || ""}
                    onChange={e => setRecipients(e.target.value)}
                  />
                </div>
                <button
                  onClick={() => {
                    const r = recipients || config?.smtp_recipient || "";
                    if (!r) { alert("Please enter at least one recipient email."); return; }
                    broadcastMutation.mutate({
                      report_date: selected.report_date?.slice ? chicagoDateString(new Date(selected.report_date)) : String(selected.report_date),
                      content: selected.content as string,
                      recipients: r,
                    });
                  }}
                  disabled={broadcastMutation.isPending}
                  style={btn("var(--accent-green)")}
                >
                  {broadcastMutation.isPending ? <Spinner /> : <Send size={14} />}
                  {broadcastMutation.isPending ? "Transmitting..." : "Transmit Report"}
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ==============================
   TAB 2: CUSTOM REPORT BUILDER
   ============================== */
function CustomReportBuilder() {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [daysBack, setDaysBack] = useState(7);
  const [generated, setGenerated] = useState<string | null>(null);
  const [saveTitle, setSaveTitle] = useState("");

  const genMutation = useMutation({
    mutationFn: (data: { target: string; days_back: number; objective: string; analyst: string }) =>
      api.post("/reporting/generate-custom", data),
    onSuccess: (r: any) => {
      if (r.data.status === "ok") {
        setGenerated(r.data.content);
        setSaveTitle(`Custom Report - ${formatInChicago(new Date(), { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })}`);
      } else {
        alert("Error: " + (r.data.message || "Generation failed."));
      }
    },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const saveMutation = useMutation({
    mutationFn: (data: { title: string; author: string; content: string }) =>
      api.post("/reporting/save-report", data),
    onSuccess: () => {
      alert("Report saved to library!");
      queryClient.invalidateQueries({ queryKey: ["saved-reports"] });
    },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <div style={cardStyle}>
        <h3 style={{ margin: "0 0 0.5rem", fontSize: "1rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.4rem" }}>
          <FileText size={16} />
          Custom Intel Report Builder
        </h3>
        <p style={{ margin: "0 0 1rem", fontSize: "0.8rem", color: "var(--text-muted)" }}>
          Search and compile intelligence articles into a formatted report.
        </p>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: 2, minWidth: 200 }}>
            <div style={sectionTitle}>
              <Target size={12} style={{ marginRight: 4, verticalAlign: "middle" }} />
              Target Entity
            </div>
            <input
              style={inputStyle}
              placeholder="e.g. LockBit, critical infrastructure, APT29"
              value={target}
              onChange={e => setTarget(e.target.value)}
            />
          </div>
          <div style={{ flex: 1, minWidth: 120 }}>
            <div style={sectionTitle}>
              <Layers size={12} style={{ marginRight: 4, verticalAlign: "middle" }} />
              Historical Depth (days)
            </div>
            <select
              style={selectStyle}
              value={daysBack}
              onChange={e => setDaysBack(Number(e.target.value))}
            >
              {[1, 3, 7, 14, 30].map(d => (
                <option key={d} value={d}>{d} day{d > 1 ? "s" : ""}</option>
              ))}
            </select>
          </div>
          <div style={{ flex: 1, minWidth: 140 }}>
            <div style={sectionTitle}>
              <User size={12} style={{ marginRight: 4, verticalAlign: "middle" }} />
              Analyst
            </div>
            <input
              style={inputStyle}
              placeholder="Your name"
              defaultValue={(() => {
                const stored = sessionStorage.getItem("noc_user");
                if (!stored) return "";
                try { const p = JSON.parse(stored); return p.full_name || p.username || ""; }
                catch { return stored; }
              })()}
              id="analyst-name"
            />
          </div>
        </div>
        <div style={{ marginTop: "0.75rem" }}>
          <div style={sectionTitle}>
            <MessageSquare size={12} style={{ marginRight: 4, verticalAlign: "middle" }} />
            AI Objective
          </div>
          <textarea
            style={textareaStyle}
            placeholder="Generate an exhaustive technical report..."
            defaultValue="Generate an exhaustive technical report covering threat actors, TTPs, IOCs, and defensive recommendations."
            id="ai-objective"
          />
        </div>
        <div style={{ marginTop: "0.75rem" }}>
          <button
            onClick={() => {
              const analyst = (document.getElementById("analyst-name") as HTMLInputElement)?.value || "Unknown";
              const objective = (document.getElementById("ai-objective") as HTMLTextAreaElement)?.value || "Generate an exhaustive technical report.";
              if (!target.trim()) { alert("Please enter a target entity."); return; }
              genMutation.mutate({ target: target.trim(), days_back: daysBack, objective, analyst });
            }}
            disabled={genMutation.isPending || !target.trim()}
            style={btn("var(--accent-blue)")}
          >
            {genMutation.isPending ? <Spinner /> : <Search size={14} />}
            {genMutation.isPending ? "Compiling..." : "Compile Custom Report"}
          </button>
          {genMutation.isError && (
            <span style={{ marginLeft: "0.75rem", fontSize: "0.8rem", color: "var(--accent-red)" }}>
              {(genMutation.error as any)?.response?.data?.detail || "Failed"}
            </span>
          )}
        </div>
      </div>

      {generated && (
        <div style={cardStyle}>
          <h4 style={{ margin: "0 0 0.75rem", fontSize: "0.9rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
            <Eye size={15} />
            Generated Report
          </h4>
          <div style={{
            background: "var(--bg-secondary)",
            borderRadius: "var(--radius-sm)",
            padding: "1rem",
            fontSize: "0.82rem",
            lineHeight: 1.6,
            color: "var(--text-primary)",
            whiteSpace: "pre-wrap",
            fontFamily: "var(--font-mono)",
            maxHeight: 500,
            overflow: "auto",
            marginBottom: "0.75rem",
          }}>
            {generated}
          </div>
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <div style={sectionTitle}>Report Title</div>
              <input
                style={inputStyle}
                value={saveTitle}
                onChange={e => setSaveTitle(e.target.value)}
              />
            </div>
            <button
              onClick={() => {
                if (!saveTitle.trim()) { alert("Please enter a report title."); return; }
                const analyst = (document.getElementById("analyst-name") as HTMLInputElement)?.value || "Unknown";
                saveMutation.mutate({ title: saveTitle, author: analyst, content: generated });
              }}
              disabled={saveMutation.isPending}
              style={btn("var(--accent-green)")}
            >
              {saveMutation.isPending ? <Spinner /> : <Save size={14} />}
              {saveMutation.isPending ? "Saving..." : "Save to Library"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ==============================
   TAB 3: SHARED LIBRARY
   ============================== */
function SharedLibrary() {
  const queryClient = useQueryClient();
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const { data: reports, isLoading } = useQuery({
    queryKey: ["saved-reports"],
    queryFn: () => api.get("/reporting/saved-reports").then(r => r.data),
    refetchInterval: 30000,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/reporting/saved-reports/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["saved-reports"] });
      setExpandedId(null);
    },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const all: any[] = Array.isArray(reports) ? reports : [];

  return (
    <div style={cardStyle}>
      <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.4rem" }}>
        <BookOpen size={16} />
        Organization Shared Library
        {!isLoading && <span style={{ color: "var(--text-muted)", fontSize: "0.8rem", fontWeight: 400 }}>({all.length})</span>}
      </h3>
      {isLoading ? (
        <div style={{ textAlign: "center", padding: "2rem" }}>
          <Spinner />
          <span style={{ marginLeft: "0.5rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>Loading reports...</span>
        </div>
      ) : all.length === 0 ? (
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>No reports saved yet.</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem" }}>
          {all.map((r: any) => {
            const isExpanded = expandedId === r.id;
            return (
              <div
                key={r.id}
                style={{
                  borderBottom: "1px solid var(--border-primary)",
                  borderRadius: "var(--radius-sm)",
                  overflow: "hidden",
                }}
              >
                <button
                  onClick={() => setExpandedId(isExpanded ? null : r.id)}
                  style={{
                    width: "100%",
                    background: "none",
                    border: "none",
                    padding: "0.7rem 0.75rem",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.5rem",
                    color: "var(--text-primary)",
                    fontSize: "0.85rem",
                    textAlign: "left",
                  }}
                >
                  {isExpanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                  <FileText size={15} style={{ flexShrink: 0, color: "var(--accent-blue)" }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {r.title}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: "0.5rem", marginTop: "0.15rem" }}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "0.2rem" }}>
                        <User size={11} />
                        {r.author || "Unknown"}
                      </span>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "0.2rem" }}>
                        <Clock size={11} />
                        {r.created_at ? formatDate(r.created_at) : ""}
                      </span>
                    </div>
                  </div>
                </button>
                {isExpanded && (
                  <div style={{ padding: "0 0.75rem 0.75rem", borderTop: "1px solid var(--border-primary)" }}>
                    <div style={{
                      background: "var(--bg-secondary)",
                      borderRadius: "var(--radius-sm)",
                      padding: "0.75rem",
                      fontSize: "0.8rem",
                      lineHeight: 1.6,
                      color: "var(--text-primary)",
                      whiteSpace: "pre-wrap",
                      fontFamily: "var(--font-mono)",
                      maxHeight: 400,
                      overflow: "auto",
                      marginTop: "0.5rem",
                      marginBottom: "0.5rem",
                    }}>
                      {r.content as string}
                    </div>
                    <button
                      onClick={() => {
                        if (window.confirm(`Delete report "${r.title}"?`)) deleteMutation.mutate(r.id);
                      }}
                      disabled={deleteMutation.isPending}
                      style={{ ...btn("var(--accent-red)"), fontSize: "0.75rem", padding: "0.35rem 0.7rem" }}
                    >
                      {deleteMutation.isPending ? <Spinner /> : <Trash2 size={13} />}
                      Delete
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

const MessageSquare = ({ size, ...props }: { size?: number; [key: string]: any }) => (
  <svg xmlns="http://www.w3.org/2000/svg" width={size || 24} height={size || 24} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
  </svg>
);
