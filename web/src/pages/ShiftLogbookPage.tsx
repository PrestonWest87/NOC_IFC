import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import {
  BookOpen, Clock, User, Edit3, Trash2, RotateCcw, Plus,
  Search, X, Loader2, Zap, Activity, FileText,
  ChevronLeft, ChevronRight, RefreshCw,
} from "lucide-react";

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

const label: React.CSSProperties = {
  fontSize: "0.75rem",
  color: "var(--text-muted)",
  marginBottom: "0.25rem",
};

const modalOverlay: React.CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "rgba(0,0,0,0.6)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 1000,
};

const modalContent: React.CSSProperties = {
  background: "var(--bg-card)",
  borderRadius: "var(--radius-md)",
  padding: "1.5rem",
  width: "560px",
  maxWidth: "90vw",
  maxHeight: "80vh",
  overflow: "auto",
  border: "1px solid var(--border-primary)",
  boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
};

export function ShiftLogbookPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const [analyst, setAnalyst] = useState(user?.full_name ?? user?.username ?? "");
  const [shiftPeriod, setShiftPeriod] = useState("Morning");
  const [customDate, setCustomDate] = useState(new Date().toISOString().split("T")[0]);
  const [role, setRole] = useState(user?.role ?? "analyst");
  const [content, setContent] = useState("");

  const [selectedEntry, setSelectedEntry] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [roleFilter, setRoleFilter] = useState("All");
  const [logViewMode, setLogViewMode] = useState<"day" | "week">("day");
  const [weekOffset, setWeekOffset] = useState(0);
  const [selectedLogDate, setSelectedLogDate] = useState(new Date().toISOString().split("T")[0]);

  const isAdmin = user?.role === "admin";

  const { data: entries, isLoading } = useQuery({
    queryKey: ["logbook", roleFilter],
    queryFn: () =>
      api.get("/logbook/entries", { params: { role_filter: roleFilter } }).then((r) => r.data),
    refetchInterval: 30000,
  });

  const autoDraftMutation = useMutation({
    mutationFn: async () => {
      const dash = await api.get("/rca/dashboard").then((r) => r.data);
      const analysis = await api.post("/rca/analyze").then((r) => r.data);
      return { dash, analysis };
    },
    onSuccess: (data) => {
      const clustered = data.analysis?.clustered ?? {};
      const alerts = data.dash?.alerts ?? [];
      if (!alerts || alerts.length === 0) {
        setContent((prev) => prev + "No active AIOps infrastructure incidents.\n\n");
        return;
      }
      const lines: string[] = [];
      for (const [site, info] of Object.entries(clustered)) {
        const d = info as any;
        const p0 = d?.patient_zero;
        if (p0?.received_at) {
          const duration = Date.now() - new Date(p0.received_at).getTime();
          const hours = Math.floor(duration / 3600000);
          const mins = Math.floor((duration % 3600000) / 60000);
          const durStr = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
          lines.push(
            `AIOps Auto-Log: ${site} offline (Origin: ${p0.node_name ?? "Unknown"}). Down for ${durStr}.`
          );
        } else {
          lines.push(`AIOps Auto-Log: ${site} - Active incident detected.`);
        }
      }
      if (lines.length === 0) {
        lines.push("No active AIOps infrastructure incidents.");
      }
      setContent((prev) => prev + lines.join("\n") + "\n\n");
    },
  });

  const saveMutation = useMutation({
    mutationFn: (params: any) => api.post("/logbook/entries", null, { params }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["logbook"] });
      setContent("");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.patch(`/logbook/entries/${id}`, { is_deleted: true }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["logbook"] });
      setSelectedEntry(null);
    },
  });

  const restoreMutation = useMutation({
    mutationFn: (id: number) => api.patch(`/logbook/entries/${id}`, { is_deleted: false }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["logbook"] });
      setSelectedEntry(null);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;
    const params: any = {
      analyst: analyst || "analyst",
      role: role || "analyst",
      shift_period: shiftPeriod,
      content: content.trim(),
    };
    if (shiftPeriod === "No Shift" && customDate) {
      params.custom_date = customDate;
    }
    saveMutation.mutate(params);
  };

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const filteredEntries = useMemo(() => {
    if (!entries) return [];
    let list = [...entries];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (e: any) =>
          (e.analyst ?? "").toLowerCase().includes(q) ||
          (e.content ?? "").toLowerCase().includes(q) ||
          (e.shift_period ?? "").toLowerCase().includes(q) ||
          (e.author_role ?? "").toLowerCase().includes(q)
      );
    }
    if (dateFrom) {
      const f = new Date(dateFrom);
      list = list.filter((e: any) => e.created_at && new Date(e.created_at) >= f);
    }
    if (dateTo) {
      const t = new Date(dateTo);
      t.setHours(23, 59, 59, 999);
      list = list.filter((e: any) => e.created_at && new Date(e.created_at) <= t);
    }
    return list.reverse();
  }, [entries, searchQuery, dateFrom, dateTo]);

  const weekStart = useMemo(() => {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    const day = d.getDay();
    const diff = d.getDate() - day + (day === 0 ? -6 : 1);
    d.setDate(diff + weekOffset * 7);
    return d;
  }, [weekOffset]);

  const weekDays = useMemo(() => {
    const days: Date[] = [];
    for (let i = 0; i < 7; i++) {
      const d = new Date(weekStart);
      d.setDate(d.getDate() + i);
      days.push(d);
    }
    return days;
  }, [weekStart]);

  const dayLogs = useMemo(() => {
    if (!entries) return [];
    const sel = new Date(selectedLogDate);
    sel.setHours(0, 0, 0, 0);
    const next = new Date(sel);
    next.setDate(next.getDate() + 1);
    return entries.filter((e: any) => {
      if (!e.created_at) return false;
      const d = new Date(e.created_at);
      return d >= sel && d < next;
    });
  }, [entries, selectedLogDate]);

  const logsForDay = (date: Date) => {
    if (!entries) return [];
    const sel = new Date(date);
    sel.setHours(0, 0, 0, 0);
    const next = new Date(sel);
    next.setDate(next.getDate() + 1);
    return entries.filter((e: any) => {
      if (!e.created_at) return false;
      const d = new Date(e.created_at);
      return d >= sel && d < next && (!e.is_deleted || isAdmin);
    });
  };

  const selectedEntryLocal = selectedEntry
    ? {
        ...selectedEntry,
        created_at_local: selectedEntry.created_at
          ? new Date(selectedEntry.created_at).toLocaleString()
          : "-",
      }
    : null;

  return (
    <div style={{ padding: "1.5rem", height: "calc(100vh - 3rem)", overflow: "auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
        <BookOpen size={22} color="var(--text-primary)" />
        <h2 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.35rem" }}>
          NOC Running Shift Log & Calendar
        </h2>
      </div>
      <p style={{ ...label, marginBottom: "1.25rem" }}>
        Incident-based running log isolated by operational role. Logs are aggregated into an automated
        shift summary upon handoff.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: "1.5rem", alignItems: "start" }}>
        {/* LEFT COLUMN - Entry Form */}
        <div>
          <div style={card}>
            <h3
              style={{
                margin: "0 0 0.5rem",
                fontSize: "1rem",
                color: "var(--text-primary)",
                display: "flex",
                alignItems: "center",
                gap: "0.35rem",
              }}
            >
              <Edit3 size={16} /> Log Active Incident / Update
            </h3>

            {/* Auto-Draft Section */}
            <div
              style={{
                marginBottom: "1rem",
                padding: "0.75rem",
                background: "var(--bg-tertiary)",
                borderRadius: "var(--radius-sm)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.35rem",
                  marginBottom: "0.25rem",
                }}
              >
                <Activity size={14} color="var(--accent-cyan)" />
                <span style={{ fontWeight: 600, fontSize: "0.85rem", color: "var(--text-primary)" }}>
                  AIOps Telemetry Integration
                </span>
              </div>
              <p style={{ ...label, marginBottom: "0.5rem" }}>
                Pulls active outages and automatically calculates the duration of the event.
              </p>
              <button
                onClick={() => autoDraftMutation.mutate()}
                disabled={autoDraftMutation.isPending}
                style={{
                  ...btnBase,
                  background: autoDraftMutation.isPending ? "var(--bg-tertiary)" : "var(--accent-blue)",
                  color: autoDraftMutation.isPending ? "var(--text-muted)" : "#fff",
                  width: "100%",
                  justifyContent: "center",
                  cursor: autoDraftMutation.isPending ? "not-allowed" : "pointer",
                }}
              >
                {autoDraftMutation.isPending ? (
                  <Loader2 size={14} />
                ) : (
                  <Zap size={14} />
                )}
                {autoDraftMutation.isPending ? "Analyzing..." : "Auto-Draft Active Outages"}
              </button>
            </div>

            {/* Entry Form */}
            <form onSubmit={handleSubmit}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "0.75rem" }}>
                <div>
                  <div style={label}>Analyst Name</div>
                  <input
                    value={analyst}
                    onChange={(e) => setAnalyst(e.target.value)}
                    placeholder="Your name"
                    style={inputBase}
                  />
                </div>
                <div>
                  <div style={label}>Role</div>
                  <input
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    placeholder="analyst"
                    style={inputBase}
                  />
                </div>
              </div>
              <div style={{ marginBottom: "0.75rem" }}>
                <div style={label}>Shift Period</div>
                <select
                  value={shiftPeriod}
                  onChange={(e) => setShiftPeriod(e.target.value)}
                  style={inputBase}
                >
                  <option value="Morning">Morning</option>
                  <option value="Afternoon">Afternoon</option>
                  <option value="Night">Night</option>
                  <option value="No Shift">No Shift (Custom Date)</option>
                </select>
              </div>
              {shiftPeriod === "No Shift" && (
                <div style={{ marginBottom: "0.75rem" }}>
                  <div style={label}>Active Shift Date</div>
                  <input
                    type="date"
                    value={customDate}
                    onChange={(e) => setCustomDate(e.target.value)}
                    style={inputBase}
                  />
                </div>
              )}
              <div style={{ marginBottom: "0.75rem" }}>
                <div style={label}>Incident Update / Running Notes</div>
                <textarea
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="Logged circuit flap on MAIN-1, dispatched ticket #12345..."
                  rows={6}
                  style={{
                    ...inputBase,
                    resize: "vertical",
                    fontFamily: "inherit",
                    minHeight: "100px",
                  }}
                />
              </div>
              <button
                type="submit"
                disabled={!content.trim() || saveMutation.isPending}
                style={{
                  ...btnBase,
                  background:
                    !content.trim() || saveMutation.isPending
                      ? "var(--bg-tertiary)"
                      : "var(--accent-blue)",
                  color:
                    !content.trim() || saveMutation.isPending
                      ? "var(--text-muted)"
                      : "#fff",
                  width: "100%",
                  justifyContent: "center",
                  cursor:
                    !content.trim() || saveMutation.isPending ? "not-allowed" : "pointer",
                }}
              >
                {saveMutation.isPending ? (
                  <Loader2 size={14} />
                ) : (
                  <Plus size={14} />
                )}
                {saveMutation.isPending ? "Saving..." : "Append to Running Log"}
              </button>
            </form>
          </div>
        </div>

        {/* RIGHT COLUMN - Entries + Explorer */}
        <div>
          {/* Recent Entries */}
          <div style={card}>
            <h3
              style={{
                margin: "0 0 0.75rem",
                fontSize: "1rem",
                color: "var(--text-primary)",
                display: "flex",
                alignItems: "center",
                gap: "0.35rem",
              }}
            >
              <BookOpen size={16} /> Recent Entries
            </h3>

            <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
              <div style={{ flex: 1, position: "relative" }}>
                <Search
                  size={14}
                  style={{ position: "absolute", left: 8, top: 8, color: "var(--text-muted)" }}
                />
                <input
                  placeholder="Search entries..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ ...inputBase, paddingLeft: "1.6rem" }}
                />
              </div>
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                style={{ ...inputBase, width: "auto", minWidth: "100px" }}
              >
                <option value="All">All Roles</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
                <option value="soc">SOC</option>
                <option value="engineering">Engineering</option>
              </select>
            </div>

            <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
              <div style={{ flex: 1 }}>
                <div style={label}>From</div>
                <input
                  type="date"
                  value={dateFrom}
                  onChange={(e) => setDateFrom(e.target.value)}
                  style={inputBase}
                />
              </div>
              <div style={{ flex: 1 }}>
                <div style={label}>To</div>
                <input
                  type="date"
                  value={dateTo}
                  onChange={(e) => setDateTo(e.target.value)}
                  style={inputBase}
                />
              </div>
            </div>

            <div
              style={{
                maxHeight: "calc(100vh - 32rem)",
                overflow: "auto",
                minHeight: "120px",
              }}
            >
              {isLoading && (
                <div style={{ ...label, textAlign: "center", padding: "1.5rem" }}>
                  <Loader2 size={16} /> Loading entries...
                </div>
              )}
              {!isLoading && filteredEntries.length === 0 && (
                <div style={{ ...label, textAlign: "center", padding: "1.5rem" }}>
                  No entries found.
                </div>
              )}
              {filteredEntries.map((e: any) => (
                <div
                  key={e.id}
                  onClick={() => setSelectedEntry(e)}
                  style={{
                    padding: "0.6rem 0",
                    borderBottom: "1px solid var(--border-primary)",
                    cursor: "pointer",
                    opacity: e.is_deleted ? 0.5 : 1,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: "0.2rem",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.8rem",
                        fontWeight: 600,
                        color: "var(--text-primary)",
                        display: "flex",
                        alignItems: "center",
                        gap: "0.25rem",
                      }}
                    >
                      <User size={12} /> {e.analyst}
                    </span>
                    <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                      <Clock
                        size={11}
                        style={{ marginRight: "0.2rem", verticalAlign: "middle" }}
                      />
                      {e.created_at
                        ? new Date(e.created_at).toLocaleString()
                        : ""}
                    </span>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      gap: "0.4rem",
                      alignItems: "center",
                      marginBottom: "0.2rem",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.7rem",
                        color: "var(--accent-cyan)",
                        background: "var(--bg-tertiary)",
                        padding: "0.1rem 0.4rem",
                        borderRadius: "var(--radius-sm)",
                      }}
                    >
                      {e.shift_period}
                    </span>
                    {e.author_role && (
                      <span
                        style={{
                          fontSize: "0.65rem",
                          color: "var(--text-muted)",
                          textTransform: "uppercase",
                        }}
                      >
                        {e.author_role}
                      </span>
                    )}
                    {e.is_deleted && (
                      <span style={{ fontSize: "0.7rem", color: "#ef4444", fontWeight: 600 }}>
                        DELETED
                      </span>
                    )}
                  </div>
                  <div
                    style={{
                      fontSize: "0.82rem",
                      color: "var(--text-secondary)",
                      lineHeight: 1.4,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                    }}
                  >
                    {e.content}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Shift Log Explorer */}
          <div style={{ ...card, marginTop: "0.75rem" }}>
            <h3
              style={{
                margin: "0 0 0.5rem",
                fontSize: "1rem",
                color: "var(--text-primary)",
                display: "flex",
                alignItems: "center",
                gap: "0.35rem",
              }}
            >
              <FileText size={16} /> Shift Log Explorer
            </h3>

            <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.75rem" }}>
              <button
                onClick={() => setLogViewMode("day")}
                style={{
                  ...btnBase,
                  background: logViewMode === "day" ? "var(--accent-blue)" : "var(--bg-tertiary)",
                  color: logViewMode === "day" ? "#fff" : "var(--text-muted)",
                  flex: 1,
                  justifyContent: "center",
                }}
              >
                Day View
              </button>
              <button
                onClick={() => setLogViewMode("week")}
                style={{
                  ...btnBase,
                  background: logViewMode === "week" ? "var(--accent-blue)" : "var(--bg-tertiary)",
                  color: logViewMode === "week" ? "#fff" : "var(--text-muted)",
                  flex: 1,
                  justifyContent: "center",
                }}
              >
                Week View
              </button>
            </div>

            {logViewMode === "day" && (
              <div>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.5rem" }}>
                  <button
                    onClick={() => {
                      const d = new Date(selectedLogDate);
                      d.setDate(d.getDate() - 1);
                      setSelectedLogDate(d.toISOString().split("T")[0]);
                    }}
                    style={{ ...btnBase, background: "var(--bg-tertiary)", color: "var(--text-primary)" }}
                  >
                    <ChevronLeft size={14} /> Previous Day
                  </button>
                  <input
                    type="date"
                    value={selectedLogDate}
                    onChange={(e) => setSelectedLogDate(e.target.value)}
                    style={{ ...inputBase, textAlign: "center" }}
                  />
                  <button
                    onClick={() => {
                      const d = new Date(selectedLogDate);
                      d.setDate(d.getDate() + 1);
                      const tomorrow = new Date();
                      tomorrow.setDate(tomorrow.getDate() + 1);
                      if (d <= tomorrow) {
                        setSelectedLogDate(d.toISOString().split("T")[0]);
                      }
                    }}
                    style={{ ...btnBase, background: "var(--bg-tertiary)", color: "var(--text-primary)" }}
                  >
                    Next Day <ChevronRight size={14} />
                  </button>
                </div>

                <div
                  style={{
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    color: "var(--text-primary)",
                    textAlign: "center",
                    marginBottom: "0.5rem",
                  }}
                >
                  Logs for{" "}
                  {new Date(selectedLogDate + "T12:00:00").toLocaleDateString(undefined, {
                    weekday: "long",
                    year: "numeric",
                    month: "long",
                    day: "numeric",
                  })}
                </div>

                <div style={{ maxHeight: "200px", overflow: "auto" }}>
                  {dayLogs.length === 0 && (
                    <div style={{ ...label, textAlign: "center", padding: "0.5rem" }}>
                      No active shift logs recorded for this date.
                    </div>
                  )}
                  {dayLogs.map((l: any) => {
                    const isDel = l.is_deleted;
                    const localTime = l.created_at
                      ? new Date(l.created_at).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                        })
                      : "";
                    const shiftAbbr = l.shift_period?.includes("Morning")
                      ? "Morning"
                      : l.shift_period?.includes("Afternoon") || l.shift_period?.includes("Evening")
                      ? "Evening"
                      : l.shift_period;
                    return (
                      <div
                        key={l.id}
                        onClick={() => setSelectedEntry(l)}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "80px 70px 100px 1fr",
                          gap: "0.5rem",
                          padding: "0.3rem 0",
                          borderBottom: "1px solid var(--border-primary)",
                          fontSize: "0.78rem",
                          cursor: "pointer",
                          opacity: isDel ? 0.5 : 1,
                          alignItems: "center",
                        }}
                      >
                        <span style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>
                          {localTime}
                        </span>
                        <span
                          style={{
                            color: "var(--accent-cyan)",
                            fontSize: "0.72rem",
                            fontWeight: 600,
                          }}
                        >
                          {shiftAbbr}
                        </span>
                        <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>
                          {l.analyst}
                        </span>
                        <span
                          style={{
                            color: isDel ? "#ef4444" : "var(--text-secondary)",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            textDecoration: isDel ? "line-through" : "none",
                          }}
                        >
                          {l.content?.slice(0, 120)}
                          {(l.content?.length ?? 0) > 120 ? "..." : ""}
                          {isDel && " (DELETED)"}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {logViewMode === "week" && (
              <div>
                <div
                  style={{
                    display: "flex",
                    gap: "0.5rem",
                    alignItems: "center",
                    justifyContent: "center",
                    marginBottom: "0.75rem",
                  }}
                >
                  <button
                    onClick={() => setWeekOffset((w) => w - 1)}
                    style={{ ...btnBase, background: "var(--bg-tertiary)", color: "var(--text-primary)" }}
                  >
                    <ChevronLeft size={14} /> Previous Week
                  </button>
                  <span
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      color: "var(--text-primary)",
                    }}
                  >
                    Week of {weekStart.toLocaleDateString(undefined, {
                      month: "long",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </span>
                  <button
                    onClick={() => setWeekOffset((w) => (w < 0 ? w + 1 : w))}
                    disabled={weekOffset >= 0}
                    style={{
                      ...btnBase,
                      background: weekOffset >= 0 ? "var(--bg-tertiary)" : "var(--bg-tertiary)",
                      color: weekOffset >= 0 ? "var(--text-muted)" : "var(--text-primary)",
                      cursor: weekOffset >= 0 ? "not-allowed" : "pointer",
                    }}
                  >
                    Next Week <ChevronRight size={14} />
                  </button>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: "0.25rem" }}>
                  {weekDays.map((d, i) => {
                    const dateStr = d.toISOString().split("T")[0];
                    const logs = logsForDay(d);
                    return (
                      <div
                        key={i}
                        style={{
                          background: "var(--bg-tertiary)",
                          borderRadius: "var(--radius-sm)",
                          padding: "0.3rem",
                          textAlign: "center",
                          cursor: "pointer",
                          border:
                            dateStr === new Date().toISOString().split("T")[0]
                              ? "1px solid var(--accent-blue)"
                              : "1px solid transparent",
                        }}
                        onClick={() => {
                          setSelectedLogDate(dateStr);
                          setLogViewMode("day");
                        }}
                      >
                        <div style={{ fontSize: "0.65rem", color: "var(--text-muted)", fontWeight: 600 }}>
                          {d.toLocaleDateString(undefined, { weekday: "short" })}
                        </div>
                        <div
                          style={{
                            fontSize: "0.7rem",
                            color: "var(--text-primary)",
                            fontWeight: 500,
                            marginBottom: "0.2rem",
                          }}
                        >
                          {d.getDate()}
                        </div>
                        {logs.length === 0 && (
                          <div style={{ fontSize: "0.6rem", color: "var(--text-muted)" }}>--</div>
                        )}
                        {logs.slice(0, 3).map((l: any) => (
                          <div
                            key={l.id}
                            style={{
                              fontSize: "0.6rem",
                              color: "var(--accent-cyan)",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              opacity: l.is_deleted ? 0.4 : 1,
                            }}
                          >
                            {l.shift_period?.includes("Morning") ? "Morn" : "Eve"} |{" "}
                            {l.created_at
                              ? new Date(l.created_at).toLocaleTimeString([], {
                                  hour: "2-digit",
                                  minute: "2-digit",
                                })
                              : ""}
                          </div>
                        ))}
                        {logs.length > 3 && (
                          <div style={{ fontSize: "0.6rem", color: "var(--text-muted)" }}>
                            +{logs.length - 3} more
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Admin Export Utility */}
          {isAdmin && (
            <div style={{ ...card, marginTop: "0.75rem" }}>
              <h3
                style={{
                  margin: "0 0 0.5rem",
                  fontSize: "1rem",
                  color: "var(--text-primary)",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.35rem",
                }}
              >
                <RefreshCw size={16} /> Admin Log Export Utility
              </h3>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end" }}>
                <div style={{ flex: 1 }}>
                  <div style={label}>Role Filter</div>
                  <select
                    value={roleFilter}
                    onChange={(e) => setRoleFilter(e.target.value)}
                    style={inputBase}
                  >
                    <option value="All">All</option>
                    <option value="analyst">Analyst</option>
                    <option value="admin">Admin</option>
                    <option value="soc">SOC</option>
                    <option value="engineering">Engineering</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={label}>Start Date</div>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    style={inputBase}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={label}>End Date</div>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    style={inputBase}
                  />
                </div>
                <button
                  onClick={() => {
                    const filtered = filteredEntries.filter((e: any) => !e.is_deleted);
                    if (filtered.length === 0) return;
                    const headers = "Local_Time,Analyst,Role,Shift_Period,Content\n";
                    const csv =
                      headers +
                      filtered
                        .map(
                          (e: any) =>
                            `"${e.created_at ? new Date(e.created_at).toLocaleString() : ""}","${(e.analyst ?? "").replace(/"/g, '""')}","${(e.author_role ?? "").toUpperCase()}","${(e.shift_period ?? "").replace(/"/g, '""')}","${(e.content ?? "").replace(/"/g, '""')}"`
                        )
                        .join("\n");
                    const blob = new Blob([csv], { type: "text/csv" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    const dateLabel = new Date().toISOString().split("T")[0];
                    a.download = `NOC_ShiftLogs_${roleFilter.toUpperCase()}_${dateLabel}.csv`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  style={{
                    ...btnBase,
                    background: "var(--accent-blue)",
                    color: "#fff",
                    whiteSpace: "nowrap",
                  }}
                >
                  Download CSV
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Detail Modal */}
      {selectedEntryLocal && (
        <div style={modalOverlay} onClick={() => setSelectedEntry(null)}>
          <div style={modalContent} onClick={(e) => e.stopPropagation()}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "1rem",
              }}
            >
              <h3 style={{ margin: 0, color: "var(--text-primary)", fontSize: "1.05rem" }}>
                Shift Log Details
              </h3>
              <button
                onClick={() => setSelectedEntry(null)}
                style={{
                  ...btnBase,
                  background: "transparent",
                  color: "var(--text-muted)",
                  padding: "0.25rem",
                }}
              >
                <X size={18} />
              </button>
            </div>

            {selectedEntry.is_deleted && (
              <div
                style={{
                  background: "rgba(220,38,38,0.15)",
                  color: "#ef4444",
                  padding: "0.5rem 0.75rem",
                  borderRadius: "var(--radius-sm)",
                  marginBottom: "0.75rem",
                  fontSize: "0.85rem",
                  fontWeight: 600,
                }}
              >
                THIS LOG HAS BEEN SOFT-DELETED AND OMITTED FROM SUMMARIES.
              </div>
            )}

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "0.75rem",
                marginBottom: "1rem",
              }}
            >
              <div>
                <div style={label}>Analyst</div>
                <div
                  style={{
                    fontSize: "0.9rem",
                    color: "var(--text-primary)",
                    fontWeight: 500,
                  }}
                >
                  {selectedEntry.analyst}
                </div>
              </div>
              <div>
                <div style={label}>Role</div>
                <div
                  style={{
                    fontSize: "0.9rem",
                    color: "var(--text-primary)",
                    fontWeight: 500,
                    textTransform: "uppercase",
                  }}
                >
                  {selectedEntry.author_role}
                </div>
              </div>
              <div>
                <div style={label}>Date / Time</div>
                <div style={{ fontSize: "0.9rem", color: "var(--text-primary)", fontWeight: 500 }}>
                  {selectedEntry.created_at_local}
                </div>
              </div>
              <div>
                <div style={label}>Shift Period</div>
                <div style={{ fontSize: "0.9rem", color: "var(--text-primary)", fontWeight: 500 }}>
                  {selectedEntry.shift_period}
                </div>
              </div>
            </div>

            <div style={{ marginBottom: "1rem" }}>
              <div style={label}>Content</div>
              <div
                style={{
                  fontSize: "0.88rem",
                  color: "var(--text-primary)",
                  whiteSpace: "pre-wrap",
                  lineHeight: 1.6,
                  marginTop: "0.25rem",
                  background: "var(--bg-tertiary)",
                  padding: "0.75rem",
                  borderRadius: "var(--radius-sm)",
                  maxHeight: "300px",
                  overflow: "auto",
                }}
              >
                {selectedEntry.content}
              </div>
            </div>

            <div style={{ display: "flex", gap: "0.75rem" }}>
              {!selectedEntry.is_deleted ? (
                <button
                  onClick={() => deleteMutation.mutate(selectedEntry.id)}
                  disabled={deleteMutation.isPending}
                  style={{
                    ...btnBase,
                    background: deleteMutation.isPending ? "var(--bg-tertiary)" : "#dc3545",
                    color: deleteMutation.isPending ? "var(--text-muted)" : "#fff",
                    flex: 1,
                    justifyContent: "center",
                    cursor: deleteMutation.isPending ? "not-allowed" : "pointer",
                  }}
                >
                  {deleteMutation.isPending ? (
                    <Loader2 size={14} />
                  ) : (
                    <Trash2 size={14} />
                  )}
                  {deleteMutation.isPending ? "Deleting..." : "Soft Delete Log"}
                </button>
              ) : isAdmin ? (
                <button
                  onClick={() => restoreMutation.mutate(selectedEntry.id)}
                  disabled={restoreMutation.isPending}
                  style={{
                    ...btnBase,
                    background: restoreMutation.isPending ? "var(--bg-tertiary)" : "var(--accent-green)",
                    color: restoreMutation.isPending ? "var(--text-muted)" : "#fff",
                    flex: 1,
                    justifyContent: "center",
                    cursor: restoreMutation.isPending ? "not-allowed" : "pointer",
                  }}
                >
                  {restoreMutation.isPending ? (
                    <Loader2 size={14} />
                  ) : (
                    <RotateCcw size={14} />
                  )}
                  {restoreMutation.isPending ? "Restoring..." : "Restore Log"}
                </button>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
