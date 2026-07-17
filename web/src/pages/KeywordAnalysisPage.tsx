import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell, LineChart, Line, Legend, Tooltip as RechartsTooltip,
} from "recharts";
import {
  Search, BarChart3, PieChart as PieIcon, TrendingUp,
  RefreshCw, Loader2, Database, Zap,
  ArrowUpDown, Target, AlertTriangle,
} from "lucide-react";
import api from "../utils/api";

const COLORS = [
  "#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6",
  "#ec4899", "#06b6d4", "#84cc16", "#f97316", "#6366f1",
  "#14b8a6", "#e11d48", "#a855f7", "#0ea5e9", "#22c55e",
];

const CAT_COLORS: Record<string, string> = {
  "Cyber: Exploits & Vulns": "#ef4444",
  "Cyber: Malware & Threats": "#dc2626",
  "Cyber: Malware": "#dc2626",
  "ICS/OT & SCADA": "#f59e0b",
  "Cloud & IT Infrastructure": "#3b82f6",
  "Physical Security & Crime": "#8b5cf6",
  "Physical Security": "#8b5cf6",
  "Severe Weather & Natural Hazards": "#06b6d4",
  "Severe Weather": "#06b6d4",
  "Geopolitics & Policy": "#10b981",
  "AI & Emerging Tech": "#ec4899",
  "Data Breach & Privacy": "#f97316",
  "General": "#6b7280",
};

function StatCard({ label, value, icon, color }: { label: string; value: string | number; icon: React.ReactNode; color?: string }) {
  return (
    <div style={{
      background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)",
      padding: "1rem 1.25rem", border: "1px solid var(--border-primary, #e2e8f0)",
      display: "flex", alignItems: "center", gap: "0.75rem",
    }}>
      <div style={{ color: color || "var(--accent-blue, #3b82f6)", flexShrink: 0 }}>{icon}</div>
      <div>
        <div style={{ fontSize: "0.72rem", color: "var(--text-muted, #94a3b8)", textTransform: "uppercase", letterSpacing: "0.5px" }}>{label}</div>
        <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--text-primary, #1e293b)" }}>{value}</div>
      </div>
    </div>
  );
}

export function KeywordAnalysisPage() {
  const queryClient = useQueryClient();
  const [subTab, setSubTab] = useState<"overview" | "keywords" | "categories" | "timeline" | "matrix">("overview");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("trigger_count");
  const [sortOrder, setSortOrder] = useState("desc");
  const [days, setDays] = useState(30);
  const [selectedKeyword, setSelectedKeyword] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("");
  const [expandedKeyword, setExpandedKeyword] = useState<number | null>(null);

  const TABS = [
    { id: "overview" as const, label: "Overview", icon: <BarChart3 size={14} /> },
    { id: "keywords" as const, label: "Keyword Analysis", icon: <Search size={14} /> },
    { id: "categories" as const, label: "Category Breakdown", icon: <PieIcon size={14} /> },
    { id: "timeline" as const, label: "Timeline", icon: <TrendingUp size={14} /> },
    { id: "matrix" as const, label: "Cross-Reference", icon: <Database size={14} /> },
  ];

  const overview = useQuery({
    queryKey: ["kw-overview"], queryFn: () => api.get("/keyword-analysis/overview").then(r => r.data), refetchInterval: 30000,
  });

  const keywordStats = useQuery({
    queryKey: ["kw-stats", sortBy, sortOrder, search], queryFn: () =>
      api.get("/keyword-analysis/keyword-stats", { params: { sort_by: sortBy, order: sortOrder, search, limit: 100 } }).then(r => r.data),
  });

  const categoryDist = useQuery({
    queryKey: ["kw-cat-dist", days], queryFn: () =>
      api.get("/keyword-analysis/category-distribution", { params: { days } }).then(r => r.data),
  });

  const timeline = useQuery({
    queryKey: ["kw-timeline", days, selectedKeyword], queryFn: () =>
      api.get("/keyword-analysis/timeline", { params: { days, keyword: selectedKeyword, interval: "day" } }).then(r => r.data),
  });

  const matrix = useQuery({
    queryKey: ["kw-matrix"], queryFn: () =>
      api.get("/keyword-analysis/category-keyword-matrix", { params: { top_n: 20 } }).then(r => r.data),
  });

  const categoryDetails = useQuery({
    queryKey: ["kw-cat-detail", selectedCategory, days], queryFn: () =>
      api.get("/keyword-analysis/category-details", { params: { category: selectedCategory, days } }).then(r => r.data),
    enabled: !!selectedCategory,
  });

  const keywordArticles = useQuery({
    queryKey: ["kw-articles", selectedKeyword], queryFn: () =>
      api.get("/keyword-analysis/keyword-articles", { params: { keyword: selectedKeyword, limit: 30 } }).then(r => r.data),
    enabled: !!selectedKeyword,
  });

  const scoreDist = useQuery({
    queryKey: ["kw-score-dist", days], queryFn: () =>
      api.get("/keyword-analysis/score-distribution", { params: { days, bucket_size: 10 } }).then(r => r.data),
  });

  const recatMut = useMutation({
    mutationFn: () => api.post("/keyword-analysis/recategorize"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["kw-cat-dist"] });
      queryClient.invalidateQueries({ queryKey: ["kw-cat-detail"] });
    },
  });

  const MetricBar = ({ value, max, color }: { value: number; max: number; color: string }) => (
    <div style={{ width: "100%", height: 6, background: "var(--bg-tertiary, #e2e8f0)", borderRadius: 3, overflow: "hidden" }}>
      <div style={{ width: `${Math.min(100, max > 0 ? (value / max) * 100 : 0)}%`, height: "100%", background: color, borderRadius: 3, transition: "width 0.3s" }} />
    </div>
  );

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload?.length) return null;
    return (
      <div style={{ background: "var(--bg-card, #1e293b)", border: "1px solid var(--border-primary, #334155)", borderRadius: 8, padding: "0.6rem 0.8rem", fontSize: "0.78rem" }}>
        <div style={{ fontWeight: 600, marginBottom: 4, color: "var(--text-primary, #e2e8f0)" }}>{label}</div>
        {payload.map((p: any, i: number) => (
          <div key={i} style={{ color: p.color, display: "flex", justifyContent: "space-between", gap: "1rem" }}>
            <span>{p.name}:</span><span style={{ fontWeight: 600 }}>{p.value}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div style={{ padding: "1.5rem", color: "var(--text-primary, #1e293b)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <h2 style={{ margin: 0, fontSize: "1.5rem" }}>Keyword & Category Analysis</h2>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <select value={days} onChange={e => setDays(Number(e.target.value))}
            style={{ padding: "0.4rem 0.6rem", borderRadius: "var(--radius-sm, 4px)", border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-input, #fff)", color: "var(--text-primary, #1e293b)", fontSize: "0.82rem" }}>
            <option value={7}>7 Days</option>
            <option value={14}>14 Days</option>
            <option value={30}>30 Days</option>
            <option value={60}>60 Days</option>
            <option value={90}>90 Days</option>
            <option value={0}>All Time</option>
          </select>
        </div>
      </div>

      <div style={{ display: "flex", gap: "0.4rem", marginBottom: "1.5rem", flexWrap: "wrap" }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setSubTab(t.id)}
            style={{
              padding: "0.45rem 0.9rem", borderRadius: "var(--radius-sm, 4px)", border: "none", cursor: "pointer",
              background: subTab === t.id ? "var(--accent-blue, #3b82f6)" : "var(--bg-card, #fff)",
              color: subTab === t.id ? "#fff" : "var(--text-secondary, #64748b)",
              fontWeight: subTab === t.id ? 600 : 400, fontSize: "0.8rem",
              display: "flex", alignItems: "center", gap: "0.3rem",
              boxShadow: subTab === t.id ? "0 1px 3px rgba(0,0,0,0.15)" : "none",
            }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* OVERVIEW TAB */}
      {subTab === "overview" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
            <StatCard label="Total Keywords" value={overview.data?.total_keywords ?? "—"} icon={<Search size={22} />} />
            <StatCard label="Active Keywords" value={overview.data?.keywords_used ?? "—"} icon={<Zap size={22} color="#10b981" />} />
            <StatCard label="Unused Keywords" value={overview.data?.keywords_unused ?? "—"} icon={<AlertTriangle size={22} color="#f59e0b" />} />
            <StatCard label="Avg Weight" value={overview.data?.avg_weight ?? "—"} icon={<ArrowUpDown size={22} />} />
            <StatCard label="Total Articles" value={overview.data?.total_articles ?? "—"} icon={<Database size={22} />} />
            <StatCard label="Articles w/ Keywords" value={overview.data?.articles_with_keywords ?? "—"} icon={<Target size={22} color="#10b981" />} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
            <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Score Distribution</h3>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={scoreDist.data || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                  <XAxis dataKey="bucket" tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Bar dataKey="count" name="Articles" radius={[4, 4, 0, 0]}>
                    {(scoreDist.data || []).map((_: any, i: number) => (
                      <Cell key={i} fill={i < 3 ? "#10b981" : i < 5 ? "#f59e0b" : "#ef4444"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Category Distribution</h3>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie data={categoryDist.data || []} dataKey="count" nameKey="category" cx="50%" cy="50%"
                    outerRadius={90} label={({ category, percent }: any) => `${(category || "").split(":")[0] || category} ${((percent || 0) * 100).toFixed(0)}%`}
                    labelLine={false} style={{ fontSize: 11 }}>
                    {(categoryDist.data || []).map((entry: any, i: number) => (
                      <Cell key={i} fill={CAT_COLORS[entry.category] || COLORS[i % COLORS.length]} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)", marginTop: "1.5rem" }}>
            <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Top 10 Keywords by Trigger Count</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={(keywordStats.data || []).slice(0, 10)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                <XAxis type="number" tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                <YAxis type="category" dataKey="word" width={120} tick={{ fontSize: 11, fill: "var(--text-primary, #1e293b)" }} />
                <RechartsTooltip content={<CustomTooltip />} />
                <Bar dataKey="trigger_count" name="Triggers" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* KEYWORDS TAB */}
      {subTab === "keywords" && (
        <div>
          <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem", flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 200, position: "relative" }}>
              <Search size={14} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
              <input type="text" placeholder="Search keywords..." value={search} onChange={e => setSearch(e.target.value)}
                style={{ width: "100%", padding: "0.5rem 0.75rem 0.5rem 2rem", borderRadius: "var(--radius-sm, 4px)", border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-input, #fff)", color: "var(--text-primary, #1e293b)", fontSize: "0.85rem", boxSizing: "border-box" }} />
            </div>
            <select value={sortBy} onChange={e => setSortBy(e.target.value)}
              style={{ padding: "0.5rem 0.75rem", borderRadius: "var(--radius-sm, 4px)", border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-input, #fff)", color: "var(--text-primary, #1e293b)", fontSize: "0.85rem" }}>
              <option value="trigger_count">Sort by Triggers</option>
              <option value="weight">Sort by Weight</option>
              <option value="avg_score_contribution">Sort by Score Contribution</option>
            </select>
            <button onClick={() => setSortOrder(o => o === "desc" ? "asc" : "desc")}
              style={{ padding: "0.5rem 0.75rem", borderRadius: "var(--radius-sm, 4px)", border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-card, #fff)", color: "var(--text-primary, #1e293b)", cursor: "pointer", fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "0.3rem" }}>
              <ArrowUpDown size={14} /> {sortOrder === "desc" ? "Desc" : "Asc"}
            </button>
          </div>

          <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", border: "1px solid var(--border-primary, #e2e8f0)", overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "40px 1.5fr 80px 100px 100px 120px", padding: "0.6rem 1rem", background: "var(--bg-tertiary, #f1f5f9)", fontSize: "0.72rem", fontWeight: 600, color: "var(--text-muted, #64748b)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              <span>#</span><span>Keyword</span><span>Weight</span><span>Triggers</span><span>Avg Score</span><span>Weight Distribution</span>
            </div>
            {(keywordStats.data || []).map((kw: any, i: number) => (
              <div key={kw.id}
                style={{
                  display: "grid", gridTemplateColumns: "40px 1.5fr 80px 100px 100px 120px", padding: "0.6rem 1rem",
                  borderTop: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem", alignItems: "center", cursor: "pointer",
                  background: selectedKeyword === kw.word ? "var(--bg-tertiary, #f1f5f9)" : "transparent",
                }}
                onClick={() => { setSelectedKeyword(selectedKeyword === kw.word ? "" : kw.word); setExpandedKeyword(expandedKeyword === kw.id ? null : kw.id); }}>
                <span style={{ color: "var(--text-muted, #94a3b8)" }}>{i + 1}</span>
                <span style={{ fontWeight: 600, color: "var(--accent-cyan, #06b6d4)" }}>{kw.word}</span>
                <span>
                  <span style={{ background: kw.weight >= 70 ? "#ef4444" : kw.weight >= 40 ? "#f59e0b" : "#10b981", color: "#fff", padding: "2px 8px", borderRadius: 12, fontSize: "0.72rem", fontWeight: 600 }}>
                    {kw.weight}
                  </span>
                </span>
                <span style={{ fontWeight: 600 }}>{kw.trigger_count}</span>
                <span style={{ color: "var(--text-muted, #94a3b8)" }}>{kw.avg_score_contribution}</span>
                <span><MetricBar value={kw.weight} max={100} color={kw.weight >= 70 ? "#ef4444" : kw.weight >= 40 ? "#f59e0b" : "#10b981"} /></span>
              </div>
            ))}
            {expandedKeyword && keywordArticles.data && keywordArticles.data.length > 0 && (
              <div style={{ padding: "1rem", background: "var(--bg-tertiary, #f8fafc)", borderTop: "2px solid var(--accent-blue, #3b82f6)" }}>
                <h4 style={{ margin: "0 0 0.75rem", fontSize: "0.9rem" }}>Articles matching "{selectedKeyword}"</h4>
                {keywordArticles.data.map((art: any) => (
                  <div key={art.id} style={{ padding: "0.5rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.8rem" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontWeight: 500 }}>{art.title}</span>
                      <span style={{ background: (art.score || 0) >= 50 ? "#ef4444" : (art.score || 0) >= 30 ? "#f59e0b" : "#10b981", color: "#fff", padding: "2px 6px", borderRadius: 8, fontSize: "0.7rem" }}>
                        Score: {Math.round(art.score || 0)}
                      </span>
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted, #94a3b8)", marginTop: 2 }}>
                      {art.source} &middot; {art.category} &middot; {art.published_date ? new Date(art.published_date).toLocaleDateString() : "Unknown"}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* CATEGORIES TAB */}
      {subTab === "categories" && (
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              {categoryDist.data?.map((cat: any) => (
                <button key={cat.category} onClick={() => setSelectedCategory(selectedCategory === cat.category ? "" : cat.category)}
                  style={{
                    padding: "0.35rem 0.7rem", borderRadius: "var(--radius-sm, 4px)", border: `1px solid ${CAT_COLORS[cat.category] || "#6b7280"}`,
                    background: selectedCategory === cat.category ? (CAT_COLORS[cat.category] || "#6b7280") : "transparent",
                    color: selectedCategory === cat.category ? "#fff" : (CAT_COLORS[cat.category] || "#6b7280"),
                    cursor: "pointer", fontSize: "0.75rem", fontWeight: 500,
                  }}>
                  {cat.category} ({cat.count})
                </button>
              ))}
            </div>
            <button onClick={() => recatMut.mutate()} disabled={recatMut.isPending}
              style={{ padding: "0.4rem 0.75rem", border: "1px solid var(--accent-blue, #3b82f6)", borderRadius: "var(--radius-sm, 4px)", background: "transparent", color: "var(--accent-blue, #3b82f6)", cursor: "pointer", fontSize: "0.8rem", fontWeight: 500, display: "flex", alignItems: "center", gap: "0.3rem" }}>
              {recatMut.isPending ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />} Recategorize All
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
            <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Category Article Count</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={categoryDist.data || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                  <XAxis dataKey="category" tick={{ fontSize: 9, fill: "var(--text-muted, #94a3b8)" }} angle={-35} textAnchor="end" height={80} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Bar dataKey="count" name="Articles" radius={[4, 4, 0, 0]}>
                    {(categoryDist.data || []).map((entry: any, idx: number) => (
                      <Cell key={idx} fill={CAT_COLORS[entry.category] || COLORS[idx % COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Average Score by Category</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={categoryDist.data || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                  <XAxis dataKey="category" tick={{ fontSize: 9, fill: "var(--text-muted, #94a3b8)" }} angle={-35} textAnchor="end" height={80} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Bar dataKey="avg_score" name="Avg Score" radius={[4, 4, 0, 0]}>
                    {(categoryDist.data || []).map((entry: any, idx: number) => (
                      <Cell key={idx} fill={CAT_COLORS[entry.category] || COLORS[idx % COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {categoryDetails.data && (
            <div style={{ marginTop: "1.5rem", background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem" }}>Deep Dive: {categoryDetails.data.category}</h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
                <div>
                  <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.9rem" }}>Top Keywords in this Category</h4>
                  {categoryDetails.data.top_keywords?.map((kw: any) => (
                    <div key={kw.word} style={{ display: "flex", justifyContent: "space-between", padding: "0.3rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem" }}>
                      <span style={{ fontWeight: 500 }}>{kw.word}</span>
                      <span style={{ color: "var(--text-muted, #94a3b8)" }}>{kw.count} articles</span>
                    </div>
                  ))}
                </div>
                <div>
                  <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.9rem" }}>Top Sources</h4>
                  {categoryDetails.data.top_sources?.map((s: any) => (
                    <div key={s.source} style={{ display: "flex", justifyContent: "space-between", padding: "0.3rem 0", borderBottom: "1px solid var(--border-primary, #e2e8f0)", fontSize: "0.82rem" }}>
                      <span style={{ fontWeight: 500 }}>{s.source}</span>
                      <span style={{ color: "var(--text-muted, #94a3b8)" }}>{s.count} articles</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TIMELINE TAB */}
      {subTab === "timeline" && (
        <div>
          <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem", flexWrap: "wrap", alignItems: "center" }}>
            <div style={{ fontSize: "0.85rem", color: "var(--text-muted, #94a3b8)" }}>Filter by keyword:</div>
            <input type="text" placeholder="Optional: filter by keyword" value={selectedKeyword} onChange={e => setSelectedKeyword(e.target.value)}
              style={{ padding: "0.5rem 0.75rem", borderRadius: "var(--radius-sm, 4px)", border: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-input, #fff)", color: "var(--text-primary, #1e293b)", fontSize: "0.85rem", width: 250 }} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "1.5rem" }}>
            <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>
                Article Volume & Keyword Match Rate ({days === 0 ? "All Time" : `${days} Days`})
              </h3>
              <ResponsiveContainer width="100%" height={350}>
                <LineChart data={timeline.data || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                  <XAxis dataKey="date" tick={{ fontSize: 10, fill: "var(--text-muted, #94a3b8)" }} angle={-45} textAnchor="end" height={60} />
                  <YAxis yAxisId="left" tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                  <YAxis yAxisId="right" orientation="right" tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} unit="%" />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Legend />
                  <Line yAxisId="left" type="monotone" dataKey="total_articles" name="Total Articles" stroke="#3b82f6" strokeWidth={2} dot={false} />
                  <Line yAxisId="left" type="monotone" dataKey="matched_articles" name="Keyword Matched" stroke="#10b981" strokeWidth={2} dot={false} />
                  <Line yAxisId="right" type="monotone" dataKey="match_rate" name="Match Rate %" stroke="#f59e0b" strokeWidth={2} dot={false} strokeDasharray="5 5" />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)" }}>
              <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Average Score Over Time</h3>
              <ResponsiveContainer width="100%" height={350}>
                <LineChart data={timeline.data || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary, #e2e8f0)" />
                  <XAxis dataKey="date" tick={{ fontSize: 10, fill: "var(--text-muted, #94a3b8)" }} angle={-45} textAnchor="end" height={60} />
                  <YAxis tick={{ fontSize: 11, fill: "var(--text-muted, #94a3b8)" }} />
                  <RechartsTooltip content={<CustomTooltip />} />
                  <Line type="monotone" dataKey="avg_score" name="Avg Score" stroke="#8b5cf6" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* MATRIX TAB */}
      {subTab === "matrix" && matrix.data && (
        <div style={{ background: "var(--bg-card, #fff)", borderRadius: "var(--radius-md, 8px)", padding: "1.25rem", border: "1px solid var(--border-primary, #e2e8f0)", overflow: "auto" }}>
          <h3 style={{ margin: "0 0 1rem", fontSize: "1rem" }}>Category x Keyword Cross-Reference Matrix</h3>
          <div style={{ fontSize: "0.78rem", color: "var(--text-muted, #94a3b8)", marginBottom: "1rem" }}>
            Shows how often top {matrix.data.keywords?.length} keywords appear in articles of each category. Values represent article counts.
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
            <thead>
              <tr>
                <th style={{ padding: "0.5rem", textAlign: "left", background: "var(--bg-tertiary, #f1f5f9)", borderBottom: "2px solid var(--border-primary, #e2e8f0)", position: "sticky", left: 0, zIndex: 1, minWidth: 160 }}>Category</th>
                {matrix.data.keywords?.map((kw: string) => (
                  <th key={kw} style={{ padding: "0.5rem", textAlign: "center", background: "var(--bg-tertiary, #f1f5f9)", borderBottom: "2px solid var(--border-primary, #e2e8f0)", minWidth: 60 }}>{kw}</th>
                ))}
                <th style={{ padding: "0.5rem", textAlign: "center", background: "var(--bg-tertiary, #f1f5f9)", borderBottom: "2px solid var(--border-primary, #e2e8f0)" }}>Total</th>
              </tr>
            </thead>
            <tbody>
              {matrix.data.matrix?.map((row: any) => {
                const maxVal = Math.max(...matrix.data.keywords.map((kw: string) => row[kw] || 0), 1);
                return (
                  <tr key={row.category}>
                    <td style={{ padding: "0.5rem", fontWeight: 600, borderBottom: "1px solid var(--border-primary, #e2e8f0)", position: "sticky", left: 0, background: "var(--bg-card, #fff)", zIndex: 1 }}>
                      <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 4, background: CAT_COLORS[row.category] || "#6b7280", marginRight: 6 }} />
                      {row.category}
                    </td>
                    {matrix.data.keywords?.map((kw: string) => {
                      const val = row[kw] || 0;
                      const intensity = val / maxVal;
                      return (
                        <td key={kw} style={{
                          padding: "0.5rem", textAlign: "center", borderBottom: "1px solid var(--border-primary, #e2e8f0)",
                          background: val > 0 ? `rgba(59, 130, 246, ${Math.min(0.3, intensity * 0.3)})` : "transparent",
                          fontWeight: val > 0 ? 600 : 400, color: val > 0 ? "var(--accent-blue, #3b82f6)" : "var(--text-muted, #94a3b8)",
                        }}>
                          {val || "—"}
                        </td>
                      );
                    })}
                    <td style={{ padding: "0.5rem", textAlign: "center", fontWeight: 700, borderBottom: "1px solid var(--border-primary, #e2e8f0)", background: "var(--bg-tertiary, #f8fafc)" }}>
                      {row.total}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
