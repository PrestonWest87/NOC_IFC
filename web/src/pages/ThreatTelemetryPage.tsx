import { useState, useMemo, useCallback, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { MapContainer } from "../components/MapContainer";
import DeckGL from "@deck.gl/react";
import { Map } from "react-map-gl/maplibre";
import "maplibre-gl/dist/maplibre-gl.css";
import { ScatterplotLayer, PolygonLayer } from "@deck.gl/layers";
import type { MapViewState } from "@deck.gl/core";
import {
  Bug, ShieldAlert, Cpu, Cloud, Shield, CloudSun, Globe, Bot, FileText,
  Pin, PinOff, ThumbsUp, ThumbsDown, Brain, ChevronLeft, ChevronRight,
  RefreshCw, AlertTriangle, CheckCircle, MapPin, Activity,
} from "lucide-react";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { getAllowedTabs } from "../utils/permissions";
import { formatInChicago, chicagoDateString, chicagoNow } from "../utils/timezone";

const CATEGORIES = [
  "All", "Cyber: Exploits & Vulns", "Cyber: Malware & Threats",
  "ICS/OT & SCADA", "Cloud & IT Infra", "Physical Security",
  "Severe Weather", "Geopolitics & Policy", "AI & Emerging Tech", "General",
];

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  "Cyber: Exploits & Vulns": <Bug size={14} />,
  "Cyber: Malware & Threats": <ShieldAlert size={14} />,
  "ICS/OT & SCADA": <Cpu size={14} />,
  "Cloud & IT Infra": <Cloud size={14} />,
  "Physical Security": <Shield size={14} />,
  "Severe Weather": <CloudSun size={14} />,
  "Geopolitics & Policy": <Globe size={14} />,
  "AI & Emerging Tech": <Bot size={14} />,
  "General": <FileText size={14} />,
};

const SUB_TABS = ["Pinned", "Live", "Low", "Search"];

function getScoreColor(score: number): string {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#eab308";
  return "#6b7280";
}

function formatDate(d: string | null | undefined): string {
  if (!d) return "Unknown";
  return formatInChicago(d, undefined, d);
}

function truncate(s: string | null | undefined, len: number): string {
  if (!s) return "";
  return s.length > len ? s.slice(0, len) + "..." : s;
}

const s: { [k: string]: React.CSSProperties } = {
  page: {
    padding: "1.5rem",
    color: "var(--text-primary, #e2e8f0)",
    fontFamily: "system-ui, sans-serif",
  },
  tabBar: {
    display: "flex",
    gap: "0.25rem",
    borderBottom: "1px solid var(--border-primary, #334155)",
    marginBottom: "1.25rem",
    flexWrap: "wrap" as const,
  },
  tab: {
    padding: "0.6rem 1.2rem",
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: "0.85rem",
    background: "transparent",
    color: "var(--text-secondary, #94a3b8)",
    borderBottom: "2px solid transparent",
    transition: "all 0.15s",
  },
  tabActive: {
    padding: "0.6rem 1.2rem",
    border: "none",
    cursor: "pointer",
    fontWeight: 600,
    fontSize: "0.85rem",
    background: "transparent",
    color: "var(--accent-blue, #38bdf8)",
    borderBottom: "2px solid var(--accent-blue, #38bdf8)",
  },
  card: {
    background: "var(--bg-card, #1e293b)",
    borderRadius: "var(--radius-md, 8px)",
    padding: "1rem",
    border: "1px solid var(--border-primary, #334155)",
    marginBottom: "0.75rem",
  },
  btn: {
    padding: "0.35rem 0.75rem",
    border: "1px solid var(--border-primary, #334155)",
    borderRadius: "var(--radius-sm, 4px)",
    cursor: "pointer",
    fontSize: "0.75rem",
    fontWeight: 500,
    background: "var(--bg-tertiary, #0f172a)",
    color: "var(--text-primary, #e2e8f0)",
    transition: "all 0.15s",
  },
  btnDanger: {
    padding: "0.35rem 0.75rem",
    border: "none",
    borderRadius: "var(--radius-sm, 4px)",
    cursor: "pointer",
    fontSize: "0.75rem",
    fontWeight: 500,
    background: "#dc2626",
    color: "#fff",
  },
  btnPrimary: {
    padding: "0.35rem 0.75rem",
    border: "none",
    borderRadius: "var(--radius-sm, 4px)",
    cursor: "pointer",
    fontSize: "0.75rem",
    fontWeight: 500,
    background: "var(--accent-blue, #2563eb)",
    color: "#fff",
  },
  input: {
    padding: "0.4rem 0.6rem",
    border: "1px solid var(--border-primary, #334155)",
    borderRadius: "var(--radius-sm, 4px)",
    fontSize: "0.8rem",
    background: "var(--bg-tertiary, #0f172a)",
    color: "var(--text-primary, #e2e8f0)",
    outline: "none",
    width: "100%",
    boxSizing: "border-box" as const,
  },
  select: {
    padding: "0.4rem 0.6rem",
    border: "1px solid var(--border-primary, #334155)",
    borderRadius: "var(--radius-sm, 4px)",
    fontSize: "0.8rem",
    background: "var(--bg-tertiary, #0f172a)",
    color: "var(--text-primary, #e2e8f0)",
    outline: "none",
  },
  badge: {
    padding: "0.1rem 0.4rem",
    borderRadius: "var(--radius-sm, 3px)",
    fontWeight: 700,
    fontSize: "0.7rem",
    color: "#fff",
    whiteSpace: "nowrap" as const,
  },
  articleTitle: {
    fontWeight: 600,
    fontSize: "0.9rem",
    color: "var(--accent-blue, #38bdf8)",
    textDecoration: "none",
  },
  caption: {
    fontSize: "0.75rem",
    color: "var(--text-secondary, #94a3b8)",
  },
  divider: {
    border: "none",
    borderTop: "1px solid var(--border-primary, #334155)",
    margin: "0.75rem 0",
  },
};

function TabButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return <button onClick={onClick} style={active ? s.tabActive : s.tab}>{label}</button>;
}

function SubTabButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        ...s.btn,
        background: active ? "var(--accent-blue, #2563eb)" : "var(--bg-tertiary, #0f172a)",
        color: active ? "#fff" : "var(--text-primary, #e2e8f0)",
        borderColor: active ? "var(--accent-blue, #2563eb)" : "var(--border-primary, #334155)",
      }}
    >
      {label}
    </button>
  );
}

function ScoreBadge({ score }: { score: number }) {
  return <span style={{ ...s.badge, background: getScoreColor(score) }}>{Math.round(score)}</span>;
}

function Pagination({
  page, totalPages, total, onPrev, onNext,
}: {
  page: number; totalPages: number; total: number; onPrev: () => void; onNext: () => void;
}) {
  if (totalPages <= 1) return null;
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "1rem", marginTop: "1rem" }}>
      <button onClick={onPrev} disabled={page <= 1} style={{ ...s.btn, opacity: page <= 1 ? 0.4 : 1 }}>
        <ChevronLeft size={14} style={{ verticalAlign: "middle" }} /> Previous
      </button>
      <span style={{ fontSize: "0.85rem", color: "var(--text-secondary, #94a3b8)" }}>
        Page <strong>{page}</strong> of {totalPages}
        <span style={{ marginLeft: "0.5rem", fontSize: "0.75rem", opacity: 0.7 }}>(Total: {total})</span>
      </span>
      <button onClick={onNext} disabled={page >= totalPages} style={{ ...s.btn, opacity: page >= totalPages ? 0.4 : 1 }}>
        Next <ChevronRight size={14} style={{ verticalAlign: "middle" }} />
      </button>
    </div>
  );
}

export function ThreatTelemetryPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const allowedThreatTabs = getAllowedTabs(user?.allowed_actions, "threatTelemetry");
  const THREAT_TABS = ["RSS Triage", "CISA KEV", "Cloud Services", "Perimeter Crime"];
  const [activeTab, setActiveTab] = useState(0);
  const [subTab, setSubTab] = useState(0);
  const [categoryFilter, setCategoryFilter] = useState("All");

  const [pagePinned, setPagePinned] = useState(1);
  const [pageLive, setPageLive] = useState(1);
  const [pageLow, setPageLow] = useState(1);
  const [pageSearch, setPageSearch] = useState(1);

  const [searchTerm, setSearchTerm] = useState("");
  const [searchMinScore, setSearchMinScore] = useState(0);
  const [searchPageSize, setSearchPageSize] = useState(20);

  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const [cooldownRss, setCooldownRss] = useState(false);
  const [cooldownKev, setCooldownKev] = useState(false);
  const [cooldownCloud, setCooldownCloud] = useState(false);

  const [radiusFilter, setRadiusFilter] = useState(1);
  const [selectedCrimeId, setSelectedCrimeId] = useState<number | null>(null);

  const feedType = SUB_TABS[subTab].toLowerCase();

  const articlesQuery = useQuery({
      queryKey: ["articles", feedType, categoryFilter, feedType === "search" ? pageSearch : (feedType === "pinned" ? pagePinned : feedType === "live" ? pageLive : pageLow), feedType === "search" ? searchPageSize : feedType === "pinned" ? 10 : feedType === "low" ? 10 : 20, searchTerm, searchMinScore],
    queryFn: () => {
      const p = feedType === "search" ? pageSearch : feedType === "pinned" ? pagePinned : feedType === "live" ? pageLive : pageLow;
      const ps = feedType === "search" ? searchPageSize : feedType === "pinned" ? 10 : feedType === "low" ? 10 : 20;
      return api.get("/threat/articles", {
        params: {
          category: feedType,
          page: p,
          page_size: ps,
          cat_filter: categoryFilter !== "All" ? categoryFilter : undefined,
          search_term: feedType === "search" && searchTerm ? searchTerm : undefined,
          min_score: feedType === "search" ? searchMinScore : 0,
        },
      }).then(r => r.data);
    },
    refetchInterval: 60000,
  });

  const cvesQuery = useQuery({
    queryKey: ["cves"],
    queryFn: () => api.get("/threat/cves", { params: { limit: 50, days_back: 30 } }).then(r => r.data),
    refetchInterval: 300000,
  });

  const outagesQuery = useQuery({
    queryKey: ["outages"],
    queryFn: () => api.get("/threat/cloud-outages", { params: { active_only: true } }).then(r => r.data),
    refetchInterval: 120000,
  });

  const resolvedQuery = useQuery({
    queryKey: ["resolved-outages"],
    queryFn: () => api.get("/threat/cloud-outages", { params: { active_only: false } }).then(r => r.data),
    enabled: activeTab === 2,
  });

  const crimesQuery = useQuery({
    queryKey: ["crimes", radiusFilter],
    queryFn: () => api.get("/threat/crime-incidents", { params: { hours_back: 168, max_distance: radiusFilter } }).then(r => r.data),
    refetchInterval: 180000,
  });

  const togglePinMut = useMutation({
    mutationFn: (articleId: number) => api.post("/dashboard/articles/toggle-pin", null, { params: { article_id: articleId } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["articles"] }); },
  });

  const boostScoreMut = useMutation({
    mutationFn: (articleId: number) => api.post("/dashboard/articles/boost-score", null, { params: { article_id: articleId, amount: 15 } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["articles"] }); },
  });

  const feedbackMut = useMutation({
    mutationFn: ({ articleId, feedback }: { articleId: number; feedback: number }) =>
      api.post("/dashboard/articles/feedback", null, { params: { article_id: articleId, feedback } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["articles"] }); },
  });

  const blufMut = useMutation({
    mutationFn: (articleId: number) => api.post("/dashboard/articles/generate-bluf", null, { params: { article_id: articleId } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["articles"] }); },
  });

  const syncFeedsMut = useMutation({
    mutationFn: () => api.post("/threat/fetch-feeds"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["articles"] });
      setCooldownRss(true);
      setTimeout(() => setCooldownRss(false), 60000);
    },
  });

  const syncKevMut = useMutation({
    mutationFn: () => api.post("/threat/sync-cisa-kev"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cves"] });
      setCooldownKev(true);
      setTimeout(() => setCooldownKev(false), 60000);
    },
  });

  const syncCloudMut = useMutation({
    mutationFn: () => api.post("/threat/sync-cloud-status"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["outages"] });
      setCooldownCloud(true);
      setTimeout(() => setCooldownCloud(false), 60000);
    },
  });

  const fetchCrimeMut = useMutation({
    mutationFn: () => api.post("/threat/fetch-crime-data"),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["crimes"] }); },
  });

  const articles: any[] = articlesQuery.data?.items ?? [];
  const totalArticles = articlesQuery.data?.total ?? 0;
  const totalPages = articlesQuery.data?.total_pages ?? 1;
  const currentPage = articlesQuery.data?.page ?? 1;

  const cves: any[] = cvesQuery.data ?? [];
  const outages: any[] = outagesQuery.data ?? [];
  const allOutages: any[] = resolvedQuery.data ?? [];
  const crimes: any[] = crimesQuery.data ?? [];

  const now = chicagoNow();
  const chicagoParts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", month: "short", day: "numeric" }).formatToParts(now);
  const chicagoLongParts = new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", month: "long", day: "numeric" }).formatToParts(now);
  const chicagoShort = chicagoParts.map(p => p.value).join(" ").toLowerCase();
  const chicagoLong = chicagoLongParts.map(p => p.value).join(" ").toLowerCase();
  const todayFmts = [
    chicagoShort,
    chicagoLong,
    chicagoDateString(now),
    `${(now.getMonth() + 1).toString().padStart(2, "0")}/${now.getDate().toString().padStart(2, "0")}/${now.getFullYear()}`,
  ];

  const activeOutages = useMemo(() => {
    return outages.filter((o: any) => {
      const text = ((o.title || "") + " " + (o.description || "")).toLowerCase();
      const isMaint = /maintenance|scheduled|upcoming|update/.test(text);
      const isActive = /in progress|started|currently undergoing/.test(text);
      if (isMaint && !isActive && !todayFmts.some(f => text.includes(f))) return false;
      return true;
    });
  }, [outages, todayFmts]);

  const filteredOutages = useMemo(() => {
    if (!selectedProvider) return activeOutages;
    return activeOutages.filter((o: any) => o.provider === selectedProvider);
  }, [activeOutages, selectedProvider]);

  const affectedProviders = useMemo(() => {
    return [...new Set(activeOutages.map((o: any) => o.provider).filter(Boolean))].sort();
  }, [activeOutages]);

  const resolvedOutages = useMemo(() => {
    return allOutages.filter((o: any) => o.is_resolved);
  }, [allOutages]);

  const selectedCrime = useMemo(() => {
    if (selectedCrimeId === null) return null;
    return crimes.find((c: any) => c.id === selectedCrimeId) ?? null;
  }, [selectedCrimeId, crimes]);

  const handlePrev = useCallback(() => {
    if (feedType === "pinned") setPagePinned(p => Math.max(1, p - 1));
    else if (feedType === "live") setPageLive(p => Math.max(1, p - 1));
    else if (feedType === "low") setPageLow(p => Math.max(1, p - 1));
    else setPageSearch(p => Math.max(1, p - 1));
  }, [feedType]);

  const handleNext = useCallback(() => {
    if (feedType === "pinned") setPagePinned(p => Math.min(totalPages, p + 1));
    else if (feedType === "live") setPageLive(p => Math.min(totalPages, p + 1));
    else if (feedType === "low") setPageLow(p => Math.min(totalPages, p + 1));
    else setPageSearch(p => Math.min(totalPages, p + 1));
  }, [feedType, totalPages]);

  const crimeMapViewState: MapViewState = useMemo(() => {
    if (selectedCrime && selectedCrime.lat && selectedCrime.lon) {
      return { latitude: selectedCrime.lat, longitude: selectedCrime.lon, zoom: 17, pitch: 0 };
    }
    const mapZoom = radiusFilter === 1 ? 15.5 : radiusFilter === 3 ? 13.5 : 12.0;
    return { latitude: 34.6755, longitude: -92.3235, zoom: mapZoom, pitch: 0 };
  }, [selectedCrime, radiusFilter]);

  const HQ: [number, number] = [-92.3235, 34.6755];

  const campusBoundary: [number, number][] = [
    [-92.325885, 34.678235], [-92.326196, 34.675942], [-92.324565, 34.675888],
    [-92.324636, 34.674884], [-92.32406120583306, 34.67474187702983],
    [-92.3238084241607, 34.67452124894587], [-92.32373734260989, 34.674349128685705],
    [-92.32376809344501, 34.673623615079805], [-92.32351586802497, 34.67332173763069],
    [-92.3220985004393, 34.67324489899573], [-92.32198879648926, 34.673705411555176],
    [-92.32118128553886, 34.673676198116304], [-92.32110794479303, 34.67493955311931],
    [-92.32189171929349, 34.67527638012709], [-92.32180319236035, 34.67672422178229],
    [-92.3216835943636, 34.678465279952555], [-92.32589779219425, 34.67833455896807],
    [-92.325885, 34.678235],
  ];

  const crimeTooltip = useCallback((info: any) => {
    if (!info.object) return null;
    const d = info.object;
    if (info.layer?.id === "crime-scatter") {
      return {
        html: `<b>${d.raw_title || "Incident"}</b><br/>
${d.distance_miles != null ? `<b>Distance:</b> ${d.distance_miles.toFixed(1)} mi<br/>` : ""}
${d.timestamp ? `<b>Time:</b> ${new Date(d.timestamp).toLocaleString("en-US", { timeZone: "America/Chicago", month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })}<br/>` : ""}
${d.category ? `<b>Category:</b> ${d.category}` : ""}`,
        style: { background: "var(--bg-card)", color: "var(--text-primary)", fontSize: "0.78rem", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.5rem" },
      };
    }
    return null;
  }, []);

  const crimeLayers = useMemo(() => {
    const base: any[] = [];

    const crimeData = crimes
      .filter((c: any) => c.lat != null && c.lon != null)
      .map((c: any) => ({
        position: [c.lon, c.lat],
        color: c.category?.toLowerCase().includes("violent") || c.category?.toLowerCase().includes("assault") || c.category?.toLowerCase().includes("weapon")
          ? [220, 38, 38, 200]
          : c.category?.toLowerCase().includes("theft") || c.category?.toLowerCase().includes("burglary") || c.category?.toLowerCase().includes("property")
          ? [245, 158, 11, 200]
          : c.category?.toLowerCase().includes("trespass") || c.category?.toLowerCase().includes("disturbance") || c.category?.toLowerCase().includes("narcotic")
          ? [234, 179, 8, 200]
          : [99, 102, 241, 200],
        radius: 40,
        raw_title: c.raw_title,
        timestamp: c.timestamp,
        distance_miles: c.distance_miles,
        category: c.category,
      }));
    if (crimeData.length > 0) {
      base.push(
        new ScatterplotLayer({
          id: "crime-scatter",
          data: crimeData,
          getPosition: (d: any) => d.position,
          getFillColor: (d: any) => d.color,
          getRadius: (d: any) => d.radius,
          pickable: true,
          autoHighlight: true,
          stroked: false,
        })
      );
    }

    if (selectedCrime && selectedCrime.lat != null && selectedCrime.lon != null) {
      base.push(
        new ScatterplotLayer({
          id: "crime-highlight",
          data: [{ position: [selectedCrime.lon, selectedCrime.lat] }],
          getPosition: (d: any) => d.position,
          getFillColor: [255, 0, 0, 200],
          getLineColor: [255, 255, 255, 255],
          stroked: true,
          lineWidthMinPixels: 3,
          getRadius: 50,
        })
      );
    }

    const radiusMeters = radiusFilter * 1609.34;
    base.push(
      new ScatterplotLayer({
        id: "hq-marker",
        data: [{ position: HQ, label: "HQ" }],
        getPosition: (d: any) => d.position,
        getFillColor: [56, 189, 248, 220],
        getLineColor: [255, 255, 255, 255],
        getRadius: 80,
        stroked: true,
        lineWidthMinPixels: 3,
        radiusMinPixels: 6,
        radiusMaxPixels: 12,
      }),
      new PolygonLayer({
        id: "campus-boundary",
        data: [{ polygon: campusBoundary }],
        getPolygon: (d: any) => d.polygon,
        getFillColor: [0, 255, 100, 30],
        getLineColor: [0, 255, 100, 200],
        lineWidthMinPixels: 2,
        stroked: true,
        filled: true,
      }),
      new ScatterplotLayer({
        id: "hq-radius",
        data: [{ position: HQ, radius: radiusMeters }],
        getPosition: (d: any) => d.position,
        getFillColor: [56, 189, 248, 12],
        getLineColor: [56, 189, 248, 60],
        getRadius: (d: any) => d.radius,
        stroked: true,
        lineWidthMinPixels: 1,
      })
    );

    return base;
  }, [crimes, selectedCrime, radiusFilter]);

  const renderArticles = (items: any[]) => {
    if (items.length === 0) {
      return <div style={{ ...s.card, textAlign: "center", color: "var(--text-secondary, #94a3b8)" }}>No articles found.</div>;
    }
    return items.map((art: any) => (
      <div key={art.id} style={s.card}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: "0.5rem", marginBottom: "0.3rem" }}>
          <ScoreBadge score={art.score} />
          <div style={{ flex: 1 }}>
            <a href={art.link} target="_blank" rel="noopener noreferrer" style={s.articleTitle}>
              {art.title}
            </a>
          </div>
        </div>
        <div style={{ ...s.caption, marginBottom: "0.3rem" }}>
          {formatDate(art.published_date)} | {art.source} | {CATEGORY_ICONS[art.category]}{" "}
          <span style={{ marginLeft: "0.15rem" }}>{art.category}</span>
        </div>
        {art.ai_bluf && (
          <div
            style={{
              ...s.card,
              padding: "0.4rem 0.6rem",
              background: "var(--bg-success-dim, rgba(34,197,94,0.1))",
              borderColor: "var(--border-success, #22c55e)",
              fontSize: "0.8rem",
              marginBottom: "0.4rem",
            }}
          >
            <strong>AI BLUF:</strong> {art.ai_bluf}
          </div>
        )}
        <div style={{ ...s.caption, fontSize: "0.8rem", marginBottom: "0.5rem" }}>
          {truncate(art.summary, 500)}
        </div>
        <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
          <button
            onClick={() => togglePinMut.mutate(art.id)}
            style={art.is_pinned ? s.btnDanger : s.btn}
            title={art.is_pinned ? "Unpin" : "Pin"}
          >
            {art.is_pinned ? <PinOff size={12} style={{ verticalAlign: "middle" }} /> : <Pin size={12} style={{ verticalAlign: "middle" }} />}
            {" "}{art.is_pinned ? "Unpin" : "Pin"}
          </button>
          <button onClick={() => boostScoreMut.mutate(art.id)} style={s.btn} title="+15 Score">
            +15 Score
          </button>
          <button onClick={() => feedbackMut.mutate({ articleId: art.id, feedback: 2 })} style={s.btn} title="Keep">
            <ThumbsUp size={12} style={{ verticalAlign: "middle" }} /> Keep
          </button>
          <button onClick={() => feedbackMut.mutate({ articleId: art.id, feedback: 1 })} style={{ ...s.btn, color: "#f87171" }} title="Dismiss">
            <ThumbsDown size={12} style={{ verticalAlign: "middle" }} /> Dismiss
          </button>
          {!art.ai_bluf && (
            <button onClick={() => blufMut.mutate(art.id)} style={{ ...s.btn, color: "var(--accent-blue, #38bdf8)" }} title="Generate BLUF">
              <Brain size={12} style={{ verticalAlign: "middle" }} /> BLUF
            </button>
          )}
        </div>
      </div>
    ));
  };

  useEffect(() => {
    if (allowedThreatTabs.length > 0 && !allowedThreatTabs.includes(String(activeTab))) {
      setActiveTab(Number(allowedThreatTabs[0]));
    }
  }, [allowedThreatTabs.join(",")]);

  return (
    <div style={s.page}>
      <h2 style={{ margin: "0 0 1.5rem", color: "var(--text-primary, #e2e8f0)", fontSize: "1.5rem" }}>
        Unified Threat Telemetry
      </h2>

      <div style={s.tabBar}>
        {THREAT_TABS.filter((_, i) => allowedThreatTabs.length === 0 || allowedThreatTabs.includes(String(i))).map((label, i) => (
          <TabButton key={label} active={activeTab === i} label={label} onClick={() => { setActiveTab(i); }} />
        ))}
      </div>

      {/* === TAB 0: RSS TRIAGE === */}
      <div style={{ display: activeTab === 0 ? '' : 'none' }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", gap: "1rem", flexWrap: "wrap" }}>
            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              style={{ ...s.select, minWidth: "220px" }}
            >
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <button
              onClick={() => syncFeedsMut.mutate()}
              disabled={cooldownRss || syncFeedsMut.isPending}
              style={{ ...s.btnPrimary, opacity: cooldownRss ? 0.5 : 1, display: "flex", alignItems: "center", gap: "0.3rem" }}
            >
              <RefreshCw size={14} className={syncFeedsMut.isPending ? "spin" : ""} />
              {cooldownRss ? "Syncing..." : "Force Fetch Feeds"}
            </button>
          </div>

          <div style={{ display: "flex", gap: "0.4rem", marginBottom: "1rem", flexWrap: "wrap" }}>
            {SUB_TABS.map((label, i) => (
              <SubTabButton
                key={label}
                active={subTab === i}
                label={label}
                onClick={() => { setSubTab(i); }}
              />
            ))}
          </div>

          {subTab === 3 && (
            <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1rem", flexWrap: "wrap", alignItems: "flex-end" }}>
              <div style={{ flex: 1, minWidth: "180px" }}>
                <div style={{ ...s.caption, marginBottom: "0.2rem" }}>Search</div>
                <input
                  type="text"
                  value={searchTerm}
                  onChange={e => setSearchTerm(e.target.value)}
                  placeholder="Search articles..."
                  style={s.input}
                />
              </div>
              <div style={{ width: "100px" }}>
                <div style={{ ...s.caption, marginBottom: "0.2rem" }}>Min Score</div>
                <input
                  type="number"
                  value={searchMinScore}
                  onChange={e => setSearchMinScore(Number(e.target.value))}
                  min={0}
                  style={s.input}
                />
              </div>
              <div style={{ width: "140px" }}>
                <div style={{ ...s.caption, marginBottom: "0.2rem" }}>Items per Page</div>
                <select
                  value={searchPageSize}
                  onChange={e => setSearchPageSize(Number(e.target.value))}
                  style={s.select}
                >
                  <option value={10}>10</option>
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                </select>
              </div>
            </div>
          )}

          {articlesQuery.isLoading ? (
            <div style={{ ...s.card, textAlign: "center", padding: "2rem" }}>
              <RefreshCw size={24} className="spin" style={{ margin: "0 auto", opacity: 0.5 }} />
            </div>
          ) : (
            <>
              <Pagination
                page={currentPage}
                totalPages={totalPages}
                total={totalArticles}
                onPrev={handlePrev}
                onNext={handleNext}
              />
              {renderArticles(articles)}
              <Pagination
                page={currentPage}
                totalPages={totalPages}
                total={totalArticles}
                onPrev={handlePrev}
                onNext={handleNext}
              />
            </>
          )}
        </div>

      {/* === TAB 1: CISA KEV === */}
      <div style={{ display: activeTab === 1 ? '' : 'none' }}>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "1rem" }}>
            <button
              onClick={() => syncKevMut.mutate()}
              disabled={cooldownKev || syncKevMut.isPending}
              style={{ ...s.btnPrimary, opacity: cooldownKev ? 0.5 : 1, display: "flex", alignItems: "center", gap: "0.3rem" }}
            >
              <RefreshCw size={14} className={syncKevMut.isPending ? "spin" : ""} />
              {cooldownKev ? "Syncing..." : "Sync CISA KEV"}
            </button>
          </div>
          {cvesQuery.isLoading ? (
            <div style={{ ...s.card, textAlign: "center", padding: "2rem" }}>
              <RefreshCw size={24} className="spin" style={{ margin: "0 auto", opacity: 0.5 }} />
            </div>
          ) : cves.length === 0 ? (
            <div style={{ ...s.card, textAlign: "center", color: "var(--text-secondary, #94a3b8)" }}>
              No CVEs found. Sync the CISA KEV database.
            </div>
          ) : (
            cves.map((cve: any) => (
              <details key={cve.id || cve.cve_id} style={{ ...s.card, padding: "0" }}>
                <summary
                  style={{
                    padding: "0.75rem 1rem",
                    cursor: "pointer",
                    fontWeight: 600,
                    fontSize: "0.85rem",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.5rem",
                    color: "var(--text-primary, #e2e8f0)",
                    listStyle: "none",
                  }}
                >
                  <Bug size={14} style={{ color: "#ef4444", flexShrink: 0 }} />
                  <span style={{ color: "var(--accent-blue, #38bdf8)" }}>{cve.cve_id}</span>
                  <span>|</span>
                  <span>{cve.vendor}</span>
                  <span>{cve.product}</span>
                  <span style={{ marginLeft: "auto", fontSize: "0.75rem", color: "var(--text-secondary, #94a3b8)" }}>
                    {formatDate(cve.date_added)}
                  </span>
                </summary>
                <div style={{ padding: "0 1rem 1rem", fontSize: "0.85rem", color: "var(--text-secondary, #94a3b8)" }}>
                  <div style={{ marginBottom: "0.5rem", fontWeight: 600, color: "var(--text-primary, #e2e8f0)" }}>
                    {cve.vulnerability_name}
                  </div>
                  <div>{cve.description}</div>
                </div>
              </details>
            ))
          )}
        </div>

      {/* === TAB 2: CLOUD SERVICES === */}
      <div style={{ display: activeTab === 2 ? '' : 'none' }}>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "1rem" }}>
            <button
              onClick={() => syncCloudMut.mutate()}
              disabled={cooldownCloud || syncCloudMut.isPending}
              style={{ ...s.btnPrimary, opacity: cooldownCloud ? 0.5 : 1, display: "flex", alignItems: "center", gap: "0.3rem" }}
            >
              <RefreshCw size={14} className={syncCloudMut.isPending ? "spin" : ""} />
              {cooldownCloud ? "Syncing..." : "Sync Cloud Status"}
            </button>
          </div>

          {outagesQuery.isLoading ? (
            <div style={{ ...s.card, textAlign: "center", padding: "2rem" }}>
              <RefreshCw size={24} className="spin" style={{ margin: "0 auto", opacity: 0.5 }} />
            </div>
          ) : activeOutages.length === 0 ? (
            <div style={{ ...s.card, textAlign: "center", padding: "1.5rem" }}>
              <CheckCircle size={24} style={{ color: "#22c55e", margin: "0 auto 0.5rem" }} />
              <div style={{ color: "var(--text-secondary, #94a3b8)", fontSize: "0.9rem" }}>
                All tracked global SaaS and IaaS providers are reporting Operational status.
              </div>
            </div>
          ) : (
            <div>
              <div style={{ ...s.card, display: "flex", alignItems: "center", gap: "0.5rem", padding: "0.75rem 1rem" }}>
                <AlertTriangle size={16} style={{ color: "#f97316", flexShrink: 0 }} />
                <span style={{ fontSize: "0.85rem", color: "var(--text-primary, #e2e8f0)" }}>
                  Active service degradations detected across <strong>{affectedProviders.length}</strong> providers.
                </span>
              </div>

              <div style={s.tabBar}>
                {affectedProviders.map((p: string) => (
                  <TabButton
                    key={p}
                    active={p === selectedProvider}
                    label={p}
                    onClick={() => setSelectedProvider(selectedProvider === p ? null : p)}
                  />
                ))}
              </div>

              {filteredOutages.length === 0 ? (
                <div style={{ ...s.card, textAlign: "center", padding: "1rem", color: "var(--text-secondary)" }}>
                  No active outages for this provider.
                </div>
              ) : filteredOutages.map((o: any) => (
                <details key={o.id} style={{ ...s.card, padding: "0" }}>
                  <summary
                    style={{
                      padding: "0.6rem 1rem",
                      cursor: "pointer",
                      fontWeight: 500,
                      fontSize: "0.85rem",
                      display: "flex",
                      alignItems: "center",
                      gap: "0.5rem",
                      color: "var(--text-primary, #e2e8f0)",
                      listStyle: "none",
                    }}
                  >
                    <Activity size={14} style={{ color: "#f97316", flexShrink: 0 }} />
                    <span style={{ fontWeight: 600 }}>{o.service}</span>
                    <span style={{ marginLeft: "auto", fontSize: "0.75rem", color: "var(--text-secondary, #94a3b8)" }}>
                      {formatDate(o.updated_at)}
                    </span>
                  </summary>
                  <div style={{ padding: "0 1rem 0.75rem", fontSize: "0.85rem", color: "var(--text-secondary, #94a3b8)" }}>
                    <div style={{ marginBottom: "0.3rem" }}>
                      <strong><a href={o.link} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent-blue, #38bdf8)" }}>{o.title}</a></strong>
                    </div>
                    <div>{o.description}</div>
                  </div>
                </details>
              ))}
            </div>
          )}

          <hr style={s.divider} />

          <details style={{ ...s.card, padding: "0" }}>
            <summary
              style={{
                padding: "0.75rem 1rem",
                cursor: "pointer",
                fontWeight: 600,
                fontSize: "0.85rem",
                color: "var(--text-primary, #e2e8f0)",
                listStyle: "none",
              }}
            >
              <ChevronRight size={14} style={{ verticalAlign: "middle", marginRight: "0.3rem" }} />
              View Historical / Resolved Incidents (Last 72 Hours)
            </summary>
            <div style={{ padding: "0 1rem 1rem" }}>
              {resolvedQuery.isLoading ? (
                <div style={{ textAlign: "center", padding: "1rem", color: "var(--text-secondary, #94a3b8)" }}>Loading...</div>
              ) : resolvedOutages.length === 0 ? (
                <div style={{ color: "var(--text-secondary, #94a3b8)", fontSize: "0.85rem" }}>No recently resolved incidents.</div>
              ) : (
                resolvedOutages.map((o: any) => (
                  <div key={o.id} style={{ padding: "0.4rem 0", fontSize: "0.8rem", borderBottom: "1px solid var(--border-primary, #334155)" }}>
                    <strong style={{ color: "var(--text-primary, #e2e8f0)" }}>{o.provider}</strong>{" "}
                    <span style={{ color: "var(--text-secondary, #94a3b8)" }}>| {o.service}</span>
                    <br />
                    <small>
                      <a href={o.link} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent-blue, #38bdf8)" }}>{o.title}</a>
                    </small>
                  </div>
                ))
              )}
            </div>
          </details>
        </div>

      {/* === TAB 3: PERIMETER CRIME === */}
      <div style={{ display: activeTab === 3 ? '' : 'none' }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", gap: "1rem", marginBottom: "1rem", flexWrap: "wrap" }}>
            <div>
              <h3 style={{ margin: 0, color: "var(--text-primary, #e2e8f0)", fontSize: "1.1rem" }}>Perimeter Crime Telemetry</h3>
              <div style={{ ...s.caption, marginTop: "0.2rem" }}>
                LRPD incident aggregation geofenced around HQ (Last 7 Days - All Categories).
              </div>
            </div>
            <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", flexWrap: "wrap" }}>
              <div>
                <div style={{ ...s.caption, marginBottom: "0.2rem" }}>Geofence Radius</div>
                <select
                  value={radiusFilter}
                  onChange={e => { setRadiusFilter(Number(e.target.value)); setSelectedCrimeId(null); }}
                  style={s.select}
                >
                  <option value={1}>1 Mile</option>
                  <option value={3}>3 Miles</option>
                  <option value={5}>5 Miles</option>
                  <option value={10}>10 Miles</option>
                </select>
              </div>
              <button
                onClick={() => fetchCrimeMut.mutate()}
                disabled={fetchCrimeMut.isPending}
                style={{ ...s.btnPrimary, display: "flex", alignItems: "center", gap: "0.3rem", height: "fit-content" }}
              >
                <RefreshCw size={14} className={fetchCrimeMut.isPending ? "spin" : ""} />
                Force Fetch LRPD
              </button>
            </div>
          </div>

          {crimesQuery.isLoading ? (
            <div style={{ ...s.card, textAlign: "center", padding: "2rem" }}>
              <RefreshCw size={24} className="spin" style={{ margin: "0 auto", opacity: 0.5 }} />
            </div>
          ) : crimes.length === 0 ? (
            <div style={{ ...s.card, textAlign: "center", padding: "1.5rem" }}>
              <MapPin size={24} style={{ color: "var(--text-secondary, #94a3b8)", margin: "0 auto 0.5rem" }} />
              <div style={{ color: "var(--text-secondary, #94a3b8)" }}>
                No crime incidents logged within {radiusFilter} miles of HQ in the last 7 days.
              </div>
            </div>
          ) : (
            <>
              <MapContainer height="600px">
                <DeckGL
                  layers={crimeLayers}
                  initialViewState={crimeMapViewState}
                  controller={true}
                  style={{ height: "600px", width: "100%" }}
                  getTooltip={crimeTooltip}
                >
                  <Map mapStyle="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json" />
                </DeckGL>
              </MapContainer>

              <hr style={s.divider} />

              <div>
                <h4 style={{ margin: "0 0 0.75rem", color: "var(--text-primary, #e2e8f0)", fontSize: "1rem" }}>
                  Raw Incident Logs ({radiusFilter} Mile Radius) — {crimes.length} incidents
                </h4>
                <div style={{ overflowX: "auto" }}>
                  <table style={{
                    width: "100%",
                    borderCollapse: "collapse",
                    fontSize: "0.8rem",
                    color: "var(--text-primary, #e2e8f0)",
                  }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid var(--border-primary, #334155)" }}>
                        <th style={{ padding: "0.5rem", textAlign: "left", color: "var(--text-secondary, #94a3b8)", fontWeight: 600 }}>Timestamp</th>
                        <th style={{ padding: "0.5rem", textAlign: "left", color: "var(--text-secondary, #94a3b8)", fontWeight: 600 }}>Distance</th>
                        <th style={{ padding: "0.5rem", textAlign: "left", color: "var(--text-secondary, #94a3b8)", fontWeight: 600 }}>Category</th>
                        <th style={{ padding: "0.5rem", textAlign: "left", color: "var(--text-secondary, #94a3b8)", fontWeight: 600 }}>Severity</th>
                        <th style={{ padding: "0.5rem", textAlign: "left", color: "var(--text-secondary, #94a3b8)", fontWeight: 600 }}>Title</th>
                      </tr>
                    </thead>
                    <tbody>
                      {crimes.map((c: any) => (
                        <tr
                          key={c.id}
                          onClick={() => setSelectedCrimeId(c.id === selectedCrimeId ? null : c.id)}
                          style={{
                            cursor: "pointer",
                            borderBottom: "1px solid var(--border-primary, #1e293b)",
                            background: c.id === selectedCrimeId ? "var(--accent-blue-dim, rgba(56,189,248,0.1))" : "transparent",
                            transition: "background 0.1s",
                          }}
                          onMouseEnter={e => { if (c.id !== selectedCrimeId) (e.currentTarget as HTMLElement).style.background = "var(--bg-tertiary, #0f172a)"; }}
                          onMouseLeave={e => { if (c.id !== selectedCrimeId) (e.currentTarget as HTMLElement).style.background = "transparent"; }}
                        >
                           <td style={{ padding: "0.4rem 0.5rem", whiteSpace: "nowrap" }}>{formatInChicago(c.timestamp)}</td>
                          <td style={{ padding: "0.4rem 0.5rem", whiteSpace: "nowrap" }}>{c.distance_miles?.toFixed(1)} mi</td>
                          <td style={{ padding: "0.4rem 0.5rem" }}>
                            <span style={{
                              ...s.badge,
                              background: c.category?.toLowerCase().includes("violent") || c.category?.toLowerCase().includes("assault")
                                ? "#dc2626" : c.category?.toLowerCase().includes("theft") || c.category?.toLowerCase().includes("property")
                                ? "#f59e0b" : c.category?.toLowerCase().includes("trespass") || c.category?.toLowerCase().includes("disturbance")
                                ? "#eab308" : "#6366f1",
                            }}>
                              {c.category}
                            </span>
                          </td>
                          <td style={{ padding: "0.4rem 0.5rem" }}>{c.severity}</td>
                          <td style={{ padding: "0.4rem 0.5rem", color: "var(--text-secondary, #94a3b8)" }}>{truncate(c.raw_title, 80)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
    </div>
  );
}
