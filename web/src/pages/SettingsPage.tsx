import { useState, useEffect, useMemo, useCallback } from "react";
import { getAllowedTabs } from "../utils/permissions";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api, { getApiErrorMessage } from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { hasActionPermission, isAdministrator } from "../utils/permissions";
import { UsersRolesTab } from "../components/UsersRolesTab";
import { ApplicationSettingsTab } from "../components/ApplicationSettingsTab";
import {
  Trash2, Upload, Download, RefreshCw, AlertTriangle, Save,
   Key, Shield, Settings as SettingsIcon, Database, FileJson,
  Rss, Cpu, Brain, Mail, Users, HardDrive, Skull, Server, Globe,
  FileSpreadsheet, Plus, Eye, EyeOff, X, User, Loader2, Palette,
  Pin, PinOff, ThumbsUp, ThumbsDown
} from "lucide-react";
import { ThemeSelector } from "../components/ThemeSelector";
import DeckGL from "@deck.gl/react";
import { ScatterplotLayer } from "@deck.gl/layers";
import { Map } from "@vis.gl/react-maplibre";
import "maplibre-gl/dist/maplibre-gl.css";

const TABS = [
  { id: "profile", label: "Profile", icon: User },
  { id: "theme", label: "Theme", icon: Palette },
  { id: "facilities", label: "Facilities", icon: Globe },
  { id: "assets", label: "Internal Assets", icon: Server },
  { id: "rss", label: "RSS Sources", icon: Rss },
  { id: "ml", label: "ML Training", icon: Brain },
  { id: "ai-smtp", label: "AI & SMTP", icon: SettingsIcon },
  { id: "application", label: "Application Settings", icon: Shield },
  { id: "users", label: "Users & Roles", icon: Users },
  { id: "backup", label: "Backup & Restore", icon: HardDrive },
  { id: "danger", label: "Danger Zone", icon: Skull },
];

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

function TabButton({ active, label, icon: Icon, onClick }: { active: boolean; label: string; icon: any; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: active ? "var(--accent-blue)" : "transparent",
        color: active ? "#fff" : "var(--text-secondary)",
        border: `1px solid ${active ? "var(--accent-blue)" : "var(--border-primary)"}`,
        borderRadius: "var(--radius-sm)",
        padding: "0.45rem 0.75rem",
        cursor: "pointer",
        fontWeight: active ? 700 : 500,
        fontSize: "0.78rem",
        display: "inline-flex",
        alignItems: "center",
        gap: "0.35rem",
        whiteSpace: "nowrap",
      }}
    >
      <Icon size={14} />
      {label}
    </button>
  );
}

function Card({ title, children, icon: Icon, wide }: { title: string; children: React.ReactNode; icon?: any; wide?: boolean }) {
  return (
    <div style={{
      background: "var(--bg-card)",
      borderRadius: "var(--radius-md)",
      padding: "1rem",
      border: "1px solid var(--border-primary)",
      gridColumn: wide ? "1 / -1" : undefined,
    }}>
      <h3 style={{ margin: "0 0 0.9rem", fontSize: "0.95rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.4rem" }}>
        {Icon && <Icon size={16} />}
        {title}
      </h3>
      {children}
    </div>
  );
}

function SectionTitle({ text }: { text: string }) {
  return <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.85rem", color: "var(--text-secondary)" }}>{text}</h4>;
}

export function SettingsPage() {
  const { user: currentUser, refreshUser } = useAuth();
  const allowedSettingsTabs = getAllowedTabs(currentUser?.allowed_actions, "settings");
  const [tab, setTab] = useState("profile");
  const queryClient = useQueryClient();
  const isAdmin = isAdministrator(currentUser);

  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ["settings-config"],
    queryFn: () => api.get("/settings/config").then(r => r.data),
    refetchInterval: 60000,
    enabled: tab === "ai-smtp",
  });

  const { data: locations, isLoading: locationsLoading, isError: locationsError, refetch: refetchLocations } = useQuery({
    queryKey: ["admin-locations"],
    queryFn: () => api.get("/settings/facilities").then(r => r.data),
    retry: 2,
    refetchOnMount: "always",
    enabled: tab === "facilities",
  });

  const { data: lists } = useQuery({
    queryKey: ["admin-lists"],
    queryFn: () => api.get("/settings/rss").then(r => r.data),
    enabled: tab === "rss",
  });

  const { data: mlCounts } = useQuery({
    queryKey: ["application-ml-counts"],
    queryFn: () => api.get("/application-settings/ml-counts").then(r => r.data),
    enabled: tab === "ml",
  });

  const saveConfigMutation = useMutation({
    mutationFn: (data: any) => {
      const payload = { ...data };
      if (!String(payload.llm_api_key || "").trim()) delete payload.llm_api_key;
      if (!String(payload.smtp_password || "").trim()) delete payload.smtp_password;
      return api.post("/admin/config", payload);
    },
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["settings-config"] }); alert("Configuration saved."); },
    onError: (e: any) => alert(getApiErrorMessage(e, "Configuration could not be saved.")),
  });

  // Tab grants control visibility. Component-level action checks decide which
  // controls are available, while sensitive APIs continue to enforce access.
  const filteredTabs = TABS.filter(t =>
    t.id === "profile" || t.id === "theme" || isAdmin || allowedSettingsTabs.includes(t.id)
  );

  useEffect(() => {
    if (!filteredTabs.some(item => item.id === tab)) {
      setTab(filteredTabs[0]?.id || "profile");
    }
  }, [filteredTabs.map(item => item.id).join(","), tab]);

  return (
    <div style={{ padding: "1.5rem" }}>
      <h2 style={{ margin: "0 0 1rem", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <SettingsIcon size={22} />
        Settings & Admin
      </h2>
      <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap", marginBottom: "1.25rem" }}>
        {filteredTabs.map(t => (
          <TabButton key={t.id} active={tab === t.id} label={t.label} icon={t.icon} onClick={() => setTab(t.id)} />
        ))}
      </div>

      {tab === "profile" && <ProfileTab user={currentUser} onProfileUpdated={refreshUser} />}
      {tab === "theme" && <ThemeTab />}
      {tab === "facilities" && <FacilitiesTab locations={locations} locationsLoading={locationsLoading} locationsError={locationsError} refetchLocations={refetchLocations} queryClient={queryClient} canEdit={isAdmin} />}
      {tab === "assets" && <AssetsTab canManage={isAdmin} />}
      {tab === "rss" && <RssTab lists={lists} queryClient={queryClient} canManage={isAdmin} />}
      {tab === "ml" && <MlTab mlCounts={mlCounts} canTrain={isAdmin || hasActionPermission(currentUser, "Action: Train ML Model")} />}
      {tab === "ai-smtp" && <AiSmtpTab config={config} configLoading={configLoading} saveConfigMutation={saveConfigMutation} readOnly={!isAdmin} />}
      {tab === "users" && <UsersRolesTab user={currentUser} />}
      {tab === "application" && <ApplicationSettingsTab user={currentUser} />}
      {tab === "backup" && <BackupRestoreTab isAdmin={isAdmin} />}
      {tab === "danger" && <DangerZoneTab isAdmin={isAdmin} />}
    </div>
  );
}

/* ============================
   0. PROFILE TAB
   ============================ */
function ProfileTab({ user, onProfileUpdated }: { user: any; onProfileUpdated: () => void }) {
  const [fullName, setFullName] = useState(user?.full_name || "");
  const [jobTitle, setJobTitle] = useState(user?.job_title || "");
  const [contactInfo, setContactInfo] = useState(user?.contact_info || "");
  const [defaultShift, setDefaultShift] = useState(user?.default_shift || "No Shift");
  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [recoveryEmail, setRecoveryEmail] = useState(user?.email || "");
  const [recoveryMessage, setRecoveryMessage] = useState("");
  const [recoveryError, setRecoveryError] = useState("");
  const [showPwd, setShowPwd] = useState(false);

  const updateProfile = useMutation({
    mutationFn: (data: any) => api.post("/auth/update-profile", data, { params: { username: user?.username } }),
    onSuccess: () => {
      onProfileUpdated();
      setOldPwd("");
      setNewPwd("");
    },
    onError: (e: any) => alert(getApiErrorMessage(e, "Profile could not be updated.")),
  });

  const requestRecoveryEmail = useMutation({
    mutationFn: () => api.post("/auth/request-recovery-email", { email: recoveryEmail }),
    onSuccess: (response) => {
      setRecoveryError("");
      setRecoveryMessage(response.data.message || "Your email request is awaiting administrator approval.");
      onProfileUpdated();
    },
    onError: (reason: any) => {
      setRecoveryMessage("");
      setRecoveryError(getApiErrorMessage(reason, "Recovery-email request could not be submitted."));
    },
  });
  const resendEmailVerification = useMutation({
    mutationFn: () => api.post("/auth/resend-recovery-email-verification"),
    onSuccess: response => setRecoveryMessage(response.data.message || "A new verification link was sent."),
    onError: (reason: any) => setRecoveryError(getApiErrorMessage(reason, "Unable to resend the verification email.")),
  });

  const handleSave = () => {
    updateProfile.mutate({
      full_name: fullName,
      job_title: jobTitle,
      contact_info: contactInfo,
      default_shift: defaultShift,
      old_password: oldPwd,
      new_password: newPwd,
    });
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem" }}>
      <Card title="Personal Information" icon={User}>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
          <div>
            <SectionTitle text="Username" />
            <input style={{ ...inputStyle, opacity: 0.6 }} value={user?.username || ""} disabled />
          </div>
          <div>
            <SectionTitle text="Full Name" />
            <input style={inputStyle} value={fullName} onChange={e => setFullName(e.target.value)} />
          </div>
          <div>
            <SectionTitle text="Job Title" />
            <input style={inputStyle} value={jobTitle} onChange={e => setJobTitle(e.target.value)} placeholder="e.g. Network Operations Analyst" />
          </div>
          <div>
            <SectionTitle text="Contact Info" />
            <input style={inputStyle} value={contactInfo} onChange={e => setContactInfo(e.target.value)} placeholder="e.g. NOC Desk / phone / email" />
          </div>
          <div>
            <SectionTitle text="Default Shift" />
            <select style={inputStyle} value={defaultShift} onChange={e => setDefaultShift(e.target.value)}>
              {["No Shift", "Morning", "Afternoon"].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
      </Card>

      <Card title="Change Password" icon={Key}>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
          <div>
            <SectionTitle text="Current Password" />
            <div style={{ position: "relative" }}>
              <input style={inputStyle} type={showPwd ? "text" : "password"} value={oldPwd} onChange={e => setOldPwd(e.target.value)} />
              <span onClick={() => setShowPwd(p => !p)} style={{ position: "absolute", right: 8, top: 8, cursor: "pointer", color: "var(--text-muted)" }}>
                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
              </span>
            </div>
          </div>
          <div>
            <SectionTitle text="New Password" />
            <input style={inputStyle} type={showPwd ? "text" : "password"} value={newPwd} onChange={e => setNewPwd(e.target.value)} />
          </div>
          <div style={{ marginTop: "0.4rem" }}>
            <SectionTitle text="Role" />
            <input style={{ ...inputStyle, opacity: 0.6 }} value={user?.role || ""} disabled />
          </div>
        </div>
      </Card>

      {user?.account_type !== "display" && <div style={{ gridColumn: "1 / -1" }}>
        <Card title="Password Recovery Email" icon={Mail}>
          <p style={{ margin: "0 0 0.75rem", color: "var(--text-muted)", fontSize: "0.8rem", lineHeight: 1.5 }}>
            This email is used to send a password-reset link if you forget your password. A user administrator must approve an email change, and the mailbox must be verified before it can be used for recovery.
          </p>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "end", flexWrap: "wrap" }}>
            <div style={{ flex: 1, minWidth: 240 }}>
              <SectionTitle text="Recovery email" />
              <input style={inputStyle} type="email" required maxLength={254} value={recoveryEmail} onChange={e => setRecoveryEmail(e.target.value)} placeholder="you@example.com" />
            </div>
            <button type="button" onClick={() => requestRecoveryEmail.mutate()} disabled={requestRecoveryEmail.isPending || !recoveryEmail.trim()} style={btn("var(--accent-purple)")}>
              <Mail size={14} /> {requestRecoveryEmail.isPending ? "Submitting..." : "Request email approval"}
            </button>
          </div>
          {(recoveryMessage || recoveryError) && <p role={recoveryError ? "alert" : "status"} style={{ color: recoveryError ? "var(--accent-red)" : "var(--accent-green)", fontSize: "0.8rem", marginBottom: 0 }}>{recoveryError || recoveryMessage}</p>}
          {user?.recovery_email_status === "pending_approval" && <p style={{ color: "var(--accent-orange)", fontSize: "0.78rem" }}>Request pending approval for {user.pending_email || "the new email address"}.</p>}
          {user?.recovery_email_status === "pending_approval" && ["admin", "administrator"].includes(String(user?.role || "").toLowerCase()) && <p role="status" style={{ color: "var(--text-muted)", fontSize: "0.76rem" }}>
            Another verified user administrator must approve this request. For a single-admin initial setup, configure the same address as `DEFAULT_ADMIN_EMAIL` and restart the API or worker.
          </p>}
          {user?.recovery_email_status === "pending_verification" && <p style={{ color: "var(--accent-orange)", fontSize: "0.78rem" }}>Administrator approval received. Check {user.pending_email || "the new email address"} for a verification link.</p>}
          {user?.recovery_email_status === "pending_verification" && <button type="button" onClick={() => resendEmailVerification.mutate()} disabled={resendEmailVerification.isPending} style={btn("var(--bg-tertiary)")}>{resendEmailVerification.isPending ? "Sending..." : "Resend verification email"}</button>}
        </Card>
      </div>}

      <div style={{ gridColumn: "1 / -1" }}>
        <button onClick={handleSave} disabled={updateProfile.isPending} style={btn("var(--accent-blue)")}>
          <Save size={14} /> {updateProfile.isPending ? "Saving..." : "Save Profile"}
        </button>
      </div>
    </div>
  );
}

/* ============================
   1. FACILITIES TAB
   ============================ */
function FacilitiesTab({ locations, locationsLoading, locationsError, refetchLocations, queryClient, canEdit }: { locations: any; locationsLoading: boolean; locationsError: boolean; refetchLocations: () => unknown; queryClient: any; canEdit: boolean }) {
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importMode, setImportMode] = useState<"add" | "upsert" | "replace">("add");
  const [editData, setEditData] = useState<any[]>([]);
  const [mapSite, setMapSite] = useState<{ name: string; lat: number; lon: number; type: string } | null>(null);

  const importMutation = useMutation({
    mutationFn: async ({ file, mode }: { file: File; mode: string }) => {
      const text = await file.text();
      const data = JSON.parse(text);
      return api.post("/admin/location/import", data, { params: { mode } });
    },
    onSuccess: () => {
      alert("Locations imported.");
      setImportFile(null);
      queryClient.invalidateQueries({ queryKey: ["admin-locations"] });
    },
    onError: (e: any) => alert("Import error: " + (e.response?.data?.detail || e.message)),
  });

  const saveMutation = useMutation({
    mutationFn: (data: any[]) => api.put("/admin/location", data),
    onSuccess: () => {
      alert("Locations saved.");
      queryClient.invalidateQueries({ queryKey: ["admin-locations"] });
    },
    onError: (e: any) => alert("Save error: " + (e.response?.data?.detail || e.message)),
  });

  const locs = Array.isArray(locations) ? locations : [];
  useEffect(() => {
    setEditData(locs.map((l: any) => ({ ...l })));
  }, [locations]);

  const updateRow = (i: number, field: string, val: any) => {
    setEditData(prev => {
      const next = [...prev];
      next[i] = { ...next[i], [field]: val };
      return next;
    });
  };

  const mapSites = useMemo(() => {
    return (locs ?? []).filter((l: any) => l.lat != null && l.lon != null).map((l: any) => ({
      name: l.name || "Unnamed",
      lat: l.lat,
      lon: l.lon,
      type: l.type || l.loc_type || "",
      alert_count: 0,
    }));
  }, [locs]);

  const mapLayers = useMemo(() => {
    if (mapSites.length === 0) return [];
    return [
      new ScatterplotLayer({
        id: "facilities",
        data: mapSites,
        getPosition: (d: any) => [d.lon, d.lat],
        getFillColor: [56, 189, 248, 200],
        getRadius: 1800,
        radiusMinPixels: 6,
        radiusMaxPixels: 15,
        pickable: true,
        stroked: true,
        getLineColor: [255, 255, 255, 200],
        lineWidthMinPixels: 1,
      }),
    ];
  }, [mapSites]);

  const handleMapClick = useCallback((info: any) => {
    if (info.object && info.layer?.id === "facilities") {
      setMapSite(info.object);
    }
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {locationsLoading && (
        <Card title="Facility Locations" icon={Globe}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            <Loader2 size={16} className="spin" /> Loading facility locations...
          </div>
        </Card>
      )}
      {locationsError && (
        <Card title="Facility Locations" icon={AlertTriangle}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem", color: "var(--accent-red)", fontSize: "0.85rem" }}>
            <span>Facility locations could not be loaded.</span>
            <button onClick={() => refetchLocations()} style={btn("var(--accent-blue)")}><RefreshCw size={14} /> Retry</button>
          </div>
        </Card>
      )}
      <Card title="Facility Map" icon={Globe} wide>
        <div style={{ height: "380px", position: "relative", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
          {mapSites.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", padding: "2rem", textAlign: "center" }}>No facility locations with coordinates loaded.</div>
          ) : (
            <DeckGL
              layers={mapLayers}
              initialViewState={{ latitude: 34.8, longitude: -92.2, zoom: 6, pitch: 0 }}
              controller={true}
              style={{ height: "100%" }}
              onClick={handleMapClick}
              getCursor={({ isDragging, isHovering }: any) => isDragging ? "grabbing" : isHovering ? "pointer" : "default"}
            >
              <Map mapStyle="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json" />
            </DeckGL>
          )}
        </div>
        {mapSite && (
          <div style={{
            position: "fixed", inset: 0, zIndex: 1000,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: "rgba(0,0,0,0.5)",
          }} onClick={() => setMapSite(null)}>
            <div onClick={(e) => e.stopPropagation()} style={{
              background: "var(--bg-card)", color: "var(--text-primary)",
              borderRadius: "var(--radius-md)", padding: "1.25rem",
              minWidth: 280, maxWidth: 360,
              boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
              border: "1px solid var(--border-primary)",
              fontSize: "0.82rem", lineHeight: 1.5,
            }}>
              <div style={{ fontWeight: 700, marginBottom: "0.75rem", fontSize: "0.9rem", borderBottom: "1px solid var(--border-primary)", paddingBottom: "0.3rem" }}>
                {mapSite.name}
              </div>
              <div style={{ marginBottom: "0.3rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Type: </span>
                <strong>{mapSite.type || "N/A"}</strong>
              </div>
              <div style={{ marginBottom: "0.3rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Latitude: </span>
                {mapSite.lat.toFixed(4)}
              </div>
              <div style={{ marginBottom: "0.3rem" }}>
                <span style={{ color: "var(--text-muted)" }}>Longitude: </span>
                {mapSite.lon.toFixed(4)}
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "0.75rem", borderTop: "1px solid var(--border-primary)", paddingTop: "0.5rem" }}>
                <button onClick={() => setMapSite(null)}
                  style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.3rem 0.7rem", fontSize: "0.78rem", cursor: "pointer" }}>
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </Card>
      {!canEdit && <Card title="Facility Directory" icon={FileSpreadsheet} wide>
        <p style={{ marginTop: 0, color: "var(--text-muted)", fontSize: "0.78rem" }}>This tab is read-only for your role. An administrator manages location imports and edits.</p>
        {locs.length === 0 ? <p style={{ color: "var(--text-muted)", fontSize: "0.82rem" }}>No locations are available for your assigned site types.</p> : (
          <div style={{ maxHeight: 320, overflowY: "auto" }}>
            {locs.map((location: any) => <div key={location.id ?? location.name} style={{ display: "flex", justifyContent: "space-between", gap: "0.75rem", padding: "0.4rem 0", borderBottom: "1px solid var(--border-primary)", fontSize: "0.78rem" }}>
              <strong>{location.name}</strong>
              <span style={{ color: "var(--text-muted)", textAlign: "right" }}>{location.loc_type || location.type || "Unknown type"} · {location.district || "Unknown district"}</span>
            </div>)}
          </div>
        )}
      </Card>}
      {canEdit && <>
      <Card title="Mass Import JSON" icon={Upload}>
        <input
          type="file"
          accept=".json"
          onChange={e => setImportFile(e.target.files?.[0] || null)}
          style={{ marginBottom: "0.6rem", color: "var(--text-primary)", fontSize: "0.8rem" }}
        />
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", marginBottom: "0.6rem" }}>
          {(["add", "upsert", "replace"] as const).map(m => (
            <label key={m} style={{ fontSize: "0.78rem", color: "var(--text-secondary)", cursor: "pointer", display: "flex", alignItems: "center", gap: "0.25rem" }}>
              <input type="radio" name="importMode" value={m} checked={importMode === m} onChange={() => setImportMode(m)} />
              {m === "add" ? "Add new only" : m === "upsert" ? "Update existing" : "Replace all"}
            </label>
          ))}
        </div>
        <button
          onClick={() => importFile && importMutation.mutate({ file: importFile, mode: importMode })}
          disabled={!importFile || importMutation.isPending}
          style={btn(importMode === "replace" ? "var(--accent-red)" : "var(--accent-blue)")}
        >
          <Upload size={14} />
          {importMutation.isPending ? "Importing..." : `Import (${importMode})`}
        </button>
      </Card>

      <Card title="Manual Adjustments" icon={FileJson} wide>
        {locs.length === 0 ? (
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>No locations loaded yet.</p>
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-primary)" }}>
                    {["Name", "Site Type", "District", "Priority", "Lat", "Lon", "ID"].map(h => (
                      <th key={h} style={{ padding: "0.4rem 0.5rem", textAlign: "left", color: "var(--text-secondary)" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {editData.map((row: any, i: number) => (
                    <tr key={row.id || i} style={{ borderBottom: "1px solid var(--border-primary)" }}>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 110 }} value={row.name || ""} onChange={e => updateRow(i, "name", e.target.value)} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 90 }} value={row.loc_type || ""} onChange={e => updateRow(i, "loc_type", e.target.value)} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 90 }} value={row.district || ""} onChange={e => updateRow(i, "district", e.target.value)} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 90 }} value={row.priority ?? ""} onChange={e => updateRow(i, "priority", e.target.value)} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 80 }} type="number" step="any" value={row.lat ?? ""} onChange={e => updateRow(i, "lat", Number(e.target.value))} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 80 }} type="number" step="any" value={row.lon ?? ""} onChange={e => updateRow(i, "lon", Number(e.target.value))} />
                      </td>
                      <td style={{ padding: "0.25rem 0.5rem", color: "var(--text-muted)", fontSize: "0.7rem" }}>{row.id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <button
              onClick={() => saveMutation.mutate(editData)}
              disabled={saveMutation.isPending}
              style={{ ...btn("var(--accent-green)"), marginTop: "0.75rem" }}
            >
              <Save size={14} />
              {saveMutation.isPending ? "Saving..." : "Save Changes"}
            </button>
          </>
        )}
      </Card>
      </>}
    </div>
  );
}

/* ============================
   2. INTERNAL ASSETS TAB
   ============================ */
function AssetsTab({ canManage }: { canManage: boolean }) {
  const [swFile, setSwFile] = useState<File | null>(null);
  const [hwFile, setHwFile] = useState<File | null>(null);
  const queryClient = useQueryClient();

  if (!canManage) {
    return <div role="status" style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "1rem", color: "var(--text-secondary)" }}>
      You can open Internal Assets settings, but asset imports are administrator-managed.
    </div>;
  }

  const uploadSw = useMutation({
    mutationFn: (file: File) => {
      const reader = new FileReader();
      return new Promise((resolve, reject) => {
        reader.onload = () => {
          const text = reader.result as string;
          const lines = text.split("\n").filter(Boolean);
          const header = lines[0].toLowerCase();
          if (!header.includes("name")) return reject(new Error("CSV must contain a 'name' column"));
          api.post("/admin/assets/software", { csv_body: text }).then(resolve).catch(reject);
        };
        reader.onerror = () => reject(new Error("Failed to read file"));
        reader.readAsText(file);
      });
    },
    onSuccess: (res: any) => { alert(res?.data?.message || "Software assets uploaded."); setSwFile(null); queryClient.invalidateQueries({ queryKey: ["settings-config"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const uploadHw = useMutation({
    mutationFn: (file: File) => {
      const reader = new FileReader();
      return new Promise((resolve, reject) => {
        reader.onload = () => {
          const text = reader.result as string;
          const lines = text.split("\n").filter(Boolean);
          const header = lines[0].toLowerCase();
          if (!header.includes("ip")) return reject(new Error("CSV must contain an 'IP Address' column"));
          api.post("/admin/assets/hardware", { csv_body: text }).then(resolve).catch(reject);
        };
        reader.onerror = () => reject(new Error("Failed to read file"));
        reader.readAsText(file);
      });
    },
    onSuccess: (res: any) => { alert(res?.data?.message || "Hardware assets uploaded."); setHwFile(null); queryClient.invalidateQueries({ queryKey: ["settings-config"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <Card title="Software Assets" icon={Cpu}>
        <p style={{ color: "var(--text-muted)", fontSize: "0.75rem", margin: "0 0 0.6rem" }}>CSV with <strong>name</strong> column required.</p>
        <input
          type="file"
          accept=".csv"
          onChange={e => setSwFile(e.target.files?.[0] || null)}
          style={{ marginBottom: "0.6rem", color: "var(--text-primary)", fontSize: "0.8rem" }}
        />
        <button onClick={() => swFile && uploadSw.mutate(swFile)} disabled={!swFile || uploadSw.isPending} style={btn("var(--accent-blue)")}>
          <Upload size={14} /> {uploadSw.isPending ? "Uploading..." : "Upload"}
        </button>
      </Card>

      <Card title="Hardware Assets" icon={Server}>
        <p style={{ color: "var(--text-muted)", fontSize: "0.75rem", margin: "0 0 0.6rem" }}>CSV with <strong>IP Address</strong> column required.</p>
        <input
          type="file"
          accept=".csv"
          onChange={e => setHwFile(e.target.files?.[0] || null)}
          style={{ marginBottom: "0.6rem", color: "var(--text-primary)", fontSize: "0.8rem" }}
        />
        <button onClick={() => hwFile && uploadHw.mutate(hwFile)} disabled={!hwFile || uploadHw.isPending} style={btn("var(--accent-blue)")}>
          <Upload size={14} /> {uploadHw.isPending ? "Uploading..." : "Upload"}
        </button>
      </Card>
    </div>
  );
}

/* ============================
   3. RSS SOURCES TAB
   ============================ */
function RssTab({ lists, queryClient, canManage }: { lists: any; queryClient: any; canManage: boolean }) {
  const [kwText, setKwText] = useState("");
  const [feedText, setFeedText] = useState("");
  const [editingKwId, setEditingKwId] = useState<number | null>(null);
  const [editWeight, setEditWeight] = useState("");

  const kwBulk = useMutation({
    mutationFn: (text: string) => {
      return api.post("/admin/keywords/bulk", null, { params: { raw_text: text } });
    },
    onSuccess: () => { alert("Keywords added."); setKwText(""); queryClient.invalidateQueries({ queryKey: ["admin-lists"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const feedBulk = useMutation({
    mutationFn: (text: string) => {
      return api.post("/admin/feeds/bulk", null, { params: { raw_text: text } });
    },
    onSuccess: () => { alert("Feeds added."); setFeedText(""); queryClient.invalidateQueries({ queryKey: ["admin-lists"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const delKw = useMutation({
    mutationFn: (id: number) => api.delete(`/admin/keywords/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-lists"] }),
  });

  const patchKw = useMutation({
    mutationFn: ({ id, weight }: { id: number; weight: number }) => api.patch(`/admin/keywords/${id}`, { weight }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["admin-lists"] }); setEditingKwId(null); },
    onError: (e: any) => alert("Error updating weight: " + (e.response?.data?.detail || e.message)),
  });

  const delFeed = useMutation({
    mutationFn: (id: number) => api.delete(`/admin/feeds/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-lists"] }),
  });

  const togglePinMut = useMutation({
    mutationFn: (articleId: number) => api.post("/dashboard/articles/toggle-pin", null, { params: { article_id: articleId } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["settings-articles"] }); },
  });

  const boostScoreMut = useMutation({
    mutationFn: (articleId: number) => api.post("/dashboard/articles/boost-score", null, { params: { article_id: articleId, amount: 15 } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["settings-articles"] }); },
  });

  const feedbackMut = useMutation({
    mutationFn: ({ articleId, feedback }: { articleId: number; feedback: number }) =>
      api.post("/dashboard/articles/feedback", null, { params: { article_id: articleId, feedback } }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["settings-articles"] }); },
  });

  const { data: recentArticles } = useQuery({
    queryKey: ["settings-articles"],
    queryFn: () => api.get("/threat/articles", { params: { category: "live", page: 1, page_size: 20 } }).then(r => r.data),
    refetchInterval: 60000,
    enabled: canManage,
  });

  const keywords = lists?.keywords ?? [];
  const feeds = lists?.feeds ?? [];
  const articles: any[] = recentArticles?.items ?? [];

  if (!canManage) {
    return <div style={{ display: "grid", gap: "1.25rem" }}>
      <div role="status" style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "0.75rem 1rem", color: "var(--text-secondary)", fontSize: "0.8rem" }}>
        Read-only access. An administrator manages RSS feeds, scoring keywords, and article feedback.
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem" }}>
        <Card title="Keywords" icon={Globe}>
          {keywords.length ? keywords.map((keyword: any) => <div key={keyword.id ?? keyword.word} style={{ padding: "0.35rem 0", borderBottom: "1px solid var(--border-primary)", fontSize: "0.8rem", color: "var(--text-primary)" }}>{keyword.word} <span style={{ color: "var(--text-muted)" }}>w:{keyword.weight}</span></div>) : <p style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>No keywords configured.</p>}
        </Card>
        <Card title="RSS Feeds" icon={Rss}>
          {feeds.length ? feeds.map((feed: any) => <div key={feed.id ?? feed.url} style={{ padding: "0.35rem 0", borderBottom: "1px solid var(--border-primary)", fontSize: "0.8rem" }}><div style={{ color: "var(--text-primary)" }}>{feed.name}</div><div style={{ color: "var(--text-muted)", fontSize: "0.7rem", overflowWrap: "anywhere" }}>{feed.url}</div></div>) : <p style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>No feeds configured.</p>}
        </Card>
      </div>
    </div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem" }}>
        <Card title="Keywords" icon={Globe}>
          <SectionTitle text='Add keywords (one per line: "word, weight")' />
          <textarea
            style={{ ...textareaStyle, marginBottom: "0.5rem" }}
            placeholder="critical, 5&#10;emergency, 4&#10;outage, 3"
            value={kwText}
            onChange={e => setKwText(e.target.value)}
          />
          <button onClick={() => kwText && kwBulk.mutate(kwText)} disabled={!kwText || kwBulk.isPending} style={btn("var(--accent-cyan)")}>
            <Plus size={14} /> {kwBulk.isPending ? "Adding..." : "Bulk Add"}
          </button>

          <div style={{ marginTop: "1rem", maxHeight: 220, overflowY: "auto" }}>
            {keywords.map((kw: any) => (
              <div key={kw.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.3rem 0", borderBottom: "1px solid var(--border-primary)", fontSize: "0.8rem" }}>
                <span style={{ color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "0.3rem" }}>
                  {kw.word}
                  {editingKwId === kw.id ? (
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={editWeight}
                      onChange={e => setEditWeight(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === "Enter") {
                          const w = parseInt(editWeight, 10);
                          if (isNaN(w) || w < 1 || w > 100) { alert("Weight must be 1-100"); return; }
                          patchKw.mutate({ id: kw.id, weight: w });
                        }
                        if (e.key === "Escape") setEditingKwId(null);
                      }}
                      onBlur={() => {
                        const w = parseInt(editWeight, 10);
                        if (!isNaN(w) && w >= 1 && w <= 100) {
                          patchKw.mutate({ id: kw.id, weight: w });
                        } else {
                          setEditingKwId(null);
                        }
                      }}
                      autoFocus
                      style={{
                        width: 50, background: "var(--bg-primary)", color: "var(--text-primary)",
                        border: "1px solid var(--accent-cyan)", borderRadius: "var(--radius-sm)",
                        padding: "0.1rem 0.25rem", fontSize: "0.75rem", textAlign: "center",
                      }}
                    />
                  ) : (
                    <span
                      onClick={() => { setEditingKwId(kw.id); setEditWeight(String(kw.weight)); }}
                      style={{ color: "var(--accent-cyan)", cursor: "pointer", fontSize: "0.7rem", borderBottom: "1px dashed var(--text-muted)" }}
                      title="Click to edit weight"
                    >
                      w:{kw.weight}
                    </span>
                  )}
                </span>
                <button onClick={() => delKw.mutate(kw.id)} style={{ background: "none", border: "none", color: "var(--accent-red)", cursor: "pointer", padding: 2 }}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        </Card>

        <Card title="RSS Feeds" icon={Rss}>
          <SectionTitle text='Add feeds (one per line: "URL, Name")' />
          <textarea
            style={{ ...textareaStyle, marginBottom: "0.5rem" }}
            placeholder="https://example.com/rss, Example Feed&#10;https://other.com/feed, Other"
            value={feedText}
            onChange={e => setFeedText(e.target.value)}
          />
          <button onClick={() => feedText && feedBulk.mutate(feedText)} disabled={!feedText || feedBulk.isPending} style={btn("var(--accent-orange)")}>
            <Plus size={14} /> {feedBulk.isPending ? "Adding..." : "Bulk Add"}
          </button>

          <div style={{ marginTop: "1rem", maxHeight: 220, overflowY: "auto" }}>
            {feeds.map((f: any) => (
              <div key={f.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.3rem 0", borderBottom: "1px solid var(--border-primary)", fontSize: "0.8rem" }}>
                <div style={{ overflow: "hidden" }}>
                  <div style={{ color: "var(--text-primary)", fontWeight: 500 }}>{f.name}</div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.7rem", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 260 }}>{f.url}</div>
                </div>
                <button onClick={() => delFeed.mutate(f.id)} style={{ background: "none", border: "none", color: "var(--accent-red)", cursor: "pointer", padding: 2 }}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Article Feedback Queue" icon={Brain} wide>
        <p style={{ color: "var(--text-muted)", fontSize: "0.75rem", margin: "0 0 0.75rem" }}>
          Recent articles — use Keep/Dismiss to train keyword weights, Pin to bookmark, +15 Score to elevate.
        </p>
        {articles.length === 0 ? (
          <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", padding: "1rem 0", textAlign: "center" }}>No articles loaded. Fetch RSS feeds to populate.</div>
        ) : (
          <div style={{ maxHeight: 400, overflowY: "auto" }}>
            {articles.map((art: any) => (
              <div key={art.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "0.5rem 0", borderBottom: "1px solid var(--border-primary)", gap: "0.5rem" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: "var(--text-primary)", fontSize: "0.82rem", fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {art.title}
                  </div>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.7rem" }}>
                    {art.source} &middot; Score: {art.score ?? "?"} &middot; {art.category}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "0.25rem", flexShrink: 0 }}>
                  <button onClick={() => togglePinMut.mutate(art.id)} style={{ background: "none", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", color: art.is_pinned ? "var(--accent-red)" : "var(--text-secondary)", cursor: "pointer", padding: "0.2rem 0.35rem", fontSize: "0.7rem", display: "inline-flex", alignItems: "center", gap: "0.15rem" }}>
                    {art.is_pinned ? <PinOff size={11} /> : <Pin size={11} />} {art.is_pinned ? "Unpin" : "Pin"}
                  </button>
                  <button onClick={() => boostScoreMut.mutate(art.id)} style={{ background: "none", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", color: "var(--text-secondary)", cursor: "pointer", padding: "0.2rem 0.35rem", fontSize: "0.7rem", display: "inline-flex", alignItems: "center", gap: "0.15rem" }}>
                    +15
                  </button>
                  <button onClick={() => feedbackMut.mutate({ articleId: art.id, feedback: 2 })} style={{ background: "none", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", color: "var(--accent-green)", cursor: "pointer", padding: "0.2rem 0.35rem", fontSize: "0.7rem", display: "inline-flex", alignItems: "center", gap: "0.15rem" }}>
                    <ThumbsUp size={11} /> Keep
                  </button>
                  <button onClick={() => feedbackMut.mutate({ articleId: art.id, feedback: 1 })} style={{ background: "none", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", color: "#f87171", cursor: "pointer", padding: "0.2rem 0.35rem", fontSize: "0.7rem", display: "inline-flex", alignItems: "center", gap: "0.15rem" }}>
                    <ThumbsDown size={11} /> Dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

/* ============================
   4. ML TRAINING TAB
   ============================ */
function MlTab({ mlCounts, canTrain }: { mlCounts: any; canTrain: boolean }) {
  const queryClient = useQueryClient();
  const retrain = useMutation({
    mutationFn: () => api.post("/application-settings/ml-retrain"),
    onSuccess: () => { alert("Model retrained."); queryClient.invalidateQueries({ queryKey: ["application-ml-counts"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem" }}>
        <Card title="Total Samples" icon={Database}>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-blue)" }}>{mlCounts?.total ?? 0}</div>
        </Card>
        <Card title="Positives (Kept)" icon={Brain}>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-orange)" }}>{mlCounts?.positive ?? 0}</div>
        </Card>
        <Card title="Negatives (Dismissed)" icon={Brain}>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-red)" }}>{mlCounts?.negative ?? 0}</div>
        </Card>
      </div>
      <Card title="Model Training">
        {canTrain ? <button onClick={() => retrain.mutate()} disabled={retrain.isPending} style={btn("var(--accent-cyan)")}>
          {retrain.isPending ? <Loader2 size={14} className="spin" /> : <RefreshCw size={14} />}
          {retrain.isPending ? "Training..." : "Retrain Model Now"}
        </button> : <p role="status" style={{ color: "var(--text-muted)", fontSize: "0.8rem", margin: 0 }}>Your role can view training statistics. Retraining requires the Train ML Model action.</p>}
      </Card>
    </div>
  );
}

/* ============================
   5. AI & SMTP TAB
   ============================ */
function AiSmtpTab({ config, configLoading, saveConfigMutation, readOnly }: { config: any; configLoading: boolean; saveConfigMutation: any; readOnly: boolean }) {
  const [form, setForm] = useState<any>(null);
  const [showKey, setShowKey] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const testConnectionMutation = useMutation({
    mutationFn: () => api.post("/llm/test-connection", {
      llm_endpoint: form?.llm_endpoint || "",
      llm_api_key: form?.llm_api_key || "",
      llm_model_name: form?.llm_model_name || "",
    }),
    onSuccess: (res) => setTestResult(res.data),
    onError: (e: any) => setTestResult({ success: false, message: e.response?.data?.detail || e.message }),
  });

  if (!configLoading && config && !form) {
    setForm({
      llm_endpoint: config.llm_endpoint || "",
      llm_api_key: config.llm_api_key || "",
      llm_model_name: config.llm_model_name || "",
      llm_context_window: config.llm_context_window ?? 128000,
      is_active: config.is_active ?? false,
      smtp_server: config.smtp_server || "",
      smtp_port: config.smtp_port ?? 587,
      smtp_username: config.smtp_username || "",
      smtp_password: config.smtp_password || "",
      smtp_sender: config.smtp_sender || "",
      smtp_recipient: config.smtp_recipient || "",
      smtp_enabled: config.smtp_enabled ?? false,
    });
  }

  const upd = (k: string, v: any) => setForm((prev: any) => ({ ...prev, [k]: v }));

  if (!form) {
    return <p style={{ color: "var(--text-muted)" }}>Loading configuration...</p>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {readOnly && <div role="status" style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "0.75rem 1rem", color: "var(--text-secondary)", fontSize: "0.8rem" }}>
        Read-only access. Only administrators can edit AI and SMTP configuration.
      </div>}
      <Card title="LLM Configuration" icon={Cpu}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <div>
            <SectionTitle text="Endpoint" />
            <input style={inputStyle} disabled={readOnly} value={form.llm_endpoint} onChange={e => upd("llm_endpoint", e.target.value)} placeholder="https://api.openai.com/v1" />
          </div>
          <div>
            <SectionTitle text="API Key" />
            <div style={{ display: "flex", gap: "0.3rem" }}>
              <input style={inputStyle} disabled={readOnly} type={showKey ? "text" : "password"} value={form.llm_api_key} onChange={e => upd("llm_api_key", e.target.value)} placeholder="sk-..." />
              {!readOnly && <button onClick={() => setShowKey(!showKey)} style={{ background: "none", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", color: "var(--text-secondary)", cursor: "pointer", padding: "0.35rem" }}>
                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>}
            </div>
          </div>
          <div>
            <SectionTitle text="Model Name" />
            <input style={inputStyle} disabled={readOnly} value={form.llm_model_name} onChange={e => upd("llm_model_name", e.target.value)} placeholder="gpt-4" />
          </div>
          <div>
            <SectionTitle text="Context Window" />
            <input style={inputStyle} disabled={readOnly} type="number" min={4096} step={4096} value={form.llm_context_window} onChange={e => upd("llm_context_window", Number(e.target.value))} placeholder="128000" />
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.6rem", flexWrap: "wrap" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.8rem", color: "var(--text-primary)", cursor: "pointer" }}>
            <input type="checkbox" disabled={readOnly} checked={form.is_active} onChange={e => upd("is_active", e.target.checked)} />
            Enable AI
          </label>
          {!readOnly && <button onClick={() => { setTestResult(null); testConnectionMutation.mutate(); }} disabled={testConnectionMutation.isPending} style={btn("var(--accent-cyan)")}>
            <RefreshCw size={14} /> {testConnectionMutation.isPending ? "Testing..." : "Test Connection"}
          </button>}
          {testResult && (
            <span style={{ fontSize: "0.78rem", color: testResult.success ? "var(--accent-green)" : "var(--accent-red)", fontWeight: 500 }}>
              {testResult.success ? "OK" : "FAIL"} &mdash; {testResult.message}
            </span>
          )}
        </div>
      </Card>

      <Card title="SMTP Broadcast" icon={Mail}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <div>
            <SectionTitle text="Server" />
            <input style={inputStyle} disabled={readOnly} value={form.smtp_server} onChange={e => upd("smtp_server", e.target.value)} placeholder="smtp.gmail.com" />
          </div>
          <div>
            <SectionTitle text="Port" />
            <input style={inputStyle} disabled={readOnly} type="number" value={form.smtp_port} onChange={e => upd("smtp_port", Number(e.target.value))} />
          </div>
          <div>
            <SectionTitle text="Username" />
            <input style={inputStyle} disabled={readOnly} value={form.smtp_username} onChange={e => upd("smtp_username", e.target.value)} />
          </div>
          <div>
            <SectionTitle text="Password" />
            <input style={inputStyle} disabled={readOnly} type="password" value={form.smtp_password} onChange={e => upd("smtp_password", e.target.value)} />
          </div>
          <div>
            <SectionTitle text="Sender" />
            <input style={inputStyle} disabled={readOnly} value={form.smtp_sender} onChange={e => upd("smtp_sender", e.target.value)} placeholder="noc@example.com" />
          </div>
          <div>
            <SectionTitle text="Recipient" />
            <input style={inputStyle} disabled={readOnly} value={form.smtp_recipient} onChange={e => upd("smtp_recipient", e.target.value)} placeholder="admin@example.com" />
          </div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginTop: "0.6rem", fontSize: "0.8rem", color: "var(--text-primary)", cursor: "pointer" }}>
          <input type="checkbox" disabled={readOnly} checked={form.smtp_enabled} onChange={e => upd("smtp_enabled", e.target.checked)} />
          SMTP Enabled
        </label>
      </Card>

      {!readOnly && <button onClick={() => saveConfigMutation.mutate(form)} disabled={saveConfigMutation.isPending} style={{ ...btn("var(--accent-green)"), alignSelf: "flex-start" }}>
        <Save size={14} /> {saveConfigMutation.isPending ? "Saving..." : "Save Configuration"}
      </button>}
    </div>
  );
}

/* ============================
   7. BACKUP & RESTORE TAB
   ============================ */
function BackupRestoreTab({ isAdmin }: { isAdmin: boolean }) {
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [importAllFile, setImportAllFile] = useState<File | null>(null);
  const [dbFile, setDbFile] = useState<File | null>(null);
  const [stageFile, setStageFile] = useState<File | null>(null);
  const [notice, setNotice] = useState("");
  const [activeRestoreId, setActiveRestoreId] = useState(() => sessionStorage.getItem("noc_restore_id") || "");
  const [restoreResult, setRestoreResult] = useState<any>(null);
  const queryClient = useQueryClient();

  const { data: legacyBackup, isLoading: legacyBackupLoading } = useQuery({
    queryKey: ["admin-backup"],
    queryFn: () => api.get("/admin/backup").then(r => r.data),
    enabled: isAdmin,
  });

  const { data: backupStatus } = useQuery({
    queryKey: ["admin-backups-status"],
    queryFn: () => api.get("/admin/backups/status").then(r => r.data),
    enabled: isAdmin,
  });
  const { data: fullBackups, isLoading: backupsLoading } = useQuery({
    queryKey: ["admin-backups"],
    queryFn: () => api.get("/admin/backups").then(r => r.data),
    enabled: isAdmin,
  });
  const { data: stagedBackups } = useQuery({
    queryKey: ["admin-staged-backups"],
    queryFn: () => api.get("/admin/backups/staged").then(r => r.data),
    enabled: isAdmin,
  });
  const { data: restoreStatus } = useQuery({
    queryKey: ["admin-backup-restore-status", activeRestoreId],
    queryFn: () => api.post("/restore-status", { restore_id: activeRestoreId }).then(r => r.data),
    enabled: !!activeRestoreId,
    refetchInterval: 1500,
    retry: 3,
  });

  useEffect(() => {
    if (!activeRestoreId || !["complete", "error"].includes(restoreStatus?.state)) return;
    setRestoreResult(restoreStatus);
    setActiveRestoreId("");
    sessionStorage.removeItem("noc_restore_id");
    if (restoreStatus.state === "complete") {
      setNotice("Restore completed. Existing sessions were revoked; sign in again to continue.");
    } else {
      setNotice(restoreStatus.message || "Restore failed. The current database was preserved or rolled back.");
    }
  }, [activeRestoreId, restoreStatus]);

  const downloadLegacyBackup = () => {
    if (!legacyBackup) return;
    const blob = new Blob([JSON.stringify(legacyBackup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `noc_legacy_backup_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const downloadFullExport = async () => {
    try {
      const res = await api.get("/admin/export-all");
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `noc_legacy_model_export_${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e: any) {
      setNotice(getApiErrorMessage(e, "Export failed."));
    }
  };

  const createBackupMutation = useMutation({
    mutationFn: () => api.post("/admin/backups"),
    onSuccess: (response) => {
      setNotice(`Encrypted full backup created: ${response.data.filename}`);
      queryClient.invalidateQueries({ queryKey: ["admin-backups"] });
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Could not create the full backup.")),
  });

  const stageBackupMutation = useMutation({
    mutationFn: (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return api.post("/admin/backups/staged", formData);
    },
    onSuccess: (response) => {
      const info = response.data;
      setNotice(`Backup authenticated and staged (${info.table_count} tables; ${info.model_included ? "model included" : "no model artifact"}).`);
      setStageFile(null);
      queryClient.invalidateQueries({ queryKey: ["admin-staged-backups"] });
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "The uploaded backup could not be validated.")),
  });

  const restoreStagedMutation = useMutation({
    mutationFn: (stageId: string) => api.post(`/admin/backups/staged/${encodeURIComponent(stageId)}/restore`),
    onSuccess: (response) => {
      const restoreId = response.data.restore_id;
      sessionStorage.setItem("noc_restore_id", restoreId);
      setActiveRestoreId(restoreId);
      setRestoreResult(null);
      setNotice("Restore started. API writes, scheduled jobs, and webhook intake are paused until it finishes.");
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Could not start the restore.")),
  });

  const deleteBackupMutation = useMutation({
    mutationFn: (backupId: string) => api.delete(`/admin/backups/${encodeURIComponent(backupId)}`),
    onSuccess: () => {
      setNotice("Manual backup deleted.");
      queryClient.invalidateQueries({ queryKey: ["admin-backups"] });
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Could not delete the backup.")),
  });

  const deleteStageMutation = useMutation({
    mutationFn: (stageId: string) => api.delete(`/admin/backups/staged/${encodeURIComponent(stageId)}`),
    onSuccess: () => {
      setNotice("Staged restore package deleted.");
      queryClient.invalidateQueries({ queryKey: ["admin-staged-backups"] });
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Could not delete the staged package.")),
  });

  const downloadEncryptedBackup = async (backupId: string) => {
    try {
      const response = await api.post(`/admin/backups/${encodeURIComponent(backupId)}/download-link`);
      const a = document.createElement("a");
      a.href = response.data.url;
      a.download = backupId;
      a.style.display = "none";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e: any) {
      setNotice(getApiErrorMessage(e, "Could not download the backup."));
    }
  };

  const restoreMutation = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      const data = JSON.parse(text);
      return api.post("/admin/restore", data);
    },
    onSuccess: () => { setNotice("Legacy restore completed."); queryClient.invalidateQueries(); },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Legacy restore failed.")),
  });

  const importAllMutation = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      const data = JSON.parse(text);
      return api.post("/admin/import-all", data);
    },
    onSuccess: (res) => {
      const counts = res.data?.counts;
      const summary = counts ? Object.entries(counts).filter(([,c]) => (c as number) > 0).map(([t, c]) => `${t}: ${c}`).join(", ") : "";
      setNotice(`Legacy full import completed. ${summary}`);
      queryClient.invalidateQueries();
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Legacy import failed.")),
  });

  const uploadDbMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return api.post("/admin/upload-db", formData);
    },
    onSuccess: (res) => {
      const counts = res.data?.counts;
      const summary = counts ? Object.entries(counts).filter(([,c]) => (c as number) > 0).map(([t, c]) => `${t}: ${c}`).join(", ") : "";
      setNotice(`Legacy database import completed. ${summary}`);
      queryClient.invalidateQueries();
    },
    onError: (e: any) => setNotice(getApiErrorMessage(e, "Legacy database import failed.")),
  });

  if (!isAdmin) {
    return <div role="status" style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "1rem", color: "var(--text-secondary)" }}>
      Backup and restore operations require administrator access.
    </div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      {notice && <div role="status" style={{ color: "var(--text-primary)", background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "0.75rem" }}>{notice}</div>}

      <Card title="Encrypted Full Backups" icon={HardDrive} wide>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: 0 }}>
          Complete SQLite online snapshots include every database table and the trained ML model when present. Archives use authenticated AES-256-GCM encryption.
          {backupStatus?.scheduled_policy ? ` ${backupStatus.scheduled_policy}` : " Scheduled backups run Sunday at 00:00 America/Chicago; the latest three are retained."}
        </p>
        {!backupStatus?.encryption_configured && <div role="alert" style={{ color: "var(--accent-orange)", margin: "0.75rem 0", fontSize: "0.8rem" }}>
          Configure BACKUP_ENCRYPTION_KEYS and BACKUP_ENCRYPTION_ACTIVE_KEY_ID in the deployment environment before creating or staging encrypted backups.
        </div>}
        <button
          onClick={() => createBackupMutation.mutate()}
          disabled={!backupStatus?.encryption_configured || createBackupMutation.isPending}
          style={btn("var(--accent-blue)")}
        >
          <HardDrive size={14} /> {createBackupMutation.isPending ? "Creating encrypted backup..." : "Create Full Backup"}
        </button>
        <p style={{ color: "var(--text-muted)", fontSize: "0.73rem", marginBottom: 0 }}>
          Manual backups are retained until explicitly deleted. Download copies to protected off-host storage; `.env` secrets are not included.
        </p>
        <div style={{ overflowX: "auto", marginTop: "1rem" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.78rem" }}>
            <thead><tr style={{ color: "var(--text-muted)", textAlign: "left" }}>
              <th style={{ padding: "0.5rem" }}>Created (UTC)</th><th>Kind</th><th>Size</th><th>Actions</th>
            </tr></thead>
            <tbody>
              {(fullBackups?.backups || []).map((item: any) => (
                <tr key={item.id} style={{ borderTop: "1px solid var(--border-primary)" }}>
                  <td style={{ padding: "0.55rem" }}>{new Date(item.created_at).toLocaleString("en-US", { timeZone: "UTC" })}</td>
                  <td>{item.kind === "scheduled" ? "Scheduled" : item.kind === "pre-restore" ? "Pre-restore safety" : "Manual"}</td>
                  <td>{formatBackupBytes(item.size_bytes)}</td>
                  <td style={{ display: "flex", gap: "0.4rem", padding: "0.45rem" }}>
                    <button onClick={() => downloadEncryptedBackup(item.id)} style={btn("var(--accent-cyan)")}><Download size={13} /> Download</button>
                    {item.kind !== "scheduled" && <button
                      onClick={() => window.confirm(`Delete ${item.kind === "pre-restore" ? "pre-restore safety" : "manual"} backup ${item.filename}?`) && deleteBackupMutation.mutate(item.id)}
                      disabled={deleteBackupMutation.isPending}
                      style={btn("var(--accent-red)")}
                    ><Trash2 size={13} /> Delete</button>}
                  </td>
                </tr>
              ))}
              {!backupsLoading && !(fullBackups?.backups || []).length && <tr><td colSpan={4} style={{ color: "var(--text-muted)", padding: "0.75rem" }}>No encrypted full backups yet.</td></tr>}
              {backupsLoading && <tr><td colSpan={4} style={{ color: "var(--text-muted)", padding: "0.75rem" }}>Loading backups…</td></tr>}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Restore an Encrypted Backup" icon={Upload} wide>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.8rem", marginTop: 0 }}>
          Uploading authenticates the encryption tag, checks hashes, and validates SQLite integrity. Restore starts here: API writes, scheduled jobs, and webhook intake pause while the database is migrated and atomically replaced. Keep enough free disk space for the package, current database, temporary restore files, and pre-restore safety snapshot.
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
          <input type="file" accept=".nocbackup" onChange={e => setStageFile(e.target.files?.[0] || null)}
            style={{ color: "var(--text-primary)", fontSize: "0.8rem", maxWidth: 420 }} />
          <button onClick={() => stageFile && stageBackupMutation.mutate(stageFile)}
            disabled={!stageFile || !backupStatus?.encryption_configured || stageBackupMutation.isPending}
            style={btn("var(--accent-orange)")}>
            <Upload size={14} /> {stageBackupMutation.isPending ? "Validating and staging..." : "Validate & Stage"}
          </button>
        </div>
        {activeRestoreId && <div role="status" aria-live="polite" style={{ marginTop: "0.9rem", padding: "0.75rem", border: "1px solid var(--accent-orange)", borderRadius: "var(--radius-sm)", color: "var(--text-primary)" }}>
          <strong>Restore in progress:</strong> {restoreStatus?.message || "Pausing writers and preparing the restore…"}
          {restoreStatus?.percent != null && <span> ({restoreStatus.percent}%)</span>}
        </div>}
        {restoreResult?.state === "complete" && restoreResult.result && <p role="status" style={{ color: "var(--accent-green)", fontSize: "0.78rem" }}>
          Restored {restoreResult.result.table_count} tables; {restoreResult.result.model_restored ? "the ML model was restored" : "no ML model was included"}. Safety backup: {restoreResult.result.pre_restore_backup || "not needed"}.
        </p>}
        <div style={{ display: "grid", gap: "0.8rem", marginTop: "1rem" }}>
          {(stagedBackups?.backups || []).map((item: any) => (
            <div key={item.stage_id} style={{ border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.75rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: "0.5rem", flexWrap: "wrap" }}>
                <span style={{ color: "var(--text-primary)", fontSize: "0.78rem" }}>{item.stage_id} · {formatBackupBytes(item.size_bytes)}</span>
                <button onClick={() => deleteStageMutation.mutate(item.stage_id)} disabled={deleteStageMutation.isPending}
                  style={btn("var(--accent-red)")}><Trash2 size={13} /> Remove staged file</button>
              </div>
              <p style={{ color: "var(--text-muted)", fontSize: "0.73rem", margin: "0.45rem 0" }}>
                Restore creates an encrypted pre-restore backup, invalidates restored sessions and outstanding account links, applies migrations, clears all staged restore packages on success, and resumes services when complete. You will need to sign in again.
              </p>
              <button
                onClick={() => window.confirm(`Restore ${item.stage_id}? Database writers will pause and all restored sessions will be revoked.`) && restoreStagedMutation.mutate(item.stage_id)}
                disabled={!!activeRestoreId || restoreStagedMutation.isPending}
                style={btn("var(--accent-orange)")}
              >
                <Database size={14} /> {restoreStagedMutation.isPending ? "Starting restore..." : "Restore now"}
              </button>
            </div>
          ))}
          {!(stagedBackups?.backups || []).length && <p style={{ color: "var(--text-muted)", fontSize: "0.75rem", margin: 0 }}>No staged restore packages.</p>}
        </div>
      </Card>

      <details style={{ color: "var(--text-secondary)", background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "0.8rem" }}>
        <summary style={{ cursor: "pointer", fontWeight: 700, fontSize: "0.8rem" }}>Legacy partial data migration tools</summary>
        <p style={{ fontSize: "0.73rem" }}>These older JSON and `.db` tools are partial imports/exports, not encrypted disaster-recovery backups. Prefer the full encrypted snapshots above.</p>
        <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap", marginBottom: "1rem" }}>
          <button onClick={downloadLegacyBackup} disabled={legacyBackupLoading || !legacyBackup} style={btn("var(--accent-blue)")}>
            <Download size={14} /> Download legacy 4-collection JSON
          </button>
          <button onClick={downloadFullExport} style={btn("var(--accent-cyan)")}>
            <Download size={14} /> Download legacy model export JSON
          </button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1rem" }}>
          <div>
            <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.8rem" }}>Restore legacy JSON (4 collections)</h4>
            <input type="file" accept=".json" onChange={e => setRestoreFile(e.target.files?.[0] || null)} style={{ marginBottom: "0.6rem", width: "100%" }} />
            <button onClick={() => restoreFile && restoreMutation.mutate(restoreFile)} disabled={!restoreFile || restoreMutation.isPending} style={btn("var(--accent-orange)")}>
              <Upload size={14} /> {restoreMutation.isPending ? "Restoring..." : "Restore legacy JSON"}
            </button>
          </div>
          <div>
            <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.8rem" }}>Import legacy model export JSON</h4>
            <input type="file" accept=".json" onChange={e => setImportAllFile(e.target.files?.[0] || null)} style={{ marginBottom: "0.6rem", width: "100%" }} />
            <button onClick={() => importAllFile && importAllMutation.mutate(importAllFile)} disabled={!importAllFile || importAllMutation.isPending} style={btn("var(--accent-green)")}>
              <FileJson size={14} /> {importAllMutation.isPending ? "Importing..." : "Import legacy JSON"}
            </button>
          </div>
          <div>
            <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.8rem" }}>Import rows from a `.db` file</h4>
            <input type="file" accept=".db" onChange={e => setDbFile(e.target.files?.[0] || null)} style={{ marginBottom: "0.6rem", width: "100%" }} />
            <button onClick={() => dbFile && uploadDbMutation.mutate(dbFile)} disabled={!dbFile || uploadDbMutation.isPending} style={btn("var(--accent-red)")}>
              <Database size={14} /> {uploadDbMutation.isPending ? "Importing..." : "Import legacy .db rows"}
            </button>
          </div>
        </div>
      </details>
    </div>
  );
}

function formatBackupBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "Unknown size";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(1)} ${units[unitIndex]}`;
}

/* ============================
   8. DANGER ZONE TAB
   ============================ */
function DangerZoneTab({ isAdmin }: { isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const [delRecord, setDelRecord] = useState({ model_name: "", record_id: "" });

  const nuke = useMutation({ mutationFn: () => api.post("/admin/nuke"), onSuccess: () => { alert("Tables nuked."); queryClient.invalidateQueries(); }, onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)) });
  const nukeCrime = useMutation({ mutationFn: () => api.post("/admin/nuke/crime"), onSuccess: () => { alert("Crime data nuked."); queryClient.invalidateQueries(); }, onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)) });
  const nukeWeather = useMutation({ mutationFn: () => api.post("/admin/nuke/weather"), onSuccess: () => { alert("Weather data nuked."); queryClient.invalidateQueries(); }, onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)) });
  const runMaint = useMutation({ mutationFn: () => api.post("/admin/maintenance"), onSuccess: () => { alert("Maintenance done."); }, onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)) });
  const clearEvents = useMutation({ mutationFn: () => api.post("/rca/clear-events"), onSuccess: () => { alert("Events cleared."); queryClient.invalidateQueries(); }, onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)) });
  const nukeAlerts = useMutation({ mutationFn: () => api.post("/rca/nuke-alerts"), onSuccess: () => { alert("Alerts nuked."); queryClient.invalidateQueries(); }, onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)) });

  const delRec = useMutation({
    mutationFn: ({ model_name, record_id }: any) => api.delete("/admin/record", { params: { model_name, record_id: Number(record_id) } }),
    onSuccess: () => { alert("Record deleted."); setDelRecord({ model_name: "", record_id: "" }); queryClient.invalidateQueries(); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  if (!isAdmin) {
    return <div role="status" style={{ background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-md)", padding: "1rem", color: "var(--text-secondary)" }}>
      Destructive database and alert actions are reserved for administrators.
    </div>;
  }

  const dangerBtn = (mutation: any, label: string, icon: any, color = "var(--accent-red)") => (
    <button onClick={() => { if (window.confirm(`Are you sure you want to ${label.toLowerCase()}?`)) mutation.mutate(); }} disabled={mutation.isPending} style={{ ...btn(color), fontSize: "0.75rem" }}>
      {icon} {mutation.isPending ? "Processing..." : label}
    </button>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <Card title="Delete Record" icon={Trash2}>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 140 }}>
            <SectionTitle text="Model Name" />
            <input style={inputStyle} placeholder="e.g. Crime" value={delRecord.model_name} onChange={e => setDelRecord(p => ({ ...p, model_name: e.target.value }))} />
          </div>
          <div style={{ flex: 1, minWidth: 100 }}>
            <SectionTitle text="Record ID" />
            <input style={inputStyle} type="number" placeholder="123" value={delRecord.record_id} onChange={e => setDelRecord(p => ({ ...p, record_id: e.target.value }))} />
          </div>
          <button onClick={() => { if (window.confirm(`Delete record ${delRecord.record_id} from ${delRecord.model_name}?`)) delRec.mutate(delRecord); }} disabled={delRec.isPending || !delRecord.model_name || !delRecord.record_id} style={btn("var(--accent-red)")}>
            <Trash2 size={14} /> {delRec.isPending ? "Deleting..." : "Delete"}
          </button>
        </div>
      </Card>

      <Card title="Destructive Actions" icon={AlertTriangle} wide>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
          {dangerBtn(nuke, "Nuke Tables", <Database size={13} />)}
          {dangerBtn(nukeCrime, "Nuke Crime Data", <FileSpreadsheet size={13} />)}
          {dangerBtn(nukeWeather, "Nuke Weather Data", <Cloud size={13} />)}
          {dangerBtn(runMaint, "Run DB Maintenance", <RefreshCw size={13} />, "var(--accent-orange)")}
          {dangerBtn(clearEvents, "Clear Timeline Events", <X size={13} />, "var(--accent-yellow)")}
          {dangerBtn(nukeAlerts, "Nuke Active Alerts", <AlertTriangle size={13} />)}
        </div>
      </Card>
    </div>
  );
}

/* ============================
   9. THEME TAB
   ============================ */
function ThemeTab() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <Card title="UI Theme" icon={Palette}>
        <ThemeSelector />
      </Card>
    </div>
  );
}

function Cloud({ size, ...props }: any) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size || 24} height={size || 24} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
    </svg>
  );
}
