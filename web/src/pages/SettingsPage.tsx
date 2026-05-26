import { useState, useEffect } from "react";
import { getAllowedTabs, TAB_PERMISSION_MAP } from "../utils/permissions";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import {
  Trash2, Upload, Download, RefreshCw, AlertTriangle, Save,
  UserPlus, Key, Shield, Settings as SettingsIcon, Database, FileJson,
  Rss, Cpu, Brain, Mail, Users, HardDrive, Skull, Server, Globe,
  FileSpreadsheet, Plus, Eye, EyeOff, X, User
} from "lucide-react";

const ALL_PAGES = [
  "Global Dashboards", "Threat Telemetry", "Regional Grid",
  "Threat Hunting & IOCs", "AIOps RCA", "Shift Logbook",
  "Reporting & Briefings", "Settings & Admin",
];

const ALL_ACTIONS = [
  "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score",
  "Action: Trigger AI Functions", "Action: Manually Sync Data", "Action: Dispatch Exec Report",
  "Action: Submit Shift Log", "Action: Dispatch RCA Tickets", "Action: Manage Site Maintenance",
  "Tab: Dashboards -> Operational", "Tab: Dashboards -> Global Risk", "Tab: Dashboards -> Internal Risk", "Tab: Dashboards -> Unified Brief",
  "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV",
  "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Perimeter Crime",
  "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
  "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
  "Tab: Threat Hunting -> Global IOC Matrix", "Tab: Threat Hunting -> Deep Hunt Builder", "Tab: Reporting -> Elastic SIEM Report",
  "Tab: AIOps RCA -> Active Board", "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
  "Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History",
  "Tab: Reporting -> Daily Fusion", "Tab: Reporting -> Report Builder", "Tab: Reporting -> Shared Library",
  "Tab: Settings -> Facility Locations", "Tab: Settings -> Internal Assets", "Tab: Settings -> RSS Sources", "Tab: Settings -> ML Training",
  "Tab: Settings -> AI & SMTP", "Tab: Settings -> Users & Roles", "Tab: Settings -> Backup & Restore", "Tab: Settings -> Danger Zone",
];

const ALL_SITE_TYPES = ["NOC", "SOC", "Data Center", "Field Office", "HQ", "Remote Site", "Cloud"];

const TABS = [
  { id: "profile", label: "Profile", icon: User },
  { id: "facilities", label: "Facilities", icon: Globe },
  { id: "assets", label: "Internal Assets", icon: Server },
  { id: "rss", label: "RSS Sources", icon: Rss },
  { id: "ml", label: "ML Training", icon: Brain },
  { id: "ai-smtp", label: "AI & SMTP", icon: SettingsIcon },
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
  const { user: currentUser } = useAuth();
  const allowedSettingsTabs = getAllowedTabs(currentUser?.allowed_actions, "settings");
  const [tab, setTab] = useState("profile");
  const queryClient = useQueryClient();

  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ["settings-config"],
    queryFn: () => api.get("/settings/config").then(r => r.data),
    refetchInterval: 60000,
  });

  const { data: roles } = useQuery({
    queryKey: ["admin-roles"],
    queryFn: () => api.get("/admin/roles").then(r => r.data),
  });

  const { data: users } = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => api.get("/settings/users").then(r => r.data),
  });

  const { data: locations } = useQuery({
    queryKey: ["admin-locations"],
    queryFn: () => api.get("/admin/location").then(r => r.data),
  });

  const { data: lists } = useQuery({
    queryKey: ["admin-lists"],
    queryFn: () => api.get("/admin/lists").then(r => r.data),
  });

  const { data: mlCounts } = useQuery({
    queryKey: ["admin-ml-counts"],
    queryFn: () => api.get("/admin/ml-counts").then(r => r.data),
  });

  const saveConfigMutation = useMutation({
    mutationFn: (data: any) => api.post("/admin/config", data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["settings-config"] }); alert("Configuration saved."); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  useEffect(() => {
    if (allowedSettingsTabs.length > 0 && !allowedSettingsTabs.includes(tab)) {
      setTab(allowedSettingsTabs[0]);
    }
  }, [allowedSettingsTabs.join(",")]);

  const SETTINGS_ACTION_IDS = new Set(Object.values(TAB_PERMISSION_MAP.settings));
  const filteredTabs = TABS.filter(t => allowedSettingsTabs.length === 0 || !SETTINGS_ACTION_IDS.has(t.id) || allowedSettingsTabs.includes(t.id));

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

      {tab === "profile" && <ProfileTab user={currentUser} />}
      {tab === "facilities" && <FacilitiesTab locations={locations} queryClient={queryClient} />}
      {tab === "assets" && <AssetsTab />}
      {tab === "rss" && <RssTab lists={lists} queryClient={queryClient} />}
      {tab === "ml" && <MlTab mlCounts={mlCounts} />}
      {tab === "ai-smtp" && <AiSmtpTab config={config} configLoading={configLoading} saveConfigMutation={saveConfigMutation} />}
      {tab === "users" && <UsersRolesTab roles={roles} users={users} queryClient={queryClient} />}
      {tab === "backup" && <BackupRestoreTab />}
      {tab === "danger" && <DangerZoneTab />}
    </div>
  );
}

/* ============================
   0. PROFILE TAB
   ============================ */
function ProfileTab({ user }: { user: any }) {
  const [fullName, setFullName] = useState(user?.full_name || "");
  const [jobTitle, setJobTitle] = useState(user?.job_title || "");
  const [contactInfo, setContactInfo] = useState(user?.contact_info || "");
  const [defaultShift, setDefaultShift] = useState(user?.default_shift || "No Shift");
  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [showPwd, setShowPwd] = useState(false);

  const updateProfile = useMutation({
    mutationFn: (data: any) => api.post("/auth/update-profile", data, { params: { username: user?.username } }),
    onSuccess: () => {
      alert("Profile updated!");
      setOldPwd("");
      setNewPwd("");
    },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
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
              {["No Shift", "Day", "Swing", "Night", "Rotating"].map(s => <option key={s} value={s}>{s}</option>)}
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
function FacilitiesTab({ locations, queryClient }: { locations: any; queryClient: any }) {
  const [importFile, setImportFile] = useState<File | null>(null);
  const [editData, setEditData] = useState<any[]>([]);

  const importMutation = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      const data = JSON.parse(text);
      return api.post("/admin/location/import", data);
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
  if (editData.length === 0 && locs.length > 0) {
    setEditData(locs.map((l: any) => ({ ...l })));
  }

  const updateRow = (i: number, field: string, val: any) => {
    setEditData(prev => {
      const next = [...prev];
      next[i] = { ...next[i], [field]: val };
      return next;
    });
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <Card title="Mass Import JSON" icon={Upload}>
        <input
          type="file"
          accept=".json"
          onChange={e => setImportFile(e.target.files?.[0] || null)}
          style={{ marginBottom: "0.6rem", color: "var(--text-primary)", fontSize: "0.8rem" }}
        />
        <button
          onClick={() => importFile && importMutation.mutate(importFile)}
          disabled={!importFile || importMutation.isPending}
          style={btn("var(--accent-blue)")}
        >
          <Upload size={14} />
          {importMutation.isPending ? "Importing..." : "Import"}
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
                    {["Name", "Type", "District", "Priority", "Lat", "Lon", "ID"].map(h => (
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
                        <input style={{ ...inputStyle, width: 90 }} value={row.type || ""} onChange={e => updateRow(i, "type", e.target.value)} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 90 }} value={row.district || ""} onChange={e => updateRow(i, "district", e.target.value)} />
                      </td>
                      <td style={{ padding: "0.25rem 0.3rem" }}>
                        <input style={{ ...inputStyle, width: 60 }} type="number" value={row.priority ?? ""} onChange={e => updateRow(i, "priority", Number(e.target.value))} />
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
    </div>
  );
}

/* ============================
   2. INTERNAL ASSETS TAB
   ============================ */
function AssetsTab() {
  const [swFile, setSwFile] = useState<File | null>(null);
  const [hwFile, setHwFile] = useState<File | null>(null);
  const queryClient = useQueryClient();

  const uploadSw = useMutation({
    mutationFn: (file: File) => {
      const reader = new FileReader();
      return new Promise((resolve, reject) => {
        reader.onload = () => {
          const text = reader.result as string;
          const lines = text.split("\n").filter(Boolean);
          const header = lines[0].toLowerCase();
          if (!header.includes("name")) return reject(new Error("CSV must contain a 'name' column"));
          api.post("/admin/config", { software_assets_csv: text }).then(resolve).catch(reject);
        };
        reader.onerror = () => reject(new Error("Failed to read file"));
        reader.readAsText(file);
      });
    },
    onSuccess: () => { alert("Software assets uploaded."); setSwFile(null); queryClient.invalidateQueries({ queryKey: ["settings-config"] }); },
    onError: (e: any) => alert("Error: " + (e.message || e.response?.data?.detail)),
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
          api.post("/admin/config", { hardware_assets_csv: text }).then(resolve).catch(reject);
        };
        reader.onerror = () => reject(new Error("Failed to read file"));
        reader.readAsText(file);
      });
    },
    onSuccess: () => { alert("Hardware assets uploaded."); setHwFile(null); queryClient.invalidateQueries({ queryKey: ["settings-config"] }); },
    onError: (e: any) => alert("Error: " + (e.message || e.response?.data?.detail)),
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
function RssTab({ lists, queryClient }: { lists: any; queryClient: any }) {
  const [kwText, setKwText] = useState("");
  const [feedText, setFeedText] = useState("");

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
    mutationFn: (_id: number) => api.post("/admin/keywords/bulk", []),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-lists"] }),
  });

  const delFeed = useMutation({
    mutationFn: (_id: number) => api.post("/admin/feeds/bulk", []),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin-lists"] }),
  });

  const keywords = lists?.keywords ?? [];
  const feeds = lists?.feeds ?? [];

  return (
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
              <span style={{ color: "var(--text-primary)" }}>{kw.word} <span style={{ color: "var(--text-muted)", fontSize: "0.7rem" }}>(w:{kw.weight})</span></span>
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
  );
}

/* ============================
   4. ML TRAINING TAB
   ============================ */
function MlTab({ mlCounts }: { mlCounts: any }) {
  const queryClient = useQueryClient();
  const retrain = useMutation({
    mutationFn: () => api.post("/admin/ml-retrain"),
    onSuccess: () => { alert("Model retrained."); queryClient.invalidateQueries({ queryKey: ["admin-ml-counts"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem" }}>
        <Card title="Total Samples" icon={Database}>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-blue)" }}>{mlCounts?.total_samples ?? 0}</div>
        </Card>
        <Card title="Positives" icon={Brain}>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-orange)" }}>{mlCounts?.positives ?? 0}</div>
        </Card>
        <Card title="Negatives" icon={Brain}>
          <div style={{ fontSize: "2rem", fontWeight: 700, color: "var(--accent-red)" }}>{mlCounts?.negatives ?? 0}</div>
        </Card>
      </div>
      <Card title="Model Training">
        <button onClick={() => retrain.mutate()} disabled={retrain.isPending} style={btn("var(--accent-cyan)")}>
          <RefreshCw size={14} /> {retrain.isPending ? "Training..." : "Retrain Model Now"}
        </button>
      </Card>
    </div>
  );
}

/* ============================
   5. AI & SMTP TAB
   ============================ */
function AiSmtpTab({ config, configLoading, saveConfigMutation }: { config: any; configLoading: boolean; saveConfigMutation: any }) {
  const [form, setForm] = useState<any>(null);
  const [showKey, setShowKey] = useState(false);

  if (!configLoading && config && !form) {
    setForm({
      llm_endpoint: config.llm_endpoint || "",
      llm_api_key: config.llm_api_key || "",
      llm_model_name: config.llm_model_name || "",
      tech_stack: config.tech_stack || "",
      is_active: config.is_active ?? false,
      smtp_server: config.smtp_server || "",
      smtp_port: config.smtp_port ?? 587,
      smtp_username: config.smtp_username || "",
      smtp_password: config.smtp_password || "",
      smtp_sender: config.smtp_sender || "",
      smtp_recipient: config.smtp_recipient || "",
      smtp_enabled: config.smtp_enabled ?? false,
      cyber_baseline: config.cyber_baseline ?? 3,
      physical_baseline: config.physical_baseline ?? 3,
      sys_countermeasures: config.sys_countermeasures ?? 3,
      net_countermeasures: config.net_countermeasures ?? 3,
    });
  }

  const upd = (k: string, v: any) => setForm((prev: any) => ({ ...prev, [k]: v }));

  if (!form) {
    return <p style={{ color: "var(--text-muted)" }}>Loading configuration...</p>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
      <Card title="LLM Configuration" icon={Cpu}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <div>
            <SectionTitle text="Endpoint" />
            <input style={inputStyle} value={form.llm_endpoint} onChange={e => upd("llm_endpoint", e.target.value)} placeholder="https://api.openai.com/v1" />
          </div>
          <div>
            <SectionTitle text="API Key" />
            <div style={{ display: "flex", gap: "0.3rem" }}>
              <input style={inputStyle} type={showKey ? "text" : "password"} value={form.llm_api_key} onChange={e => upd("llm_api_key", e.target.value)} placeholder="sk-..." />
              <button onClick={() => setShowKey(!showKey)} style={{ background: "none", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", color: "var(--text-secondary)", cursor: "pointer", padding: "0.35rem" }}>
                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>
          <div>
            <SectionTitle text="Model Name" />
            <input style={inputStyle} value={form.llm_model_name} onChange={e => upd("llm_model_name", e.target.value)} placeholder="gpt-4" />
          </div>
          <div>
            <SectionTitle text="Tech Stack" />
            <input style={inputStyle} value={form.tech_stack} onChange={e => upd("tech_stack", e.target.value)} placeholder="Python, FastAPI, React" />
          </div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginTop: "0.6rem", fontSize: "0.8rem", color: "var(--text-primary)", cursor: "pointer" }}>
          <input type="checkbox" checked={form.is_active} onChange={e => upd("is_active", e.target.checked)} />
          Enable AI
        </label>
      </Card>

      <Card title="SMTP Broadcast" icon={Mail}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
          <div>
            <SectionTitle text="Server" />
            <input style={inputStyle} value={form.smtp_server} onChange={e => upd("smtp_server", e.target.value)} placeholder="smtp.gmail.com" />
          </div>
          <div>
            <SectionTitle text="Port" />
            <input style={inputStyle} type="number" value={form.smtp_port} onChange={e => upd("smtp_port", Number(e.target.value))} />
          </div>
          <div>
            <SectionTitle text="Username" />
            <input style={inputStyle} value={form.smtp_username} onChange={e => upd("smtp_username", e.target.value)} />
          </div>
          <div>
            <SectionTitle text="Password" />
            <input style={inputStyle} type="password" value={form.smtp_password} onChange={e => upd("smtp_password", e.target.value)} />
          </div>
          <div>
            <SectionTitle text="Sender" />
            <input style={inputStyle} value={form.smtp_sender} onChange={e => upd("smtp_sender", e.target.value)} placeholder="noc@example.com" />
          </div>
          <div>
            <SectionTitle text="Recipient" />
            <input style={inputStyle} value={form.smtp_recipient} onChange={e => upd("smtp_recipient", e.target.value)} placeholder="admin@example.com" />
          </div>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginTop: "0.6rem", fontSize: "0.8rem", color: "var(--text-primary)", cursor: "pointer" }}>
          <input type="checkbox" checked={form.smtp_enabled} onChange={e => upd("smtp_enabled", e.target.checked)} />
          SMTP Enabled
        </label>
      </Card>

      <Card title="Threat Matrix Baseline Overrides" icon={Shield}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", maxWidth: 400 }}>
          <div>
            <SectionTitle text="Cyber Baseline" />
            <input style={inputStyle} type="number" min={1} max={5} value={form.cyber_baseline} onChange={e => upd("cyber_baseline", Number(e.target.value))} />
          </div>
          <div>
            <SectionTitle text="Physical Baseline" />
            <input style={inputStyle} type="number" min={1} max={5} value={form.physical_baseline} onChange={e => upd("physical_baseline", Number(e.target.value))} />
          </div>
        </div>
      </Card>

      <Card title="CIS Countermeasures" icon={Shield}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem", maxWidth: 500 }}>
          <div>
            <SectionTitle text={`System (${form.sys_countermeasures}/5)`} />
            <input type="range" min={1} max={5} step={1} value={form.sys_countermeasures} onChange={e => upd("sys_countermeasures", Number(e.target.value))} style={{ width: "100%" }} />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)" }}>
              <span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>
            </div>
          </div>
          <div>
            <SectionTitle text={`Network (${form.net_countermeasures}/5)`} />
            <input type="range" min={1} max={5} step={1} value={form.net_countermeasures} onChange={e => upd("net_countermeasures", Number(e.target.value))} style={{ width: "100%" }} />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "var(--text-muted)" }}>
              <span>1</span><span>2</span><span>3</span><span>4</span><span>5</span>
            </div>
          </div>
        </div>
      </Card>

      <button onClick={() => saveConfigMutation.mutate(form)} disabled={saveConfigMutation.isPending} style={{ ...btn("var(--accent-green)"), alignSelf: "flex-start" }}>
        <Save size={14} /> {saveConfigMutation.isPending ? "Saving..." : "Save Configuration"}
      </button>
    </div>
  );
}

/* ============================
   6. USERS & ROLES TAB
   ============================ */
function CheckboxGroup({ label, options, selected, onChange }: { label: string; options: string[]; selected: string[]; onChange: (v: string[]) => void }) {
  const toggle = (opt: string) => {
    onChange(selected.includes(opt) ? selected.filter(x => x !== opt) : [...selected, opt]);
  };
  return (
    <div>
      <SectionTitle text={label} />
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem" }}>
        {options.map(opt => (
          <label key={opt} style={{
            display: "inline-flex", alignItems: "center", gap: "0.25rem",
            fontSize: "0.78rem", cursor: "pointer",
            padding: "0.2rem 0.5rem", borderRadius: "var(--radius-sm)",
            background: selected.includes(opt) ? "var(--accent-blue)" : "var(--bg-tertiary)",
            color: selected.includes(opt) ? "#fff" : "var(--text-secondary)",
            border: `1px solid ${selected.includes(opt) ? "var(--accent-blue)" : "var(--border-primary)"}`,
          }}>
            <input type="checkbox" checked={selected.includes(opt)} onChange={() => toggle(opt)} style={{ display: "none" }} />
            {opt}
          </label>
        ))}
      </div>
    </div>
  );
}

function UsersRolesTab({ roles, users, queryClient }: { roles: any; users: any; queryClient: any }) {
  const [newUser, setNewUser] = useState({ username: "", password: "", full_name: "", role: "viewer" });
  const [roleChange, setRoleChange] = useState({ username: "", new_role: "viewer" });
  const [newRole, setNewRole] = useState({ name: "", allowed_pages: [] as string[], allowed_actions: [] as string[], allowed_site_types: [] as string[] });
  const [editRole, setEditRole] = useState<any>(null);
  const [resetPw, setResetPw] = useState({ username: "", new_password: "" });

  const createUser = useMutation({
    mutationFn: (data: any) => api.post("/admin/users", data),
    onSuccess: () => { alert("User created."); setNewUser({ username: "", password: "", full_name: "", role: "viewer" }); queryClient.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const changeRole = useMutation({
    mutationFn: ({ username, new_role }: any) => api.put(`/admin/users/${username}/role`, { role: new_role }),
    onSuccess: () => { alert("Role updated."); queryClient.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const createRole = useMutation({
    mutationFn: (data: any) => api.post("/admin/roles", data),
    onSuccess: () => { alert("Role created."); setNewRole({ name: "", allowed_pages: [], allowed_actions: [], allowed_site_types: [] }); queryClient.invalidateQueries({ queryKey: ["admin-roles"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const editRoleMutation = useMutation({
    mutationFn: (data: any) => api.put(`/admin/roles/${data.name}`, data),
    onSuccess: () => { alert("Role updated."); setEditRole(null); queryClient.invalidateQueries({ queryKey: ["admin-roles"] }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const resetPwMutation = useMutation({
    mutationFn: ({ username, new_password }: any) => api.post(`/admin/users/${username}/reset-password`, { new_password }),
    onSuccess: () => { alert("Password reset."); setResetPw({ username: "", new_password: "" }); },
    onError: (e: any) => alert("Error: " + (e.response?.data?.detail || e.message)),
  });

  const roleOpts = Array.isArray(roles) ? roles.map((r: any) => r.name) : ["admin", "analyst", "viewer"];
  const userList = Array.isArray(users) ? users : [];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem" }}>
      <Card title="Create User" icon={UserPlus}>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          <input style={inputStyle} placeholder="Username" value={newUser.username} onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))} />
          <input style={inputStyle} type="password" placeholder="Password" value={newUser.password} onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))} />
          <input style={inputStyle} placeholder="Full Name" value={newUser.full_name} onChange={e => setNewUser(p => ({ ...p, full_name: e.target.value }))} />
          <select style={inputStyle} value={newUser.role} onChange={e => setNewUser(p => ({ ...p, role: e.target.value }))}>
            {roleOpts.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <button onClick={() => createUser.mutate(newUser)} disabled={createUser.isPending || !newUser.username} style={btn("var(--accent-blue)")}>
            <UserPlus size={14} /> {createUser.isPending ? "Creating..." : "Create User"}
          </button>
        </div>
      </Card>

      <Card title="Change User Role" icon={Shield}>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          <select style={inputStyle} value={roleChange.username} onChange={e => setRoleChange(p => ({ ...p, username: e.target.value }))}>
            <option value="">Select user...</option>
            {userList.map((u: any) => <option key={u.id || u.username} value={u.username}>{u.username}</option>)}
          </select>
          <select style={inputStyle} value={roleChange.new_role} onChange={e => setRoleChange(p => ({ ...p, new_role: e.target.value }))}>
            {roleOpts.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <button onClick={() => changeRole.mutate(roleChange)} disabled={changeRole.isPending || !roleChange.username} style={btn("var(--accent-orange)")}>
            <Shield size={14} /> {changeRole.isPending ? "Updating..." : "Change Role"}
          </button>
        </div>
      </Card>

      <Card title="Create Custom Role" icon={Users}>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
          <div>
            <SectionTitle text="Role Name" />
            <input style={inputStyle} placeholder="e.g. senior-analyst" value={newRole.name} onChange={e => setNewRole(p => ({ ...p, name: e.target.value }))} />
          </div>
          <CheckboxGroup label="Allowed Pages" options={ALL_PAGES} selected={newRole.allowed_pages} onChange={v => setNewRole(p => ({ ...p, allowed_pages: v }))} />
          <CheckboxGroup label="Allowed Actions" options={ALL_ACTIONS} selected={newRole.allowed_actions} onChange={v => setNewRole(p => ({ ...p, allowed_actions: v }))} />
          <CheckboxGroup label="Allowed Site Types" options={ALL_SITE_TYPES} selected={newRole.allowed_site_types} onChange={v => setNewRole(p => ({ ...p, allowed_site_types: v }))} />
          <button onClick={() => createRole.mutate(newRole)} disabled={createRole.isPending || !newRole.name} style={btn("var(--accent-green)")}>
            <Plus size={14} /> {createRole.isPending ? "Creating..." : "Create Role"}
          </button>
        </div>
      </Card>

      <Card title="Edit Existing Role" icon={SettingsIcon}>
        {Array.isArray(roles) && roles.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
            <select style={inputStyle} value={editRole?.id || ""} onChange={e => {
              const r = (roles as any[]).find((x: any) => x.name === e.target.value);
              setEditRole(r ? { ...r, allowed_pages: r.allowed_pages || [], allowed_actions: r.allowed_actions || [], allowed_site_types: r.allowed_site_types || [] } : null);
            }}>
              <option value="">Select role to edit...</option>
              {roles.map((r: any) => <option key={r.name} value={r.name}>{r.name}</option>)}
            </select>
            {editRole && (
              <>
                <div>
                  <SectionTitle text="Role Name" />
                  <input style={inputStyle} value={editRole.name} onChange={e => setEditRole((p: any) => ({ ...p, name: e.target.value }))} />
                </div>
                <CheckboxGroup label="Allowed Pages" options={ALL_PAGES} selected={editRole.allowed_pages || []} onChange={v => setEditRole((p: any) => ({ ...p, allowed_pages: v }))} />
                <CheckboxGroup label="Allowed Actions" options={ALL_ACTIONS} selected={editRole.allowed_actions || []} onChange={v => setEditRole((p: any) => ({ ...p, allowed_actions: v }))} />
                <CheckboxGroup label="Allowed Site Types" options={ALL_SITE_TYPES} selected={editRole.allowed_site_types || []} onChange={v => setEditRole((p: any) => ({ ...p, allowed_site_types: v }))} />
                <button onClick={() => editRoleMutation.mutate(editRole)} disabled={editRoleMutation.isPending} style={btn("var(--accent-yellow)")}>
                  <Save size={14} /> {editRoleMutation.isPending ? "Saving..." : "Update Role"}
                </button>
              </>
            )}
          </div>
        ) : (
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>No roles available.</p>
        )}
      </Card>

      <Card title="Reset Password" icon={Key} wide>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 180 }}>
            <SectionTitle text="Username" />
            <select style={inputStyle} value={resetPw.username} onChange={e => setResetPw(p => ({ ...p, username: e.target.value }))}>
              <option value="">Select user...</option>
              {userList.map((u: any) => <option key={u.id || u.username} value={u.username}>{u.username}</option>)}
            </select>
          </div>
          <div style={{ flex: 1, minWidth: 180 }}>
            <SectionTitle text="New Password" />
            <input style={inputStyle} type="password" value={resetPw.new_password} onChange={e => setResetPw(p => ({ ...p, new_password: e.target.value }))} />
          </div>
          <button onClick={() => resetPwMutation.mutate(resetPw)} disabled={resetPwMutation.isPending || !resetPw.username || !resetPw.new_password} style={btn("var(--accent-red)")}>
            <Key size={14} /> {resetPwMutation.isPending ? "Resetting..." : "Reset Password"}
          </button>
        </div>
      </Card>
    </div>
  );
}

/* ============================
   7. BACKUP & RESTORE TAB
   ============================ */
function BackupRestoreTab() {
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const queryClient = useQueryClient();

  const { data: backup, isLoading: backupLoading } = useQuery({
    queryKey: ["admin-backup"],
    queryFn: () => api.get("/admin/backup").then(r => r.data),
  });

  const downloadBackup = () => {
    if (!backup) return;
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `noc_backup_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const restoreMutation = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      const data = JSON.parse(text);
      return api.post("/admin/restore", data);
    },
    onSuccess: () => { alert("Restore completed."); queryClient.invalidateQueries(); },
    onError: (e: any) => alert("Restore error: " + (e.response?.data?.detail || e.message)),
  });

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.25rem" }}>
      <Card title="Export Backup" icon={Download}>
        <p style={{ color: "var(--text-muted)", fontSize: "0.8rem", margin: "0 0 0.75rem" }}>Download a full JSON backup of the database.</p>
        <button onClick={downloadBackup} disabled={backupLoading || !backup} style={btn("var(--accent-blue)")}>
          <Download size={14} /> {backupLoading ? "Loading..." : "Download Backup JSON"}
        </button>
        {backup && (
          <div style={{ marginTop: "0.75rem", maxHeight: 300, overflow: "auto", background: "var(--bg-secondary)", borderRadius: "var(--radius-sm)", padding: "0.75rem", fontSize: "0.7rem", fontFamily: "var(--font-mono)", color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>
            {JSON.stringify(backup, null, 2).slice(0, 2000)}
            {JSON.stringify(backup, null, 2).length > 2000 ? "..." : ""}
          </div>
        )}
      </Card>

      <Card title="Import Restore" icon={Upload}>
        <p style={{ color: "var(--text-muted)", fontSize: "0.8rem", margin: "0 0 0.75rem" }}>Upload a previously exported backup JSON file to restore.</p>
        <input
          type="file"
          accept=".json"
          onChange={e => setRestoreFile(e.target.files?.[0] || null)}
          style={{ marginBottom: "0.6rem", color: "var(--text-primary)", fontSize: "0.8rem" }}
        />
        <button onClick={() => restoreFile && restoreMutation.mutate(restoreFile)} disabled={!restoreFile || restoreMutation.isPending} style={btn("var(--accent-orange)")}>
          <Upload size={14} /> {restoreMutation.isPending ? "Restoring..." : "Restore from JSON"}
        </button>
      </Card>
    </div>
  );
}

/* ============================
   8. DANGER ZONE TAB
   ============================ */
function DangerZoneTab() {
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

function Cloud({ size, ...props }: any) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size || 24} height={size || 24} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
    </svg>
  );
}
