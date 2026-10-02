import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock, Gauge, Globe, Save } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";
import { hasActionPermission } from "../utils/permissions";

type ApplicationUser = { role?: string; allowed_actions?: string[] } | null;
type SchedulerJob = {
  key: string;
  label: string;
  description: string;
  schedule: { schedule_type: "interval" | "daily" | "weekly"; every_value?: number; unit?: string; run_at?: string; weekday?: string; timezone?: string; enabled: boolean };
  min_value?: number;
  max_value?: number;
  can_disable: boolean;
  startup_run: boolean;
  updated_by?: string | null;
  updated_at?: string | null;
};

const inputStyle: React.CSSProperties = {
  background: "var(--bg-input)", color: "var(--text-primary)",
  border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)",
  padding: "0.5rem 0.6rem", fontSize: "0.82rem", width: "100%", boxSizing: "border-box",
};
const saveButton: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: "0.4rem", padding: "0.5rem 0.8rem",
  color: "#fff", background: "var(--accent-blue)", border: 0, borderRadius: "var(--radius-sm)",
  cursor: "pointer", fontWeight: 650, fontSize: "0.78rem",
};
const card: React.CSSProperties = {
  background: "var(--bg-card)", border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-md)", padding: "1rem",
};

export function ApplicationSettingsTab({ user }: { user: ApplicationUser }) {
  const queryClient = useQueryClient();
  const canManageApp = hasActionPermission(user, "Action: Manage Application Settings");
  const canAdjustRisk = hasActionPermission(user, "Action: Adjust Risk Scoring Overrides");
  const canManageScheduler = hasActionPermission(user, "Action: Manage Scheduler Settings");
  const [applicationForm, setApplicationForm] = useState<any>(null);
  const [riskForm, setRiskForm] = useState<any>(null);
  const [schedulerDraft, setSchedulerDraft] = useState<Record<string, SchedulerJob["schedule"]>>({});
  const [schedulerDirty, setSchedulerDirty] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const applicationQuery = useQuery({
    queryKey: ["application-settings"],
    queryFn: () => api.get("/application-settings").then(r => r.data),
  });
  const riskQuery = useQuery({
    queryKey: ["risk-scoring-settings"],
    queryFn: () => api.get("/application-settings/risk-scoring").then(r => r.data),
  });
  const schedulerQuery = useQuery({
    queryKey: ["scheduler-settings"],
    queryFn: () => api.get("/application-settings/scheduler").then(r => r.data),
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (applicationQuery.data) setApplicationForm(applicationQuery.data);
  }, [applicationQuery.data]);
  useEffect(() => {
    if (riskQuery.data) setRiskForm(riskQuery.data);
  }, [riskQuery.data]);
  useEffect(() => {
    const rows = schedulerQuery.data?.jobs as SchedulerJob[] | undefined;
    if (rows) setSchedulerDraft(previous => {
      const next = { ...previous };
      rows.forEach(job => {
        if (!schedulerDirty.has(job.key) || !next[job.key]) next[job.key] = { ...job.schedule };
      });
      return next;
    });
  }, [schedulerQuery.data, schedulerDirty]);

  const saveMutation = useMutation({
    mutationFn: ({ path, data }: { path: string; data: any }) => api.put(path, data),
    onSuccess: (_response, variables) => {
      setError("");
      setNotice(variables.path.endsWith("risk-scoring") ? "Risk scoring settings saved." : "Application settings saved.");
      queryClient.invalidateQueries({ queryKey: [variables.path.endsWith("risk-scoring") ? "risk-scoring-settings" : "application-settings"] });
      queryClient.invalidateQueries({ queryKey: ["sys-config"] });
      queryClient.invalidateQueries({ queryKey: ["executive-intel"] });
    },
    onError: (reason: any) => { setNotice(""); setError(getApiErrorMessage(reason)); },
  });

  const schedulerMutation = useMutation({
    mutationFn: ({ key, schedule }: { key: string; schedule: SchedulerJob["schedule"] }) =>
      api.patch(`/application-settings/scheduler/jobs/${encodeURIComponent(key)}`, { schedule }),
    onSuccess: (_response, variables) => {
      setError("");
      setNotice("Schedule saved. The worker applies changes dynamically within 30 seconds.");
      setSchedulerDirty(previous => {
        const next = new Set(previous);
        next.delete(variables.key);
        return next;
      });
      queryClient.invalidateQueries({ queryKey: ["scheduler-settings"] });
    },
    onError: (reason: any) => { setNotice(""); setError(getApiErrorMessage(reason)); },
  });

  const updateApp = (key: string, value: any) => setApplicationForm((previous: any) => ({ ...previous, [key]: value }));
  const updateRisk = (key: string, value: any) => setRiskForm((previous: any) => ({ ...previous, [key]: value }));
  const updateJob = (job: SchedulerJob, patch: Partial<SchedulerJob["schedule"]>) => {
    setSchedulerDraft(previous => ({
      ...previous,
      [job.key]: { ...(previous[job.key] || job.schedule), ...patch },
    }));
    setSchedulerDirty(previous => new Set(previous).add(job.key));
  };
  const saveJob = (job: SchedulerJob) => {
    schedulerMutation.mutate({ key: job.key, schedule: schedulerDraft[job.key] || job.schedule });
  };

  if (applicationQuery.isLoading || riskQuery.isLoading || schedulerQuery.isLoading || !applicationForm || !riskForm) {
    return <div style={card} role="status">Loading application settings...</div>;
  }
  if (applicationQuery.isError || riskQuery.isError || schedulerQuery.isError) {
    const failure = applicationQuery.error || riskQuery.error || schedulerQuery.error;
    return <div style={{ ...card, color: "var(--accent-red)" }} role="alert">{getApiErrorMessage(failure, "Unable to load application settings.")}</div>;
  }

  const jobs: SchedulerJob[] = schedulerQuery.data?.jobs || [];
  return (
    <div style={{ display: "grid", gap: "1rem" }}>
      <div>
        <h3 style={{ margin: "0 0 0.25rem", color: "var(--text-primary)" }}>Application Settings</h3>
        <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.8rem" }}>Operational defaults, risk-scoring controls, and validated background-job schedules.</p>
      </div>
      {(notice || error) && <div role={error ? "alert" : "status"} aria-live="polite" style={{ ...card, color: error ? "var(--accent-red)" : "var(--accent-green)", padding: "0.7rem 0.9rem" }}>{error || notice}</div>}
      {!canManageApp && !canAdjustRisk && !canManageScheduler && <div role="status" style={card}>
        This tab is available in view-only mode. Editing requires the corresponding application-settings, risk-scoring, or scheduler management action.
      </div>}

      {canManageApp && <section style={card}>
        <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}><Globe size={16} /> Application defaults and sign-in alerts</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "0.75rem" }}>
          <label style={{ fontSize: "0.78rem" }}>Public application address<input type="url" value={applicationForm.public_app_url || ""} onChange={e => updateApp("public_app_url", e.target.value)} style={{ ...inputStyle, marginTop: 4 }} placeholder="https://noc.example.com" /></label>
          <label style={{ fontSize: "0.78rem" }}>Technology stack<input value={applicationForm.tech_stack || ""} onChange={e => updateApp("tech_stack", e.target.value)} style={{ ...inputStyle, marginTop: 4 }} /></label>
          <label style={{ fontSize: "0.78rem" }}>Monitored ASNs<input value={applicationForm.monitored_asns || ""} onChange={e => updateApp("monitored_asns", e.target.value)} style={{ ...inputStyle, marginTop: 4 }} /></label>
        </div>
        <div style={{ marginTop: "0.8rem", borderTop: "1px solid var(--border-primary)", paddingTop: "0.8rem" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", fontSize: "0.8rem" }}><input type="checkbox" checked={!!applicationForm.failed_login_alert_enabled} onChange={e => updateApp("failed_login_alert_enabled", e.target.checked)} /> Enable failed-login alerts</label>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: "0.65rem", marginTop: "0.65rem" }}>
            <label style={{ fontSize: "0.75rem" }}>Recipients<textarea value={applicationForm.failed_login_alert_recipients || ""} onChange={e => updateApp("failed_login_alert_recipients", e.target.value)} style={{ ...inputStyle, marginTop: 4, minHeight: 68 }} placeholder="security@example.com" /></label>
            <label style={{ fontSize: "0.75rem" }}>Failed attempts<input type="number" min={2} max={100} value={applicationForm.failed_login_alert_threshold ?? 5} onChange={e => updateApp("failed_login_alert_threshold", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
            <label style={{ fontSize: "0.75rem" }}>Window (minutes)<input type="number" min={1} max={60} value={applicationForm.failed_login_alert_window_minutes ?? 5} onChange={e => updateApp("failed_login_alert_window_minutes", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
          </div>
        </div>
        <button type="button" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate({ path: "/application-settings", data: applicationForm })} style={{ ...saveButton, marginTop: "0.8rem" }}><Save size={14} /> Save application defaults</button>
      </section>}

      {canAdjustRisk && <section style={card}>
        <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}><Gauge size={16} /> Risk-scoring overrides</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>Changes are used by subsequent scoring runs. Values of zero leave the corresponding baseline or override unset.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "0.65rem" }}>
          <label style={{ fontSize: "0.75rem" }}>Scoring mode<select value={riskForm.scoring_mode || "auto"} onChange={e => updateRisk("scoring_mode", e.target.value)} style={{ ...inputStyle, marginTop: 4 }}><option value="auto">Auto</option><option value="manual">Manual</option><option value="hybrid">Hybrid</option></select></label>
          <label style={{ fontSize: "0.75rem" }}>Cyber baseline (0-5)<input type="number" min={0} max={5} value={riskForm.baseline_override_cyber ?? 0} onChange={e => updateRisk("baseline_override_cyber", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
          <label style={{ fontSize: "0.75rem" }}>Physical baseline (0-5)<input type="number" min={0} max={5} value={riskForm.baseline_override_phys ?? 0} onChange={e => updateRisk("baseline_override_phys", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
          {(["cyber_criticality_override", "cyber_lethality_override", "physical_criticality_override", "physical_lethality_override", "internal_criticality_override", "internal_lethality_override"] as const).map(key => <label key={key} style={{ fontSize: "0.75rem" }}>{key.replace(/_/g, " ")} (0-5)<input type="number" min={0} max={5} value={riskForm[key] ?? 0} onChange={e => updateRisk(key, Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>)}
          <label style={{ fontSize: "0.75rem" }}>Global risk offset (-3 to 3)<input type="number" min={-3} max={3} value={riskForm.global_risk_offset ?? 0} onChange={e => updateRisk("global_risk_offset", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
          <label style={{ fontSize: "0.75rem" }}>Internal risk offset (-3 to 3)<input type="number" min={-3} max={3} value={riskForm.internal_risk_offset ?? 0} onChange={e => updateRisk("internal_risk_offset", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
          <label style={{ fontSize: "0.75rem" }}>System countermeasures (1-5)<input type="number" min={1} max={5} value={riskForm.sys_countermeasures ?? 3} onChange={e => updateRisk("sys_countermeasures", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
          <label style={{ fontSize: "0.75rem" }}>Network countermeasures (1-5)<input type="number" min={1} max={5} value={riskForm.net_countermeasures ?? 3} onChange={e => updateRisk("net_countermeasures", Number(e.target.value))} style={{ ...inputStyle, marginTop: 4 }} /></label>
        </div>
        <button type="button" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate({ path: "/application-settings/risk-scoring", data: riskForm })} style={{ ...saveButton, marginTop: "0.8rem" }}><Save size={14} /> Save risk scoring</button>
      </section>}

      {canManageScheduler && <section style={card}>
        <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}><Clock size={16} /> Scheduler timing</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>Changes reload in the worker within 30 seconds. Bounds protect escalation SLAs and upstream service limits; escalation cannot be disabled.</p>
        <p role="status" style={{ color: schedulerQuery.data?.revision === schedulerQuery.data?.applied_revision ? "var(--accent-green)" : "var(--accent-orange)", fontSize: "0.75rem" }}>
          {schedulerQuery.data?.revision === schedulerQuery.data?.applied_revision ? "Worker schedule is current." : `Worker is applying schedule revision ${schedulerQuery.data?.revision} (currently ${schedulerQuery.data?.applied_revision}).`}
        </p>
        <div style={{ display: "grid", gap: "0.65rem" }}>
          {jobs.map(job => {
            const schedule = schedulerDraft[job.key] || job.schedule;
            return <div key={job.key} style={{ display: "grid", gridTemplateColumns: "minmax(220px, 1.5fr) minmax(160px, 1fr) minmax(120px, 0.8fr) auto auto", gap: "0.65rem", alignItems: "center", padding: "0.65rem 0", borderTop: "1px solid var(--border-primary)" }}>
              <div><strong style={{ fontSize: "0.8rem" }}>{job.label}</strong><div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>{job.description}</div>{job.startup_run && <div style={{ fontSize: "0.68rem", color: "var(--accent-orange)" }}>Also runs during worker startup</div>}</div>
              {schedule.schedule_type === "interval" ? <label style={{ fontSize: "0.72rem" }}>Every<input type="number" min={job.min_value} max={job.max_value} value={schedule.every_value} onChange={e => updateJob(job, { every_value: Number(e.target.value) })} style={{ ...inputStyle, marginTop: 3 }} /></label> : <label style={{ fontSize: "0.72rem" }}>{schedule.schedule_type === "weekly" ? "Day and time" : "Time (Central)"}<div style={{ display: "flex", gap: 4, marginTop: 3 }}>{schedule.schedule_type === "weekly" && <select value={schedule.weekday} onChange={e => updateJob(job, { weekday: e.target.value })} style={inputStyle}>{["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"].map(day => <option key={day} value={day}>{day}</option>)}</select>}<input type="time" value={schedule.run_at} onChange={e => updateJob(job, { run_at: e.target.value })} style={inputStyle} /></div></label>}
              {schedule.schedule_type === "interval" ? <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>{schedule.unit} · allowed {job.min_value}-{job.max_value}</span> : <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>America/Chicago</span>}
              <label style={{ display: "flex", alignItems: "center", gap: 5, fontSize: "0.73rem", whiteSpace: "nowrap" }}><input type="checkbox" checked={schedule.enabled} disabled={!job.can_disable} onChange={e => updateJob(job, { enabled: e.target.checked })} /> Enabled</label>
              <button type="button" disabled={schedulerMutation.isPending} onClick={() => saveJob(job)} style={{ ...saveButton, whiteSpace: "nowrap" }}><Save size={13} /> Save</button>
            </div>;
          })}
        </div>
      </section>}
    </div>
  );
}
