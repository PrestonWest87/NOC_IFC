import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, RotateCcw, Save } from "lucide-react";
import api, { getApiErrorMessage } from "../utils/api";

const fields = [
  "risk_alert_recipients", "remedyforce_ticket_email", "noc_notify_email",
  "noc_onpage_email", "itnetwork_onpage_email", "elastic_url", "elastic_verify_certs",
  "elastic_ca_certs", "elastic_request_timeout", "elastic_max_results",
  "crime_alert_sms", "crime_alert_email",
] as const;

const inputStyle: React.CSSProperties = {
  background: "var(--bg-input)", color: "var(--text-primary)",
  border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)",
  padding: "0.5rem 0.6rem", fontSize: "0.8rem", width: "100%", boxSizing: "border-box",
};
const buttonStyle: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: "0.4rem", padding: "0.5rem 0.8rem",
  color: "#fff", background: "var(--accent-blue)", border: 0, borderRadius: "var(--radius-sm)",
  cursor: "pointer", fontWeight: 650, fontSize: "0.76rem",
};
const secondaryButtonStyle: React.CSSProperties = {
  ...buttonStyle, color: "var(--text-primary)", background: "var(--bg-input)",
  border: "1px solid var(--border-primary)",
};
const cardStyle: React.CSSProperties = {
  background: "var(--bg-card)", border: "1px solid var(--border-primary)",
  borderRadius: "var(--radius-md)", padding: "1rem",
};

const recipientFields = [
  { key: "remedyforce_ticket_email", label: "Remedyforce ticket destination", placeholder: "remedyforce@example.com" },
  { key: "noc_notify_email", label: "NOC notification destination", placeholder: "noc@example.com" },
  { key: "noc_onpage_email", label: "NOC on-page destination", placeholder: "noc-onpage@example.com" },
  { key: "itnetwork_onpage_email", label: "IT/network on-page destination", placeholder: "itnetwork-onpage@example.com" },
  { key: "crime_alert_sms", label: "Crime alert SMS gateway email", placeholder: "5551234567@carrier.example" },
  { key: "crime_alert_email", label: "Crime alert email fallback", placeholder: "security@example.com" },
] as const;

/** Administrator-granted editable environment overrides for alert routing and Elastic. */
export function OperationalIntegrationSettings() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<any>(null);
  const [apiKeyDraft, setApiKeyDraft] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [dirtyFields, setDirtyFields] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const query = useQuery({
    queryKey: ["integration-settings"],
    queryFn: () => api.get("/application-settings/integrations").then(response => response.data),
  });
  useEffect(() => {
    if (query.data) setForm(query.data);
  }, [query.data]);

  const saveMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.put("/application-settings/integrations", data),
    onSuccess: () => {
      setError("");
      setNotice("Notification and integration settings saved.");
      setApiKeyDraft("");
      setDirtyFields(new Set());
      queryClient.invalidateQueries({ queryKey: ["integration-settings"] });
    },
    onError: reason => { setNotice(""); setError(getApiErrorMessage(reason)); },
  });

  const saveAll = () => {
    const data: Record<string, unknown> = Object.fromEntries([...dirtyFields].map(key => [key, form[key]]));
    if (apiKeyDraft.trim()) data.elastic_api_key = apiKeyDraft.trim();
    if (!Object.keys(data).length) {
      setNotice("No integration changes to save.");
      setError("");
      return;
    }
    saveMutation.mutate(data);
  };
  const source = (key: string) => form?.sources?.[key] || "environment";
  const update = (key: string, value: unknown) => {
    setForm((previous: any) => ({ ...previous, [key]: value }));
    setDirtyFields(previous => new Set(previous).add(key));
  };

  if (query.isLoading || !form) {
    return <section style={cardStyle} role="status">Loading notification and integration settings...</section>;
  }
  if (query.isError) {
    return <section style={{ ...cardStyle, color: "var(--accent-red)" }} role="alert">
      {getApiErrorMessage(query.error, "Unable to load notification and integration settings.")}
    </section>;
  }

  return (
    <section style={cardStyle}>
      <h3 style={{ marginTop: 0 }}>Notification destinations and Elastic integration</h3>
      <p style={{ marginTop: 0, color: "var(--text-muted)", fontSize: "0.76rem" }}>
        Saved values apply to the API and worker without a restart. Blank destinations disable them. “Reset to environment” removes saved overrides and restores the corresponding environment values.
      </p>
      {(notice || error) && <div role={error ? "alert" : "status"} aria-live="polite" style={{ ...cardStyle, marginBottom: "0.75rem", padding: "0.6rem", color: error ? "var(--accent-red)" : "var(--accent-green)" }}>{error || notice}</div>}

      <label style={{ display: "block", fontSize: "0.76rem", marginBottom: "0.7rem" }}>
        Risk alert and daily brief recipients
        <textarea value={form.risk_alert_recipients || ""} onChange={event => update("risk_alert_recipients", event.target.value)} style={{ ...inputStyle, display: "block", marginTop: 4, minHeight: 62 }} placeholder="noc@example.com, security@example.com" />
        <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Comma-separated · source: {source("risk_alert_recipients")}</span>
      </label>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "0.7rem" }}>
        {recipientFields.map(field => <label key={field.key} style={{ fontSize: "0.76rem" }}>
          {field.label}
          <input value={form[field.key] || ""} onChange={event => update(field.key, event.target.value)} style={{ ...inputStyle, display: "block", marginTop: 4 }} placeholder={field.placeholder} />
          <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Source: {source(field.key)}</span>
        </label>)}
      </div>

      <div style={{ borderTop: "1px solid var(--border-primary)", marginTop: "0.85rem", paddingTop: "0.85rem" }}>
        <h4 style={{ margin: "0 0 0.65rem", fontSize: "0.83rem", color: "var(--text-secondary)" }}>Elastic telemetry</h4>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "0.7rem" }}>
          <label style={{ fontSize: "0.76rem" }}>
            Elastic URL (blank disables sync)
            <input type="url" value={form.elastic_url || ""} onChange={event => update("elastic_url", event.target.value)} style={{ ...inputStyle, display: "block", marginTop: 4 }} placeholder="https://elastic.example:9200" />
            <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Reachable from API and worker · source: {source("elastic_url")}</span>
          </label>
          <label style={{ fontSize: "0.76rem" }}>
            Elastic API key
            <div style={{ display: "flex", gap: 4, marginTop: 4 }}>
              <input type={showApiKey ? "text" : "password"} value={apiKeyDraft} onChange={event => setApiKeyDraft(event.target.value)} style={inputStyle} placeholder={form.elastic_api_key_configured ? "Saved key configured; blank keeps it" : "API key"} />
              <button type="button" aria-label={showApiKey ? "Hide Elastic API key" : "Show Elastic API key"} onClick={() => setShowApiKey(value => !value)} style={{ ...buttonStyle, padding: "0.35rem" }}>{showApiKey ? <EyeOff size={14} /> : <Eye size={14} />}</button>
            </div>
            <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Configured: {form.elastic_api_key_configured ? "Yes" : "No"} · source: {source("elastic_api_key")}</span>
          </label>
          <label style={{ fontSize: "0.76rem" }}>
            CA certificate path
            <input value={form.elastic_ca_certs || ""} onChange={event => update("elastic_ca_certs", event.target.value)} style={{ ...inputStyle, display: "block", marginTop: 4 }} placeholder="/app/certs/elastic-ca.pem" />
            <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Source: {source("elastic_ca_certs")}</span>
          </label>
          <label style={{ fontSize: "0.76rem" }}>
            Request timeout (seconds)
            <input type="number" min={0.1} max={120} step={0.1} value={form.elastic_request_timeout ?? 15} onChange={event => update("elastic_request_timeout", event.target.value === "" ? "" : Number(event.target.value))} style={{ ...inputStyle, display: "block", marginTop: 4 }} />
            <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Source: {source("elastic_request_timeout")}</span>
          </label>
          <label style={{ fontSize: "0.76rem" }}>
            Maximum results
            <input type="number" min={1} max={5000} step={1} value={form.elastic_max_results ?? 500} onChange={event => update("elastic_max_results", event.target.value === "" ? "" : Number(event.target.value))} style={{ ...inputStyle, display: "block", marginTop: 4 }} />
            <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Source: {source("elastic_max_results")}</span>
          </label>
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", marginTop: "0.65rem", fontSize: "0.77rem" }}>
          <input type="checkbox" checked={form.elastic_verify_certs !== false} onChange={event => update("elastic_verify_certs", event.target.checked)} />
          Verify Elastic TLS certificates
          <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>Source: {source("elastic_verify_certs")}</span>
        </label>
      </div>

      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.85rem" }}>
        <button type="button" disabled={saveMutation.isPending} onClick={saveAll} style={buttonStyle}><Save size={14} /> Save destinations and Elastic</button>
        <button type="button" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate({ ...Object.fromEntries(fields.map(key => [key, null])), elastic_api_key: null })} style={secondaryButtonStyle}><RotateCcw size={14} /> Reset to environment</button>
        <button type="button" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate({ elastic_api_key: "" })} style={secondaryButtonStyle}>Clear stored key</button>
        <button type="button" disabled={saveMutation.isPending} onClick={() => saveMutation.mutate({ elastic_api_key: null })} style={secondaryButtonStyle}>Use environment key</button>
      </div>
    </section>
  );
}
