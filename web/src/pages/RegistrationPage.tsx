import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import api from "../utils/api";
import { useAuth } from "../utils/AuthContext";
import { PAGE_ROUTE_MAP } from "../utils/routeConfig";
import { THEMES } from "../components/ThemeSelector";

export function RegistrationPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  useAuth();
  const inviteToken = params.get("token") || "";
  const [invite, setInvite] = useState<{ username: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [form, setForm] = useState({ password: "", confirm: "", full_name: "", job_title: "", contact_info: "", default_shift: "No Shift", theme: "standard" });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!inviteToken) {
      setError("This registration link is missing its invitation token.");
      return;
    }
    api.get("/auth/register/validate", { params: { token: inviteToken } })
      .then((response) => setInvite(response.data))
      .catch((reason) => setError(reason.response?.data?.detail || "This registration link is invalid or expired."));
  }, [inviteToken]);

  const update = (key: string, value: string) => setForm((previous) => ({ ...previous, [key]: value }));
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    if (form.password.length < 12) return setError("Password must be at least 12 characters.");
    if (form.password !== form.confirm) return setError("Passwords do not match.");
    setLoading(true);
    try {
      const response = await api.post("/auth/register", { token: inviteToken, ...form });
      sessionStorage.setItem("noc_token", response.data.token);
      sessionStorage.setItem("noc_user", JSON.stringify(response.data.user));
      setMessage("Registration complete. Loading your workspace...");
      const firstAllowed = response.data.user.allowed_pages?.[0];
      navigate(firstAllowed ? PAGE_ROUTE_MAP[firstAllowed] || "/" : "/", { replace: true });
      window.location.reload();
    } catch (reason: any) {
      setError(reason.response?.data?.detail || "Registration failed. Please request a new link.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--bg-primary)", color: "var(--text-primary)", padding: "1rem" }}>
      <form onSubmit={submit} style={{ width: 460, maxWidth: "100%", background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-lg)", padding: "2rem", boxShadow: "var(--shadow-lg)" }}>
        <h1 style={{ margin: "0 0 0.35rem", fontSize: "1.35rem" }}>Create NOC Account</h1>
        <p style={{ margin: "0 0 1.25rem", color: "var(--text-muted)", fontSize: "0.82rem" }}>
          Complete your profile and choose a secure password.
        </p>
        {error && <div role="alert" style={{ background: "var(--shade-red)", color: "var(--accent-red)", padding: "0.6rem", borderRadius: "var(--radius-sm)", marginBottom: "1rem", fontSize: "0.82rem" }}>{error}</div>}
        {message && <div role="status" style={{ color: "var(--accent-green)", marginBottom: "1rem", fontSize: "0.82rem" }}>{message}</div>}
        {invite && (
          <>
            <div style={{ padding: "0.7rem", background: "var(--bg-tertiary)", borderRadius: "var(--radius-sm)", marginBottom: "1rem", fontSize: "0.82rem" }}>
              Username: <strong>{invite.username}</strong><br />Assigned role: <strong>{invite.role}</strong>
            </div>
            <div style={{ display: "grid", gap: "0.65rem" }}>
              <input aria-label="Password" required type="password" minLength={12} placeholder="Password (12+ characters)" value={form.password} onChange={(e) => update("password", e.target.value)} />
              <input aria-label="Confirm password" required type="password" minLength={12} placeholder="Confirm password" value={form.confirm} onChange={(e) => update("confirm", e.target.value)} />
              <input aria-label="Full name" required placeholder="Full name" value={form.full_name} onChange={(e) => update("full_name", e.target.value)} />
              <input aria-label="Job title" placeholder="Job title" value={form.job_title} onChange={(e) => update("job_title", e.target.value)} />
              <input aria-label="Contact information" placeholder="Contact information" value={form.contact_info} onChange={(e) => update("contact_info", e.target.value)} />
              <select aria-label="Default shift" value={form.default_shift} onChange={(e) => update("default_shift", e.target.value)}>
                <option>No Shift</option><option>Morning</option><option>Afternoon</option><option>Evening</option>
              </select>
              <select aria-label="Theme" value={form.theme} onChange={(e) => update("theme", e.target.value)}>
                {THEMES.map((theme) => <option key={theme.id} value={theme.id}>{theme.label}</option>)}
              </select>
              <button type="submit" disabled={loading} style={{ padding: "0.7rem", border: "none", borderRadius: "var(--radius-sm)", background: "var(--accent-blue)", color: "#fff", fontWeight: 700 }}>
                {loading ? "Creating account..." : "Create Account"}
              </button>
            </div>
          </>
        )}
      </form>
    </div>
  );
}
