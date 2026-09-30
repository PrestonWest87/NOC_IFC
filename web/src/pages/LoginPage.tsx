import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../utils/AuthContext";
import { PAGE_ROUTE_MAP } from "../utils/routeConfig";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const user = await login(username, password);
      const firstAllowed = user.allowed_pages?.[0];
      navigate(firstAllowed ? PAGE_ROUTE_MAP[firstAllowed] || "/" : "/", { replace: true });
    } catch {
      setError("Invalid credentials");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#0a1628", fontFamily: "system-ui, sans-serif" }}>
      <form onSubmit={handleSubmit} style={{ background: "#1e293b", padding: "2.5rem", borderRadius: 8, width: 360, boxShadow: "0 4px 24px rgba(0,0,0,0.4)" }}>
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <h1 style={{ color: "#fff", fontSize: "1.3rem", margin: "0 0 0.25rem" }}>NOC Fusion Center</h1>
          <p style={{ color: "#64748b", fontSize: "0.85rem", margin: 0 }}>Intelligence Fusion Gateway</p>
        </div>
        <section
          role="note"
          aria-label="Restricted system notice"
          style={{ background: "#0f172a", border: "1px solid #475569", borderLeft: "3px solid #f59e0b", borderRadius: 4, padding: "0.7rem 0.75rem", marginBottom: "1rem" }}
        >
          <div style={{ color: "#fbbf24", fontSize: "0.72rem", fontWeight: 700, letterSpacing: "0.04em", marginBottom: "0.3rem" }}>
            RESTRICTED SYSTEM — AUTHORIZED USE ONLY
          </div>
          <p style={{ color: "#cbd5e1", fontSize: "0.7rem", lineHeight: 1.45, margin: 0 }}>
            This system is for authorized users only. Access and activity may be monitored, recorded, and audited. By accessing this system, you consent to such monitoring. Unauthorized use is prohibited and may result in disciplinary action and civil or criminal penalties.
          </p>
        </section>
        {error && <div style={{ background: "#7f1d1d", color: "#fca5a5", padding: "0.5rem", borderRadius: 4, marginBottom: "1rem", fontSize: "0.85rem", textAlign: "center" }}>{error}</div>}
        <div style={{ marginBottom: "1rem" }}>
          <label style={{ display: "block", color: "#94a3b8", fontSize: "0.8rem", marginBottom: "0.3rem" }}>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} style={{ width: "100%", padding: "0.6rem", borderRadius: 4, border: "1px solid #334155", background: "#0f172a", color: "#fff", boxSizing: "border-box" }} />
        </div>
        <div style={{ marginBottom: "1.5rem" }}>
          <label style={{ display: "block", color: "#94a3b8", fontSize: "0.8rem", marginBottom: "0.3rem" }}>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: "100%", padding: "0.6rem", borderRadius: 4, border: "1px solid #334155", background: "#0f172a", color: "#fff", boxSizing: "border-box" }} />
        </div>
        <button type="submit" disabled={loading} style={{ width: "100%", padding: "0.7rem", borderRadius: 4, border: "none", background: "#2563eb", color: "#fff", fontWeight: 600, cursor: "pointer", opacity: loading ? 0.7 : 1 }}>
          {loading ? "Signing in..." : "Sign In"}
        </button>
      </form>
    </div>
  );
}
