import { useState } from "react";
import { Link } from "react-router-dom";
import api, { getApiErrorMessage } from "../utils/api";

export function ForgotPasswordPage() {
  const [identifier, setIdentifier] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setMessage("");
    setLoading(true);
    try {
      const response = await api.post("/auth/request-password-reset", { identifier: identifier.trim() });
      setMessage(response.data.message);
    } catch (reason: any) {
      setError(getApiErrorMessage(reason, "Unable to submit your recovery request."));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "var(--bg-primary)", color: "var(--text-primary)", padding: "1rem" }}>
      <form onSubmit={submit} style={{ width: 420, maxWidth: "100%", padding: "2rem", background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-lg)" }}>
        <h1 style={{ marginTop: 0, fontSize: "1.25rem" }}>Request password reset</h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.85rem", lineHeight: 1.5 }}>
          Enter your username or approved recovery email. A user administrator must review every reset request.
          Accounts without an approved recovery email require administrator-assisted recovery.
        </p>
        {message && <p role="status" style={{ color: "var(--accent-green)", fontSize: "0.85rem" }}>{message}</p>}
        {error && <p role="alert" style={{ color: "var(--accent-red)", fontSize: "0.85rem" }}>{error}</p>}
        <label htmlFor="recovery-identifier" style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.8rem" }}>Username or email</label>
        <input id="recovery-identifier" required maxLength={254} autoComplete="username" value={identifier} onChange={e => setIdentifier(e.target.value)} style={{ width: "100%", boxSizing: "border-box", padding: "0.65rem", borderRadius: 4, border: "1px solid var(--border-primary)", background: "var(--bg-input)", color: "var(--text-primary)" }} />
        <button type="submit" disabled={loading || !identifier.trim()} style={{ width: "100%", marginTop: "1rem", padding: "0.7rem", border: 0, borderRadius: 4, background: "var(--accent-blue)", color: "white", fontWeight: 700 }}>
          {loading ? "Submitting..." : "Submit recovery request"}
        </button>
        <p style={{ marginBottom: 0, textAlign: "center", fontSize: "0.8rem" }}><Link to="/login">Return to sign in</Link></p>
      </form>
    </main>
  );
}
