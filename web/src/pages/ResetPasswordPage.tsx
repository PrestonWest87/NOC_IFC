import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api, { getApiErrorMessage } from "../utils/api";

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get("token") || "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setMessage("");
    if (!token) return setError("This reset link is missing its token.");
    if (password.length < 12) return setError("Password must be at least 12 characters.");
    if (password !== confirm) return setError("Passwords do not match.");
    setLoading(true);
    try {
      const response = await api.post("/auth/reset-password", { token, new_password: password });
      setMessage(response.data.message);
      setPassword("");
      setConfirm("");
    } catch (reason: any) {
      setError(getApiErrorMessage(reason, "Unable to reset password."));
    } finally {
      setLoading(false);
    }
  };

  return (
    <main style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "var(--bg-primary)", color: "var(--text-primary)", padding: "1rem" }}>
      <form onSubmit={submit} style={{ width: 420, maxWidth: "100%", padding: "2rem", background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-lg)" }}>
        <h1 style={{ marginTop: 0, fontSize: "1.25rem" }}>Choose a new password</h1>
        <p style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>Reset links expire after one hour and can be used once.</p>
        {message && <p role="status" style={{ color: "var(--accent-green)" }}>{message}</p>}
        {error && <p role="alert" style={{ color: "var(--accent-red)" }}>{error}</p>}
        <label htmlFor="new-password" style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.8rem" }}>New password</label>
        <input id="new-password" required minLength={12} autoComplete="new-password" type="password" value={password} onChange={e => setPassword(e.target.value)} style={{ width: "100%", boxSizing: "border-box", padding: "0.65rem", borderRadius: 4, border: "1px solid var(--border-primary)", background: "var(--bg-input)", color: "var(--text-primary)" }} />
        <label htmlFor="confirm-password" style={{ display: "block", margin: "0.75rem 0 0.35rem", fontSize: "0.8rem" }}>Confirm password</label>
        <input id="confirm-password" required minLength={12} autoComplete="new-password" type="password" value={confirm} onChange={e => setConfirm(e.target.value)} style={{ width: "100%", boxSizing: "border-box", padding: "0.65rem", borderRadius: 4, border: "1px solid var(--border-primary)", background: "var(--bg-input)", color: "var(--text-primary)" }} />
        <button type="submit" disabled={loading || !token} style={{ width: "100%", marginTop: "1rem", padding: "0.7rem", border: 0, borderRadius: 4, background: "var(--accent-blue)", color: "white", fontWeight: 700 }}>
          {loading ? "Resetting..." : "Reset password"}
        </button>
        <p style={{ marginBottom: 0, textAlign: "center", fontSize: "0.8rem" }}><Link to="/login">Return to sign in</Link></p>
      </form>
    </main>
  );
}
