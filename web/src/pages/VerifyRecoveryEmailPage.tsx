import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import api, { getApiErrorMessage } from "../utils/api";

export function VerifyRecoveryEmailPage() {
  const [params] = useSearchParams();
  const token = params.get("token") || "";
  const [message, setMessage] = useState("Verifying your recovery email...");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!token) {
      setError("This verification link is missing its token.");
      setMessage("");
      return;
    }
    api.get("/auth/verify-recovery-email", { params: { token } })
      .then(response => setMessage(response.data.message || "Recovery email verified."))
      .catch(reason => {
        setMessage("");
        setError(getApiErrorMessage(reason, "This verification link is invalid or expired."));
      });
  }, [token]);

  return (
    <main style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "var(--bg-primary)", color: "var(--text-primary)", padding: "1rem" }}>
      <section style={{ width: 420, maxWidth: "100%", padding: "2rem", background: "var(--bg-card)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-lg)" }}>
        <h1 style={{ marginTop: 0, fontSize: "1.25rem" }}>Recovery email</h1>
        {message && <p role="status">{message}</p>}
        {error && <p role="alert" style={{ color: "var(--accent-red)" }}>{error}</p>}
        <Link to="/login">Return to sign in</Link>
      </section>
    </main>
  );
}
