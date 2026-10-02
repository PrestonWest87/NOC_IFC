import { Component, lazy, Suspense, useEffect, useState, type ErrorInfo, type ReactNode } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "./utils/AuthContext";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/LoginPage";
import { RegistrationPage } from "./pages/RegistrationPage";
import { ForgotPasswordPage } from "./pages/ForgotPasswordPage";
import { ResetPasswordPage } from "./pages/ResetPasswordPage";
import { VerifyRecoveryEmailPage } from "./pages/VerifyRecoveryEmailPage";
import { PAGE_PERMISSION_MAP } from "./utils/routeConfig";
import { useAIOpsWebSocket } from "./hooks/useAIOpsWebSocket";
import { ThemeSync } from "./components/ThemeSelector";
import { hasPagePermission } from "./utils/permissions";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then(m => ({ default: m.DashboardPage })));
const ThreatTelemetryPage = lazy(() => import("./pages/ThreatTelemetryPage").then(m => ({ default: m.ThreatTelemetryPage })));
const RegionalGridPage = lazy(() => import("./pages/RegionalGridPage").then(m => ({ default: m.RegionalGridPage })));
const ThreatHuntingPage = lazy(() => import("./pages/ThreatHuntingPage").then(m => ({ default: m.ThreatHuntingPage })));
const AiopsRcaPage = lazy(() => import("./pages/AiopsRcaPage").then(m => ({ default: m.AiopsRcaPage })));
const ShiftLogbookPage = lazy(() => import("./pages/ShiftLogbookPage").then(m => ({ default: m.ShiftLogbookPage })));
const ReportingPage = lazy(() => import("./pages/ReportingPage").then(m => ({ default: m.ReportingPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then(m => ({ default: m.SettingsPage })));
const KeywordAnalysisPage = lazy(() => import("./pages/KeywordAnalysisPage").then(m => ({ default: m.KeywordAnalysisPage })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      refetchOnReconnect: true,
      retry: 1,
    },
  },
});

class PageErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("NOC page render error", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: "2rem", color: "var(--text-primary)", fontFamily: "var(--font-sans)" }}>
          <h2>Workspace page failed to load</h2>
          <p style={{ color: "var(--text-secondary)" }}>{this.state.error.message}</p>
          <button onClick={() => window.location.reload()} style={{ padding: "0.5rem 0.8rem", cursor: "pointer" }}>
            Reload page
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function ProtectedRoute({ children, path }: { children: React.ReactNode; path?: string }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (path) {
    const pageName = PAGE_PERMISSION_MAP[path];
    if (pageName && !hasPagePermission(user, pageName)) {
      return (
        <Layout>
          <section role="alert" style={{ margin: "2rem", padding: "1.25rem", border: "1px solid var(--accent-red)", borderRadius: "var(--radius-md)", color: "var(--text-primary)" }}>
            <h2 style={{ marginTop: 0 }}>Access denied</h2>
            <p>Your role does not include the <strong>{pageName}</strong> page.</p>
            <p style={{ color: "var(--text-muted)" }}>Contact an administrator to request access. Your session is still active.</p>
          </section>
        </Layout>
      );
    }
  }
  return <Layout>{children}</Layout>;
}

function PermissionNoticeHost() {
  const [message, setMessage] = useState("");
  useEffect(() => {
    const show = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      setMessage(typeof detail === "string" ? detail : detail?.message || "You do not have permission to perform this action.");
    };
    window.addEventListener("noc:permission-denied", show);
    return () => window.removeEventListener("noc:permission-denied", show);
  }, []);
  if (!message) return null;
  return (
    <div role="alert" aria-live="assertive" style={{ position: "fixed", right: 16, top: 16, zIndex: 4000, maxWidth: 440, padding: "0.9rem 1rem", border: "1px solid var(--accent-orange)", borderRadius: "var(--radius-md)", background: "var(--bg-card)", color: "var(--text-primary)", boxShadow: "var(--shadow-lg)" }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: "0.75rem" }}>
        <span>{message}</span>
        <button type="button" onClick={() => setMessage("")} aria-label="Dismiss permission message" style={{ background: "none", border: 0, color: "inherit", cursor: "pointer", fontSize: "1.1rem" }}>×</button>
      </div>
    </div>
  );
}

function AppRoutes() {
  return (
    <Suspense fallback={<div style={{ padding: "2rem", color: "var(--text-primary)" }}>Loading NOC workspace...</div>}>
      <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegistrationPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/verify-email" element={<VerifyRecoveryEmailPage />} />
      <Route path="/" element={<ProtectedRoute path="/"><DashboardPage /></ProtectedRoute>} />
      <Route path="/threat-telemetry" element={<ProtectedRoute path="/threat-telemetry"><ThreatTelemetryPage /></ProtectedRoute>} />
      <Route path="/regional-grid" element={<ProtectedRoute path="/regional-grid"><RegionalGridPage /></ProtectedRoute>} />
      <Route path="/threat-hunting" element={<ProtectedRoute path="/threat-hunting"><ThreatHuntingPage /></ProtectedRoute>} />
      <Route path="/aiops-rca" element={<ProtectedRoute path="/aiops-rca"><AiopsRcaPage /></ProtectedRoute>} />
      <Route path="/shift-logbook" element={<ProtectedRoute path="/shift-logbook"><ShiftLogbookPage /></ProtectedRoute>} />
      <Route path="/reporting" element={<ProtectedRoute path="/reporting"><ReportingPage /></ProtectedRoute>} />
      <Route path="/settings" element={<ProtectedRoute path="/settings"><SettingsPage /></ProtectedRoute>} />
      <Route path="/keyword-analysis" element={<ProtectedRoute path="/keyword-analysis"><KeywordAnalysisPage /></ProtectedRoute>} />
      </Routes>
    </Suspense>
  );
}

function RealtimeBridge() {
  useAIOpsWebSocket();
  return null;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <AuthProvider>
          <PermissionNoticeHost />
          <ThemeSync />
          <RealtimeBridge />
          <PageErrorBoundary><AppRoutes /></PageErrorBoundary>
        </AuthProvider>
      </HashRouter>
    </QueryClientProvider>
  );
}
