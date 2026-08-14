import { Component, lazy, Suspense, type ErrorInfo, type ReactNode } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "./utils/AuthContext";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/LoginPage";
import { RegistrationPage } from "./pages/RegistrationPage";
import { PAGE_PERMISSION_MAP, PAGE_ROUTE_MAP } from "./utils/routeConfig";
import { useAIOpsWebSocket } from "./hooks/useAIOpsWebSocket";
import { ThemeSync } from "./components/ThemeSelector";

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
      refetchOnReconnect: false,
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
  if (user.allowed_pages && user.allowed_pages.length === 0) {
    return <div style={{ padding: "2rem", color: "var(--text-primary)" }}>Access denied. Contact an administrator.</div>;
  }
  if (path) {
    const pageName = PAGE_PERMISSION_MAP[path];
    if (pageName && !user.allowed_pages?.includes(pageName)) {
      const fallback = user.allowed_pages?.[0] ? PAGE_ROUTE_MAP[user.allowed_pages[0]] || "/" : "/";
      return <Navigate to={fallback} replace />;
    }
  }
  return <Layout>{children}</Layout>;
}

function AppRoutes() {
  return (
    <Suspense fallback={<div style={{ padding: "2rem", color: "var(--text-primary)" }}>Loading NOC workspace...</div>}>
      <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegistrationPage />} />
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
          <ThemeSync />
          <RealtimeBridge />
          <PageErrorBoundary><AppRoutes /></PageErrorBoundary>
        </AuthProvider>
      </HashRouter>
    </QueryClientProvider>
  );
}
