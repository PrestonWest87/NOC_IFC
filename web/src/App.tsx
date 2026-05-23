import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider, useAuth } from "./utils/AuthContext";
import { Layout } from "./components/Layout";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { ThreatTelemetryPage } from "./pages/ThreatTelemetryPage";
import { RegionalGridPage } from "./pages/RegionalGridPage";
import { ThreatHuntingPage } from "./pages/ThreatHuntingPage";
import { AiopsRcaPage } from "./pages/AiopsRcaPage";
import { ShiftLogbookPage } from "./pages/ShiftLogbookPage";
import { ReportingPage } from "./pages/ReportingPage";
import { SettingsPage } from "./pages/SettingsPage";

const queryClient = new QueryClient();

const PAGE_PERMISSION_MAP: Record<string, string> = {
  "/": "Global Dashboards",
  "/threat-telemetry": "Threat Telemetry",
  "/regional-grid": "Regional Grid",
  "/threat-hunting": "Threat Hunting & IOCs",
  "/aiops-rca": "AIOps RCA",
  "/shift-logbook": "Shift Logbook",
  "/reporting": "Reporting & Briefings",
  "/settings": "Settings & Admin",
};

function ProtectedRoute({ children, path }: { children: React.ReactNode; path?: string }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (path) {
    const pageName = PAGE_PERMISSION_MAP[path];
    if (pageName && !user.allowed_pages?.includes(pageName)) {
      return <Navigate to="/" replace />;
    }
  }
  return <Layout>{children}</Layout>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<ProtectedRoute path="/"><DashboardPage /></ProtectedRoute>} />
      <Route path="/threat-telemetry" element={<ProtectedRoute path="/threat-telemetry"><ThreatTelemetryPage /></ProtectedRoute>} />
      <Route path="/regional-grid" element={<ProtectedRoute path="/regional-grid"><RegionalGridPage /></ProtectedRoute>} />
      <Route path="/threat-hunting" element={<ProtectedRoute path="/threat-hunting"><ThreatHuntingPage /></ProtectedRoute>} />
      <Route path="/aiops-rca" element={<ProtectedRoute path="/aiops-rca"><AiopsRcaPage /></ProtectedRoute>} />
      <Route path="/shift-logbook" element={<ProtectedRoute path="/shift-logbook"><ShiftLogbookPage /></ProtectedRoute>} />
      <Route path="/reporting" element={<ProtectedRoute path="/reporting"><ReportingPage /></ProtectedRoute>} />
      <Route path="/settings" element={<ProtectedRoute path="/settings"><SettingsPage /></ProtectedRoute>} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <HashRouter>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </HashRouter>
    </QueryClientProvider>
  );
}
