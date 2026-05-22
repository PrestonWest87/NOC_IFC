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

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
      <Route path="/threat-telemetry" element={<ProtectedRoute><ThreatTelemetryPage /></ProtectedRoute>} />
      <Route path="/regional-grid" element={<ProtectedRoute><RegionalGridPage /></ProtectedRoute>} />
      <Route path="/threat-hunting" element={<ProtectedRoute><ThreatHuntingPage /></ProtectedRoute>} />
      <Route path="/aiops-rca" element={<ProtectedRoute><AiopsRcaPage /></ProtectedRoute>} />
      <Route path="/shift-logbook" element={<ProtectedRoute><ShiftLogbookPage /></ProtectedRoute>} />
      <Route path="/reporting" element={<ProtectedRoute><ReportingPage /></ProtectedRoute>} />
      <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
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
