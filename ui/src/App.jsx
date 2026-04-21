import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainLayout from './components/MainLayout';
import GlobalDashboards from './pages/GlobalDashboards'; // <-- Import the new page
import RegionalMap from './components/RegionalMap'; // Make sure the Map is still available for the Grid page!

// Placeholders for the other routes
const Telemetry = () => <div><h1>📡 Threat Telemetry</h1><p>RSS Feeds, KEVs, and Crime Maps will go here.</p></div>;
const RegionalGrid = () => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', height: '100%' }}>
    <h1>🗺️ Regional Grid</h1>
    <RegionalMap />
  </div>
);

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          {/* Inject the real GlobalDashboards component into the root path */}
          <Route index element={<GlobalDashboards />} />
          <Route path="telemetry" element={<Telemetry />} />
          <Route path="grid" element={<RegionalGrid />} />
          <Route path="hunting" element={<div><h1>🎯 Threat Hunting</h1></div>} />
          <Route path="aiops" element={<div><h1>⚡ AIOps RCA</h1></div>} />
          <Route path="logs" element={<div><h1>📝 Shift Logbook</h1></div>} />
          <Route path="reporting" element={<div><h1>📑 Reporting & Briefings</h1></div>} />
          <Route path="settings" element={<div><h1>⚙️ Settings & Admin</h1></div>} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
