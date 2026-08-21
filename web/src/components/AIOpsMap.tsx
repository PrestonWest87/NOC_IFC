import { useMemo, useCallback, useRef, useState, useEffect } from "react";
import DeckGL from "@deck.gl/react";
import { ScatterplotLayer } from "@deck.gl/layers";
import { Map } from "react-map-gl/maplibre";
import type { MapViewState } from "@deck.gl/core";
import "maplibre-gl/dist/maplibre-gl.css";

interface Site {
  name: string;
  lat: number;
  lon: number;
  alert_count: number;
}

interface AIOpsMapProps {
  sites: Site[];
  viewState?: MapViewState;
  height?: string;
  tabKey?: string | number;
}

const INITIAL_VIEW: MapViewState = {
  latitude: 34.8,
  longitude: -92.2,
  zoom: 6,
  pitch: 0,
};

const DARK_MATTER = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json";

export function AIOpsMap({ sites, viewState = INITIAL_VIEW, height = "100%", tabKey }: AIOpsMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [fs, setFs] = useState(false);
  const [selectedSite, setSelectedSite] = useState<Site | null>(null);

  useEffect(() => {
    const onFsChange = () => setFs(document.fullscreenElement === containerRef.current);
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, []);

  const toggleFs = useCallback(() => {
    if (!containerRef.current) return;
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      containerRef.current.requestFullscreen();
    }
  }, []);

  const tooltip = useCallback((info: any) => {
    if (!info.object || info.layer?.id !== "sites") return null;
    const d = info.object;
    return {
      text: `${d.name}\nAlerts: ${d.alert_count}\nStatus: ${d.alert_count > 0 ? "Degraded" : "Operational"}`,
      style: { background: "var(--bg-card)", color: "var(--text-primary)", fontSize: "0.78rem", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.5rem" },
    };
  }, []);

  const handleClick = useCallback((info: any) => {
    if (info.object && info.layer?.id === "sites") {
      setSelectedSite(info.object as Site);
    }
  }, []);

  const layers = useMemo(() => {
    const siteData = sites.map((s) => ({
      name: s.name,
      position: [s.lon, s.lat] as [number, number],
      color: s.alert_count > 0 ? [255, 0, 0, 200] : [0, 255, 0, 160],
      alert_count: s.alert_count,
    }));

    const alertData = sites
      .filter((s) => s.alert_count > 0)
      .map((s) => ({
        position: [s.lon, s.lat] as [number, number],
        radius: 4000 + s.alert_count * 2500,
      }));

    return [
      new ScatterplotLayer({
        id: "sites",
        data: siteData,
        getPosition: (d) => d.position,
        getFillColor: (d) => d.color,
        getRadius: 1800,
        pickable: true,
        radiusMinPixels: 4,
        radiusMaxPixels: 20,
      }),
      ...(alertData.length > 0
        ? [
            new ScatterplotLayer({
              id: "alert-pulses",
              data: alertData,
              getPosition: (d) => d.position,
              getFillColor: [255, 0, 0, 40],
              getRadius: (d) => d.radius,
              radiusMinPixels: 8,
              radiusMaxPixels: 100,
            }),
          ]
        : []),
    ];
  }, [sites]);

  return (
    <div ref={containerRef} style={{ height, width: "100%", position: "relative", minHeight: 300 }}>
      <button
        onClick={toggleFs}
        title={fs ? "Exit Fullscreen" : "Fullscreen"}
        style={{
          position: "absolute", top: 8, right: 8, zIndex: 10,
          background: "var(--bg-card, #1e293b)", border: "1px solid var(--border-primary, #334155)",
          borderRadius: "var(--radius-sm, 4px)", color: "var(--text-secondary, #94a3b8)",
          cursor: "pointer", padding: "4px 8px", fontSize: "0.78rem",
          display: "flex", alignItems: "center", gap: "4px",
        }}
      >
        {fs ? "Exit" : "Fullscreen"}
      </button>
      <DeckGL key={tabKey} layers={layers} initialViewState={viewState} controller={true}
        style={{ height: "100%", width: "100%", position: "relative" }} getTooltip={tooltip} onClick={handleClick}>
        <Map mapStyle={DARK_MATTER} />
      </DeckGL>

      {selectedSite && (
        <div style={{
          position: "fixed", inset: 0, zIndex: 1000,
          display: "flex", alignItems: "center", justifyContent: "center",
          background: "rgba(0,0,0,0.5)",
        }} onClick={() => setSelectedSite(null)}>
          <div onClick={(e) => e.stopPropagation()} style={{
            background: "var(--bg-card)", color: "var(--text-primary)",
            borderRadius: "var(--radius-md)", padding: "1.25rem",
            minWidth: 280, maxWidth: 360,
            boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
            border: "1px solid var(--border-primary)",
            fontSize: "0.82rem", lineHeight: 1.5,
          }}>
            <div style={{ fontWeight: 700, marginBottom: "0.75rem", fontSize: "0.9rem", borderBottom: "1px solid var(--border-primary)", paddingBottom: "0.3rem" }}>
              {selectedSite.name}
            </div>
            <div style={{ marginBottom: "0.3rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Status: </span>
              <span style={{ color: selectedSite.alert_count > 0 ? "var(--accent-red)" : "var(--accent-green)", fontWeight: 600 }}>
                {selectedSite.alert_count > 0 ? "Degraded" : "Operational"}
              </span>
            </div>
            <div style={{ marginBottom: "0.3rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Active Alerts: </span>
              <strong>{selectedSite.alert_count}</strong>
            </div>
            <div style={{ marginBottom: "0.3rem" }}>
              <span style={{ color: "var(--text-muted)" }}>Coordinates: </span>
              {selectedSite.lat.toFixed(4)}, {selectedSite.lon.toFixed(4)}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "0.75rem", borderTop: "1px solid var(--border-primary)", paddingTop: "0.5rem" }}>
              <button onClick={() => setSelectedSite(null)}
                style={{ background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.3rem 0.7rem", fontSize: "0.78rem", cursor: "pointer" }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
