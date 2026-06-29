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
      html: `<b>${d.name}</b><br/>Alerts: ${d.alert_count}<br/>Status: ${d.alert_count > 0 ? "\u26a0 Degraded" : "\u2713 Operational"}`,
      style: { background: "var(--bg-card)", color: "var(--text-primary)", fontSize: "0.78rem", border: "1px solid var(--border-primary)", borderRadius: "var(--radius-sm)", padding: "0.5rem" },
    };
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
        style={{ height: "100%", width: "100%", position: "relative" }} getTooltip={tooltip}>
        <Map mapStyle={DARK_MATTER} />
      </DeckGL>
    </div>
  );
}
