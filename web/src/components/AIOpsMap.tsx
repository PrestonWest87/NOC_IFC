import { useMemo } from "react";
import DeckGL from "@deck.gl/react";
import { ScatterplotLayer } from "@deck.gl/layers";
import type { MapViewState } from "@deck.gl/core";

interface Site {
  name: string;
  lat: number;
  lon: number;
  alert_count: number;
}

interface AIOpsMapProps {
  sites: Site[];
  viewState?: MapViewState;
}

const INITIAL_VIEW: MapViewState = {
  latitude: 34.8,
  longitude: -92.2,
  zoom: 6,
  pitch: 0,
};

export function AIOpsMap({ sites, viewState = INITIAL_VIEW }: AIOpsMapProps) {
  const layers = useMemo(() => {
    const siteData = sites.map((s) => ({
      name: s.name,
      position: [s.lon, s.lat] as [number, number],
      color: s.alert_count > 0 ? [255, 0, 0, 200] : [0, 255, 0, 160],
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
      }),
      ...(alertData.length > 0
        ? [
            new ScatterplotLayer({
              id: "alert-pulses",
              data: alertData,
              getPosition: (d) => d.position,
              getFillColor: [255, 0, 0, 40],
              getRadius: (d) => d.radius,
            }),
          ]
        : []),
    ];
  }, [sites]);

  return <DeckGL layers={layers} initialViewState={viewState} controller={true} />;
}
