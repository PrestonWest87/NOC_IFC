import { MapLibreOverlay } from "@deck.gl/maplibre";
import type { MapLibreOverlayProps } from "@deck.gl/maplibre";
import { Map as MapLibreMap, useControl } from "@vis.gl/react-maplibre";
import type { MapViewState } from "@deck.gl/core";
import { setWorkerUrl } from "maplibre-gl";
import maplibreWorkerUrl from "maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url";
import "maplibre-gl/dist/maplibre-gl.css";

setWorkerUrl(maplibreWorkerUrl);

const CONUS_BOUNDS: [number, number, number, number] = [-125, 24, -66, 50];
const DEFAULT_VIEW: MapViewState = {
  longitude: -92.2,
  latitude: 34.8,
  zoom: 5.5,
  pitch: 0,
};

/** Local, contiguous-US-only vector basemap with no remote style/tile dependency. */
const CONUS_STYLE = {
  version: 8,
  name: "NOC Contiguous US",
  sources: {
    conus_states: {
      type: "geojson",
      data: "/maps/conus-states-v1.geojson",
      attribution: "U.S. Census Bureau 2017 cartographic boundaries via us-atlas",
    },
    arkansas_border_counties: {
      type: "geojson",
      data: "/maps/arkansas-border-counties-v1.geojson",
      attribution: "U.S. Census Bureau 2017 cartographic boundaries via us-atlas",
    },
  },
  layers: [
    {
      id: "noc-background",
      type: "background",
      paint: { "background-color": "#08111f" },
    },
    {
      id: "noc-state-fill",
      type: "fill",
      source: "conus_states",
      paint: { "fill-color": "#102035", "fill-outline-color": "#6c86a3" },
    },
    {
      id: "noc-state-boundaries",
      type: "line",
      source: "conus_states",
      paint: { "line-color": "#7089a5", "line-width": 1.1, "line-opacity": 0.9 },
    },
    {
      id: "noc-arkansas-region-counties",
      type: "line",
      source: "arkansas_border_counties",
      minzoom: 4.5,
      paint: { "line-color": "#35516d", "line-width": 0.65, "line-opacity": 0.8 },
    },
  ],
} as const;

type DeckOverlayProps = Pick<
  MapLibreOverlayProps,
  "layers" | "onClick" | "onHover" | "getTooltip" | "getCursor"
>;

interface ConusMapProps extends DeckOverlayProps {
  onViewportChange?: (bounds: [number, number, number, number]) => void;
  initialViewState?: MapViewState;
  style?: React.CSSProperties;
}

/** Attach deck.gl to MapLibre's overlay canvas above the shared local basemap. */
function DeckGLOverlay(props: DeckOverlayProps) {
  const overlayProps: MapLibreOverlayProps = {
    interleaved: false,
    layers: props.layers,
    ...(props.onClick !== undefined ? { onClick: props.onClick } : {}),
    ...(props.onHover !== undefined ? { onHover: props.onHover } : {}),
    ...(props.getTooltip !== undefined ? { getTooltip: props.getTooltip } : {}),
    ...(props.getCursor !== undefined ? { getCursor: props.getCursor } : {}),
  };
  const overlay = useControl<MapLibreOverlay>(() => new MapLibreOverlay(overlayProps));
  overlay.setProps(overlayProps);
  return null;
}

/** Shared local basemap and explicitly overlaid deck.gl renderer. */
export function ConusMap({
  layers = [],
  onClick,
  onHover,
  getTooltip,
  getCursor,
  onViewportChange,
  initialViewState = DEFAULT_VIEW,
  style,
}: ConusMapProps) {
  const reportViewport = (event: any) => {
    if (!onViewportChange) return;
    const bounds = event?.target?.getBounds?.();
    if (!bounds) return;
    onViewportChange([
      bounds.getWest(), bounds.getSouth(), bounds.getEast(), bounds.getNorth(),
    ]);
  };
  return (
    <MapLibreMap
      mapStyle={CONUS_STYLE as any}
      maxBounds={CONUS_BOUNDS}
      initialViewState={initialViewState}
      renderWorldCopies={false}
      minZoom={3}
      maxZoom={16}
      onLoad={reportViewport}
      onMoveEnd={reportViewport}
      style={{ width: "100%", height: "100%", ...style }}
    >
      <DeckGLOverlay layers={layers} onClick={onClick} onHover={onHover} getTooltip={getTooltip} getCursor={getCursor} />
    </MapLibreMap>
  );
}
