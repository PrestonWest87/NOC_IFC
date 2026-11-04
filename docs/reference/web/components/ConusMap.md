# ConusMap

## Overview

Shared MapLibre and deck.gl map component for all operational map surfaces. It uses an in-repository style with no remote style, sprites, glyphs, or tile requests; `maxBounds` and `renderWorldCopies={false}` keep the map within the contiguous United States. Dynamic deck.gl layers are attached through `MapLibreOverlay` in overlaid mode, which renders on a dedicated canvas above the MapLibre basemap.

## Precompiled boundary data

`web/scripts/build-basemap.mjs` reads pinned Census cartographic-boundary TopoJSON from `us-atlas`, keeps the contiguous 48 states plus DC, and emits the checked-in, versioned GeoJSON under `web/public/maps/`:

- `conus-states-v1.geojson` — state fills and outlines for the full contiguous US.
- `arkansas-border-counties-v1.geojson` — county outlines for Arkansas and its six neighboring states.

The prebuild runs for both Vite development and production builds. The API/worker Docker build also generates and packages the county artifact so geographic filtering has the same offline-ready source. Nginx gzip-compresses and caches the versioned static data.

## Interface

| Prop | Type | Description |
|---|---|---|
| `layers` | `Layer[]` | deck.gl overlay layers; facility markers and selected hazard layers are rendered above the basemap. |
| `initialViewState` | `MapViewState` | Initial center, zoom, pitch, and bearing for the MapLibre camera. |
| `onClick` | deck.gl picking callback | Optional layer-picking handler. |
| `onHover` | deck.gl picking callback | Optional layer-hover handler. |
| `getTooltip` | deck.gl tooltip callback | Optional tooltip renderer for picked features. |
| `getCursor` | deck.gl cursor callback | Optional cursor renderer for map interactions. |
| `onViewportChange` | `((bounds: [west, south, east, north]) => void) \| undefined` | Reports the current WGS84 map bounds on load and after movement; Regional Grid uses it to scope overlays and map compilation. |
| `style` | `CSSProperties` | Map container sizing; defaults to full width and height. |

The style paints a dark background, contiguous-US states and boundaries, and county lines once zoomed in. The shared component passes map layers to `MapLibreOverlay` with `interleaved: false`, keeping deck.gl markers and hazard polygons above the basemap. Dynamic hazard data is not baked into the map files. `setWorkerUrl` points MapLibre at Vite's emitted worker asset.

## Dependencies

- `@vis.gl/react-maplibre`
- `@deck.gl/maplibre` `MapLibreOverlay` and `useControl`
- `@deck.gl/core` map view and layer types
- Census 2017 boundaries redistributed by `us-atlas` 3.0.1 and decoded at build time with `topojson-client` 3.1.0
- `maplibre-gl` worker URL and `maplibre-gl/dist/maplibre-gl.css`
