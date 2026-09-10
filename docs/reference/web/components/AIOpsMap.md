# AIOpsMap

## Overview

Interactive geospatial visualization component for AIOps RCA. Renders NOC facility sites on a MapLibre dark-matter basemap using DeckGL scatterplot layers. Displays site health status via color-coded markers and alert-pulse radius overlays.

---

## Interface: `Site`

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Human-readable site name |
| `lat` | `number` | Latitude coordinate |
| `lon` | `number` | Longitude coordinate |
| `alert_count` | `number` | Active alert count for the site |

---

## Interface: `AIOpsMapProps`

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `sites` | `Site[]` | (required) | Array of monitored locations to display |
| `viewState` | `MapViewState` | `{ latitude: 34.8, longitude: -92.2, zoom: 6, pitch: 0 }` | Initial camera position and zoom |
| `height` | `string` | `"100%"` | CSS height of the map container |
| `tabKey` | `string \| number` | `undefined` | Forces DeckGL re-mount when changed (used for tab reset) |

---

## Constants

### `INITIAL_VIEW`
- **Type**: `MapViewState`
- **Value**: `{ latitude: 34.8, longitude: -92.2, zoom: 6, pitch: 0 }`
- **Purpose**: Default viewState centered on the continental United States.

### `DARK_MATTER`
- **Type**: `string`
- **Value**: `"https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json"`
- **Purpose**: CARTO Dark Matter MapLibre GL style URL.

---

## Functions

### `AIOpsMap` (component)

- **Purpose**: Renders a full-screen or fixed-height interactive map with site markers and alert pulse zones.
- **Flow**:
  1. Mounts a container `ref` and a fullscreen toggle button.
  2. Listens for `fullscreenchange` events to sync the button label.
  3. Builds two DeckGL `ScatterplotLayer` instances:
     - `"sites"` layer — pickable circles; green (`[0,255,0,160]`) if `alert_count === 0`, red (`[255,0,0,200]`) otherwise.
     - `"alert-pulses"` layer — semi-transparent red circles only rendered when at least one site has an alert; radius scales as `4000 + alert_count * 2500`.
  4. Passes `key={tabKey}` to `DeckGL` to force re-initialization when the tab changes.
- **Returns**: A `<div>` wrapping a `<DeckGL>` component with a fullscreen button overlay.

---

## Internal Functions

### `tooltip(info)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `info` | `any` | DeckGL picking info object with `.object` and `.layer.id` |

- **Returns**: `{ html: string, style: object }` or `null`.
- **Flow**: Returns a tooltip string with site name, alert count, and operational status. Styled with CSS custom properties.

### `toggleFs()`

- **Returns**: `void`
- **Flow**: Toggles the container element between fullscreen and normal mode using `document.fullscreenElement` / `requestFullscreen()` / `exitFullscreen()`.

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `@deck.gl/react` | DeckGL React component wrapper |
| `@deck.gl/layers` | `ScatterplotLayer` for marker rendering |
| `react-map-gl/maplibre` | MapLibre GL JS React bindings |
| `@deck.gl/core` | `MapViewState` type |
| `maplibre-gl/dist/maplibre-gl.css` | MapLibre base styles |
| `React` (useMemo, useCallback, useRef, useState, useEffect) | React lifecycle and memoization |
