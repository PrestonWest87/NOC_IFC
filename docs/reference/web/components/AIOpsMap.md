# AIOpsMap

## Overview

Standalone interactive geospatial component that renders NOC facility sites on the shared local contiguous-US basemap using deck.gl scatterplot layers attached through the shared MapLibre overlay. It displays color-coded site markers, alert-pulse overlays, a tooltip, and a selected-site dialog. No current routed page imports this component; page routes compose their own map views.

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
| `tabKey` | `string \| number` | `undefined` | Forces the shared map/overlay to remount when changed (used for tab reset) |

---

## Constants

### `INITIAL_VIEW`
- **Type**: `MapViewState`
- **Value**: `{ latitude: 34.8, longitude: -92.2, zoom: 6, pitch: 0 }`
- **Purpose**: Default viewState centered on the continental United States.

### `ConusMap`
- **Purpose**: Shared local contiguous-US state and Arkansas-border county basemap; uses no remote world style or tile service.

---

## Functions

### `AIOpsMap` (component)

- **Purpose**: Renders a full-screen or fixed-height interactive map with site markers and alert pulse zones.
- **Flow**:
  1. Mounts a container `ref` and a fullscreen toggle button.
  2. Listens for `fullscreenchange` events to sync the button label.
  3. Builds two deck.gl `ScatterplotLayer` instances:
     - `"sites"` layer — pickable circles; green (`[0,255,0,160]`) if `alert_count === 0`, red (`[255,0,0,200]`) otherwise.
     - `"alert-pulses"` layer — semi-transparent red circles only rendered when at least one site has an alert; radius scales as `4000 + alert_count * 2500`.
  4. Passes `key={tabKey}` to `ConusMap` to force re-initialization when the tab changes.
- **Returns**: A `<div>` wrapping `ConusMap` with a fullscreen button overlay.

---

## Internal Functions

### `tooltip(info)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `info` | `any` | deck.gl picking info object with `.object` and `.layer.id` |

- **Returns**: `{ text: string, style: object }` or `null`.
- **Flow**: Returns a tooltip string with site name, alert count, and operational status. Styled with CSS custom properties.

### `handleClick(info)`

Selects a site marker and opens a dialog with its status, alert count, and coordinates. Clicking the backdrop or the dialog's Close button clears the selection.

### `toggleFs()`

- **Returns**: `void`
- **Flow**: Toggles the container element between fullscreen and normal mode using `document.fullscreenElement` / `requestFullscreen()` / `exitFullscreen()`.

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `@deck.gl/maplibre` | `MapLibreOverlay` renders deck.gl layers above the MapLibre canvas |
| `@deck.gl/layers` | `ScatterplotLayer` for marker rendering |
| `ConusMap` | Shared local MapLibre style and county/state boundaries |
| `@deck.gl/core` | `MapViewState` type |
| `maplibre-gl/dist/maplibre-gl.css` | MapLibre base styles |
| `React` (useMemo, useCallback, useRef, useState, useEffect) | React lifecycle and memoization |
