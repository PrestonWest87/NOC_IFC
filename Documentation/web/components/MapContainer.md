# MapContainer

## Overview

Generic map wrapper component that detects when its children are ready to render (after layout measurement) and provides fullscreen toggle capability. Used as a container for DeckGL maps or other visualization canvases.

---

## Interface: `MapContainerProps`

| Prop | Type | Description |
|------|------|-------------|
| `height` | `string` | CSS height of the container (e.g. `"500px"`, `"100%"`) |
| `children` | `ReactNode` | Map or visualization content rendered inside |

---

## Functions

### `MapContainer` (component)

- **Purpose**: Delays rendering of its children until the container has a non-zero layout size, preventing DeckGL/WebGL initialization failures in hidden tabs. Also provides a fullscreen toggle button.
- **Flow**:
  1. On mount, checks if `ref.current` has non-zero `offsetHeight` / `offsetWidth`.
  2. If already measured, sets `ready = true` immediately.
  3. If not yet measured, creates a `ResizeObserver` that sets `ready = true` on the first non-zero content rect, then disconnects.
  4. Listens for `fullscreenchange` events to sync the fullscreen button label.
  5. Only renders `children` when `ready === true`.
  6. Fullscreen toggle calls `requestFullscreen()` / `exitFullscreen()` on the container element.
- **Returns**: A `<div>` wrapper with card styling containing a fullscreen button and conditionally rendered children.

---

## Internal Functions

### `toggleFs()`

- **Returns**: `void`
- **Flow**: Toggles fullscreen state on the container `ref` element.

---

## State

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ready` | `boolean` | `false` | Whether the container has a non-zero layout size |
| `fs` | `boolean` | `false` | Whether the container is currently in fullscreen mode |

---

## Ref

| Ref | Type | Description |
|-----|------|-------------|
| `ref` | `RefObject<HTMLDivElement>` | Reference to the root container element |

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `react` (useState, useCallback, useEffect, useRef) | React lifecycle, state, refs |
