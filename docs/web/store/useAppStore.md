# useAppStore

## Overview

Zustand-based global state store for real-time dashboard data and WebSocket connection status. Provides a lightweight shared-state mechanism between the WebSocket hook and consuming page components.

---

## Interfaces

### `AlertItem`

| Property | Type | Description |
|----------|------|-------------|
| `id` | `number \| string` (optional) | Unique alert identifier |
| `node_name` | `string` (optional) | Name of the affected node |
| `severity` | `string` (optional) | Alert severity level (e.g. "CRITICAL", "HIGH", "WARNING") |
| `status` | `string` (optional) | Current alert status (e.g. "open", "acknowledged", "closed") |
| `mapped_location` | `string` (optional) | Human-readable location of the alert |

### `DashboardPayload`

| Property | Type | Description |
|----------|------|-------------|
| `type` | `string` (optional) | Message type discriminator |
| `alerts` | `AlertItem[]` (optional) | Array of current alerts |
| `events` | `unknown[]` (optional) | Array of events (generic) |
| `grid` | `unknown[]` (optional) | Grid-related data (generic) |
| `alert_count` | `number` (optional) | Total alert count |

### `AppState`

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `dashboard` | `DashboardPayload \| null` | `null` | Latest dashboard payload received via WebSocket |
| `connected` | `boolean` | `false` | Whether the WebSocket is connected |
| `setDashboard` | `(data: DashboardPayload) => void` | — | Zustand action to update the dashboard payload |
| `setConnected` | `(connected: boolean) => void` | — | Zustand action to update the connection status |

---

## Store

### `useAppStore`

- **Created with**: `create<AppState>((set) => ({ ... }))` from Zustand.
- **Purpose**: Singleton global store that holds the latest real-time dashboard data and WebSocket connection flag.

| Action | Implementation | Description |
|--------|---------------|-------------|
| `setDashboard(data)` | `set({ dashboard: data })` | Replaces the entire dashboard payload |
| `setConnected(connected)` | `set({ connected })` | Sets the connection flag |

---

## Usage Pattern

```typescript
import { useAppStore } from "../store/useAppStore";

// Selector pattern
const dashboard = useAppStore((s) => s.dashboard);
const connected = useAppStore((s) => s.connected);
const setDashboard = useAppStore((s) => s.setDashboard);
```

The `useAIOpsWebSocket` hook writes to this store on every WebSocket message. Page components consume the store via selectors to re-render when data changes.

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `zustand` | Lightweight state management library |
