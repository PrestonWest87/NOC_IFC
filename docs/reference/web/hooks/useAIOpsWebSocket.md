# useAIOpsWebSocket

## Overview

Custom React hook that establishes and maintains a persistent WebSocket connection to the backend. Receives real-time dashboard update payloads, stores them in the Zustand app store, and triggers browser notifications for CRITICAL or HIGH severity alerts.

---

## Interfaces

### `DashboardPayload`

Defined in `useAppStore`. See [Store: useAppStore](../store/useAppStore.md).

---

## Functions

### `useAIOpsWebSocket()` (hook)

- **Purpose**: Connects to the backend WebSocket at the current host (`ws://` or `wss://` depending on page protocol) and streams dashboard payloads into the Zustand store. Implements exponential-backoff reconnection and deduplicated critical alert notifications.
- **Returns**:

| Return Property | Type | Description |
|----------------|------|-------------|
| `data` | `DashboardPayload \| null` | The most recent WebSocket message payload |
| `connected` | `boolean` | Whether the WebSocket is currently open |

- **Flow**:
  1. On mount, calls the inner `connect()` function.
  2. `connect()` determines the protocol (`ws:` or `wss:`) and creates a new `WebSocket` to `{protocol}//{host}/ws`.
  3. **onopen**: Sets `connected` to `true` in both local state and the Zustand store. Resets `retryRef` to 0.
  4. **onmessage**: Parses the JSON payload as a `DashboardPayload`. Updates local `data` state and calls `setStoreDashboard()`. Iterates over `payload.alerts` — for each alert with an unseen ID (tracked in `knownAlertIds`), if severity is `"CRITICAL"` or `"HIGH"`, calls `triggerCriticalNotification()` and adds the ID to the dedup set.
  5. **onclose**: Sets `connected` to `false` in both local state and the store. Schedules a reconnection via `setTimeout` with exponential backoff capped at 30 seconds (`min(1000 * 2^retry, 30000)`).
  6. **onerror**: Calls `ws.close()` to trigger the `onclose` handler.
  7. On cleanup (unmount), closes the WebSocket.
- **Dependencies**: `[setStoreDashboard, setStoreConnected]` — these are stable zustand selectors.

---

## Refs

| Ref | Type | Description |
|-----|------|-------------|
| `wsRef` | `MutableRefObject<WebSocket \| null>` | Holds the current WebSocket instance |
| `retryRef` | `MutableRefObject<number>` | Incremented on each reconnect attempt for exponential backoff calculation |
| `knownAlertIds` | `MutableRefObject<Set<string>>` | Deduplication set for alert notifications; prevents duplicate browser notifications |

---

## State

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `data` | `DashboardPayload \| null` | `null` | Latest dashboard payload from WebSocket |
| `connected` | `boolean` | `false` | WebSocket connection status |

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `react` (useEffect, useRef, useState) | React lifecycle and mutable refs |
| `../utils/notifications` (`triggerCriticalNotification`) | Browser Notification API wrapper |
| `../store/useAppStore` (`useAppStore`, `DashboardPayload`) | Zustand global store for dashboard state |
