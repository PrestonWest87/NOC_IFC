# Hook: `useAIOpsWebSocket`

**Source:** `web/src/hooks/useAIOpsWebSocket.ts`

Maintains the authenticated browser WebSocket connection and synchronizes realtime AIOps events with local Zustand and React Query state.

## Return Value

```ts
{ data: DashboardPayload | null; connected: boolean }
```

The hook also publishes a `sendMessage` callback into `useAppStore` for components that need to send authorized UI commands.

## Connection Flow

1. Reads the session token from `useAuth()`.
2. Does not connect until a token exists.
3. Uses `wss` for HTTPS pages and `ws` otherwise.
4. Connects to the current host at `/ws?token=<encoded-token>`.
5. Sets local and store connected state on open and resets retry count.
6. Reconnects after close with exponential backoff: `1s`, `2s`, `4s`, up to `30s`.
7. Closes the socket and clears the retry timer during effect cleanup.

## Outbound Messages

The store callback serializes and sends a message only when the socket is open. The API currently authorizes RCA-related message types according to the authenticated user’s action permissions.

## Inbound Message Handling

| Message type | Behavior |
|---|---|
| `INVESTIGATING_UPDATE` | Updates the Zustand investigating-site state. |
| `RCA_UPDATE` | Invalidates `rca-dashboard` and `rca-analyze` queries. |
| `dashboard_update` | Updates local/store dashboard state and merges alerts/events/grid into an existing `rca-dashboard` query without creating a partial query before the initial GET. |

Malformed JSON is ignored. New CRITICAL/HIGH alert IDs trigger browser notifications once per hook lifetime using a `Set` of known IDs.

## Dependencies

- `useAuth` for the current session token.
- `useQueryClient` for RCA invalidation and cache synchronization.
- `useAppStore` for dashboard, connection, investigating-site, and send-message state.
- `triggerCriticalNotification` for browser alert notifications.
