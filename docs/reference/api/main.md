# Module: `src.api.main`

Creates the FastAPI application, mounts REST routers, coordinates SQLite/restore startup, and hosts the authenticated AIOps WebSocket. The active entry point is `uvicorn src.api.main:app --host 0.0.0.0 --port 8101`.

## Application and router inventory

`app` is titled `NOC Fusion Enterprise API`, reports version `2.0.0`, installs `authentication_middleware`, and configures CORS from `settings.cors_origins`.

| Router | Prefix |
|---|---|
| `auth` | `/api/v1/auth` |
| `dashboard` | `/api/v1/dashboard` |
| `threat` | `/api/v1/threat` |
| `regional` | `/api/v1/regional` |
| `hunting` | `/api/v1/hunting` |
| `rca` | `/api/v1/rca` |
| `aiops` | `/api/v1/aiops` |
| `logbook` | `/api/v1/logbook` |
| `reporting` | `/api/v1/reporting` |
| `settings` | `/api/v1/settings` |
| `settings_admin` | `/api/v1/admin` |
| `llm` | `/api/v1/llm` |
| `email` | `/api/v1/email` |
| `keyword_analysis` | `/api/v1/keyword-analysis` |
| `permissions` | `/api/v1/permissions` |
| `user_admin` | `/api/v1/user-admin` |
| `application_settings` | `/api/v1/application-settings` |

The checked-out app's OpenAPI schema contains 177 paths and 189 HTTP operations. `docs/API.md` is the human reference for request behavior and route permissions.

## `lifespan(app)`

On ordinary startup, calls `init_db()` before creating the broadcaster task. If a durable restore marker already exists, it avoids normal database initialization, starts the broadcaster loop in maintenance mode, and attempts `resume_pending_restore()` through `src.core.ui_restore`. On shutdown it cancels the broadcaster and absorbs `asyncio.CancelledError`.

## `broadcaster()`

Runs every ten seconds. Before database work, it registers itself as an API background writer with `restore_control`; it releases that registration in `finally` so a UI restore can wait for in-flight writes. With no connected clients it skips service queries. With clients it:

1. Fetches AIOps alerts, global timeline events, outage grid, active unresolved-alert counts, and cached locations.
2. Computes separate site-scoped timeline lists for the distinct non-administrator allowed-site sets connected at that cycle.
3. Sends a `dashboard_update` through `ConnectionManager.broadcast_json(transform=...)`; the per-connection transform checks AIOps page and Active Board grants and filters alerts/events/grid/counts to the connected user's allowed site types.
4. Logs unexpected errors and continues after the next sleep.

The message includes `type`, `alerts`, `events`, `grid`, `active_issue_counts`, and `alert_count`. `ConnectionManager` is process-local; it is not a cross-replica pub/sub implementation.

## Health and restore-status routes

### `GET /health`

Liveness check; does not query SQLite. Returns `{"status":"ok","ws_clients":<count>}`.

### `GET /ready`

Returns `{"status":"ready"}` after `SELECT 1`. Returns HTTP 503 while a restore marker is active or if SQLite cannot answer.

### `POST /api/v1/restore-status`

Accepts `{ "restore_id": "..." }` without a normal session token. `restore_control.restore_status()` validates the random capability ID and its 24-hour lifetime; unknown/expired IDs return 404. The endpoint exposes restore progress, not database contents or file paths.

## `websocket_endpoint(websocket)`

The connection requires a valid `?token=<opaque session token>`, page grant `AIOps RCA`, and tab grant `Tab: AIOps RCA -> Active Board`. The handler also rejects connections during restore maintenance (close code 1012).

After acceptance:

- The connection registry stores both the WebSocket and the current authenticated user.
- The receive loop times out after 30 seconds; on timeout it rechecks the token and required grants. It also rechecks them before processing each received message, so revocation takes effect on the next check.
- A message exceeding `settings.websocket_max_message_bytes` is closed with code 1009. Invalid JSON and non-object messages are ignored.
- Only `INVESTIGATING_UPDATE` and `RCA_UPDATE` are recognized. Both require `Action: Dispatch RCA Tickets`; unrecognized/unauthorized types receive a structured permission error. Parsed objects with more than ten top-level keys are ignored.
- `INVESTIGATING_UPDATE` additionally requires the sender to access the named site. The broadcast transform suppresses that site update for recipients without access.
- `RCA_UPDATE` is a resynchronization event broadcast to eligible AIOps clients; it does not itself perform a database mutation.

The server-originated dashboard data path is separate from client commands. See [`ws_manager.md`](ws_manager.md), [`routes/rca.md`](routes/rca.md), and [`PERMISSIONS.md`](../../PERMISSIONS.md).

## Direct execution

The `__main__` block runs Uvicorn on `0.0.0.0:8101` with reload enabled for direct development. Docker Compose starts the same app without reload.
