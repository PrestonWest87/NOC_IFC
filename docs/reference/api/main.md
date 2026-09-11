# Module: `src.api.main`

FastAPI application entry point for the active API container. This module configures logging, database startup, authentication middleware, CORS, all route routers, health endpoints, the WebSocket broadcaster, and the authenticated WebSocket protocol.

## Module Objects

### `manager: ConnectionManager`

Process-local connection registry used by the broadcaster and route-triggered realtime updates. It does not provide cross-process fan-out; multiple API replicas require an external pub/sub layer.

### `app: FastAPI`

Created with title `NOC Fusion Enterprise API`, version `2.0.0`, and the `lifespan` context manager. The routers define their own `/api/v1/...` prefixes; `main.py` includes the router objects without adding a second prefix.

Registered routers:

| Module | Prefix |
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

Middleware order and behavior:

- `authentication_middleware` resolves a database session token for protected `/api/v1` requests.
- `OPTIONS`, `/health`, `/ready`, login, and registration validation are public pass-through paths.
- CORS origins are read from `settings.cors_origins`; credentials, methods, and headers are allowed.

## Functions

### `broadcaster() -> None`

Infinite async task started during application lifespan. If no WebSocket clients exist, it sleeps for 10 seconds without querying the database. When clients exist:

1. Runs `svc.get_aiops_dashboard_data` in a worker thread via `asyncio.to_thread`.
2. Builds `{type, alerts, events, grid, alert_count}` with `type="dashboard_update"`.
3. Awaits `manager.broadcast_json(payload)`.
4. Logs exceptions and continues.
5. Sleeps 10 seconds after each iteration.

The thread handoff keeps synchronous database/service work from blocking the event loop. Connection-level failures are removed by `ConnectionManager.broadcast_json`.

### `lifespan(app: FastAPI)`

Async context manager used by FastAPI startup/shutdown.

Startup:

1. Calls `src.core.db.init_db()`.
2. Creates an asyncio task for `broadcaster()`.
3. Yields control to Uvicorn.

Shutdown cancels the broadcaster task and absorbs `asyncio.CancelledError` after cleanup.

### `health() -> dict`

`GET /health` liveness endpoint. Returns:

```json
{"status": "ok", "ws_clients": 0}
```

It does not query the database.

### `ready() -> dict`

`GET /ready` readiness endpoint. Executes `SELECT 1` through the configured SQLAlchemy engine. Returns `{"status": "ready"}` on success and raises HTTP `503` with `database unavailable` when the database cannot respond.

### `websocket_endpoint(websocket: WebSocket)`

`/ws` authenticated realtime endpoint.

1. Reads `token` from the query string.
2. Resolves the user with `svc.get_user_by_token` in a worker thread.
3. Closes with code `1008` if no user is found.
4. Awaits `manager.connect(websocket)` after successful authentication.
5. Reads client text messages continuously.
6. Rejects messages larger than `settings.websocket_max_message_bytes` with code `1009`.
7. Parses JSON object messages. `INVESTIGATING_UPDATE` and `RCA_UPDATE` require `Action: Dispatch RCA Tickets`.
8. Rejects unauthorized commands with an error JSON response.
9. Broadcasts authorized command messages to all connected clients.
10. Removes the socket on disconnect or unexpected error.

The server-to-client dashboard stream is emitted by `broadcaster`; client command messages are not treated as arbitrary application actions.

## Direct Execution

The `__main__` block runs `uvicorn src.api.main:app` on `0.0.0.0:8101` with reload enabled for direct development execution. Docker uses the non-reload Compose command.
