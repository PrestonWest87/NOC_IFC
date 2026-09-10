# Module: `src.api.main`

FastAPI application entry point for the NOC Fusion Enterprise API. Configures middleware, registers all route routers, manages the WebSocket broadcaster lifecycle, and provides health and WebSocket endpoints.

---

## Function: `broadcaster()`

### Purpose
Background coroutine that periodically fetches AIOps dashboard data and broadcasts it to all connected WebSocket clients as `dashboard_update` payloads.

### Parameters
None.

### Returns
None. Runs as an infinite `asyncio` task.

### Raises
None caught internally at the top level; exceptions are logged via `logger.error`.

### Flow
1. Infinite loop with `asyncio.sleep(10)` interval; when no clients exist it sleeps and skips the query.
2. Calls `src.services.get_aiops_dashboard_data()` to retrieve alerts, events, and grid state.
3. Constructs a `dashboard_update` payload containing `type`, `alerts`, `events`, `grid`, and `alert_count`.
4. Calls `ConnectionManager.broadcast_json()` to push the payload to all connected WebSocket clients.
5. On any exception, logs the error and continues the loop.

### Dependencies
- `src.services` (named `svc`) — `get_aiops_dashboard_data()`
- `src.api.ws_manager.ConnectionManager` — global `manager` instance

---

## Context Manager: `lifespan(app: FastAPI)`

### Purpose
ASGI lifespan context manager that initializes the database, starts the WebSocket broadcaster background task, and cleans up on shutdown.

### Parameters
| Parameter | Type     | Description                            |
|-----------|----------|----------------------------------------|
| `app`     | `FastAPI`| The FastAPI application instance.      |

### Yields
None. Control is yielded to the ASGI server after initialization.

### Raises
- `asyncio.CancelledError` — caught during task cancellation on shutdown.

### Flow
1. Calls `init_db()` to ensure database tables and seed data exist.
2. Creates an `asyncio.Task` for the `broadcaster()` coroutine.
3. Logs server start message.
4. Yields control to the server.
5. On shutdown, cancels the broadcaster task and awaits its completion (ignoring `CancelledError`).

### Dependencies
- `src.core.db.init_db`
- `broadcaster()` function (above)

---

## Module-Level Object: `app`

### Purpose
The `FastAPI` ASGI application instance with title `"NOC Fusion Enterprise API"`, version `"2.0.0"`, and the `lifespan` lifecycle handler.

### Configuration
- **Authentication middleware**: `authentication_middleware` protects `/api/v1/*` except login, registration, health, and readiness.
- **CORS Middleware**: uses the comma-separated `CORS_ORIGINS` setting and allows credentials, methods, and headers.

### Routers Registered
| Router Module      | Prefix                  |
|--------------------|-------------------------|
| `aiops`            | `/api/v1/aiops`         |
| `threat`           | `/api/v1/threat`        |
| `settings`         | `/api/v1/settings`      |
| `reporting`        | `/api/v1/reporting`     |
| `auth`             | `/api/v1/auth`          |
| `dashboard`        | `/api/v1/dashboard`     |
| `regional`         | `/api/v1/regional`      |
| `hunting`          | `/api/v1/hunting`       |
| `rca`              | `/api/v1/rca`           |
| `logbook`          | `/api/v1/logbook`       |
| `settings_admin`   | `/api/v1/admin`         |
| `llm`              | `/api/v1/llm`           |
| `email`            | `/api/v1/email`         |
| `keyword_analysis`  | `/api/v1/keyword-analysis` |

### Dependencies
- `fastapi.FastAPI`
- `fastapi.middleware.cors.CORSMiddleware`
- All 14 route modules under `src.api.routes`

---

## Endpoint: `GET /health`

### Purpose
Lightweight health-check endpoint returning API status and connected WebSocket client count.

### Parameters
None.

### Returns
```json
{
  "status": "ok",
  "ws_clients": <int>
}
```

### Raises
None.

### Flow
Returns a dictionary with a static status string and the current WebSocket connection count from the connection manager.

### Dependencies
- `ConnectionManager.count` (property)

---

## Endpoint: `WebSocket /ws`

### Purpose
Real-time WebSocket endpoint that authenticates a session token, broadcasts dashboard updates through the connection manager, and accepts authorized RCA synchronization commands.

### Parameters
| Parameter   | Type        | Description                      |
|-------------|-------------|----------------------------------|
| `websocket` | `WebSocket` | The incoming WebSocket connection.|

### Returns
None. Maintains an open WebSocket connection, reading (and discarding) text messages from the client.

### Raises
- `WebSocketDisconnect` — handled gracefully by removing the client from the manager.
- Any other exception — logged and triggers disconnect cleanup.

### Flow
1. Reads `token` from the query string and resolves the database user.
2. Closes with code `1008` if authentication fails; otherwise accepts and registers the socket.
3. Rejects messages larger than `WEBSOCKET_MAX_MESSAGE_BYTES` with code `1009`.
4. Parses JSON objects and requires `Action: Dispatch RCA Tickets` for `INVESTIGATING_UPDATE` and `RCA_UPDATE` messages.
5. Broadcasts authorized synchronization messages; removes the socket on disconnect or error.

### Dependencies
- `ConnectionManager.connect()`
- `ConnectionManager.disconnect()`

---

## `__main__` Block

### Purpose
Allows running the API directly via `python src/api/main.py`.

### Flow
Calls `uvicorn.run("src.api.main:app", host="0.0.0.0", port=8101, reload=True)` for development mode with hot reload.

### Dependencies
- `uvicorn`
