# Module: `src.api.ws_manager`

`ConnectionManager` is the process-local registry for authenticated AIOps WebSocket clients. It does not persist connections or fan out across multiple API processes.

## State

- `active_connections`: current `fastapi.WebSocket` instances.
- `connection_users`: current authenticated user object for each registered socket. `src.api.main` uses it to authorize and transform outgoing data per connection.

## Methods

| Method | Behavior |
|---|---|
| `connect(websocket, user=None)` | Accepts the socket, registers it once, stores its user, and logs the count. |
| `update_user(websocket, user)` | Replaces the registered user object after API revalidation, if the socket remains active. |
| `disconnect(websocket)` | Removes a socket and its user mapping; repeated calls are safe. |
| `close_all(code=1012, reason="Service maintenance")` | Closes and unregisters every current connection, used before database-file replacement. |
| `broadcast_json(data, transform=None)` | Concurrently sends one JSON message to a snapshot of connections. If supplied, `transform(data, user)` may return a per-user payload or `None` to suppress delivery. Each socket send has a three-second timeout; failed sockets are removed after the send gather completes. |
| `count` | Number of active connections. Used by `/health` and the broadcaster's no-client fast path. |

Messages use `json.dumps(..., default=str)`. One send failure does not prevent attempts to other sockets. Registry operations are in-process; multi-replica fan-out requires a separate pub/sub system.
