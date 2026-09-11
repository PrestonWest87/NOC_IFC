# Module: `src.api.ws_manager`

`ConnectionManager` is the in-process WebSocket registry used by `src.api.main` and background-triggered RCA updates.

## `ConnectionManager`

### `__init__(self)`

Initializes `active_connections` as an empty list of FastAPI `WebSocket` objects. The list is process-local and is not persisted.

### `connect(self, websocket: WebSocket) -> None`

Async method. Awaits `websocket.accept()`, then adds the socket only if it is not already registered. Duplicate connection objects are ignored. It logs the resulting connection count.

### `disconnect(self, websocket: WebSocket) -> None`

Removes a socket only when it is present. Repeated cleanup calls are safe and do not raise `ValueError`.

### `broadcast_json(self, data: dict[str, Any]) -> None`

Async method that serializes `data` with `json.dumps(..., default=str)` and sends the same text payload concurrently to a snapshot of active connections.

- Each send is wrapped in `asyncio.wait_for(..., timeout=3)`.
- `asyncio.gather` waits for all send attempts.
- A failed or timed-out connection is returned by the send helper and removed after the gather completes.
- Failures on one connection do not prevent attempts to other connections.

### `count -> int`

Property returning `len(active_connections)`. Used by `/health` and the broadcaster’s no-client fast path.
