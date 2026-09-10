# Module: `src.api.ws_manager`

WebSocket connection manager for the NOC Fusion Enterprise API. Manages active client connections, handles connect/disconnect lifecycle, and provides JSON broadcasting capabilities with automatic stale connection cleanup.

---

## Class: `ConnectionManager`

### Purpose
Singleton-style manager that maintains a list of active WebSocket connections and provides methods for accepting new clients, removing disconnected clients, and broadcasting JSON payloads to all connected clients.

---

### Method: `__init__(self)`

#### Purpose
Initializes the manager with an empty list of active connections.

#### Parameters
None.

#### Returns
None.

#### Raises
None.

#### Flow
Sets `self.active_connections` to an empty `list[WebSocket]`.

#### Dependencies
None.

---

### Method: `connect(self, websocket: WebSocket)`

#### Purpose
Accepts a new WebSocket connection and registers it in the active connections list.

#### Parameters
| Parameter   | Type        | Description                         |
|-------------|-------------|-------------------------------------|
| `websocket` | `WebSocket` | The WebSocket connection to accept. |

#### Returns
None.

#### Raises
None. Defers to `websocket.accept()` which may raise a `WebSocketException` if the connection is invalid.

#### Flow
1. Calls `websocket.accept()` to complete the WebSocket handshake.
2. Appends the connection to `self.active_connections`.
3. Logs the new connection with total count.

#### Dependencies
- `fastapi.WebSocket`

---

### Method: `disconnect(self, websocket: WebSocket)`

#### Purpose
Removes a WebSocket connection from the active connections list on disconnect or error.

#### Parameters
| Parameter   | Type        | Description                            |
|-------------|-------------|----------------------------------------|
| `websocket` | `WebSocket` | The WebSocket connection to remove.    |

#### Returns
None.

#### Raises
- `ValueError` — if the connection is not found in the list (silently propagates).

#### Flow
1. Removes the connection from `self.active_connections`.
2. Logs the disconnection with remaining total count.

#### Dependencies
- `fastapi.WebSocket`

---

### Method: `broadcast_json(self, data: dict[str, Any])`

#### Purpose
Serializes a dictionary to JSON and sends it to every active WebSocket connection. Automatically removes stale connections that fail to receive the message.

#### Parameters
| Parameter | Type               | Description                       |
|-----------|--------------------|-----------------------------------|
| `data`    | `dict[str, Any]`   | The payload to broadcast.         |

#### Returns
None.

#### Raises
None. All send exceptions are caught and handled by removing the stale connection.

#### Flow
1. Serializes `data` to a JSON string using `json.dumps()` with `default=str` to handle non-serializable types (e.g., `datetime`).
2. Iterates over all active connections, calling `conn.send_text(message)`.
3. If any connection raises an exception during send, it is added to a `stale` list.
4. After the loop, all stale connections are removed from `self.active_connections`.

#### Dependencies
- `json` (stdlib)
- `fastapi.WebSocket.send_text()`

---

### Property: `count(self) -> int`

#### Purpose
Returns the number of currently active WebSocket connections.

#### Parameters
None.

#### Returns
| Type  | Description                           |
|-------|---------------------------------------|
| `int` | The count of active connections.      |

#### Raises
None.

#### Flow
Returns `len(self.active_connections)`.

#### Dependencies
None.
