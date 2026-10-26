"""In-memory WebSocket connection registry and best-effort JSON broadcaster.

The application authenticates/authorizes clients before registration and supplies
per-user transforms when data must be filtered by site scope.
"""

import json
import asyncio
import logging
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Track one process's authorized WebSockets and broadcast transformed JSON."""

    def __init__(self):
        """Initialize the live socket list and its per-connection user map."""
        self.active_connections: list[WebSocket] = []
        self.connection_users: dict[WebSocket, Any] = {}

    async def connect(self, websocket: WebSocket, user=None):
        """Accept and register a socket after the API endpoint has authorized its user."""
        await websocket.accept()
        if websocket not in self.active_connections:
            self.active_connections.append(websocket)
        self.connection_users[websocket] = user
        logger.info("WebSocket client connected. Total: %d", len(self.active_connections))

    def update_user(self, websocket: WebSocket, user):
        """Replace a connection's cached identity after session revalidation."""
        if websocket in self.active_connections:
            self.connection_users[websocket] = user

    def disconnect(self, websocket: WebSocket):
        """Remove a socket and its identity mapping if it is currently registered."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            self.connection_users.pop(websocket, None)
            logger.info("WebSocket client disconnected. Total: %d", len(self.active_connections))

    async def close_all(self, code: int = 1012, reason: str = "Service maintenance"):
        """Close connected clients before an offline database replacement."""
        for connection in tuple(self.active_connections):
            try:
                await connection.close(code=code, reason=reason)
            except Exception:
                logger.debug("Unable to close WebSocket during maintenance", exc_info=True)
            finally:
                self.disconnect(connection)

    async def broadcast_json(self, data: dict[str, Any], transform=None):
        """Send JSON to a snapshot of connected clients and drop failed sockets.

        `transform`, when supplied, receives the message and recipient user and
        may return `None` to suppress delivery or a recipient-specific payload.
        Each send is bounded to three seconds.
        """
        async def send(conn, user):
            """Transform and send one recipient payload; return failed sockets for cleanup."""
            outgoing = transform(data, user) if transform else data
            if outgoing is None:
                return None
            try:
                await asyncio.wait_for(conn.send_text(json.dumps(outgoing, default=str)), timeout=3)
                return None
            except Exception:
                return conn

        results = await asyncio.gather(*(
            send(conn, self.connection_users.get(conn))
            for conn in tuple(self.active_connections)
        ), return_exceptions=False)
        stale = [conn for conn in results if conn is not None]
        for conn in stale:
            self.disconnect(conn)

    @property
    def count(self) -> int:
        """Return the number of sockets currently registered in this process."""
        return len(self.active_connections)
