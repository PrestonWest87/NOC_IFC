import json
import asyncio
import logging
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.connection_users: dict[WebSocket, Any] = {}

    async def connect(self, websocket: WebSocket, user=None):
        await websocket.accept()
        if websocket not in self.active_connections:
            self.active_connections.append(websocket)
        self.connection_users[websocket] = user
        logger.info("WebSocket client connected. Total: %d", len(self.active_connections))

    def update_user(self, websocket: WebSocket, user):
        if websocket in self.active_connections:
            self.connection_users[websocket] = user

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            self.connection_users.pop(websocket, None)
            logger.info("WebSocket client disconnected. Total: %d", len(self.active_connections))

    async def broadcast_json(self, data: dict[str, Any], transform=None):
        async def send(conn, user):
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
        return len(self.active_connections)
