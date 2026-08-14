import json
import asyncio
import logging
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Total: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info("WebSocket client disconnected. Total: %d", len(self.active_connections))

    async def broadcast_json(self, data: dict[str, Any]):
        message = json.dumps(data, default=str)
        async def send(conn):
            try:
                await asyncio.wait_for(conn.send_text(message), timeout=3)
                return None
            except Exception:
                return conn

        results = await asyncio.gather(*(send(conn) for conn in tuple(self.active_connections)))
        stale = [conn for conn in results if conn is not None]
        for conn in stale:
            self.active_connections.remove(conn)

    @property
    def count(self) -> int:
        return len(self.active_connections)
