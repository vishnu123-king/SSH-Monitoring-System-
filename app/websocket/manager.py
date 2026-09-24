"""WebSocket connection manager for real-time alert and telemetry broadcasting."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Set
from fastapi import WebSocket

logger = logging.getLogger("ssh_monitor.websocket")


class WebSocketManager:
    """Manages active WebSocket connections from web dashboards and CLI clients."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new client connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info("WebSocket client connected. Total active: %d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a disconnected client."""
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info("WebSocket client disconnected. Total active: %d", len(self.active_connections))

    async def broadcast(self, message_type: str, data: Dict[str, Any]) -> None:
        """Broadcast structured JSON payload to all connected clients."""
        if not self.active_connections:
            return

        payload = {
            "type": message_type,
            "data": data,
        }
        raw_json = json.dumps(payload, default=str)

        disconnected: Set[WebSocket] = set()
        async with self._lock:
            connections = list(self.active_connections)

        for conn in connections:
            try:
                await conn.send_text(raw_json)
            except Exception as exc:
                logger.debug("Failed sending WebSocket frame to client: %s", exc)
                disconnected.add(conn)

        if disconnected:
            async with self._lock:
                for dead_conn in disconnected:
                    self.active_connections.discard(dead_conn)
            logger.debug("Cleaned up %d disconnected WebSocket clients", len(disconnected))


ws_manager = WebSocketManager()
