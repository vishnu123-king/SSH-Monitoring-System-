"""Unit and integration tests for real-time WebSocket manager and alerts endpoint."""

from __future__ import annotations

import asyncio
import pytest
from fastapi.testclient import TestClient
from app.websocket.manager import ws_manager


def test_websocket_ping_pong(client: TestClient):
    with client.websocket_connect("/ws/alerts") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == '{"type":"pong"}'


@pytest.mark.asyncio
async def test_websocket_broadcast_direct():
    # Test WebSocketManager dispatch logic with empty and mock connections
    manager = ws_manager
    await manager.broadcast("test.ping", {"status": "ok"})
    # Should complete without error when no connections are active
    assert len(manager.active_connections) == 0
