import asyncio
import json
from typing import Dict, Set, Any
from fastapi import WebSocket, WebSocketDisconnect


class ConnectionManager:
    """Manages WebSocket connections for real-time progress updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)

    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket) -> None:
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all connected clients."""
        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.add(connection)

        for conn in disconnected:
            self.active_connections.discard(conn)

    async def broadcast_progress(self, task_type: str, current: int, total: int,
                                  message: str, success: bool = True,
                                  extra: Dict[str, Any] = None) -> None:
        """Broadcast a progress update."""
        data = {
            'type': 'progress',
            'task_type': task_type,
            'current': current,
            'total': total,
            'percentage': round((current / total) * 100, 1) if total > 0 else 0,
            'message': message,
            'success': success
        }
        if extra:
            data.update(extra)
        await self.broadcast(data)

    async def broadcast_complete(self, task_type: str, results: Dict[str, Any]) -> None:
        """Broadcast task completion."""
        await self.broadcast({
            'type': 'complete',
            'task_type': task_type,
            'results': results
        })

    async def broadcast_error(self, task_type: str, error: str) -> None:
        """Broadcast an error message."""
        await self.broadcast({
            'type': 'error',
            'task_type': task_type,
            'error': error
        })


manager = ConnectionManager()
