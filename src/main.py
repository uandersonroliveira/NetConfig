import json
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

from .api.routes import router as api_router
from .api.websocket import manager

app = FastAPI(
    title="NetConfig",
    description="Network Switch Configuration Manager",
    version="1.0.0"
)

app.include_router(api_router)

static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def root():
    """Serve the main web interface."""
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "NetConfig API", "docs": "/docs"}


@app.websocket("/ws/progress")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time progress updates."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


def load_config() -> dict:
    """Load application configuration."""
    config_file = Path(__file__).parent.parent / "config.json"
    if config_file.exists():
        with open(config_file, 'r') as f:
            return json.load(f)
    return {"server": {"host": "0.0.0.0", "port": 8080}}


if __name__ == "__main__":
    config = load_config()
    server_config = config.get("server", {})

    print("\n" + "=" * 50)
    print("  NetConfig - Network Switch Configuration Manager")
    print("=" * 50)
    print(f"\n  Web Interface: http://{server_config.get('host', '127.0.0.1')}:{server_config.get('port', 8080)}")
    print(f"  API Documentation: http://{server_config.get('host', '127.0.0.1')}:{server_config.get('port', 8080)}/docs")
    print("\n" + "=" * 50 + "\n")

    uvicorn.run(
        app,
        host=server_config.get("host", "0.0.0.0"),
        port=server_config.get("port", 8080),
        log_level="info"
    )
