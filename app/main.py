"""Main FastAPI Application Entrypoint.

Configures application lifecycle, CORS, security headers middleware, WebSocket endpoint,
static frontend file serving, and REST API routing.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import api_router
from app.config import settings
from app.database.database import init_db
from app.services.monitor import monitor_service
from app.websocket.manager import ws_manager

# Configure structured logging
log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format=log_format,
)
logger = logging.getLogger("ssh_monitor.app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager handling startup and graceful shutdown."""
    logger.info("Initializing %s v%s", settings.app_name, settings.version)
    # 1. Initialize SQLite Database & Tables
    init_db()

    # 2. Start Monitor Service & Journal Collector
    await monitor_service.start()

    yield

    # 3. Gracefully stop services
    await monitor_service.stop()
    logger.info("Application shutdown complete.")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Linux SSH security monitoring, intrusion detection, and real-time dashboard API.",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Enforce strict security headers across all HTTP responses."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data:;"
    )
    return response


# Include REST API
app.include_router(api_router)


# WebSocket endpoint for real-time security alerts and telemetry
@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket connection for alert streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive receiver
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug("WebSocket exception: %s", exc)
        await ws_manager.disconnect(websocket)


# Serve Static Frontend Dashboard
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

if frontend_dir.exists():
    css_dir = frontend_dir / "css"
    js_dir = frontend_dir / "js"
    if css_dir.exists():
        app.mount("/css", StaticFiles(directory=str(css_dir)), name="css")
    if js_dir.exists():
        app.mount("/js", StaticFiles(directory=str(js_dir)), name="js")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        index_file = frontend_dir / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return {"message": "Frontend index.html not found"}
