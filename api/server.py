"""
api/server.py
─────────────
Enterprise FastAPI Orchestrator for Honeypot-System v2.0.
Coordinates asynchronous decoy network listeners, real-time WebSocket attack streams,
threat dossiers, session playback API, and SOC dashboard static assets.
"""

import asyncio
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.feed import router as feed_router
from core.config import settings
from core.database import (
    get_recent_attacks,
    get_system_stats,
    init_db,
    register_attack_listener,
)
from services.ftp_service import start_ftp_service, stop_ftp_service
from services.http_service import start_http_service, stop_http_service
from services.ssh_service import start_ssh_service, stop_ssh_service
from services.telnet_service import start_telnet_service, stop_telnet_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("honeypot.server")


class ConnectionManager:
    """Manages active WebSocket connections for streaming real-time intrusion telemetry."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast_attack(self, attack_data: Dict[str, Any]) -> None:
        """Broadcast newly recorded attack to all active dashboard clients."""
        if not self.active_connections:
            return

        payload_str = json.dumps({"type": "attack_event", "data": attack_data})
        disconnected: List[WebSocket] = []

        for connection in self.active_connections:
            try:
                await connection.send_text(payload_str)
            except Exception:
                disconnected.append(connection)

        for dead in disconnected:
            self.disconnect(dead)


ws_manager = ConnectionManager()
_service_tasks: List[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager:
    Initializes database schema, mounts event listeners, and starts all background decoy services.
    """
    logger.info("=================================================================")
    logger.info("  Honeypot-System v2.0 Enterprise Deception Grid Starting        ")
    logger.info("=================================================================")

    # 1. Initialize SQLite Database & Migrations
    await init_db()

    # 2. Register real-time WebSocket dispatcher callback
    register_attack_listener(ws_manager.broadcast_attack)

    # 3. Launch Decoy Services non-blockingly
    _service_tasks.append(
        asyncio.create_task(
            start_ssh_service(settings.HOST, settings.SSH_PORT),
            name="ssh_decoy_task"
        )
    )
    _service_tasks.append(
        asyncio.create_task(
            start_http_service(settings.HOST, settings.HTTP_PORT),
            name="http_decoy_task"
        )
    )
    _service_tasks.append(
        asyncio.create_task(
            start_ftp_service(settings.HOST, settings.FTP_PORT),
            name="ftp_decoy_task"
        )
    )
    _service_tasks.append(
        asyncio.create_task(
            start_telnet_service(settings.HOST, settings.TELNET_PORT),
            name="telnet_decoy_task"
        )
    )

    logger.info(
        "All decoys operational: SSH (%d), HTTP (%d), FTP (%d), Telnet (%d)",
        settings.SSH_PORT, settings.HTTP_PORT, settings.FTP_PORT, settings.TELNET_PORT
    )
    logger.info("Enterprise SOC Dashboard & API active on http://0.0.0.0:%d", settings.API_PORT)

    yield

    # Shutdown sequence
    logger.info("Initiating graceful shutdown of Honeypot-System v2.0 decoys...")
    stop_ssh_service()
    await stop_http_service()
    await stop_ftp_service()
    await stop_telnet_service()

    for task in _service_tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*_service_tasks, return_exceptions=True)
    logger.info("Honeypot-System v2.0 stopped cleanly.")


app = FastAPI(
    title="Honeypot-System v2.0 Enterprise API",
    description="Autonomous Multi-Service Deception Grid & Real-Time Threat Intelligence Pipeline",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Threat Intelligence Feeds router
app.include_router(feed_router)

# Mount static web assets
static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=FileResponse)
async def serve_dashboard() -> FileResponse:
    """Serve the single-page dark-mode SOC dashboard."""
    index_file = static_dir / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard index.html not found.")
    return FileResponse(index_file)


@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint indicating active sensor status, listeners, and memory metrics."""
    return {
        "status": "HEALTHY",
        "sensor_name": settings.SENSOR_NAME,
        "services": {
            "ssh": {"port": settings.SSH_PORT, "active": True, "type": "Medium-Interaction (VFS)"},
            "http": {"port": settings.HTTP_PORT, "active": True, "type": "Multi-Surface Decoy"},
            "ftp": {"port": settings.FTP_PORT, "active": True, "type": "RFC 959 Trap"},
            "telnet": {"port": settings.TELNET_PORT, "active": True, "type": "RFC 854 Mirai IoT Trap"},
        }
    }


@app.get("/api/v1/stats")
async def get_stats() -> Dict[str, Any]:
    """Retrieve telemetry metrics, attack volumes, risk scores, and MITRE distributions."""
    return await get_system_stats()


@app.get("/api/v1/attacks/recent")
async def get_recent_attacks_api(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve the latest intrusions logged across all decoy services."""
    return await get_recent_attacks(limit=limit)


@app.get("/api/v1/attacker/{ip}")
async def get_attacker_dossier(ip: str) -> Dict[str, Any]:
    """
    Generate an in-depth Threat Actor Dossier for an individual attacking IP address,
    including attack timeline, observed credentials, fingerprints, and aggregated risk score.
    """
    async with aiosqlite.connect(settings.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT id, timestamp, service, payload, credentials,
                   geoip_country, geoip_city, latitude, longitude,
                   mitre_technique_id, mitre_name, mitre_tactic,
                   fingerprint, risk_score, severity
            FROM attacks
            WHERE source_ip = ?
            ORDER BY id DESC
            LIMIT 50
        """, (ip,)) as cursor:
            rows = await cursor.fetchall()
            if not rows:
                raise HTTPException(status_code=404, detail=f"No telemetry found for IP: {ip}")

            attacks = [dict(r) for r in rows]
            latest = attacks[0]

            services_targeted = sorted(list(set(a["service"] for a in attacks)))
            credentials_attempted = sorted(list(set(a["credentials"] for a in attacks if a["credentials"])))
            mitre_techniques = sorted(list(set(a["mitre_technique_id"] for a in attacks if a["mitre_technique_id"])))
            max_risk = max(a.get("risk_score", 25) for a in attacks)

            return {
                "source_ip": ip,
                "total_events": len(attacks),
                "first_seen": attacks[-1]["timestamp"],
                "last_seen": latest["timestamp"],
                "max_risk_score": max_risk,
                "primary_severity": latest.get("severity", "LOW"),
                "primary_fingerprint": latest.get("fingerprint", "Generic Reconnaissance Probe"),
                "geolocation": {
                    "country": latest.get("geoip_country"),
                    "city": latest.get("geoip_city"),
                    "lat": latest.get("latitude"),
                    "lon": latest.get("longitude")
                },
                "services_targeted": services_targeted,
                "credentials_attempted": credentials_attempted,
                "mitre_techniques": mitre_techniques,
                "timeline": attacks[:20]
            }


@app.get("/api/v1/session/{session_id}/replay")
async def get_session_replay(session_id: str) -> Dict[str, Any]:
    """Deliver recorded keystroke stream for an interactive attacker session."""
    recordings_dir = Path(settings.RECORDINGS_DIR)
    target_file = recordings_dir / f"ssh_{session_id}.json"

    if not target_file.exists():
        target_file = recordings_dir / f"{session_id}.json"

    if not target_file.exists():
        raise HTTPException(status_code=404, detail=f"No recording found for session {session_id}")

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error reading session file: {exc}")


@app.websocket("/ws/attacks")
async def websocket_attacks_endpoint(websocket: WebSocket) -> None:
    """Real-time bi-directional WebSocket channel streaming live decoy intrusions."""
    await ws_manager.connect(websocket)
    try:
        await websocket.send_text(json.dumps({
            "type": "connection_ack",
            "sensor": settings.SENSOR_NAME,
            "message": "Connected to Honeypot-System v2.0 real-time telemetry feed"
        }))
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug("WebSocket error: %s", exc)
        ws_manager.disconnect(websocket)
