"""
main.py
───────
Honeypot-System v2.0: Autonomous Multi-Service Deception Grid & Real-Time Threat Intelligence.
Launches the FastAPI orchestrator and all asynchronous decoy listeners (SSH, HTTP, FTP, Telnet).

Usage:
    python main.py
"""

import sys
import uvicorn
from core.config import settings


def main() -> None:
    """Launch the main ASGI application and service orchestrator."""
    print("=" * 70)
    print("  Honeypot-System v2.0: Autonomous Multi-Service Deception Grid")
    print(f"  Sensor Name : {settings.SENSOR_NAME}")
    print(f"  API Server  : http://{settings.HOST}:{settings.API_PORT}")
    print(f"  Decoy Ports : SSH={settings.SSH_PORT}, HTTP={settings.HTTP_PORT}, FTP={settings.FTP_PORT}, Telnet={settings.TELNET_PORT}")
    print("=" * 70)

    uvicorn.run(
        "api.server:app",
        host=settings.HOST,
        port=settings.API_PORT,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
