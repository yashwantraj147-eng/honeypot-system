"""
services/http_service.py
────────────────────────
Asynchronous Web Decoy Trap (aiohttp.web).
Features fake credential lures (/.env, /wp-login.php, /actuator/health),
active scanner tarpitting, and defense gzip decompression bombs.
"""

import asyncio
from collections import defaultdict
import datetime
import gzip
import json
import logging
import time
from typing import Dict, List, Optional

from aiohttp import web

from core.classifier import classify_payload
from core.config import settings
from core.database import log_attack

logger = logging.getLogger("honeypot.http")

# Track request timestamps per IP for tarpit rate detection: {ip: [timestamps]}
_ip_request_history: Dict[str, List[float]] = defaultdict(list)

# Pre-generate 10MB uncompressed gzip bomb (compresses to ~9.7KB)
_GZIP_BOMB_PAYLOAD = gzip.compress(b"\x00" * 10_000_000, compresslevel=9)

_APP_RUNNER: Optional[web.AppRunner] = None
_SITE: Optional[web.TCPSite] = None


def _get_client_ip(request: web.Request) -> str:
    """Extract real client IP considering forward headers."""
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    peername = request.transport.get_extra_info("peername")
    if peername:
        return peername[0]
    return "127.0.0.1"


def _should_tarpit(ip: str) -> bool:
    """Determine whether request frequency warrants tarpit throttling."""
    if not settings.TARPIT_ENABLED:
        return False
    now = time.time()
    # Retain only timestamps from the last 10 seconds
    timestamps = [t for t in _ip_request_history[ip] if now - t < 10.0]
    timestamps.append(now)
    _ip_request_history[ip] = timestamps
    return len(timestamps) > 10


def _is_malicious_probe(request: web.Request) -> bool:
    """Detect directory traversal patterns or automated scanner user-agents."""
    path = request.path_qs.lower()
    user_agent = request.headers.get("User-Agent", "").lower()

    traversal_triggers = ("..", "%2e%2e", "/etc/passwd", "win.ini", "boot.ini", "%00")
    scanner_agents = ("nikto", "sqlmap", "nmap", "masscan", "zgrab", "acunetix", "dirbuster", "gobuster", "wpscan")

    if any(trigger in path for trigger in traversal_triggers):
        return True
    if any(agent in user_agent for agent in scanner_agents):
        return True
    return False


async def _stream_tarpit(request: web.Request, body: bytes, content_type: str = "text/plain") -> web.StreamResponse:
    """Stream response in slow byte increments to stall automated bot workers."""
    response = web.StreamResponse(status=200, headers={"Content-Type": content_type})
    await response.prepare(request)
    chunk_size = max(1, settings.TARPIT_BYTE_RATE)

    for i in range(0, len(body), chunk_size):
        chunk = body[i:i + chunk_size]
        await response.write(chunk)
        await asyncio.sleep(1.0)
    await response.write_eof()
    return response


# ── Route Handlers ──

async def handle_env(request: web.Request) -> web.Response:
    """Trap: Fake .env leak with simulated high-value cloud credentials."""
    client_ip = _get_client_ip(request)
    tags = classify_payload(request.path)
    if not tags:
        tags = [{
            "technique_id": "T1552.001",
            "name": "Credentials in Files: Local Environment",
            "tactic": "Credential Access"
        }]

    await log_attack(
        source_ip=client_ip,
        service="HTTP",
        payload=f"GET {request.path}",
        mitre_tags=tags
    )

    env_content = (
        "# Enterprise Core Environment Configuration\n"
        "APP_NAME=Enterprise-ERP-Core\n"
        "APP_ENV=production\n"
        "APP_KEY=base64:XG8d2LqK4kL9wZ8N1pQ6rT3vY5xW7zM2sA4fC6hJ8=\n"
        "APP_DEBUG=false\n"
        "APP_URL=https://core-portal.internal.corp\n\n"
        "# Primary Production Database\n"
        "DB_CONNECTION=mysql\n"
        "DB_HOST=10.0.12.44\n"
        "DB_PORT=3306\n"
        "DB_DATABASE=erp_production\n"
        "DB_USERNAME=db_admin_prod\n"
        "DB_PASSWORD=P@ssw0rd2024!SecureDbProd_X9\n\n"
        "# AWS Cloud Storage & KMS\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "AWS_DEFAULT_REGION=us-east-1\n"
        "AWS_BUCKET=internal-finance-backups-s3\n\n"
        "# Authentication & API Tokens\n"
        "JWT_SECRET=c2VjdXJlX2p3dF90b2tlbl9zaWduaW5nX2tleV8yMDI2X2hhc2hfdmFsdWU=\n"
        "REDIS_HOST=10.0.12.45\n"
        "REDIS_PASSWORD=R3d!sM@sterC4che2026\n"
        "STRIPE_API_TOKEN=mock_decoy_stripe_token_for_honeypot_telemetry\n"
    )

    body_bytes = env_content.encode("utf-8")
    if _should_tarpit(client_ip):
        return await _stream_tarpit(request, body_bytes, "text/plain")

    return web.Response(text=env_content, content_type="text/plain", status=200)


async def handle_login_get(request: web.Request) -> web.Response:
    """Render authentic dark-themed corporate admin login decoy portal."""
    client_ip = _get_client_ip(request)
    await log_attack(
        source_ip=client_ip,
        service="HTTP",
        payload=f"GET {request.path}",
        mitre_tags=[{
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application: Reconnaissance",
            "tactic": "Initial Access"
        }]
    )

    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internal Infrastructure Portal - Identity Gateway</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #0b0f19; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-card { background: #161e2e; border: 1px solid #2d3748; padding: 2.5rem; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
        .logo { font-size: 1.25rem; font-weight: 700; color: #38bdf8; letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 0.5rem; }
        .subtitle { font-size: 0.85rem; color: #94a3b8; margin-bottom: 2rem; }
        .form-group { margin-bottom: 1.25rem; }
        label { display: block; font-size: 0.85rem; font-weight: 500; margin-bottom: 0.5rem; color: #cbd5e1; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem 1rem; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #fff; font-size: 0.95rem; outline: none; }
        input:focus { border-color: #38bdf8; box-shadow: 0 0 0 2px rgba(56,189,248,0.2); }
        .btn-submit { width: 100%; padding: 0.85rem; background: #0284c7; border: none; border-radius: 6px; color: #fff; font-weight: 600; font-size: 0.95rem; cursor: pointer; transition: background 0.2s; margin-top: 1rem; }
        .btn-submit:hover { background: #0369a1; }
        .footer-note { font-size: 0.75rem; text-align: center; color: #64748b; margin-top: 2rem; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">CorpShield Access Gateway</div>
        <div class="subtitle">Authorized Personnel & Federated SAML Login</div>
        <form method="POST">
            <div class="form-group">
                <label for="log">Username or Email</label>
                <input type="text" id="log" name="log" autocomplete="username" required>
            </div>
            <div class="form-group">
                <label for="pwd">Security Password</label>
                <input type="password" id="pwd" name="pwd" autocomplete="current-password" required>
            </div>
            <button type="submit" class="btn-submit">Sign In to Dashboard</button>
        </form>
        <div class="footer-note">All activity is cryptographically signed and audited.</div>
    </div>
</body>
</html>"""
    return web.Response(text=html_content, content_type="text/html", status=200)


async def handle_login_post(request: web.Request) -> web.Response:
    """Capture attacker submitted credentials and record brute-force telemetry."""
    client_ip = _get_client_ip(request)
    data = {}
    try:
        data = await request.post()
    except Exception:
        pass

    username = data.get("log") or data.get("username") or data.get("user") or "unknown"
    password = data.get("pwd") or data.get("password") or data.get("pass") or "unknown"
    cred_str = f"{username}:{password}"

    logger.warning("[HTTP] Captured credentials from %s -> %s", client_ip, cred_str)

    await log_attack(
        source_ip=client_ip,
        service="HTTP",
        payload=f"POST {request.path} [auth attempt]",
        credentials=cred_str,
        mitre_tags=[{
            "technique_id": "T1110",
            "name": "Brute Force: Credential Stuffing",
            "tactic": "Credential Access"
        }]
    )

    # Return authentic authentication error
    error_html = """<!DOCTYPE html>
<html>
<body style="background:#0b0f19;color:#f87171;font-family:sans-serif;padding:3rem;text-align:center;">
    <h2>Authentication Failure</h2>
    <p style="color:#94a3b8;margin-top:1rem;">Invalid security token or password. Access attempt has been registered with SecOps.</p>
    <a href="/login" style="color:#38bdf8;display:inline-block;margin-top:1.5rem;text-decoration:none;">&larr; Back to Login</a>
</body>
</html>"""
    return web.Response(text=error_html, content_type="text/html", status=401)


async def handle_actuator(request: web.Request) -> web.Response:
    """Trap: Spring Boot Actuator health and telemetry endpoints."""
    client_ip = _get_client_ip(request)
    await log_attack(
        source_ip=client_ip,
        service="HTTP",
        payload=f"GET {request.path}",
        mitre_tags=[{
            "technique_id": "T1082",
            "name": "System Information Discovery: Spring Actuator",
            "tactic": "Discovery"
        }]
    )

    data = {
        "status": "UP",
        "components": {
            "db": {
                "status": "UP",
                "details": {
                    "database": "PostgreSQL",
                    "validationQuery": "isValid()"
                }
            },
            "diskSpace": {
                "status": "UP",
                "details": {
                    "total": 499963174912,
                    "free": 214748364800,
                    "threshold": 10485760
                }
            },
            "ping": {"status": "UP"}
        }
    }
    return web.json_response(data)


async def handle_config_json(request: web.Request) -> web.Response:
    """Trap: Emulated frontend microservices cluster config."""
    client_ip = _get_client_ip(request)
    await log_attack(
        source_ip=client_ip,
        service="HTTP",
        payload=f"GET {request.path}",
        mitre_tags=[{
            "technique_id": "T1082",
            "name": "System Information Discovery: Frontend Config",
            "tactic": "Discovery"
        }]
    )

    data = {
        "environment": "production",
        "cluster": "k8s-us-east-01.internal.corp",
        "auth_realm": "CORP-SSO",
        "auth_endpoint": "https://auth.internal.corp/oauth/v2/token",
        "api_gateway": "https://api.internal.corp/v1",
        "telemetry_enabled": True
    }
    return web.json_response(data)


async def handle_catchall(request: web.Request) -> web.Response:
    """Catch-all for scanning probes, directory traversals, and automated tools."""
    client_ip = _get_client_ip(request)

    # Active Defense: Trigger gzip decompression bomb if path traversal or scanner agent detected
    if _is_malicious_probe(request):
        logger.warning("[HTTP] Malicious scanner detected from %s. Deploying Gzip Defense Bomb.", client_ip)
        await log_attack(
            source_ip=client_ip,
            service="HTTP",
            payload=f"{request.method} {request.path_qs} [GZIP_BOMB_DEPLOYED]",
            mitre_tags=[{
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application: Scanner / Path Traversal",
                "tactic": "Initial Access"
            }]
        )
        return web.Response(
            body=_GZIP_BOMB_PAYLOAD,
            headers={
                "Content-Encoding": "gzip",
                "Content-Type": "text/html",
                "X-Honeypot-Defense": "Active-Tarpit-Triggered"
            },
            status=200
        )

    # Standard reconnaissance classification
    tags = classify_payload(request.path_qs)
    await log_attack(
        source_ip=client_ip,
        service="HTTP",
        payload=f"{request.method} {request.path_qs}",
        mitre_tags=tags
    )

    fake_404 = (
        "<html>\r\n"
        "<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>404 Not Found</h1></center>\r\n"
        "<hr><center>nginx/1.22.1 (Ubuntu)</center>\r\n"
        "</body>\r\n"
        "</html>"
    )

    if _should_tarpit(client_ip):
        return await _stream_tarpit(request, fake_404.encode("utf-8"), "text/html")

    return web.Response(text=fake_404, content_type="text/html", status=404)


async def start_http_service(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Initialize and run the asynchronous HTTP Decoy web server."""
    global _APP_RUNNER, _SITE

    app = web.Application()

    # Route registrations
    app.router.add_get("/.env", handle_env)
    app.router.add_get("/.env.local", handle_env)
    app.router.add_get("/.env.production", handle_env)

    app.router.add_get("/wp-login.php", handle_login_get)
    app.router.add_post("/wp-login.php", handle_login_post)
    app.router.add_get("/admin", handle_login_get)
    app.router.add_post("/admin", handle_login_post)
    app.router.add_get("/login", handle_login_get)
    app.router.add_post("/login", handle_login_post)

    app.router.add_get("/actuator/health", handle_actuator)
    app.router.add_get("/config.json", handle_config_json)

    # Catch-all
    app.router.add_route("*", "/{tail:.*}", handle_catchall)

    _APP_RUNNER = web.AppRunner(app)
    await _APP_RUNNER.setup()
    _SITE = web.TCPSite(_APP_RUNNER, host, port)
    await _SITE.start()
    logger.info("HTTP Honeypot listening on %s:%d", host, port)


async def stop_http_service() -> None:
    """Gracefully shutdown HTTP decoy server."""
    global _APP_RUNNER, _SITE
    if _SITE:
        await _SITE.stop()
    if _APP_RUNNER:
        await _APP_RUNNER.cleanup()
