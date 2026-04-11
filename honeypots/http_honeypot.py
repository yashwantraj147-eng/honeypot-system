"""
honeypots/http_honeypot.py
──────────────────────────
Flask-based HTTP honeypot that presents:
  • A fake login form (POST /login)
  • A fake admin panel (GET /admin)
  • A fake file upload endpoint (POST /upload)
  • A catch-all route that logs every request

Logs: method, path, headers, cookies, form data, uploaded files,
query strings, and raw bodies.
"""

import json
import logging
import os

from flask import Flask, request, render_template_string, redirect, url_for

from core.config_loader import cfg
from core.enrichment import process_event
from core.rate_limiter import allow as rate_ok
from core.logger import init_db, setup_file_logging

_log = logging.getLogger("honeypotnet.http")
_http_cfg = cfg["services"]["http"]

app = Flask(__name__)
# Spoof the server header so scanners see "Apache"
_SERVER_BANNER = _http_cfg.get("server_banner", "Apache/2.4.54 (Ubuntu)")

# ────────────────────────────────────────────────────────────
#  Inline templates (no external files needed for the honeypot)
# ────────────────────────────────────────────────────────────

_LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login — Internal Portal</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#1a1a2e;
       display:flex;justify-content:center;align-items:center;height:100vh}
  .card{background:#16213e;padding:40px 36px;border-radius:12px;
        box-shadow:0 8px 32px rgba(0,0,0,.45);width:100%;max-width:380px}
  .card h2{color:#e94560;margin-bottom:24px;text-align:center;font-size:1.6em}
  .card input{width:100%;padding:12px;margin-bottom:16px;border:none;
              border-radius:6px;background:#0f3460;color:#fff;font-size:1em}
  .card input::placeholder{color:#8899a6}
  .card button{width:100%;padding:12px;border:none;border-radius:6px;
               background:#e94560;color:#fff;font-size:1.05em;cursor:pointer;
               transition:background .2s}
  .card button:hover{background:#c73350}
  .err{color:#e94560;text-align:center;margin-bottom:12px;font-size:.9em}
</style>
</head>
<body>
<div class="card">
  <h2>🔒 Internal Portal</h2>
  {% if error %}<p class="err">{{ error }}</p>{% endif %}
  <form method="POST" action="/login">
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>
"""

_ADMIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>Admin Dashboard</title>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#0f0f23;color:#ccc;padding:30px}
  h1{color:#e94560}
  table{width:100%;border-collapse:collapse;margin-top:20px}
  th,td{padding:10px 14px;border:1px solid #333;text-align:left}
  th{background:#16213e;color:#e94560}
  .btn{background:#e94560;color:#fff;padding:8px 16px;border:none;
       border-radius:4px;cursor:pointer;margin:6px}
</style>
</head>
<body>
<h1>⚙️ Admin Dashboard</h1>
<p>Welcome, <b>admin</b>. Server status: <span style="color:#33d9b2">● online</span></p>
<table>
  <tr><th>Service</th><th>Status</th><th>Uptime</th></tr>
  <tr><td>Web Server</td><td style="color:#33d9b2">Running</td><td>14d 3h</td></tr>
  <tr><td>Database</td><td style="color:#33d9b2">Running</td><td>14d 3h</td></tr>
  <tr><td>Mail Server</td><td style="color:#ff6b6b">Stopped</td><td>—</td></tr>
</table>
<br>
<button class="btn" onclick="alert('Restarting...')">Restart Services</button>
<button class="btn" onclick="alert('Backup started')">Backup Now</button>
<h2 style="margin-top:30px">File Upload</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file" style="color:#ccc"><br><br>
  <button class="btn" type="submit">Upload</button>
</form>
</body>
</html>
"""

_UPLOAD_SUCCESS = """
<!DOCTYPE html><html><head><title>Upload OK</title>
<style>body{font-family:Arial;background:#0f0f23;color:#33d9b2;display:flex;
justify-content:center;align-items:center;height:100vh}
h2{text-align:center}</style></head>
<body><h2>✅ File uploaded successfully.<br><a href="/admin" style="color:#e94560">Back</a></h2></body></html>
"""


# ────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────

def _request_meta() -> dict:
    """Extract request metadata for logging."""
    return {
        "method": request.method,
        "path": request.path,
        "query": dict(request.args),
        "headers": dict(request.headers),
        "cookies": dict(request.cookies),
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "content_type": request.content_type,
    }


# Monkey-patch Werkzeug's dev server to use our banner.
# The dev server sets the Server header at the WSGI layer, so we must
# override it here rather than in an after_request hook.
try:
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = _SERVER_BANNER

    # Override version_string() to prevent the "Python/x.y.z" suffix
    WSGIRequestHandler.version_string = lambda self: _SERVER_BANNER  # type: ignore[assignment]
except ImportError:
    pass


@app.before_request
def _rate_check():
    """Reject IPs that exceed the global rate limit."""
    ip = request.remote_addr
    if not rate_ok(ip):
        _log.warning("Rate-limited HTTP from %s", ip)
        return "429 Too Many Requests", 429


# ────────────────────────────────────────────────────────────
#  Routes
# ────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Redirect root to the fake login page."""
    _log_request("page_view")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Fake login form — logs every credential pair."""
    ip = request.remote_addr
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        meta = _request_meta()
        meta["form"] = {"username": username, "password": password}
        process_event(
            src_ip=ip,
            service="http",
            action="login_attempt",
            payload=meta,
            details=f"HTTP login: {username}/{password}",
        )
        # Always show "invalid" so they try more creds
        return render_template_string(_LOGIN_PAGE, error="Invalid credentials. Try again.")

    _log_request("login_page_view")
    return render_template_string(_LOGIN_PAGE, error=None)


@app.route("/admin", methods=["GET"])
def admin_panel():
    """Fake admin panel — any visitor gets logged."""
    _log_request("admin_panel_access")
    return render_template_string(_ADMIN_PAGE)


@app.route("/upload", methods=["POST"])
def upload():
    """Fake file upload — saves the filename & size for analysis."""
    ip = request.remote_addr
    meta = _request_meta()
    uploaded = request.files.get("file")
    if uploaded:
        file_data = uploaded.read()
        meta["upload"] = {
            "filename": uploaded.filename,
            "size_bytes": len(file_data),
            "content_type": uploaded.content_type,
        }
        # Optionally persist the file for forensics
        upload_dir = os.path.join("data", "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        safe_name = f"{ip}_{uploaded.filename}".replace("/", "_").replace("\\", "_")
        with open(os.path.join(upload_dir, safe_name), "wb") as f:
            f.write(file_data)
    process_event(
        src_ip=ip,
        service="http",
        action="file_upload",
        payload=meta,
        details=f"Upload: {uploaded.filename if uploaded else 'empty'}",
    )
    return render_template_string(_UPLOAD_SUCCESS)


@app.route("/robots.txt")
def robots():
    """Deliberately expose 'secret' paths to lure scanners."""
    _log_request("robots_txt")
    return (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup\n"
        "Disallow: /config\n"
        "Disallow: /phpmyadmin\n"
    ), 200, {"Content-Type": "text/plain"}


@app.route("/.env")
@app.route("/wp-login.php")
@app.route("/phpmyadmin")
@app.route("/config")
@app.route("/backup")
@app.route("/.git/config")
def honeypot_traps():
    """
    Common scanner targets — log the hit and serve a plausible response.
    """
    _log_request("scanner_probe")
    return "Not Found", 404


# Catch-all for anything else
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path):
    """Log every request that doesn't match a specific route."""
    _log_request("catch_all")
    return "Not Found", 404


# ────────────────────────────────────────────────────────────
#  Generic request logger
# ────────────────────────────────────────────────────────────

def _log_request(action: str) -> None:
    """Record any request to the central DB."""
    ip = request.remote_addr
    meta = _request_meta()
    # Capture raw body for POST / PUT if it's not a file upload
    if request.method in ("POST", "PUT", "PATCH") and not request.files:
        try:
            meta["body"] = request.get_data(as_text=True)[:4096]
        except Exception:
            meta["body"] = "<unreadable>"
    process_event(
        src_ip=ip,
        service="http",
        action=action,
        payload=meta,
        details=f"{request.method} {request.path}",
    )


# ────────────────────────────────────────────────────────────
#  Entrypoint
# ────────────────────────────────────────────────────────────

def start() -> None:
    """Run the HTTP honeypot."""
    init_db()
    setup_file_logging()

    host = _http_cfg["host"]
    port = _http_cfg["port"]
    _log.info("HTTP honeypot listening on %s:%d", host, port)
    # Disable reloader in production; debug=False hides tracebacks
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    start()
