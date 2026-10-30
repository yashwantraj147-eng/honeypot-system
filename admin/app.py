"""
admin/app.py
────────────
Flask web dashboard for reviewing captured honeypot data.

Features:
  • Login-protected admin panel with rate-limiting and constant-time password validation
  • Live event table with filters (service, IP, date range)
  • Pagination
  • CSV export of filtered results
  • Summary statistics cards
  • Localhost-bound by default for operational security
"""

import csv
import hmac
import io
import logging
import time
from collections import defaultdict
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    Response,
    jsonify,
)

from core.config_loader import cfg
from core.logger import init_db, query_events, count_events, get_service_stats, get_unique_ips

_log = logging.getLogger("honeypotnet.admin")
_admin_cfg = cfg.get("admin", {})

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)
app.secret_key = _admin_cfg.get("secret_key", "change-me-to-a-random-64-char-string")

# In-memory brute force protection: IP -> list of timestamps
_failed_attempts = defaultdict(list)
_MAX_FAILURES = 5
_LOCKOUT_WINDOW = 300  # 5 minutes


# ────────────────────────────────────────────────────────────
#  Auth helpers
# ────────────────────────────────────────────────────────────

def _is_rate_limited(ip: str) -> bool:
    """Check if the requesting IP has exceeded login attempt threshold."""
    now = time.time()
    # Prune old attempts
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < _LOCKOUT_WINDOW]
    return len(_failed_attempts[ip]) >= _MAX_FAILURES


def _record_failure(ip: str) -> None:
    _failed_attempts[ip].append(time.time())


def _clear_failures(ip: str) -> None:
    _failed_attempts.pop(ip, None)


def _login_required(f):
    """Simple session-based auth decorator."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    client_ip = request.remote_addr or "127.0.0.1"

    if request.method == "POST":
        if _is_rate_limited(client_ip):
            return render_template(
                "login.html",
                error="Too many failed login attempts. Please wait 5 minutes before trying again."
            ), 429

        u = request.form.get("username", "")
        p = request.form.get("password", "")

        expected_user = _admin_cfg.get("username", "admin")
        expected_pass = _admin_cfg.get("password", "")

        # Constant-time comparison to protect against timing side-channel attacks
        is_user_valid = hmac.compare_digest(u.encode("utf-8"), expected_user.encode("utf-8"))
        is_pass_valid = hmac.compare_digest(p.encode("utf-8"), expected_pass.encode("utf-8"))

        if is_user_valid and is_pass_valid:
            _clear_failures(client_ip)
            session["logged_in"] = True
            return redirect(url_for("dashboard"))

        _record_failure(client_ip)
        error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ────────────────────────────────────────────────────────────
#  Dashboard
# ────────────────────────────────────────────────────────────

@app.route("/")
@_login_required
def dashboard():
    """Main dashboard page — renders the event table with filters."""
    # Read filter / pagination params
    service = request.args.get("service", "")
    src_ip = request.args.get("src_ip", "")
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")
    page = max(int(request.args.get("page", 1)), 1)
    per_page = 50

    total = count_events(
        service=service or None,
        src_ip=src_ip or None,
        start_date=start_date or None,
        end_date=end_date or None,
    )
    events = query_events(
        service=service or None,
        src_ip=src_ip or None,
        start_date=start_date or None,
        end_date=end_date or None,
        limit=per_page,
        offset=(page - 1) * per_page,
    )
    stats = get_service_stats()
    unique_ips = get_unique_ips()
    total_pages = max((total + per_page - 1) // per_page, 1)

    return render_template(
        "dashboard.html",
        events=events,
        stats=stats,
        unique_ips=unique_ips,
        total=total,
        page=page,
        total_pages=total_pages,
        current_service=service,
        current_ip=src_ip,
        start_date=start_date,
        end_date=end_date,
    )


@app.route("/api/events")
@_login_required
def api_events():
    """JSON endpoint for programmatic query access."""
    service = request.args.get("service")
    src_ip = request.args.get("src_ip")
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))

    events = query_events(service=service, src_ip=src_ip, limit=limit, offset=offset)
    return jsonify({"count": len(events), "events": events})


@app.route("/api/stats")
@_login_required
def api_stats():
    """Summary metrics in JSON format."""
    return jsonify({
        "services": get_service_stats(),
        "unique_ips": get_unique_ips(),
        "total_events": count_events(),
    })


@app.route("/export/csv")
@_login_required
def export_csv():
    """Stream filtered query results as a CSV download."""
    service = request.args.get("service") or None
    src_ip = request.args.get("src_ip") or None
    start_date = request.args.get("start_date") or None
    end_date = request.args.get("end_date") or None

    events = query_events(
        service=service,
        src_ip=src_ip,
        start_date=start_date,
        end_date=end_date,
        limit=10000,
    )

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "id", "timestamp", "src_ip", "service", "action",
            "payload", "geo_country", "geo_city", "geo_lat",
            "geo_lon", "abuse_score",
        ],
    )
    writer.writeheader()
    writer.writerows(events)

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=honeypot_export.csv"},
    )


# ────────────────────────────────────────────────────────────
#  Entrypoint
# ────────────────────────────────────────────────────────────

def start() -> None:
    init_db()
    # Bound to 127.0.0.1 by default for defense-in-depth
    host = _admin_cfg.get("host", "127.0.0.1")
    port = _admin_cfg.get("port", 5000)
    _log.info("Admin panel starting on %s:%d", host, port)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    start()
