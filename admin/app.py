"""
admin/app.py
────────────
Flask web dashboard for reviewing captured honeypot data.

Features:
  • Login-protected admin panel
  • Live event table with filters (service, IP, date range)
  • Pagination
  • CSV export of filtered results
  • Summary statistics cards
"""

import csv
import io
import logging
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
app.secret_key = _admin_cfg.get("secret_key", "change-me")


# ────────────────────────────────────────────────────────────
#  Auth helpers
# ────────────────────────────────────────────────────────────

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
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == _admin_cfg["username"] and p == _admin_cfg["password"]:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
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
        per_page=per_page,
        # Pass current filters back so the template can preserve them
        f_service=service,
        f_src_ip=src_ip,
        f_start_date=start_date,
        f_end_date=end_date,
    )


# ────────────────────────────────────────────────────────────
#  API endpoints
# ────────────────────────────────────────────────────────────

@app.route("/api/stats")
@_login_required
def api_stats():
    """JSON stats for potential AJAX widgets."""
    return jsonify(get_service_stats())


@app.route("/export/csv")
@_login_required
def export_csv():
    """Stream matching events as a CSV download."""
    service = request.args.get("service", "") or None
    src_ip = request.args.get("src_ip", "") or None
    start_date = request.args.get("start_date", "") or None
    end_date = request.args.get("end_date", "") or None

    events = query_events(
        service=service,
        src_ip=src_ip,
        start_date=start_date,
        end_date=end_date,
        limit=100_000,
        offset=0,
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
    host = _admin_cfg.get("host", "0.0.0.0")
    port = _admin_cfg.get("port", 5000)
    _log.info("Admin panel on %s:%d", host, port)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    start()
