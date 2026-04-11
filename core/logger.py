"""
core/logger.py
──────────────
Central logging to SQLite + rotating text files.

Schema
------
events(
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT,       -- ISO-8601 UTC
    src_ip      TEXT,
    service     TEXT,       -- ssh | http | ftp | telnet
    action      TEXT,       -- login_attempt | command | request | upload …
    payload     TEXT,       -- JSON-encoded detail blob
    geo_country TEXT,
    geo_city    TEXT,
    geo_lat     REAL,
    geo_lon     REAL,
    abuse_score INTEGER     -- AbuseIPDB confidence score (0-100, -1 = unknown)
)
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from core.config_loader import cfg

# ── Module-level logger for internal diagnostics ──
_log = logging.getLogger("honeypotnet")

# ── Thread-local storage so each thread gets its own DB connection ──
_local = threading.local()

_DB_PATH: str = cfg["general"]["database_path"]
_LOG_DIR: str = cfg["general"]["log_dir"]

# ── Ensure directories exist ──
os.makedirs(os.path.dirname(_DB_PATH) or ".", exist_ok=True)
os.makedirs(_LOG_DIR, exist_ok=True)


# ────────────────────────────────────────────────────────────
#  Internal helpers
# ────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    """Return a thread-local SQLite connection, creating it if needed."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")  # better concurrent-read perf
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return conn


def init_db() -> None:
    """Create the events table (idempotent)."""
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            service     TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            payload     TEXT,
            geo_country TEXT,
            geo_city    TEXT,
            geo_lat     REAL,
            geo_lon     REAL,
            abuse_score INTEGER DEFAULT -1
        )
        """
    )
    # Index on IP and service for dashboard filtering
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_service ON events(service)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)"
    )
    conn.commit()


# ────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────

def log_event(
    src_ip: str,
    service: str,
    action: str,
    payload: dict | None = None,
    geo: dict | None = None,
    abuse_score: int = -1,
) -> int:
    """
    Insert an event into the database and return the new row ID.

    Parameters
    ----------
    src_ip : str          Attacker source IP.
    service : str         One of ssh, http, ftp, telnet.
    action : str          Free-form action tag (e.g. ``login_attempt``).
    payload : dict|None   Arbitrary data — serialised as JSON.
    geo : dict|None       Keys: country, city, lat, lon.
    abuse_score : int     AbuseIPDB confidence (0-100) or -1 if unknown.

    Returns
    -------
    int   The rowid of the inserted event.
    """
    now = datetime.now(timezone.utc).isoformat()
    payload_json = json.dumps(payload) if payload else None
    geo = geo or {}

    conn = _get_conn()
    cur = conn.execute(
        """
        INSERT INTO events
            (timestamp, src_ip, service, action, payload,
             geo_country, geo_city, geo_lat, geo_lon, abuse_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now,
            src_ip,
            service,
            action,
            payload_json,
            geo.get("country"),
            geo.get("city"),
            geo.get("lat"),
            geo.get("lon"),
            abuse_score,
        ),
    )
    conn.commit()

    # Also write a one-liner to the rotating text log
    _log.info(
        "[%s] %s | %s | %s | %s",
        now, src_ip, service, action,
        json.dumps(payload, default=str) if payload else "-",
    )
    return cur.lastrowid  # type: ignore[return-value]


def query_events(
    service: str | None = None,
    src_ip: str | None = None,
    limit: int = 500,
    offset: int = 0,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict]:
    """
    Retrieve events with optional filters.
    Returns a list of dicts (column-name → value).
    """
    clauses: list[str] = []
    params: list = []

    if service:
        clauses.append("service = ?")
        params.append(service)
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if start_date:
        clauses.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("timestamp <= ?")
        params.append(end_date)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM events{where} ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    conn = _get_conn()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.row_factory = None
    return [dict(row) for row in rows]


def count_events(
    service: str | None = None,
    src_ip: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> int:
    """Return total event count (with optional filters) for pagination."""
    clauses: list[str] = []
    params: list = []
    if service:
        clauses.append("service = ?")
        params.append(service)
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if start_date:
        clauses.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("timestamp <= ?")
        params.append(end_date)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = _get_conn()
    row = conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()
    return row[0]


def get_unique_ips() -> list[str]:
    """Return distinct attacker IPs seen so far."""
    conn = _get_conn()
    rows = conn.execute("SELECT DISTINCT src_ip FROM events ORDER BY src_ip").fetchall()
    return [r[0] for r in rows]


def get_service_stats() -> dict[str, int]:
    """Return {service: event_count} summary."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT service, COUNT(*) FROM events GROUP BY service"
    ).fetchall()
    return {r[0]: r[1] for r in rows}


# ────────────────────────────────────────────────────────────
#  Rotating file-log setup (called once at startup)
# ────────────────────────────────────────────────────────────

def setup_file_logging() -> None:
    """Configure a rotating file handler for the module logger."""
    handler = RotatingFileHandler(
        os.path.join(_LOG_DIR, "honeypot.log"),
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
    )
    formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    _log.addHandler(handler)
    _log.setLevel(getattr(logging, cfg["general"]["log_level"].upper(), logging.INFO))
    # Also echo to stderr during development
    _log.addHandler(logging.StreamHandler())
