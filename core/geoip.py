"""
core/geoip.py
─────────────
IP geolocation via ip-api.com (free tier — 45 req/min, no key).

The module maintains a simple in-memory LRU cache so repeated
lookups for the same attacker IP don't burn through the rate limit.
Private/reserved IPs are short-circuited to avoid wasted calls.
"""

import ipaddress
import logging
import threading
import time
from functools import lru_cache

import requests

from core.config_loader import cfg

_log = logging.getLogger("honeypotnet.geoip")
_geo_cfg = cfg.get("geoip", {})
_API_URL: str = _geo_cfg.get("api_url", "http://ip-api.com/json/")
_RATE_LIMIT: int = _geo_cfg.get("rate_limit_per_minute", 45)
_ENABLED: bool = _geo_cfg.get("enabled", True)

# Simple token-bucket rate limiter (thread-safe)
_lock = threading.Lock()
_tokens: float = float(_RATE_LIMIT)
_last_refill: float = time.monotonic()


def _consume_token() -> bool:
    """Try to consume one rate-limit token.  Returns False if exhausted."""
    global _tokens, _last_refill
    with _lock:
        now = time.monotonic()
        elapsed = now - _last_refill
        # Refill tokens proportionally to elapsed time
        _tokens = min(_RATE_LIMIT, _tokens + elapsed * (_RATE_LIMIT / 60.0))
        _last_refill = now
        if _tokens >= 1.0:
            _tokens -= 1.0
            return True
        return False


def _is_private(ip: str) -> bool:
    """Return True if the IP is private/reserved (no point querying geo)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # malformed → treat as private


@lru_cache(maxsize=2048)
def lookup(ip: str) -> dict:
    """
    Return geolocation data for *ip*.

    Returns
    -------
    dict with keys: country, city, lat, lon, isp, org
    On failure or private IPs an empty-ish dict is returned.
    """
    if _is_private(ip):
        return {
            "country": "Private",
            "city": "N/A",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "N/A",
            "org": "N/A",
        }

    if not _ENABLED:
        return {"country": None, "city": None, "lat": None, "lon": None}

    if not _consume_token():
        _log.warning("GeoIP rate limit reached — skipping lookup for %s", ip)
        return {"country": None, "city": None, "lat": None, "lon": None}

    try:
        resp = requests.get(
            f"{_API_URL}{ip}",
            params={"fields": "status,country,city,lat,lon,isp,org"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
            }
        _log.warning("GeoIP lookup failed for %s: %s", ip, data)
    except Exception as exc:
        _log.error("GeoIP request error for %s: %s", ip, exc)

    return {"country": None, "city": None, "lat": None, "lon": None}
