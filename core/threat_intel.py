"""
core/threat_intel.py
────────────────────
Check attacker IPs against AbuseIPDB (free tier — 1 000 checks/day).

Results are cached so the same IP is never checked twice in a session.
"""

import logging
import threading
from functools import lru_cache

import requests

from core.config_loader import cfg

_log = logging.getLogger("honeypotnet.threat_intel")
_ti_cfg = cfg.get("threat_intel", {})
_ENABLED: bool = _ti_cfg.get("enabled", True)
_API_KEY: str = _ti_cfg.get("abuseipdb_api_key", "")
_API_URL: str = _ti_cfg.get("abuseipdb_url", "https://api.abuseipdb.com/api/v2/check")
_THRESHOLD: int = _ti_cfg.get("confidence_threshold", 50)

# Guard against hammering the API from multiple threads at once
_lock = threading.Lock()


@lru_cache(maxsize=4096)
def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for *ip*.

    Returns
    -------
    dict with keys:
        abuse_score       int   (0-100, or -1 on failure)
        is_known_attacker bool
        total_reports     int
        country_code      str|None
        domain            str|None
    """
    default = {
        "abuse_score": -1,
        "is_known_attacker": False,
        "total_reports": 0,
        "country_code": None,
        "domain": None,
    }

    if not _ENABLED or not _API_KEY or _API_KEY.startswith("YOUR_"):
        _log.debug("Threat-intel disabled or no API key — skipping %s", ip)
        return default

    with _lock:
        try:
            resp = requests.get(
                _API_URL,
                headers={
                    "Key": _API_KEY,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": "",
                },
                timeout=10,
            )
            if resp.status_code == 429:
                _log.warning("AbuseIPDB rate limit hit — skipping %s", ip)
                return default
            resp.raise_for_status()

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "abuse_score": score,
                "is_known_attacker": score >= _THRESHOLD,
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "domain": data.get("domain"),
            }
        except Exception as exc:
            _log.error("AbuseIPDB check failed for %s: %s", ip, exc)
            return default
