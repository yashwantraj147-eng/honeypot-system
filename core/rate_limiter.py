"""
core/rate_limiter.py
────────────────────
Per-IP connection rate limiter shared by all honeypot services.
Uses a sliding-window counter stored in a dict protected by a lock.
"""

import threading
import time

from core.config_loader import cfg

_rl_cfg = cfg.get("rate_limiting", {})
_ENABLED: bool = _rl_cfg.get("enabled", True)
_MAX_CONN: int = _rl_cfg.get("max_connections", 30)
_WINDOW: int = _rl_cfg.get("window_seconds", 60)

# { ip: [timestamp, timestamp, …] }
_hits: dict[str, list[float]] = {}
_lock = threading.Lock()


def allow(ip: str) -> bool:
    """
    Return True if *ip* is allowed another connection.
    Automatically prunes stale timestamps.
    """
    if not _ENABLED:
        return True

    now = time.monotonic()
    with _lock:
        times = _hits.setdefault(ip, [])
        # Prune entries outside the window
        cutoff = now - _WINDOW
        _hits[ip] = times = [t for t in times if t > cutoff]
        if len(times) >= _MAX_CONN:
            return False
        times.append(now)
        return True
