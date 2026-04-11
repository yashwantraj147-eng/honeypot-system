"""
core/enrichment.py
──────────────────
Convenience wrapper that enriches an attacker IP with geolocation,
threat-intel score, and triggers alerting — all in one call.
Used by every honeypot to avoid duplicating look-up logic.
"""

from core import geoip, threat_intel, alerting, logger


def process_event(
    src_ip: str,
    service: str,
    action: str,
    payload: dict | None = None,
    details: str = "",
) -> int:
    """
    1. Geo-locate the IP.
    2. Query threat intelligence.
    3. Store in DB.
    4. Fire alert.

    Returns the DB event row-id.
    """
    geo = geoip.lookup(src_ip)
    ti = threat_intel.check_ip(src_ip)
    abuse_score = ti.get("abuse_score", -1)

    row_id = logger.log_event(
        src_ip=src_ip,
        service=service,
        action=action,
        payload=payload,
        geo=geo,
        abuse_score=abuse_score,
    )

    alerting.send_alert(
        src_ip=src_ip,
        service=service,
        action=action,
        details=details,
        geo=geo,
        abuse_score=abuse_score,
    )
    return row_id
