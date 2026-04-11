"""
core/alerting.py
────────────────
Alert dispatchers — Email (SMTP) and Telegram Bot.

Each dispatcher honours a per-IP cooldown to avoid flooding the
operator's inbox or chat.  The cooldown window is set in config.yaml
(``alerting.cooldown_seconds``).
"""

import logging
import smtplib
import threading
import time
from email.mime.text import MIMEText

import requests

from core.config_loader import cfg

_log = logging.getLogger("honeypotnet.alerting")
_alert_cfg = cfg.get("alerting", {})
_COOLDOWN: int = _alert_cfg.get("cooldown_seconds", 300)

# Track last alert time per IP so we don't spam
_cooldown_map: dict[str, float] = {}
_cd_lock = threading.Lock()


def _check_cooldown(ip: str) -> bool:
    """Return True if enough time has passed since the last alert for *ip*."""
    with _cd_lock:
        last = _cooldown_map.get(ip, 0.0)
        if time.monotonic() - last < _COOLDOWN:
            return False
        _cooldown_map[ip] = time.monotonic()
        return True


# ────────────────────────────────────────────────────────────
#  Email alert
# ────────────────────────────────────────────────────────────

def _send_email(subject: str, body: str) -> None:
    """Send an alert email via SMTP.  Called in a background thread."""
    ecfg = _alert_cfg.get("email", {})
    if not ecfg.get("enabled"):
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = ecfg["from_addr"]
    msg["To"] = ", ".join(ecfg["to_addrs"])

    try:
        with smtplib.SMTP(ecfg["smtp_host"], ecfg["smtp_port"]) as server:
            if ecfg.get("use_tls"):
                server.starttls()
            server.login(ecfg["username"], ecfg["password"])
            server.sendmail(ecfg["from_addr"], ecfg["to_addrs"], msg.as_string())
        _log.info("Email alert sent: %s", subject)
    except Exception as exc:
        _log.error("Email alert failed: %s", exc)


# ────────────────────────────────────────────────────────────
#  Telegram alert
# ────────────────────────────────────────────────────────────

def _send_telegram(text: str) -> None:
    """Send a Telegram message via Bot API.  Called in a background thread."""
    tcfg = _alert_cfg.get("telegram", {})
    if not tcfg.get("enabled"):
        return

    token = tcfg.get("bot_token", "")
    chat_id = tcfg.get("chat_id", "")
    if not token or not chat_id or token.startswith("YOUR_"):
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            _log.info("Telegram alert sent")
        else:
            _log.warning("Telegram alert HTTP %d: %s", resp.status_code, resp.text)
    except Exception as exc:
        _log.error("Telegram alert failed: %s", exc)


# ────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────

def send_alert(
    src_ip: str,
    service: str,
    action: str,
    details: str = "",
    geo: dict | None = None,
    abuse_score: int = -1,
) -> None:
    """
    Dispatch alert via all enabled channels (non-blocking).

    Alerts are rate-limited per *src_ip* so a single scanner
    doesn't generate thousands of messages.
    """
    if not _check_cooldown(src_ip):
        _log.debug("Alert suppressed (cooldown) for %s", src_ip)
        return

    instance = cfg["general"].get("instance_name", "HoneypotNet")
    geo = geo or {}
    country = geo.get("country", "N/A")
    city = geo.get("city", "N/A")

    subject = f"[{instance}] 🚨 {service.upper()} alert from {src_ip}"
    body = (
        f"Instance : {instance}\n"
        f"Service  : {service}\n"
        f"Action   : {action}\n"
        f"Source IP: {src_ip}\n"
        f"Location : {city}, {country}\n"
        f"Abuse    : {abuse_score}/100\n"
        f"Details  : {details}\n"
    )

    telegram_text = (
        f"🚨 *{instance}*\n"
        f"*Service:* `{service}`\n"
        f"*Action:* `{action}`\n"
        f"*IP:* `{src_ip}`\n"
        f"*Loc:* {city}, {country}\n"
        f"*Abuse:* {abuse_score}/100\n"
        f"_{details}_"
    )

    # Fire-and-forget in background threads so honeypots don't block
    threading.Thread(target=_send_email, args=(subject, body), daemon=True).start()
    threading.Thread(target=_send_telegram, args=(telegram_text,), daemon=True).start()
