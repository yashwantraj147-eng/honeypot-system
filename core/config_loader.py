"""
core/config_loader.py
─────────────────────
Loads config.yaml (or config.example.yaml fallback) and exposes it as module-level dict.
Supports environment variable overrides for sensitive credentials:
  • HONEYPOT_ADMIN_USERNAME
  • HONEYPOT_ADMIN_PASSWORD
  • HONEYPOT_SECRET_KEY
  • ABUSEIPDB_API_KEY
  • TELEGRAM_BOT_TOKEN
  • TELEGRAM_CHAT_ID
"""

import os
import secrets
import logging
import yaml

_log = logging.getLogger("honeypotnet.config")

_BASE_DIR = os.path.dirname(os.path.dirname(__file__))
_PRIMARY_PATH = os.path.join(_BASE_DIR, "config.yaml")
_FALLBACK_PATH = os.path.join(_BASE_DIR, "config.example.yaml")

_CONFIG_PATH = os.environ.get("HONEYPOT_CONFIG")
if not _CONFIG_PATH:
    _CONFIG_PATH = _PRIMARY_PATH if os.path.exists(_PRIMARY_PATH) else _FALLBACK_PATH


def _load() -> dict:
    """Read and parse YAML config with environment variable overrides."""
    if os.path.exists(_CONFIG_PATH):
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    else:
        data = {}

    # Defaults structure
    data.setdefault("general", {})
    data.setdefault("admin", {})
    data.setdefault("threat_intel", {})
    data.setdefault("alerting", {})

    # Environment variable overrides
    if "HONEYPOT_ADMIN_USERNAME" in os.environ:
        data["admin"]["username"] = os.environ["HONEYPOT_ADMIN_USERNAME"]
    if "HONEYPOT_ADMIN_PASSWORD" in os.environ:
        data["admin"]["password"] = os.environ["HONEYPOT_ADMIN_PASSWORD"]

    # Secure fallback for secret key
    if not data["admin"].get("secret_key"):
        env_secret = os.environ.get("HONEYPOT_SECRET_KEY")
        data["admin"]["secret_key"] = env_secret or secrets.token_hex(32)

    # Secure fallback for admin password if completely unset
    if not data["admin"].get("password"):
        generated_pw = secrets.token_urlsafe(12)
        data["admin"]["password"] = generated_pw
        _log.warning(
            "[SECURITY NOTICE] No admin password configured. Generated one-time password: %s",
            generated_pw
        )

    # Threat intel & alert overrides
    if "ABUSEIPDB_API_KEY" in os.environ:
        data["threat_intel"]["abuseipdb_api_key"] = os.environ["ABUSEIPDB_API_KEY"]
        data["threat_intel"]["enabled"] = True

    telegram = data["alerting"].setdefault("telegram", {})
    if "TELEGRAM_BOT_TOKEN" in os.environ:
        telegram["bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"]
        telegram["enabled"] = True
    if "TELEGRAM_CHAT_ID" in os.environ:
        telegram["chat_id"] = os.environ["TELEGRAM_CHAT_ID"]

    return data


# Singleton config dict — imported everywhere as `from core.config_loader import cfg`
cfg = _load()
