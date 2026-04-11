"""
main.py
───────
Single-process launcher that starts all enabled honeypots
and the admin panel as threads.

Usage:  python main.py
"""

import threading
import logging

from core.config_loader import cfg
from core.logger import init_db, setup_file_logging

_log = logging.getLogger("honeypotnet")


def main() -> None:
    """Initialise the DB, start all enabled services."""
    init_db()
    setup_file_logging()
    _log.info("=== HoneypotNet starting ===")

    services_cfg = cfg.get("services", {})
    threads: list[threading.Thread] = []

    # ── SSH ──
    if services_cfg.get("ssh", {}).get("enabled"):
        from honeypots.ssh_honeypot import start as ssh_start
        t = threading.Thread(target=ssh_start, name="ssh-honeypot", daemon=True)
        threads.append(t)

    # ── HTTP ──
    if services_cfg.get("http", {}).get("enabled"):
        from honeypots.http_honeypot import start as http_start
        t = threading.Thread(target=http_start, name="http-honeypot", daemon=True)
        threads.append(t)

    # ── FTP ──
    if services_cfg.get("ftp", {}).get("enabled"):
        from honeypots.ftp_honeypot import start as ftp_start
        t = threading.Thread(target=ftp_start, name="ftp-honeypot", daemon=True)
        threads.append(t)

    # ── Telnet ──
    if services_cfg.get("telnet", {}).get("enabled"):
        from honeypots.telnet_honeypot import start as telnet_start
        t = threading.Thread(target=telnet_start, name="telnet-honeypot", daemon=True)
        threads.append(t)

    # ── Admin dashboard ──
    from admin.app import start as admin_start
    t = threading.Thread(target=admin_start, name="admin-panel", daemon=True)
    threads.append(t)

    for t in threads:
        _log.info("Starting %s …", t.name)
        t.start()

    _log.info("All services launched. Press Ctrl+C to stop.")

    # Block the main thread until interrupt
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        _log.info("Shutting down …")


if __name__ == "__main__":
    main()
