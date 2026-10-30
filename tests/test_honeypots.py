"""
tests/test_honeypots.py
───────────────────────
Unit and integration tests for the HoneypotNet system.

Run:  pytest tests/ -v
"""

import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

# ────────────────────────────────────────────────────────────
#  Patch the config before any honeypot module is imported.
#  This avoids filesystem side-effects and port collisions.
# ────────────────────────────────────────────────────────────

_tmp = tempfile.mkdtemp()
_test_db = os.path.join(_tmp, "test_honeypot.db")

_TEST_CONFIG = {
    "general": {
        "instance_name": "TestNet",
        "database_path": _test_db,
        "log_level": "DEBUG",
        "log_dir": os.path.join(_tmp, "logs"),
    },
    "services": {
        "ssh": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 22220,
            "host_key_file": os.path.join(_tmp, "test_ssh_key"),
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-Test",
            "max_auth_attempts": 3,
        },
        "http": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 18080,
            "server_banner": "Apache/2.4.54 (Test)",
        },
        "ftp": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 22121,
            "banner": "220 ProFTPD Test",
            "max_auth_attempts": 3,
        },
        "telnet": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 23230,
            "banner": "TestOS 1.0",
            "hostname": "test-host",
        },
    },
    "admin": {
        "host": "127.0.0.1",
        "port": 15000,
        "secret_key": "test-secret",
        "username": "admin",
        "password": "testpass",
    },
    "geoip": {"enabled": False},
    "threat_intel": {"enabled": False, "abuseipdb_api_key": ""},
    "alerting": {
        "cooldown_seconds": 0,
        "email": {"enabled": False},
        "telegram": {"enabled": False},
    },
    "rate_limiting": {"enabled": True, "max_connections": 100, "window_seconds": 60},
}

# Patch before imports
import core.config_loader

core.config_loader.cfg = _TEST_CONFIG

def setUpModule():
    from core.logger import init_db
    init_db()

from core.logger import init_db, log_event, query_events, count_events, get_service_stats, setup_file_logging
from core.geoip import lookup as geo_lookup, _is_private
from core.threat_intel import check_ip
from core.rate_limiter import allow as rate_ok
from core.alerting import _check_cooldown


# ════════════════════════════════════════════════════════════
#  Test: Core Logger
# ════════════════════════════════════════════════════════════

class TestLogger(unittest.TestCase):
    """Tests for core/logger.py."""

    @classmethod
    def setUpClass(cls):
        init_db()
        setup_file_logging()

    def test_log_event_inserts_row(self):
        """log_event should return a positive row ID."""
        rid = log_event(
            src_ip="10.0.0.1",
            service="ssh",
            action="login_attempt",
            payload={"username": "root", "password": "toor"},
        )
        self.assertGreater(rid, 0)

    def test_query_returns_logged_event(self):
        """query_events should find the event we just inserted."""
        log_event(
            src_ip="10.0.0.99",
            service="ftp",
            action="test_query",
            payload={"test": True},
        )
        events = query_events(src_ip="10.0.0.99")
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["service"], "ftp")

    def test_count_events(self):
        """count_events should match len(query_events)."""
        log_event(src_ip="10.0.0.50", service="http", action="count_test")
        total = count_events(service="http")
        events = query_events(service="http", limit=100000)
        self.assertEqual(total, len(events))

    def test_service_stats(self):
        """get_service_stats should return counts per service."""
        stats = get_service_stats()
        self.assertIsInstance(stats, dict)
        # We've logged at least one ssh and one ftp event above
        self.assertIn("ssh", stats)

    def test_payload_is_json(self):
        """Payload should be stored as valid JSON."""
        log_event(
            src_ip="10.0.0.2",
            service="telnet",
            action="json_test",
            payload={"key": "value", "nested": {"a": 1}},
        )
        events = query_events(src_ip="10.0.0.2")
        parsed = json.loads(events[0]["payload"])
        self.assertEqual(parsed["key"], "value")
        self.assertEqual(parsed["nested"]["a"], 1)


# ════════════════════════════════════════════════════════════
#  Test: GeoIP
# ════════════════════════════════════════════════════════════

class TestGeoIP(unittest.TestCase):
    """Tests for core/geoip.py."""

    def test_private_ip_detection(self):
        self.assertTrue(_is_private("192.168.1.1"))
        self.assertTrue(_is_private("10.0.0.1"))
        self.assertTrue(_is_private("127.0.0.1"))
        self.assertFalse(_is_private("8.8.8.8"))

    def test_lookup_private_returns_private(self):
        """Private IPs should short-circuit to 'Private'."""
        result = geo_lookup("192.168.1.1")
        self.assertEqual(result["country"], "Private")

    def test_lookup_disabled_returns_none(self):
        """When geoip.enabled=False, country should be None."""
        # Config already has enabled=False
        result = geo_lookup("8.8.8.8")
        # Since disabled, we expect None country
        self.assertIn(result["country"], (None, "Private"))


# ════════════════════════════════════════════════════════════
#  Test: Threat Intel
# ════════════════════════════════════════════════════════════

class TestThreatIntel(unittest.TestCase):
    """Tests for core/threat_intel.py."""

    def test_disabled_returns_defaults(self):
        """When disabled, check_ip should return safe defaults."""
        result = check_ip("1.2.3.4")
        self.assertEqual(result["abuse_score"], -1)
        self.assertFalse(result["is_known_attacker"])


# ════════════════════════════════════════════════════════════
#  Test: Rate Limiter
# ════════════════════════════════════════════════════════════

class TestRateLimiter(unittest.TestCase):
    """Tests for core/rate_limiter.py."""

    def test_allows_under_limit(self):
        """Should allow connections under the limit."""
        # Using a unique IP to avoid interference
        for _ in range(10):
            self.assertTrue(rate_ok("10.99.99.1"))

    def test_blocks_over_limit(self):
        """Should block after exceeding max_connections."""
        ip = "10.99.99.2"
        for _ in range(100):
            rate_ok(ip)
        self.assertFalse(rate_ok(ip))


# ════════════════════════════════════════════════════════════
#  Test: Alerting
# ════════════════════════════════════════════════════════════

class TestAlerting(unittest.TestCase):
    """Tests for core/alerting.py."""

    def test_cooldown_allows_first(self):
        """First alert for a new IP should pass cooldown."""
        # cooldown_seconds=0 so everything passes
        self.assertTrue(_check_cooldown("10.88.88.1"))

    def test_send_alert_does_not_crash(self):
        """send_alert should not raise even with disabled backends."""
        from core.alerting import send_alert
        send_alert(
            src_ip="10.88.88.2",
            service="test",
            action="unit_test",
            details="testing",
        )


# ════════════════════════════════════════════════════════════
#  Test: FTP Honeypot protocol
# ════════════════════════════════════════════════════════════

class TestFTPHoneypot(unittest.TestCase):
    """Integration test — start the FTP honeypot and connect to it."""

    @classmethod
    def setUpClass(cls):
        """Launch the FTP honeypot in a background thread."""
        from honeypots.ftp_honeypot import start as ftp_start
        cls._thread = threading.Thread(target=ftp_start, daemon=True)
        cls._thread.start()
        time.sleep(1)  # Give it a moment to bind

    def test_ftp_banner(self):
        """Should receive the configured FTP banner on connect."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 22121))
        banner = s.recv(1024).decode()
        self.assertIn("220", banner)
        s.sendall(b"QUIT\r\n")
        s.close()

    def test_ftp_login(self):
        """USER + PASS should be accepted and logged."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 22121))
        s.recv(1024)  # banner

        s.sendall(b"USER testuser\r\n")
        resp = s.recv(1024).decode()
        self.assertIn("331", resp)

        s.sendall(b"PASS testpass\r\n")
        resp = s.recv(1024).decode()
        self.assertIn("230", resp)

        s.sendall(b"QUIT\r\n")
        s.close()

        # Verify the event was recorded
        events = query_events(service="ftp", src_ip="127.0.0.1")
        login_events = [e for e in events if e["action"] == "login_attempt"]
        self.assertTrue(len(login_events) >= 1)


# ════════════════════════════════════════════════════════════
#  Test: Telnet Honeypot protocol
# ════════════════════════════════════════════════════════════

class TestTelnetHoneypot(unittest.TestCase):
    """Integration test — start the Telnet honeypot and connect."""

    @classmethod
    def setUpClass(cls):
        from honeypots.telnet_honeypot import start as telnet_start
        cls._thread = threading.Thread(target=telnet_start, daemon=True)
        cls._thread.start()
        time.sleep(1)

    def test_telnet_banner(self):
        """Should receive the configured Telnet banner."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 23230))
        data = s.recv(1024).decode()
        self.assertIn("TestOS", data)
        s.close()


# ════════════════════════════════════════════════════════════
#  Test: HTTP Honeypot
# ════════════════════════════════════════════════════════════

class TestHTTPHoneypot(unittest.TestCase):
    """Integration test — start HTTP honeypot and make requests."""

    @classmethod
    def setUpClass(cls):
        from honeypots.http_honeypot import start as http_start
        cls._thread = threading.Thread(target=http_start, daemon=True)
        cls._thread.start()
        time.sleep(1.5)

    def test_login_page(self):
        """GET /login should return the fake login form."""
        import requests as req
        resp = req.get("http://127.0.0.1:18080/login", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Internal Portal", resp.text)

    def test_login_post(self):
        """POST /login should log the credentials."""
        import requests as req
        resp = req.post(
            "http://127.0.0.1:18080/login",
            data={"username": "admin", "password": "admin123"},
            timeout=5,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Invalid credentials", resp.text)

    def test_admin_page(self):
        """GET /admin should return the fake admin panel."""
        import requests as req
        resp = req.get("http://127.0.0.1:18080/admin", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Admin Dashboard", resp.text)

    def test_robots_txt(self):
        """GET /robots.txt should expose honeypot paths."""
        import requests as req
        resp = req.get("http://127.0.0.1:18080/robots.txt", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("/phpmyadmin", resp.text)

    def test_server_banner(self):
        """The Server header should match the configured banner."""
        import requests as req
        resp = req.get("http://127.0.0.1:18080/login", timeout=5)
        self.assertEqual(resp.headers.get("Server"), "Apache/2.4.54 (Test)")


# ════════════════════════════════════════════════════════════
#  Test: Admin Dashboard
# ════════════════════════════════════════════════════════════

class TestAdminDashboard(unittest.TestCase):
    """Integration test — start admin panel and test auth + pages."""

    @classmethod
    def setUpClass(cls):
        from admin.app import app
        cls.app = app
        cls.client = app.test_client()
        cls.app.config["TESTING"] = True

    def test_login_required(self):
        """Dashboard should redirect to login when unauthenticated."""
        # Use a fresh test client to avoid session leakage from other tests
        with self.app.test_client() as c:
            resp = c.get("/")
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers["Location"])

    def test_login_valid(self):
        """Valid credentials should set session and redirect."""
        resp = self.client.post(
            "/login",
            data={"username": "admin", "password": "testpass"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dashboard", resp.data)

    def test_login_invalid(self):
        """Invalid credentials should show error."""
        resp = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid credentials", resp.data)

    def test_csv_export(self):
        """CSV export should return downloadable file."""
        # Login first
        self.client.post("/login", data={"username": "admin", "password": "testpass"})
        resp = self.client.get("/export/csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        self.assertIn(b"timestamp", resp.data)

    def test_api_stats(self):
        """JSON stats endpoint should return valid JSON."""
        self.client.post("/login", data={"username": "admin", "password": "testpass"})
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIsInstance(data, dict)

    def test_logout(self):
        """Logout should clear session and redirect."""
        self.client.post("/login", data={"username": "admin", "password": "testpass"})
        resp = self.client.get("/logout")
        self.assertEqual(resp.status_code, 302)


if __name__ == "__main__":
    unittest.main()
