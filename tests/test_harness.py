"""
tests/test_harness.py
─────────────────────
Automated Multi-Protocol Intrusion Simulator & Verification Suite.
Exercises SSH (2222), HTTP (8080), FTP (2121), Telnet (2323),
and verifies threat intelligence ingestion via REST & STIX 2.1 APIs (9090).
"""

import asyncio
import os
import socket
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import time
from typing import Dict, Any
import paramiko
import pytest
import requests
import uvicorn
import threading

from core.config import settings

TARGET_HOST = "127.0.0.1"


@pytest.fixture(scope="session", autouse=True)
def ensure_honeypot_running():
    """Ensure the honeypot background grid is operational for test execution."""
    server_running = False
    try:
        r = requests.get(f"http://{TARGET_HOST}:{settings.API_PORT}/api/v1/health", timeout=1.0)
        if r.status_code == 200:
            server_running = True
    except Exception:
        server_running = False

    if not server_running:
        from api.server import app
        config = uvicorn.Config(app, host=TARGET_HOST, port=settings.API_PORT, log_level="warning")
        server = uvicorn.Server(config)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        for _ in range(25):
            time.sleep(0.4)
            try:
                r = requests.get(f"http://{TARGET_HOST}:{settings.API_PORT}/api/v1/health", timeout=1.0)
                if r.status_code == 200:
                    break
            except Exception:
                pass
    yield


def test_http_decoy() -> bool:
    """Simulate web attack vectors: credential leak, admin brute-force, and scanner probe."""
    print("\n[+] Testing HTTP Decoy on port", settings.HTTP_PORT)
    base_url = f"http://{TARGET_HOST}:{settings.HTTP_PORT}"

    # 1. Test .env credential harvester lure
    resp_env = requests.get(f"{base_url}/.env", timeout=5)
    assert resp_env.status_code == 200, f"Expected 200 for /.env, got {resp_env.status_code}"
    assert "DB_PASSWORD=" in resp_env.text, "Fake credentials missing from /.env"
    print("    [✓] /.env leak lure verified (captured DB_PASSWORD)")

    # 2. Test admin login portal brute force
    resp_login = requests.post(
        f"{base_url}/wp-login.php",
        data={"log": "admin_root", "pwd": "MaliciousPassword2026!"},
        timeout=5
    )
    assert resp_login.status_code == 401, f"Expected 401 for bad auth, got {resp_login.status_code}"
    print("    [✓] /wp-login.php brute force credential interception verified")

    # 3. Test Spring Actuator discovery
    resp_actuator = requests.get(f"{base_url}/actuator/health", timeout=5)
    assert resp_actuator.status_code == 200, "Actuator health endpoint failed"
    assert resp_actuator.json().get("status") == "UP"
    print("    [✓] /actuator/health Spring Boot decoy verified")

    # 4. Test Scanner detection / Gzip Defense trigger
    resp_scan = requests.get(
        f"{base_url}/../../etc/passwd",
        headers={"User-Agent": "sqlmap/1.6.12#stable"},
        timeout=10
    )
    assert resp_scan.status_code == 200, "Active defense probe failed"
    assert len(resp_scan.content) == 10_000_000, f"Expected 10MB decompressed bomb, got {len(resp_scan.content)}"
    print("    [✓] Active Defense Gzip Bomb triggered on path traversal/scanner probe (10MB payload safely expanded)")


def test_ftp_decoy() -> None:
    """Connect to FTP port 2121, verify banner, and attempt authentication."""
    print("\n[+] Testing FTP Decoy on port", settings.FTP_PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)

    try:
        s.connect((TARGET_HOST, settings.FTP_PORT))
        banner = s.recv(1024).decode("utf-8", "ignore")
        assert "220 ProFTPD" in banner, f"Unexpected FTP banner: {banner}"
        print("    [✓] ProFTPD banner verified:", banner.strip())

        # Send USER
        s.sendall(b"USER superadmin\r\n")
        resp_user = s.recv(1024).decode("utf-8", "ignore")
        assert "331" in resp_user, f"Expected 331, got: {resp_user}"

        # Send PASS
        s.sendall(b"PASS P@ssword123\r\n")
        resp_pass = s.recv(1024).decode("utf-8", "ignore")
        assert "530" in resp_pass, f"Expected 530 Login incorrect, got: {resp_pass}"
        print("    [✓] FTP credential harvesting verified (superadmin:P@ssword123 rejected with 530)")
    finally:
        s.close()


def test_telnet_decoy() -> None:
    """Connect to Telnet port 2323 and simulate Mirai IoT botnet brute-force combo."""
    print("\n[+] Testing Telnet Decoy on port", settings.TELNET_PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)

    try:
        s.connect((TARGET_HOST, settings.TELNET_PORT))
        # Read until login prompt arrives
        banner = ""
        for _ in range(5):
            chunk = s.recv(1024).decode("utf-8", "ignore")
            banner += chunk
            if "login:" in banner.lower() or "ubuntu" in banner.lower():
                break
            time.sleep(0.1)

        assert "login:" in banner.lower() or "ubuntu" in banner.lower(), f"Unexpected banner: {banner}"
        print("    [✓] Telnet login prompt verified")

        # Send Mirai default username
        s.sendall(b"root\r\n")
        time.sleep(0.2)

        # Receive password prompt
        prompt = ""
        for _ in range(5):
            chunk = s.recv(1024).decode("utf-8", "ignore")
            prompt += chunk
            if "password" in prompt.lower():
                break
            time.sleep(0.1)

        assert "password" in prompt.lower(), f"Expected Password prompt, got: {prompt}"

        # Send Mirai default password
        s.sendall(b"xc3511\r\n")
        time.sleep(0.2)

        # Receive rejection
        resp = ""
        for _ in range(5):
            chunk = s.recv(1024).decode("utf-8", "ignore")
            resp += chunk
            if "incorrect" in resp.lower() or "login:" in resp.lower():
                break
            time.sleep(0.1)

        assert "incorrect" in resp.lower() or "login:" in resp.lower()
        print("    [✓] Telnet Mirai botnet combo harvested (root:xc3511)")
    finally:
        s.close()


def test_ssh_decoy() -> None:
    """Connect to SSH decoy on port 2222, execute Linux reconnaissance commands, and exit."""
    print("\n[+] Testing SSH Decoy on port", settings.SSH_PORT)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=TARGET_HOST,
            port=settings.SSH_PORT,
            username="root",
            password="toor_password_2026",
            timeout=5.0,
            allow_agent=False,
            look_for_keys=False
        )
        print("    [✓] SSH Authentication accepted (lure successful)")

        channel = client.invoke_shell()
        time.sleep(0.5)
        # Read welcome banner
        banner = channel.recv(2048).decode("utf-8", "ignore")
        assert "Ubuntu" in banner, f"Missing Ubuntu banner: {banner}"
        print("    [✓] Interactive shell prompt received")

        # Send whoami
        channel.send("whoami\r\n")
        time.sleep(0.4)
        out_whoami = channel.recv(1024).decode("utf-8", "ignore")
        assert "root" in out_whoami, f"Unexpected whoami output: {out_whoami}"
        print("    [✓] Executed 'whoami' -> received 'root'")

        # Send uname -a
        channel.send("uname -a\r\n")
        time.sleep(0.4)
        out_uname = channel.recv(1024).decode("utf-8", "ignore")
        assert "Linux ubuntu-server-01" in out_uname, f"Unexpected uname output: {out_uname}"
        print("    [✓] Executed 'uname -a' -> simulated Linux kernel info returned")

        # Send cat /etc/passwd
        channel.send("cat /etc/passwd\r\n")
        time.sleep(0.4)
        out_passwd = channel.recv(2048).decode("utf-8", "ignore")
        assert "www-data" in out_passwd, "Missing passwd content"
        print("    [✓] Executed 'cat /etc/passwd' -> simulated account discovery output returned")

        # Clean exit
        channel.send("exit\r\n")
        time.sleep(0.2)
        channel.close()
        client.close()
    except Exception as exc:
        print("    [✗] SSH Test failed:", exc)
        client.close()
        raise exc


def test_api_and_feeds() -> None:
    """Verify that all intrusions were classified and ingested into stats and threat feeds."""
    print("\n[+] Testing Telemetry API and Threat Intelligence Feeds on port", settings.API_PORT)
    api_base = f"http://{TARGET_HOST}:{settings.API_PORT}"

    # Wait briefly for database commits
    time.sleep(1.0)

    # 1. Check System Stats
    res_stats = requests.get(f"{api_base}/api/v1/stats", timeout=5)
    assert res_stats.status_code == 200, f"Stats failed: {res_stats.status_code}"
    stats = res_stats.json()
    assert stats["total_attacks"] >= 4, f"Expected at least 4 attacks logged, got {stats['total_attacks']}"
    assert "SSH" in stats["attacks_per_service"], "SSH attacks not reflected in per-service stats"
    assert "HTTP" in stats["attacks_per_service"], "HTTP attacks not reflected in per-service stats"
    assert "FTP" in stats["attacks_per_service"], "FTP attacks not reflected in per-service stats"
    assert "TELNET" in stats["attacks_per_service"], "TELNET attacks not reflected in per-service stats"
    print(f"    [✓] Aggregate statistics validated ({stats['total_attacks']} total intrusions recorded)")

    # 2. Check Recent Attacks Endpoint
    res_recent = requests.get(f"{api_base}/api/v1/attacks/recent?limit=20", timeout=5)
    assert res_recent.status_code == 200
    attacks = res_recent.json()
    assert len(attacks) > 0, "No attacks returned by /recent"

    # Verify MITRE classification mapping
    mitre_ids = [a.get("mitre_technique_id") for a in attacks if a.get("mitre_technique_id")]
    assert any(m in mitre_ids for m in ("T1110", "T1087", "T1082", "T1190")), f"MITRE classification missing: {mitre_ids}"
    print(f"    [✓] MITRE ATT&CK technique classifications confirmed: {set(mitre_ids)}")

    # 3. Check CIDR Plain-text Firewall Blocklist
    res_fw = requests.get(f"{api_base}/api/v1/feed/firewall.txt", timeout=5)
    assert res_fw.status_code == 200
    assert "Honeypot-System v2.0" in res_fw.text
    print("    [✓] Firewall CIDR Feed (/api/v1/feed/firewall.txt) active and formatted")

    # 4. Check OASIS STIX 2.1 Threat Intel Bundle
    res_stix = requests.get(f"{api_base}/api/v1/feed/stix.json", timeout=5)
    assert res_stix.status_code == 200
    stix_data = res_stix.json()
    assert stix_data.get("type") == "bundle"
    assert "objects" in stix_data
    print("    [✓] STIX 2.1 Threat Intel Bundle (/api/v1/feed/stix.json) compliant")

    # 5. Check Session Replay Endpoint
    recordings = list(Path(settings.RECORDINGS_DIR).glob("*.json"))
    if recordings:
        sample_file = recordings[0].stem
        session_id = sample_file.replace("ssh_", "")
        res_replay = requests.get(f"{api_base}/api/v1/session/{session_id}/replay", timeout=5)
        assert res_replay.status_code == 200
        replay_data = res_replay.json()
        assert "events" in replay_data
        print(f"    [✓] Session Replay API (/api/v1/session/{session_id}/replay) verified ({len(replay_data['events'])} events)")


def run_full_suite():
    """Run all test vectors sequentially and output results banner."""
    print("=" * 72)
    print("  HONEYPOT-SYSTEM v2.0 - INTEGRATED ATTACK SIMULATION SUITE")
    print("=" * 72)

    passed = 0
    total = 5

    tests = [
        ("HTTP Decoy", test_http_decoy),
        ("FTP Decoy", test_ftp_decoy),
        ("Telnet Decoy", test_telnet_decoy),
        ("SSH Decoy", test_ssh_decoy),
        ("API & Threat Intel Feeds", test_api_and_feeds),
    ]

    for name, test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"    [✗] {name} encountered an error: {e}")

    print("\n" + "=" * 72)
    print(f"  TEST RESULTS: {passed}/{total} Test Vectors Passed Successfully.")
    print("=" * 72)

    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    # Check if honeypot server is already running, else start it in background thread
    server_running = False
    try:
        r = requests.get(f"http://{TARGET_HOST}:{settings.API_PORT}/api/v1/health", timeout=1.0)
        if r.status_code == 200:
            server_running = True
    except Exception:
        server_running = False

    server_thread = None
    if not server_running:
        print("[*] Honeypot server not detected. Launching in background thread for testing...")
        from api.server import app
        
        config = uvicorn.Config(app, host=TARGET_HOST, port=settings.API_PORT, log_level="warning")
        server = uvicorn.Server(config)
        
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        
        # Wait for startup
        for _ in range(15):
            time.sleep(0.5)
            try:
                r = requests.get(f"http://{TARGET_HOST}:{settings.API_PORT}/api/v1/health", timeout=1.0)
                if r.status_code == 200:
                    print("[*] Background Honeypot server is online and healthy.")
                    break
            except Exception:
                pass

    run_full_suite()
