"""
services/ssh_service.py
───────────────────────
Paramiko-based SSH Decoy Service.
Provides an interactive in-memory pseudo-shell, credential harvester,
command execution classifier, and full session keystroke recorder.
"""

import asyncio
import datetime
import json
import logging
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

import paramiko

from core.classifier import classify_payload
from core.config import settings
from core.database import close_session, log_attack, start_session

logger = logging.getLogger("honeypot.ssh")

# Shared RSA Host Key
_HOST_KEY: Optional[paramiko.RSAKey] = None
_RUNNING = True
_SERVER_SOCK: Optional[socket.socket] = None


def get_or_generate_host_key() -> paramiko.RSAKey:
    """Load existing RSA host key or generate a fresh 2048-bit key."""
    global _HOST_KEY
    if _HOST_KEY is not None:
        return _HOST_KEY

    key_dir = Path(settings.DB_PATH).parent
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / "ssh_host_rsa"

    if key_path.exists():
        try:
            _HOST_KEY = paramiko.RSAKey.from_private_key_file(str(key_path))
            logger.info("Loaded SSH host key from %s", key_path)
            return _HOST_KEY
        except Exception as exc:
            logger.warning("Failed loading host key (%s). Generating new key.", exc)

    logger.info("Generating fresh 2048-bit RSA SSH host key...")
    _HOST_KEY = paramiko.RSAKey.generate(2048)
    _HOST_KEY.write_private_key_file(str(key_path))
    return _HOST_KEY


class SSHHoneypotInterface(paramiko.ServerInterface):
    """Paramiko ServerInterface implementation designed to lure attackers."""

    def __init__(self, client_ip: str, loop: asyncio.AbstractEventLoop):
        self.client_ip = client_ip
        self.loop = loop
        self.authenticated = False
        self.credentials: List[str] = []

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        cred_str = f"{username}:{password}"
        self.credentials.append(cred_str)
        logger.warning("[SSH] Auth attempt from %s -> %s", self.client_ip, cred_str)

        # Log brute-force credential attempt to database
        mitre_tags = classify_payload(f"USER {username} PASS {password}", is_auth=True)
        asyncio.run_coroutine_threadsafe(
            log_attack(
                source_ip=self.client_ip,
                service="SSH",
                payload=f"AUTH: user='{username}' pass='{password}'",
                credentials=cred_str,
                mitre_tags=mitre_tags
            ),
            self.loop
        )
        self.authenticated = True
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        return True

    def get_allowed_auths(self, username: str) -> str:
        return "password"


def _handle_mock_command(command: str) -> str:
    """
    Emulate high-fidelity Linux command output for attacker reconnaissance commands.
    """
    cmd = command.strip()
    cmd_lower = cmd.lower()
    parts = cmd.split()
    base_cmd = parts[0].lower() if parts else ""

    if not cmd:
        return ""

    if base_cmd == "uname":
        return "Linux ubuntu-server-01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"

    if base_cmd == "whoami":
        return "root\r\n"

    if base_cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\r\n"

    if base_cmd == "pwd":
        return "/root\r\n"

    if base_cmd == "hostname":
        return "ubuntu-server-01\r\n"

    if base_cmd == "ls":
        return "bin   dev  home  lib64       media  opt   root  sbin  sys  usr\r\nboot  etc  lib   lost+found  mnt    proc  run   srv   tmp  var\r\n"

    if base_cmd == "cat":
        arg = " ".join(parts[1:]).strip() if len(parts) > 1 else ""
        if "passwd" in arg:
            return (
                "root:x:0:0:root:/root:/bin/bash\r\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
                "sync:x:4:65534:sync:/bin:/bin/sync\r\n"
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin\r\n"
                "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\r\n"
                "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\r\n"
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\r\n"
                "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\r\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
                "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\r\n"
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
                "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\r\n"
                "sshd:x:103:65534::/run/sshd:/usr/sbin/nologin\r\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\r\n"
            )
        if "shadow" in arg:
            return "cat: /etc/shadow: Permission denied\r\n"
        if "release" in arg or "version" in arg:
            return (
                "DISTRIB_ID=Ubuntu\r\n"
                "DISTRIB_RELEASE=22.04\r\n"
                "DISTRIB_CODENAME=jammy\r\n"
                "DISTRIB_DESCRIPTION=\"Ubuntu 22.04.3 LTS\"\r\n"
                "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\r\n"
            )
        return f"cat: {arg}: No such file or directory\r\n"

    if base_cmd in ("wget", "curl"):
        url = parts[1] if len(parts) > 1 else "http://example.com"
        return (
            f"Connecting to {url}... connected.\r\n"
            "HTTP request sent, awaiting response... 200 OK\r\n"
            "Length: 24892 (24K) [application/octet-stream]\r\n"
            "Saving to: 'payload.sh'\r\n"
            "payload.sh          100%[===================>]  24.31K  --.-KB/s    in 0.01s\r\n"
            "2026-11-05 12:00:00 (2.41 MB/s) - 'payload.sh' saved [24892/24892]\r\n"
        )

    if base_cmd in ("ifconfig", "ip"):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 192.168.1.105  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
            "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\r\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
        )

    if base_cmd == "ps":
        return (
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
            "root           1  0.0  0.1 168924 11200 ?        Ss   08:00   0:01 /sbin/init\r\n"
            "root         701  0.0  0.0  14210  3120 ?        Ss   08:00   0:00 /usr/sbin/cron -f\r\n"
            "root         745  0.0  0.1  16824  8920 ?        Ss   08:00   0:00 /usr/sbin/sshd -D\r\n"
            "root        1120  0.0  0.1  18920  9450 ?        Ss   10:14   0:00 sshd: root@pts/0\r\n"
            "root        1145  0.0  0.0  12480  4900 pts/0    Ss   10:14   0:00 -bash\r\n"
        )

    if base_cmd in ("lscpu", "df", "free", "uptime", "netstat", "arp", "w", "last"):
        return f"Linux subsystem output for {base_cmd} (ok).\r\n"

    return f"bash: {base_cmd}: command not found\r\n"


def _handle_ssh_client_thread(client_sock: socket.socket, addr: tuple, loop: asyncio.AbstractEventLoop) -> None:
    """Thread worker handling SSH transport, authentication, and interactive terminal."""
    client_ip = addr[0]
    session_id = uuid.uuid4().hex[:12]
    recording_file = f"ssh_{session_id}.json"
    recording_path = os.path.join(settings.RECORDINGS_DIR, recording_file)
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    events: List[Dict[str, Any]] = []
    transport: Optional[paramiko.Transport] = None
    channel: Optional[paramiko.Channel] = None

    try:
        transport = paramiko.Transport(client_sock)
        host_key = get_or_generate_host_key()
        transport.add_server_key(host_key)

        server_interface = SSHHoneypotInterface(client_ip, loop)
        transport.start_server(server=server_interface)

        channel = transport.accept(20)
        if channel is None:
            return

        # Register session in database
        asyncio.run_coroutine_threadsafe(
            start_session(session_id, client_ip, "SSH", recording_file),
            loop
        )

        banner = (
            "\r\n"
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n"
            "\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n"
            "\r\n"
            "Last login: Thu Nov  5 10:14:22 2026 from 192.168.1.1\r\n"
        )
        channel.send(banner.encode("utf-8"))
        prompt = b"root@ubuntu-server-01:~# "
        channel.send(prompt)

        events.append({"timestamp": time.time(), "type": "stdout", "data": banner + "root@ubuntu-server-01:~# "})

        cmd_buffer: List[str] = []

        while _RUNNING and not channel.closed:
            data = channel.recv(1024)
            if not data:
                break

            events.append({"timestamp": time.time(), "type": "stdin", "data": data.decode("latin1", "ignore")})

            for byte in data:
                char = chr(byte)

                # Carriage return or newline: execute buffer
                if char in ("\r", "\n"):
                    channel.send(b"\r\n")
                    raw_cmd = "".join(cmd_buffer).strip()
                    cmd_buffer = []

                    if raw_cmd:
                        # Classify and log command to database
                        tags = classify_payload(raw_cmd)
                        asyncio.run_coroutine_threadsafe(
                            log_attack(
                                source_ip=client_ip,
                                service="SSH",
                                payload=raw_cmd,
                                mitre_tags=tags
                            ),
                            loop
                        )

                        if raw_cmd.lower() in ("exit", "logout", "quit"):
                            channel.send(b"logout\r\n")
                            return

                        output = _handle_mock_command(raw_cmd)
                        channel.send(output.encode("utf-8"))
                        events.append({"timestamp": time.time(), "type": "stdout", "data": output})

                    channel.send(prompt)
                    events.append({"timestamp": time.time(), "type": "stdout", "data": prompt.decode("utf-8")})

                # Backspace
                elif byte in (8, 127):
                    if cmd_buffer:
                        cmd_buffer.pop()
                        channel.send(b"\b \b")

                # Ctrl+C
                elif byte == 3:
                    cmd_buffer = []
                    channel.send(b"^C\r\n" + prompt)

                # Ctrl+D
                elif byte == 4:
                    if not cmd_buffer:
                        return

                # Normal printable characters
                elif 32 <= byte <= 126:
                    cmd_buffer.append(char)
                    channel.send(char.encode("utf-8"))

    except Exception as exc:
        logger.debug("[SSH] Connection exception with %s: %s", client_ip, exc)
    finally:
        ended_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # Save keystroke recording JSON
        try:
            with open(recording_path, "w", encoding="utf-8") as f:
                json.dump({
                    "session_id": session_id,
                    "source_ip": client_ip,
                    "service": "SSH",
                    "started_at": started_at,
                    "ended_at": ended_at,
                    "events": events
                }, f, indent=2)
        except Exception as exc:
            logger.error("[SSH] Error saving session recording: %s", exc)

        asyncio.run_coroutine_threadsafe(close_session(session_id), loop)

        if channel:
            try:
                channel.close()
            except Exception:
                pass
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


async def start_ssh_service(host: str = "0.0.0.0", port: int = 2222) -> None:
    """
    Start non-blocking asynchronous SSH Decoy socket listener.
    Isolates per-connection transport execution inside dedicated threads.
    """
    global _RUNNING, _SERVER_SOCK
    _RUNNING = True
    loop = asyncio.get_running_loop()

    _SERVER_SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _SERVER_SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _SERVER_SOCK.setblocking(False)
    _SERVER_SOCK.bind((host, port))
    _SERVER_SOCK.listen(128)

    logger.info("SSH Honeypot listening on %s:%d", host, port)

    while _RUNNING:
        try:
            client_sock, addr = await loop.sock_accept(_SERVER_SOCK)
            # Dispatch client handling to worker thread so async loop is never blocked
            t = threading.Thread(
                target=_handle_ssh_client_thread,
                args=(client_sock, addr, loop),
                daemon=True,
                name=f"ssh-worker-{addr[0]}"
            )
            t.start()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            if not _RUNNING:
                break
            logger.debug("[SSH] Accept loop exception: %s", exc)
            await asyncio.sleep(0.1)


def stop_ssh_service() -> None:
    """Gracefully terminate SSH listener."""
    global _RUNNING, _SERVER_SOCK
    _RUNNING = False
    if _SERVER_SOCK:
        try:
            _SERVER_SOCK.close()
        except Exception:
            pass

