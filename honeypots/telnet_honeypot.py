"""
honeypots/telnet_honeypot.py
────────────────────────────
Low-interaction Telnet honeypot that:
  • Presents a realistic Linux login prompt
  • Logs username / password pairs
  • Provides a fake shell with believable responses
  • Records every keystroke / command

Uses raw sockets — no external Telnet library required.
"""

import logging
import socket
import threading

from core.config_loader import cfg
from core.enrichment import process_event
from core.rate_limiter import allow as rate_ok
from core.logger import init_db, setup_file_logging

_log = logging.getLogger("honeypotnet.telnet")
_tel_cfg = cfg["services"]["telnet"]
_HOSTNAME = _tel_cfg.get("hostname", "gateway-srv01")
_BANNER = _tel_cfg.get("banner", "Ubuntu 22.04 LTS")


def _recv_line(sock: socket.socket, echo: bool = True, mask: bool = False) -> str:
    """
    Read bytes until CR or LF, optionally echoing back.
    If *mask* is True, echo asterisks instead of the real chars (for passwords).
    """
    buf = b""
    while True:
        try:
            ch = sock.recv(1)
        except Exception:
            return ""
        if not ch:
            return ""
        if ch in (b"\r", b"\n"):
            if echo:
                sock.sendall(b"\r\n")
            break
        buf += ch
        if echo:
            sock.sendall(b"*" if mask else ch)
    return buf.decode(errors="replace").strip()


def _handle_client(client_sock: socket.socket, addr: tuple) -> None:
    """Simulate a Telnet login + shell session."""
    client_ip = addr[0]
    _log.info("Telnet connection from %s:%d", *addr)

    try:
        # Suppress Telnet option negotiation bytes that many clients send.
        # We simply ignore them; real Telnet servers do complex negotiation
        # but attackers' automated scripts usually don't care.
        client_sock.settimeout(120)

        # Banner
        client_sock.sendall(f"\r\n{_BANNER}\r\n".encode())
        client_sock.sendall(f"{_HOSTNAME} login: ".encode())
        username = _recv_line(client_sock, echo=True)

        client_sock.sendall(b"Password: ")
        password = _recv_line(client_sock, echo=True, mask=True)

        # Log the credential pair
        process_event(
            src_ip=client_ip,
            service="telnet",
            action="login_attempt",
            payload={"username": username, "password": password},
            details=f"Telnet creds: {username}/{password}",
        )

        if not username:
            client_sock.close()
            return

        # "Accept" the login
        client_sock.sendall(
            f"\r\nWelcome to {_BANNER}\r\n"
            f"Last login: Mon Jan  5 09:14:22 2025 from 10.0.2.2\r\n\r\n".encode()
        )

        # Interactive shell loop
        prompt = f"{username}@{_HOSTNAME}:~$ "
        client_sock.sendall(prompt.encode())

        while True:
            cmd = _recv_line(client_sock, echo=True)
            if not cmd:
                break

            process_event(
                src_ip=client_ip,
                service="telnet",
                action="command",
                payload={"username": username, "command": cmd},
                details=f"Telnet cmd: {cmd}",
            )

            response = _fake_response(cmd, username)
            if response is None:
                # "exit" → gracefully close
                client_sock.sendall(b"logout\r\n")
                break

            client_sock.sendall(f"{response}\r\n".encode())
            client_sock.sendall(prompt.encode())

    except socket.timeout:
        _log.debug("Telnet timeout from %s", client_ip)
    except Exception as exc:
        _log.debug("Telnet connection closed for %s: %s", client_ip, exc)
    finally:
        client_sock.close()


def _fake_response(cmd: str, username: str) -> str | None:
    """
    Return a plausible response string.
    Returns None to signal the session should end.
    """
    cmd_lower = cmd.lower().strip()
    first = cmd_lower.split()[0] if cmd_lower.split() else ""

    if first in ("exit", "logout", "quit"):
        return None

    table = {
        "id": f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)",
        "whoami": username,
        "hostname": _HOSTNAME,
        "uname": "Linux",
        "uname -a": f"Linux {_HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "pwd": f"/home/{username}",
        "ls": "Desktop  Documents  Downloads  .bash_history  .profile",
        "ls -la": (
            "total 28\n"
            f"drwxr-xr-x  4 {username} {username} 4096 Jan  5 09:14 .\n"
            "drwxr-xr-x  3 root  root  4096 Dec 20 11:30 ..\n"
            f"-rw-------  1 {username} {username}  180 Jan  5 09:14 .bash_history\n"
            f"-rw-r--r--  1 {username} {username}  807 Dec 20 11:30 .profile\n"
            f"drwxr-xr-x  2 {username} {username} 4096 Jan  5 09:14 Desktop\n"
            f"drwxr-xr-x  2 {username} {username} 4096 Jan  5 09:14 Documents"
        ),
        "cat /etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            f"{username}:x:1000:1000:{username}:/home/{username}:/bin/bash"
        ),
        "ifconfig": (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255"
        ),
        "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
        "uptime": " 09:14:22 up 14 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01",
        "df -h": (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        40G   12G   26G  32% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm"
        ),
        "ps aux": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 169316 11800 ?        Ss   Jan05   0:03 /sbin/init\n"
            f"{username}  1234  0.0  0.0   8532  4004 pts/0    Ss   09:14   0:00 -bash"
        ),
        "w": (
            " 09:14:22 up 14 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\n"
            f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{username} pts/0    10.0.2.2         09:14    0.00s  0.01s  0.00s w"
        ),
        "help": "GNU bash, version 5.1.16(1)-release. Type 'help' for more info.",
    }

    for key, val in table.items():
        if cmd_lower == key:
            return val

    return f"-bash: {first}: command not found"


# ────────────────────────────────────────────────────────────
#  Main listener
# ────────────────────────────────────────────────────────────

def start() -> None:
    """Bind the Telnet honeypot socket and accept connections."""
    init_db()
    setup_file_logging()

    host = _tel_cfg["host"]
    port = _tel_cfg["port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    _log.info("Telnet honeypot listening on %s:%d", host, port)

    while True:
        client_sock, addr = sock.accept()
        if not rate_ok(addr[0]):
            _log.warning("Rate-limited Telnet from %s", addr[0])
            client_sock.close()
            continue
        t = threading.Thread(
            target=_handle_client,
            args=(client_sock, addr),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    start()
