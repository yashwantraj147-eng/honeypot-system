"""
honeypots/ssh_honeypot.py
─────────────────────────
Paramiko-based SSH honeypot that logs:
  • Every authentication attempt (username + password)
  • Every shell command issued after "successful" login
  • Client version strings

The server uses a realistic OpenSSH banner (configurable) and
auto-generates an RSA host key on first run.
"""

import logging
import os
import socket
import threading

import paramiko

from core.config_loader import cfg
from core.enrichment import process_event
from core.rate_limiter import allow as rate_ok
from core.logger import init_db, setup_file_logging

_log = logging.getLogger("honeypotnet.ssh")
_ssh_cfg = cfg["services"]["ssh"]


# ────────────────────────────────────────────────────────────
#  Host-key management
# ────────────────────────────────────────────────────────────

def _get_host_key() -> paramiko.RSAKey:
    """Load or generate a 2048-bit RSA host key."""
    path = _ssh_cfg["host_key_file"]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.isfile(path):
        return paramiko.RSAKey.from_private_key_file(path)
    _log.info("Generating new SSH host key → %s", path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


# ────────────────────────────────────────────────────────────
#  Paramiko server interface (defines auth behaviour)
# ────────────────────────────────────────────────────────────

class _HoneypotServerInterface(paramiko.ServerInterface):
    """
    Accept **every** password authentication so the attacker
    believes they have gained access.  Key-based auth is rejected
    to force password usage (more interesting telemetry).
    """

    def __init__(self, client_ip: str) -> None:
        super().__init__()
        self.client_ip = client_ip
        self.username: str = ""

    # Allow password auth flow
    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        # Log the credential pair
        process_event(
            src_ip=self.client_ip,
            service="ssh",
            action="login_attempt",
            payload={"username": username, "password": password},
            details=f"SSH creds: {username}/{password}",
        )
        # Always "succeed" so we can capture post-auth commands
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True


# ────────────────────────────────────────────────────────────
#  Per-connection handler
# ────────────────────────────────────────────────────────────

def _handle_client(client_sock: socket.socket, addr: tuple) -> None:
    """Handle a single SSH client connection."""
    client_ip = addr[0]
    _log.info("SSH connection from %s:%d", *addr)

    transport = paramiko.Transport(client_sock)
    transport.local_version = _ssh_cfg.get("banner", "SSH-2.0-OpenSSH_8.9p1")
    host_key = _get_host_key()
    transport.add_server_key(host_key)

    server = _HoneypotServerInterface(client_ip)
    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        _log.warning("SSH negotiation failed from %s: %s", client_ip, exc)
        transport.close()
        return

    # Wait up to 30 s for the client to authenticate
    chan = transport.accept(30)
    if chan is None:
        _log.info("SSH channel not opened by %s", client_ip)
        transport.close()
        return

    # Send a fake shell prompt and read commands
    chan.send(f"{server.username}@gateway-srv01:~$ ".encode())
    command_buffer = b""
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break
            # Echo keystrokes back (interactive feel)
            chan.send(data)

            command_buffer += data
            # When the attacker presses Enter we have a full command
            if b"\n" in command_buffer or b"\r" in command_buffer:
                cmd = command_buffer.decode(errors="replace").strip()
                if cmd:
                    process_event(
                        src_ip=client_ip,
                        service="ssh",
                        action="command",
                        payload={"username": server.username, "command": cmd},
                        details=f"Cmd: {cmd}",
                    )
                    # Fake responses for common recon commands
                    response = _fake_response(cmd)
                    chan.send(response.encode())
                    chan.send(f"\n{server.username}@gateway-srv01:~$ ".encode())
                command_buffer = b""
    except Exception as exc:
        _log.debug("SSH channel closed for %s: %s", client_ip, exc)
    finally:
        chan.close()
        transport.close()


def _fake_response(cmd: str) -> str:
    """Return a plausible response for common recon commands."""
    cmd_lower = cmd.lower().strip()

    responses = {
        "id": "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)",
        "whoami": "admin",
        "uname -a": "Linux gateway-srv01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "uname": "Linux",
        "hostname": "gateway-srv01",
        "pwd": "/home/admin",
        "ls": "Desktop  Documents  Downloads  .bash_history  .ssh  .profile",
        "ls -la": (
            "total 36\n"
            "drwxr-xr-x  5 admin admin 4096 Jan  5 09:14 .\n"
            "drwxr-xr-x  3 root  root  4096 Dec 20 11:30 ..\n"
            "-rw-------  1 admin admin  220 Dec 20 11:30 .bash_history\n"
            "drwx------  2 admin admin 4096 Jan  5 09:14 .ssh\n"
            "-rw-r--r--  1 admin admin  807 Dec 20 11:30 .profile\n"
            "drwxr-xr-x  2 admin admin 4096 Jan  5 09:14 Desktop\n"
            "drwxr-xr-x  2 admin admin 4096 Jan  5 09:14 Documents\n"
            "drwxr-xr-x  2 admin admin 4096 Jan  5 09:14 Downloads"
        ),
        "cat /etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "admin:x:1000:1000:admin:/home/admin:/bin/bash"
        ),
        "ifconfig": (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
            "        ether 08:00:27:d4:69:ad  txqueuelen 1000"
        ),
        "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
        "wget": "wget: missing URL\nUsage: wget [OPTION]... [URL]...",
        "curl": "curl: try 'curl --help' for more information",
        "exit": "",
    }

    for key, val in responses.items():
        if cmd_lower.startswith(key):
            return val

    # Default: command-not-found style
    return f"-bash: {cmd.split()[0] if cmd.split() else cmd}: command not found"


# ────────────────────────────────────────────────────────────
#  Main listener
# ────────────────────────────────────────────────────────────

def start() -> None:
    """Bind the SSH honeypot socket and accept connections forever."""
    init_db()
    setup_file_logging()

    host = _ssh_cfg["host"]
    port = _ssh_cfg["port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    _log.info("SSH honeypot listening on %s:%d", host, port)

    while True:
        client_sock, addr = sock.accept()
        if not rate_ok(addr[0]):
            _log.warning("Rate-limited SSH from %s", addr[0])
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
