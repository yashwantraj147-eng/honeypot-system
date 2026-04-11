"""
honeypots/ftp_honeypot.py
─────────────────────────
Low-interaction FTP honeypot that:
  • Presents a realistic ProFTPD banner
  • Accepts USER / PASS commands and logs credential pairs
  • Responds to basic FTP verbs (LIST, PWD, SYST, etc.)
  • Logs every command the attacker sends

Uses raw sockets for full control over the protocol dialogue.
"""

import logging
import socket
import threading

from core.config_loader import cfg
from core.enrichment import process_event
from core.rate_limiter import allow as rate_ok
from core.logger import init_db, setup_file_logging

_log = logging.getLogger("honeypotnet.ftp")
_ftp_cfg = cfg["services"]["ftp"]

# Fake directory listing returned on LIST
_FAKE_LISTING = (
    "-rw-r--r--   1 root  root     4096 Jan  5 09:14 index.html\r\n"
    "-rw-------   1 root  root      220 Dec 20 11:30 .htpasswd\r\n"
    "drwxr-xr-x   2 root  root     4096 Jan  5 09:14 backup\r\n"
    "drwxr-xr-x   2 root  root     4096 Dec 20 11:30 logs\r\n"
    "-rw-r--r--   1 root  root    10240 Jan  3 22:45 database.sql\r\n"
)


def _handle_client(client_sock: socket.socket, addr: tuple) -> None:
    """Speak the FTP protocol just enough to capture creds and recon."""
    client_ip = addr[0]
    _log.info("FTP connection from %s:%d", *addr)

    username = ""
    authenticated = False
    attempts = 0
    max_attempts = _ftp_cfg.get("max_auth_attempts", 5)

    try:
        # Send banner
        banner = _ftp_cfg.get("banner", "220 ProFTPD 1.3.5e Server (Debian)")
        client_sock.sendall(f"{banner}\r\n".encode())

        while True:
            data = client_sock.recv(1024)
            if not data:
                break
            line = data.decode(errors="replace").strip()
            if not line:
                continue

            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            # ── USER command ──
            if cmd == "USER":
                username = arg
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="user_command",
                    payload={"username": username},
                    details=f"FTP USER {username}",
                )
                client_sock.sendall(b"331 Password required.\r\n")

            # ── PASS command ──
            elif cmd == "PASS":
                password = arg
                attempts += 1
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="login_attempt",
                    payload={"username": username, "password": password},
                    details=f"FTP creds: {username}/{password}",
                )
                if attempts >= max_attempts:
                    client_sock.sendall(b"530 Too many failures.\r\n")
                    break
                # "Accept" the login
                authenticated = True
                client_sock.sendall(b"230 Login successful.\r\n")

            # ── Post-auth commands ──
            elif cmd == "SYST":
                client_sock.sendall(b"215 UNIX Type: L8\r\n")

            elif cmd == "PWD":
                client_sock.sendall(b'257 "/" is the current directory.\r\n')

            elif cmd == "TYPE":
                client_sock.sendall(b"200 Type set.\r\n")

            elif cmd == "PASV":
                # We don't actually open a data port — just ack
                client_sock.sendall(b"227 Entering Passive Mode (127,0,0,1,0,0).\r\n")

            elif cmd == "LIST" or cmd == "NLST":
                client_sock.sendall(b"150 Opening data connection.\r\n")
                # In a real PASV flow the listing goes on the data channel.
                # Here we cheat and send it on the control channel — many
                # automated scanners don't notice the difference.
                client_sock.sendall(_FAKE_LISTING.encode())
                client_sock.sendall(b"226 Transfer complete.\r\n")
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="list_command",
                    payload={"username": username, "command": line},
                    details="FTP LIST",
                )

            elif cmd == "CWD":
                client_sock.sendall(b"250 Directory changed.\r\n")
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="cwd_command",
                    payload={"username": username, "path": arg},
                    details=f"FTP CWD {arg}",
                )

            elif cmd == "RETR":
                client_sock.sendall(b"550 Permission denied.\r\n")
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="retr_command",
                    payload={"username": username, "file": arg},
                    details=f"FTP RETR {arg}",
                )

            elif cmd == "STOR":
                client_sock.sendall(b"550 Permission denied.\r\n")
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="stor_command",
                    payload={"username": username, "file": arg},
                    details=f"FTP STOR {arg}",
                )

            elif cmd == "QUIT":
                client_sock.sendall(b"221 Goodbye.\r\n")
                break

            elif cmd == "FEAT":
                client_sock.sendall(
                    b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n"
                )

            else:
                # Log unknown commands — could be exploit payloads
                process_event(
                    src_ip=client_ip,
                    service="ftp",
                    action="unknown_command",
                    payload={"username": username, "raw": line},
                    details=f"FTP unknown: {line}",
                )
                client_sock.sendall(b"502 Command not implemented.\r\n")

    except Exception as exc:
        _log.debug("FTP connection closed for %s: %s", client_ip, exc)
    finally:
        client_sock.close()


# ────────────────────────────────────────────────────────────
#  Main listener
# ────────────────────────────────────────────────────────────

def start() -> None:
    """Bind the FTP honeypot socket and accept connections."""
    init_db()
    setup_file_logging()

    host = _ftp_cfg["host"]
    port = _ftp_cfg["port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    _log.info("FTP honeypot listening on %s:%d", host, port)

    while True:
        client_sock, addr = sock.accept()
        if not rate_ok(addr[0]):
            _log.warning("Rate-limited FTP from %s", addr[0])
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
