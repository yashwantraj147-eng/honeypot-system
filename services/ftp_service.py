"""
services/ftp_service.py
───────────────────────
Asynchronous FTP Trap (RFC 959 Decoy).
Harvests brute-force authentication credentials and mimics vulnerable ProFTPD server.
"""

import asyncio
import logging
from typing import Optional

from core.classifier import classify_payload
from core.database import log_attack

logger = logging.getLogger("honeypot.ftp")

_SERVER: Optional[asyncio.Server] = None


async def handle_ftp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle incoming FTP client connections and command negotiation."""
    peername = writer.get_extra_info("peername")
    client_ip = peername[0] if peername else "127.0.0.1"

    current_user: Optional[str] = None

    try:
        # Initial greeting banner
        banner = b"220 ProFTPD 1.3.5 Server (Ubuntu) [::ffff:127.0.0.1]\r\n"
        writer.write(banner)
        await writer.drain()

        while not writer.is_closing():
            line_bytes = await reader.readline()
            if not line_bytes:
                break

            line = line_bytes.decode("utf-8", "ignore").strip()
            if not line:
                continue

            parts = line.split(maxsplit=1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                current_user = arg
                writer.write(f"331 Password required for {arg}\r\n".encode("utf-8"))
                await writer.drain()

            elif cmd == "PASS":
                password = arg
                user_str = current_user or "unknown"
                cred_str = f"{user_str}:{password}"
                logger.warning("[FTP] Auth attempt from %s -> %s", client_ip, cred_str)

                # Classify and log attack to database
                mitre_tags = classify_payload(f"USER {user_str} PASS {password}", is_auth=True)
                await log_attack(
                    source_ip=client_ip,
                    service="FTP",
                    payload=f"USER {user_str} PASS {password}",
                    credentials=cred_str,
                    mitre_tags=mitre_tags
                )

                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
                # Terminate on failed attempt to induce brute-force tool retry loops
                break

            elif cmd == "SYST":
                writer.write(b"215 UNIX Type: L8\r\n")
                await writer.drain()

            elif cmd == "FEAT":
                writer.write(b"211-Features:\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n211 End\r\n")
                await writer.drain()

            elif cmd in ("QUIT", "BYE"):
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break

            elif cmd == "HELP":
                writer.write(b"214-The following commands are recognized:\r\n USER PASS SYST QUIT HELP\r\n214 Have a nice day.\r\n")
                await writer.drain()

            else:
                # Log unexpected commands as probe payloads
                tags = classify_payload(line)
                await log_attack(
                    source_ip=client_ip,
                    service="FTP",
                    payload=line,
                    mitre_tags=tags
                )
                writer.write(b"500 Unknown command.\r\n")
                await writer.drain()

    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as exc:
        logger.debug("[FTP] Client exception with %s: %s", client_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_ftp_service(host: str = "0.0.0.0", port: int = 2121) -> None:
    """Launch asynchronous non-blocking FTP decoy TCP listener."""
    global _SERVER
    _SERVER = await asyncio.start_server(handle_ftp_client, host, port)
    logger.info("FTP Honeypot listening on %s:%d", host, port)
    async with _SERVER:
        await _SERVER.serve_forever()


async def stop_ftp_service() -> None:
    """Terminate FTP decoy server."""
    global _SERVER
    if _SERVER:
        _SERVER.close()
        await _SERVER.wait_closed()

