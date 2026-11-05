"""
services/telnet_service.py
──────────────────────────
Asynchronous Telnet IoT Decoy (RFC 854).
Lures Mirai / BusyBox botnet crawlers, captures automated brute-force combos,
and logs reconnaissance probes.
"""

import asyncio
import logging
from typing import Optional

from core.classifier import classify_payload
from core.database import log_attack

logger = logging.getLogger("honeypot.telnet")

_SERVER: Optional[asyncio.Server] = None


def _strip_telnet_iac(data: bytes) -> bytes:
    """Strip Telnet Interpret As Command (IAC) control negotiation sequences."""
    clean = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF:  # IAC
            # Typically 3-byte commands (IAC + WILL/WONT/DO/DONT + OPTION)
            if i + 1 < len(data) and data[i + 1] in (251, 252, 253, 254):
                i += 3
            elif i + 1 < len(data) and data[i + 1] == 250:  # SB subnegotiation
                end = data.find(b"\xff\xf0", i)
                if end != -1:
                    i = end + 2
                else:
                    break
            else:
                i += 2
        else:
            clean.append(data[i])
            i += 1
    return bytes(clean)


async def handle_telnet_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Interact with incoming Telnet clients and extract botnet credentials."""
    peername = writer.get_extra_info("peername")
    client_ip = peername[0] if peername else "127.0.0.1"

    try:
        # Telnet negotiation + authentic Ubuntu login banner
        initial_msg = b"\xff\xfd\x03\xff\xfb\x01\r\nUbuntu 22.04.3 LTS\r\n\r\nubuntu-iot-gateway login: "
        writer.write(initial_msg)
        await writer.drain()

        # Read username
        username = ""
        while not writer.is_closing():
            raw_line = await reader.readline()
            if not raw_line:
                return
            clean_line = _strip_telnet_iac(raw_line).decode("utf-8", "ignore").strip()
            if clean_line:
                username = clean_line
                break

        # Prompt for password
        writer.write(b"Password: ")
        await writer.drain()

        # Read password
        password = ""
        while not writer.is_closing():
            raw_line = await reader.readline()
            if not raw_line:
                return
            clean_line = _strip_telnet_iac(raw_line).decode("utf-8", "ignore").strip()
            if clean_line:
                password = clean_line
                break

        cred_str = f"{username}:{password}"
        logger.warning("[Telnet] Botnet auth attempt from %s -> %s", client_ip, cred_str)

        # Log brute-force telemetry
        mitre_tags = classify_payload(f"USER {username} PASS {password}", is_auth=True)
        await log_attack(
            source_ip=client_ip,
            service="TELNET",
            payload=f"TELNET_AUTH: user='{username}' pass='{password}'",
            credentials=cred_str,
            mitre_tags=mitre_tags
        )

        # Simulate authentication rejection
        writer.write(b"\r\nLogin incorrect\r\n\r\nubuntu-iot-gateway login: ")
        await writer.drain()

        # Give client a short window to send bot commands if already piped
        try:
            extra_data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            if extra_data:
                extra_clean = _strip_telnet_iac(extra_data).decode("utf-8", "ignore").strip()
                if extra_clean:
                    tags = classify_payload(extra_clean)
                    await log_attack(
                        source_ip=client_ip,
                        service="TELNET",
                        payload=extra_clean,
                        mitre_tags=tags
                    )
        except asyncio.TimeoutError:
            pass

    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as exc:
        logger.debug("[Telnet] Client exception with %s: %s", client_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_telnet_service(host: str = "0.0.0.0", port: int = 2323) -> None:
    """Launch asynchronous non-blocking Telnet decoy TCP listener."""
    global _SERVER
    _SERVER = await asyncio.start_server(handle_telnet_client, host, port)
    logger.info("Telnet Honeypot listening on %s:%d", host, port)
    async with _SERVER:
        await _SERVER.serve_forever()


async def stop_telnet_service() -> None:
    """Terminate Telnet decoy server."""
    global _SERVER
    if _SERVER:
        _SERVER.close()
        await _SERVER.wait_closed()
