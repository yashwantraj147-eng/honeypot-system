"""
services/ssh_service.py
───────────────────────
Enterprise Paramiko-based SSH Decoy & Interactive Linux Sandbox.
Features an in-memory Virtual File System (VFS), stateful directory navigation,
malware ingress interception & quarantining, and TTY session keystroke recording.
"""

import asyncio
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import re
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


class VirtualFileSystem:
    """
    In-memory stateful Linux Virtual File System (VFS).
    Supports persistent per-session file creation, deletion, navigation, and inspection.
    """

    def __init__(self):
        self.cwd = "/root"
        self.tree: Dict[str, Dict[str, Any]] = {
            "/": {
                "type": "dir",
                "children": {
                    "bin": {
                        "type": "dir",
                        "children": {
                            "sh": {"type": "file", "size": 125688, "perm": "rwxr-xr-x"},
                            "bash": {"type": "file", "size": 1396520, "perm": "rwxr-xr-x"},
                            "ls": {"type": "file", "size": 142144, "perm": "rwxr-xr-x"},
                            "cat": {"type": "file", "size": 43520, "perm": "rwxr-xr-x"},
                            "ps": {"type": "file", "size": 168200, "perm": "rwxr-xr-x"},
                            "whoami": {"type": "file", "size": 39368, "perm": "rwxr-xr-x"},
                            "uname": {"type": "file", "size": 43496, "perm": "rwxr-xr-x"},
                            "wget": {"type": "file", "size": 548920, "perm": "rwxr-xr-x"},
                            "curl": {"type": "file", "size": 268400, "perm": "rwxr-xr-x"},
                        }
                    },
                    "etc": {
                        "type": "dir",
                        "children": {
                            "passwd": {
                                "type": "file",
                                "content": (
                                    "root:x:0:0:root:/root:/bin/bash\n"
                                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                                    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                                    "sshd:x:103:65534::/run/sshd:/usr/sbin/nologin\n"
                                    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                                ),
                                "perm": "rw-r--r--"
                            },
                            "shadow": {
                                "type": "file",
                                "content": "Permission denied\n",
                                "perm": "r--------"
                            },
                            "os-release": {
                                "type": "file",
                                "content": (
                                    "NAME=\"Ubuntu\"\n"
                                    "VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n"
                                    "ID=ubuntu\n"
                                    "VERSION_ID=\"22.04\"\n"
                                    "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"
                                ),
                                "perm": "rw-r--r--"
                            },
                            "issue": {
                                "type": "file",
                                "content": "Ubuntu 22.04.3 LTS \\n \\l\n",
                                "perm": "rw-r--r--"
                            }
                        }
                    },
                    "home": {
                        "type": "dir",
                        "children": {
                            "ubuntu": {
                                "type": "dir",
                                "children": {
                                    ".bashrc": {"type": "file", "content": "# ~/.bashrc\n", "perm": "rw-r--r--"}
                                }
                            }
                        }
                    },
                    "root": {
                        "type": "dir",
                        "children": {
                            ".bashrc": {"type": "file", "content": "# root ~/.bashrc\n", "perm": "rw-r--r--"},
                            ".bash_history": {"type": "file", "content": "systemctl restart nginx\nwget\n", "perm": "rw-------"}
                        }
                    },
                    "tmp": {
                        "type": "dir",
                        "children": {}
                    },
                    "var": {
                        "type": "dir",
                        "children": {
                            "log": {
                                "type": "dir",
                                "children": {
                                    "auth.log": {"type": "file", "content": "sshd[112]: Accepted password for root\n", "perm": "rw-r-----"}
                                }
                            }
                        }
                    }
                }
            }
        }

    def resolve_path(self, target: str) -> str:
        """Resolve relative or absolute path into normalized Unix path."""
        if not target or target == "~":
            return "/root"
        if target.startswith("/"):
            path = target
        else:
            path = f"{self.cwd}/{target}"
        
        parts = [p for p in path.split("/") if p and p != "."]
        stack = []
        for p in parts:
            if p == "..":
                if stack:
                    stack.pop()
            else:
                stack.append(p)
        return "/" + "/".join(stack)

    def get_node(self, path: str) -> Optional[Dict[str, Any]]:
        """Traverse VFS tree and return node metadata dictionary."""
        norm = self.resolve_path(path)
        if norm == "/":
            return self.tree["/"]
        
        parts = [p for p in norm.split("/") if p]
        curr = self.tree["/"]
        for p in parts:
            if curr.get("type") != "dir" or p not in curr.get("children", {}):
                return None
            curr = curr["children"][p]
        return curr

    def change_dir(self, target: str) -> bool:
        """Change current working directory if target is a valid directory."""
        dest = self.resolve_path(target)
        node = self.get_node(dest)
        if node and node.get("type") == "dir":
            self.cwd = dest
            return True
        return False

    def list_dir(self, target: Optional[str] = None, show_all: bool = False, long_format: bool = False) -> str:
        """List directory entries with realistic Linux file permissions and dates."""
        dest = self.resolve_path(target or self.cwd)
        node = self.get_node(dest)
        if not node:
            return f"ls: cannot access '{target}': No such file or directory\r\n"
        if node.get("type") == "file":
            return f"{target}\r\n"

        children = node.get("children", {})
        entries = sorted(children.keys())
        if show_all:
            entries = [".", ".."] + entries

        if not long_format:
            # Inline column listing
            return "  ".join(entries) + "\r\n"

        # Long format (ls -la)
        lines = [f"total {len(entries) * 4}"]
        date_str = datetime.datetime.now().strftime("%b %d %H:%M")
        for name in entries:
            child = children.get(name, {})
            is_dir = child.get("type") == "dir" or name in (".", "..")
            perm = "drwxr-xr-x" if is_dir else f"-{child.get('perm', 'rw-r--r--')}"
            size = child.get("size", len(child.get("content", ""))) if not is_dir else 4096
            lines.append(f"{perm} 1 root root {size:>7} {date_str} {name}")
        return "\r\n".join(lines) + "\r\n"

    def read_file(self, target: str) -> str:
        """Read text contents of a VFS file."""
        dest = self.resolve_path(target)
        node = self.get_node(dest)
        if not node:
            return f"cat: {target}: No such file or directory\r\n"
        if node.get("type") == "dir":
            return f"cat: {target}: Is a directory\r\n"
        return node.get("content", "") + "\r\n"

    def write_file(self, target: str, content: str, append: bool = False) -> None:
        """Write or append text content to a VFS file, creating parent nodes if required."""
        dest = self.resolve_path(target)
        parts = [p for p in dest.split("/") if p]
        if not parts:
            return
        filename = parts[-1]
        parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        parent = self.get_node(parent_path)
        if parent and parent.get("type") == "dir":
            children = parent.setdefault("children", {})
            if filename in children and append:
                children[filename]["content"] = children[filename].get("content", "") + content
            else:
                children[filename] = {
                    "type": "file",
                    "content": content,
                    "size": len(content),
                    "perm": "rwxr-xr-x"
                }

    def remove(self, target: str) -> str:
        """Remove a file or directory from VFS."""
        dest = self.resolve_path(target)
        if dest in ("/", "/root", "/bin", "/etc"):
            return f"rm: cannot remove '{target}': Permission denied\r\n"
        parts = [p for p in dest.split("/") if p]
        if not parts:
            return ""
        filename = parts[-1]
        parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        parent = self.get_node(parent_path)
        if parent and filename in parent.get("children", {}):
            del parent["children"][filename]
            return ""
        return f"rm: cannot remove '{target}': No such file or directory\r\n"


class SSHHoneypotInterface(paramiko.ServerInterface):
    """Paramiko ServerInterface implementation designed to lure attackers."""

    def __init__(self, client_ip: str, loop: asyncio.AbstractEventLoop):
        self.client_ip = client_ip
        self.loop = loop
        self.authenticated = False
        self.credentials: List[str] = []
        self.client_fingerprint: str = "Unknown SSH Client"

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
                payload=f"AUTH: user='{username}' pass='{password}' [Client: {self.client_fingerprint}]",
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


def _handle_shell_command(cmd_line: str, vfs: VirtualFileSystem, session_history: List[str]) -> str:
    """
    Execute attacker command against stateful VFS and return authentic Linux terminal output.
    """
    cmd_clean = cmd_line.strip()
    session_history.append(cmd_clean)

    # Handle output redirection: echo "payload" > /tmp/a.sh
    redir_match = re.search(r"^(.*?)\s*(>>|>)\s*([^\s]+)$", cmd_clean)
    if redir_match:
        exec_part = redir_match.group(1).strip()
        op = redir_match.group(2)
        target_file = redir_match.group(3).strip()
        
        # Execute left command and capture output
        if exec_part.startswith("echo"):
            content = exec_part[4:].strip().strip("\"'")
        else:
            content = _handle_shell_command(exec_part, vfs, [])
        
        vfs.write_file(target_file, content + "\n", append=(op == ">>"))
        return ""

    parts = cmd_clean.split()
    if not parts:
        return ""
    base_cmd = parts[0].lower()
    args = parts[1:]

    # 1. Navigation
    if base_cmd == "cd":
        target = args[0] if args else "/root"
        if not vfs.change_dir(target):
            return f"-bash: cd: {target}: No such file or directory\r\n"
        return ""

    if base_cmd == "pwd":
        return f"{vfs.cwd}\r\n"

    # 2. Directory Listing (ls)
    if base_cmd == "ls":
        show_all = any("-a" in a for a in args) or any("a" in a and a.startswith("-") for a in args)
        long_format = any("-l" in a for a in args) or any("l" in a and a.startswith("-") for a in args)
        target_path = None
        for a in args:
            if not a.startswith("-"):
                target_path = a
                break
        return vfs.list_dir(target_path, show_all=show_all, long_format=long_format)

    # 3. File Operations
    if base_cmd == "cat":
        if not args:
            return ""
        arg = args[0]
        if "passwd" in arg:
            return vfs.read_file("/etc/passwd")
        if "shadow" in arg:
            return "cat: /etc/shadow: Permission denied\r\n"
        if "os-release" in arg or "release" in arg or "version" in arg:
            return vfs.read_file("/etc/os-release")
        return vfs.read_file(arg)

    if base_cmd == "touch":
        if args:
            vfs.write_file(args[0], "")
        return ""

    if base_cmd == "mkdir":
        if args:
            dest = vfs.resolve_path(args[0])
            parts = [p for p in dest.split("/") if p]
            parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
            parent = vfs.get_node(parent_path)
            if parent and parent.get("type") == "dir":
                parent.setdefault("children", {})[parts[-1]] = {"type": "dir", "children": {}}
        return ""

    if base_cmd == "rm":
        if not args:
            return "rm: missing operand\r\n"
        target = args[-1]
        return vfs.remove(target)

    # 4. Identity & System Reconnaissance
    if base_cmd == "whoami":
        return "root\r\n"

    if base_cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\r\n"

    if base_cmd == "uname":
        if any("-a" in a for a in args):
            return "Linux ubuntu-server-01 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
        return "Linux\r\n"

    if base_cmd == "hostname":
        return "ubuntu-server-01\r\n"

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

    # 5. Ingress Tool Interception (wget / curl)
    if base_cmd in ("wget", "curl"):
        url = args[0] if args else "http://example.com/payload.sh"
        for a in args:
            if a.startswith("http://") or a.startswith("https://") or a.startswith("ftp://"):
                url = a
                break
        filename = url.split("/")[-1] or "downloaded_payload.sh"
        # Save payload file into VFS
        vfs.write_file(f"{vfs.cwd}/{filename}", "#!/bin/bash\n# Simulated Malware Payload\n")
        return (
            f"Connecting to {url}... connected.\r\n"
            "HTTP request sent, awaiting response... 200 OK\r\n"
            "Length: 28416 (28K) [application/octet-stream]\r\n"
            f"Saving to: '{filename}'\r\n"
            f"{filename}          100%[===================>]  27.75K  --.-KB/s    in 0.01s\r\n"
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (2.77 MB/s) - '{filename}' saved [28416/28416]\r\n"
        )

    if base_cmd == "history":
        lines = [f" {i+1}  {cmd}" for i, cmd in enumerate(session_history)]
        return "\r\n".join(lines) + "\r\n"

    if base_cmd in ("lscpu", "df", "free", "uptime", "netstat", "arp", "w", "last", "chmod"):
        return f"Linux subsystem executed {base_cmd} (exit status: 0).\r\n"

    return f"-bash: {base_cmd}: command not found\r\n"


def _handle_ssh_client_thread(client_sock: socket.socket, addr: tuple, loop: asyncio.AbstractEventLoop) -> None:
    """Thread worker handling SSH transport, VFS sandbox, and interactive terminal."""
    client_ip = addr[0]
    session_id = uuid.uuid4().hex[:12]
    recording_file = f"ssh_{session_id}.json"
    recording_path = os.path.join(settings.RECORDINGS_DIR, recording_file)
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    events: List[Dict[str, Any]] = []
    transport: Optional[paramiko.Transport] = None
    channel: Optional[paramiko.Channel] = None
    vfs = VirtualFileSystem()
    session_history: List[str] = []

    try:
        transport = paramiko.Transport(client_sock)
        host_key = get_or_generate_host_key()
        transport.add_server_key(host_key)

        server_interface = SSHHoneypotInterface(client_ip, loop)
        server_interface.client_fingerprint = transport.remote_version or "Unknown SSH Client"
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

        def get_prompt() -> bytes:
            path_display = "~" if vfs.cwd == "/root" else vfs.cwd
            return f"root@ubuntu-server-01:{path_display}# ".encode("utf-8")

        prompt = get_prompt()
        channel.send(prompt)
        events.append({"timestamp": time.time(), "type": "stdout", "data": banner + prompt.decode("utf-8")})

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

                        output = _handle_shell_command(raw_cmd, vfs, session_history)
                        channel.send(output.encode("utf-8"))
                        events.append({"timestamp": time.time(), "type": "stdout", "data": output})

                    prompt = get_prompt()
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
                    channel.send(b"^C\r\n" + get_prompt())

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
                    "client_fingerprint": getattr(server_interface, "client_fingerprint", "Unknown"),
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
