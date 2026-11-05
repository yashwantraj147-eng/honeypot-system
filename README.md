<div align="center">

# 🍯 Honeypot-System v2.0
### Autonomous Multi-Service Deception Grid & Real-Time Threat Intelligence Pipeline

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker Ready](https://img.shields.io/badge/docker-compose%20ready-2496ED.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1%20Mapped-red.svg?style=for-the-badge)](https://attack.mitre.org/)
[![STIX 2.1](https://img.shields.io/badge/Threat%20Intel-STIX%202.1-orange.svg?style=for-the-badge)](https://oasis-open.github.io/cti-documentation/)

<p align="center">
  <b>Transform attacker curiosity into high-fidelity defensive threat intelligence.</b><br>
  Honeypot-System v2.0 deploys low-interaction and medium-interaction decoys across <b>SSH, HTTP, FTP, and Telnet</b> to harvest credentials, classify intrusion techniques using <b>MITRE ATT&CK</b> heuristics in real time, neutralize automated scanners with <b>active tarpitting and safe gzip decompression bombs</b>, and generate automated blocklists for perimeter firewalls (<b>pfSense / OPNsense / FortiGate</b>) and SIEMs (<b>Splunk / Elastic / Sentinel</b>).
</p>

[Quick Start](#-quick-start) •
[Architecture](#-system-architecture) •
[Decoy Matrix](#-decoy-services-matrix) •
[Threat Feeds](#-threat-intelligence-pipeline) •
[MITRE ATT&CK Coverage](#-mitre-attck-matrix) •
[SOC Dashboard](#-real-time-soc-dashboard) •
[API Reference](#-rest--websocket-api-reference)

---

</div>

## 🚀 Key Innovations in v2.0

- ⚡ **Pure Asynchronous Architecture:** Zero thread bottlenecks. Network socket traps (FTP, Telnet), HTTP web servers (`aiohttp`), and database queries (`aiosqlite`) are native `asyncio` with strict per-connection failure isolation.
- 🐚 **Interactive SSH Pseudo-Shell:** Complete emulated Ubuntu TTY terminal powered by Paramiko. Captures keystrokes, provides realistic outputs for commands (`uname`, `whoami`, `cat /etc/passwd`, `wget`), and records full playback files (`recordings/ssh_{session_id}.json`).
- 🌐 **Web Traps & Active Defense:** Exposes simulated `/.env` cloud credentials, `/wp-login.php`, `/admin`, and Spring Boot `/actuator/health`. Automatically triggers **10-byte/sec streaming tarpits** against high-frequency bots and serves **safe gzip decompression defense bombs** against path traversal crawlers (`nikto`, `sqlmap`).
- 📡 **Automated Threat Intelligence Feeds:**
  - `GET /api/v1/feed/firewall.txt`: Plain-text `<ip>/32` CIDR blocklist consumable directly by firewall alias tables (pfSense, OPNsense, FortiOS, iptables).
  - `GET /api/v1/feed/stix.json`: OASIS STIX 2.1 standard JSON bundle for enterprise SIEM ingestion.
- 🖥️ **Dark-Mode SOC Dashboard:** Real-time single-page interface with Leaflet.js dark radar map, live WebSocket intrusion ticker, MITRE ATT&CK breakdown charts, and an in-browser CRT terminal session replay player.

---

## 🏛 System Architecture

```text
                      ┌─────────────────────────────────────────────────────────┐
                      │              INTERNET / ADVERSARY ACTORS                │
                      └────────────────────────────┬────────────────────────────┘
                                                   │
          ┌─────────────────┬──────────────────────┼──────────────────────┬─────────────────┐
          │ :22             │ :80                  │ :21                  │ :23             │
          ▼                 ▼                      ▼                      ▼                 ▼
   ┌──────────────┐  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐  ┌──────────────┐
   │  SSH Decoy   │  │  HTTP Decoy  │       │  FTP Decoy   │       │ Telnet Decoy │  │ Active Def.  │
   │   (Paramiko  │  │   (aiohttp   │       │  (RFC 959    │       │  (RFC 854    │  │ (Tarpit &    │
   │ Pseudo-TTY)  │  │ Admin/Env)   │       │  ProFTPD)    │       │  Mirai IoT)  │  │  Gzip Bomb)  │
   └──────┬───────┘  └──────┬───────┘       └──────┬───────┘       └──────┬───────┘  └──────┬───────┘
          │                 │                      │                      │                 │
          └─────────────────┴──────────────────────┼──────────────────────┴─────────────────┘
                                                   │ Raw Payloads & Credentials
                                                   ▼
                                    ┌─────────────────────────────┐
                                    │    MITRE ATT&CK Engine      │
                                    │  (Regex & Heuristics Core)  │
                                    └──────────────┬──────────────┘
                                                   │ Enriched Telemetry
                                                   ▼
                                    ┌─────────────────────────────┐
                                    │   Async Database Engine     │
                                    │  (aiosqlite + GeoIP Cache)  │
                                    └──────────────┬──────────────┘
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼                                                   ▼
          ┌─────────────────────────────┐                     ┌─────────────────────────────┐
          │  FastAPI WebSocket Hub      │                     │ Threat Intelligence Feeds   │
          │  - Live Attack Stream       │                     │ - /feed/firewall.txt (CIDR) │
          │  - Leaflet.js Radar Map     │                     │ - /feed/stix.json (STIX 2.1)│
          │  - Keystroke Session Player │                     │ - /stats & /recent API      │
          └─────────────────────────────┘                     └─────────────────────────────┘
```

---

## ⚡ Quick Start

### 1. One-Click Deployment (Docker Compose)

Deploy the entire honeypot grid and SOC dashboard instantly with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/your-org/honeypot-system.git
cd honeypot-system

# Build and start all services in detached mode
docker compose up --build -d
```

The deception grid is now armed and listening on:
- **SSH Decoy:** `0.0.0.0:22` (or host port mapped to `2222`)
- **HTTP Decoy:** `0.0.0.0:80` (or host port mapped to `8080`)
- **FTP Decoy:** `0.0.0.0:21` (or host port mapped to `2121`)
- **Telnet Decoy:** `0.0.0.0:23` (or host port mapped to `2323`)
- **SOC Dashboard & Threat API:** `http://localhost:9090`

### 2. Standalone Native Deployment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install exact pinned production dependencies
pip install -r requirements.txt

# Launch the orchestrator
python main.py
```

Access the SOC dashboard in your browser at `http://localhost:9090`.

---

## 🎯 Decoy Services Matrix

| Service | Port | Banner / Simulation | Targeted Vectors | Defense Behavior |
| :--- | :---: | :--- | :--- | :--- |
| **SSH** | `22` / `2222` | `Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0)` | Brute-force auth, shell reconnaissance (`whoami`, `uname -a`, `cat /etc/passwd`, `wget`) | In-memory pseudo-shell, full TTY keystroke recorder saved to `recordings/` |
| **HTTP** | `80` / `8080` | `nginx/1.22.1 (Ubuntu)` | `/.env` leaks, `/wp-login.php`, `/admin`, `/actuator/health`, directory traversal | 10 B/s streaming tarpit for bot scrapers; 10MB gzip bomb on scanner traversal |
| **FTP** | `21` / `2121` | `220 ProFTPD 1.3.5 Server (Ubuntu)` | Anonymous login, dictionary brute-force, `USER`/`PASS` harvesting | Harvests credentials, returns realistic `530 Login incorrect` error codes |
| **Telnet** | `23` / `2323` | `Ubuntu 22.04.3 LTS login:` | Mirai / BusyBox IoT botnets, default credential spraying (`root/xc3511`) | Negotiates RFC 854 IAC sequences, captures username/password combos |

---

## 🛡️ Threat Intelligence Pipeline

Honeypot-System v2.0 serves as an autonomous threat intelligence generation node. IPs that repeatedly probe your decoys (`MALICIOUS_IP_THRESHOLD >= 5`) are automatically promoted to high-confidence threat feeds.

### 1. Firewall Ingestion (`/api/v1/feed/firewall.txt`)

Plain-text blocklist formatted with `<ip>/32\n` records.

#### **pfSense Integration:**
1. Navigate to **Firewall** ➔ **Aliases** ➔ **IP**.
2. Click **Add**. Set **Name** to `Honeypot_Blocklist`.
3. Set **Type** to `URL Table (IPs)`.
4. Enter URL: `http://<your-honeypot-ip>:9090/api/v1/feed/firewall.txt`.
5. Set Update Frequency to `1` day or `12` hours.
6. Create a WAN firewall rule with action `Block`, source `Single Host or Alias: Honeypot_Blocklist`.

#### **OPNsense Integration:**
1. Navigate to **Firewall** ➔ **Aliases**.
2. Add new alias: Type `URL Table (IPs)`.
3. Set Content to `http://<your-honeypot-ip>:9090/api/v1/feed/firewall.txt`.
4. Apply to WAN rules.

#### **Linux iptables Automation:**
```bash
curl -s http://localhost:9090/api/v1/feed/firewall.txt | grep -E "^[0-9]" | while read ip; do
    iptables -A INPUT -s "$ip" -j DROP
done
```

---

### 2. SIEM & SOAR Integration (`/api/v1/feed/stix.json`)

Compliant with **OASIS STIX 2.1 Specification**. Every indicator includes:
- Observable pattern: `[ipv4-addr:value = 'x.x.x.x']`
- Confidence rating: `90`
- Indicator types: `["malicious-activity", "anonymizing"]`
- External references mapped directly to **MITRE ATT&CK** technique IDs.

Directly ingestible by:
- **Splunk Enterprise Security (Threat Intelligence Framework)**
- **Elastic Security (Threat Intel Module)**
- **Microsoft Sentinel (Threat Intelligence Platforms Data Connector)**
- **OpenCTI & MISP**

---

## 🔍 MITRE ATT&CK Matrix

Incoming network commands, URI queries, and authentication attempts are evaluated against heuristic rules:

| Technique ID | Technique Name | Tactic | Trigger Patterns / Detection Logic |
| :--- | :--- | :--- | :--- |
| **T1110** | Brute Force | Credential Access | Rapid authentication attempts on SSH, Telnet (Mirai combos), FTP (`USER`/`PASS`), or HTTP `/wp-login.php`. |
| **T1059.004** | Command and Scripting Interpreter: Unix Shell | Execution | Shell invocations (`sh`, `bash`, `python`, `perl`), chained commands (`&&`, `\|`, `;`), command substitutions. |
| **T1082** | System Information Discovery | Discovery | Commands including `uname -a`, `lscpu`, `df -h`, `cat /etc/*release`, `/actuator/health`, `/config.json`. |
| **T1087** | Account Discovery | Discovery | Attacker commands `whoami`, `id`, `cat /etc/passwd`, `cat /etc/shadow`, `w`, `last`. |
| **T1105** | Ingress Tool Transfer | Command & Control | Download utilities: `wget`, `curl`, `tftp`, `sftp`, `busybox wget`, `scp`, `nc`. |
| **T1070.004** | Indicator Removal: File Deletion / Anti-Forensics | Defense Evasion | Anti-forensic commands: `rm -rf`, `history -c`, `unset HISTFILE`, `shred`, `export HISTFILE=/dev/null`. |
| **T1046** | Network Service Discovery | Discovery | Network scanning commands: `netstat`, `ss`, `nmap`, `arp -a`, `ifconfig`, `ip a`. |
| **T1190** | Exploit Public-Facing Application | Initial Access | Directory traversal (`../`, `..\`), web scanner User-Agents (`nikto`, `sqlmap`), SQLi probes. |
| **T1552.001** | Credentials in Files: Local Environment | Credential Access | Probes against `/.env`, `/.env.local`, AWS secret patterns, config files. |

---

## 📊 Real-Time SOC Dashboard

The built-in single-page dashboard (`http://localhost:9090`) features:

1. **Global Deception Radar:** Interactive dark-mode world map (Leaflet.js) rendering real-time pulsating red markers at attacker geocoordinates.
2. **Real-Time Attack Ingestion Pipeline:** WebSocket-driven telemetry table showing live timestamps, attacker IPs, target service, payloads, and MITRE badges.
3. **MITRE ATT&CK Tactics Breakdown:** Visual distribution bars highlighting current attacker focus (Brute Force vs Recon vs Execution).
4. **Terminal Session Replayer:** Click **"Replay"** on any captured SSH intrusion to launch an embedded CRT hacker terminal modal and watch the exact keystroke playback with authentic typing speed.

---

## 🛠️ REST & WebSocket API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/` | `GET` | Serves the interactive dark-mode SOC dashboard |
| `/api/v1/health` | `GET` | Returns sensor health status and active port matrix |
| `/api/v1/stats` | `GET` | Aggregated intrusion counts, unique IPs, and MITRE distributions |
| `/api/v1/attacks/recent` | `GET` | Retrieve the latest 50 logged intrusion events |
| `/api/v1/session/{id}/replay` | `GET` | Delivers raw keystroke and timing events from `recordings/` |
| `/api/v1/feed/firewall.txt` | `GET` | Plain-text CIDR blocklist for pfSense / OPNsense / iptables |
| `/api/v1/feed/stix.json` | `GET` | OASIS STIX 2.1 JSON threat intelligence bundle |
| `/ws/attacks` | `WebSocket` | Bi-directional streaming channel for real-time attack notifications |

---

## 🧪 Automated Attack Verification Suite

The repository includes a comprehensive multi-protocol attack simulator in `tests/test_harness.py`:

```bash
# Execute standalone test harness
python tests/test_harness.py

# Or run via pytest
pytest tests/test_harness.py -v
```

The harness automatically:
1. Attacks the HTTP decoy, checks `/.env` leak lure, `/wp-login.php` brute force, and triggers the 10MB Gzip defense bomb.
2. Connects to FTP (2121), tests banner negotiation and credential harvesting.
3. Connects to Telnet (2323), simulates Mirai IoT botnet credential spray.
4. Spawns an interactive SSH session (2222), executes commands (`whoami`, `uname -a`, `cat /etc/passwd`), and verifies keystroke logging.
5. Verifies API statistics, MITRE technique tagging, CIDR feeds, and STIX 2.1 compliance.

---

## 📁 Repository File Structure

```text
honeypot-system/
├── core/
│   ├── __init__.py
│   ├── config.py             # Pydantic-settings configuration with env overrides
│   ├── database.py           # Async SQLite engine (aiosqlite) with automated migrations
│   └── classifier.py         # MITRE ATT&CK regex & heuristic categorization engine
├── services/
│   ├── __init__.py
│   ├── ssh_service.py        # Paramiko SSH decoy: in-memory pseudo-shell & TTY session logger
│   ├── http_service.py       # Async HTTP trap: fake admin, .env leak, tarpit & gzip defense
│   ├── ftp_service.py        # Async FTP trap for brute-force credential harvesting
│   └── telnet_service.py     # Async Telnet IoT decoy mimicking BusyBox / Mirai vectors
├── api/
│   ├── __init__.py
│   ├── server.py             # FastAPI backend with WebSocket hub for real-time telemetry
│   ├── feed.py               # Threat Intel feeds: STIX 2.1 JSON and plain-text CIDR blocklists
│   └── static/
│       ├── index.html        # Dark-mode dashboard (Tailwind CSS CDN + Leaflet.js radar map)
│       ├── app.js            # WebSocket client, live attack stream, and terminal replay modal
│       └── style.css         # Custom animations (pulsing radar dots, glowing terminal styling)
├── recordings/               # Directory for storing raw JSON attacker keystroke sessions
├── tests/
│   ├── __init__.py
│   └── test_harness.py       # Automated multi-protocol attack simulator & test suite
├── docker-compose.yml        # Port mappings (22, 80, 21, 23, 9090), volumes, persistent storage
├── Dockerfile                # Multi-stage lightweight Python 3.11/3.12 container
├── main.py                   # Production launcher
├── requirements.txt          # Explicit, pinned dependencies
└── README.md                 # Project documentation & integration guides
```

---

## ⚙️ Environment Configuration

Configuration variables can be overridden via environment variables or a `.env` file:

```env
SSH_PORT=2222
HTTP_PORT=8080
FTP_PORT=2121
TELNET_PORT=2323
API_PORT=9090
DB_PATH=data/honeypot.db
RECORDINGS_DIR=recordings
TARPIT_ENABLED=true
TARPIT_BYTE_RATE=10
MALICIOUS_IP_THRESHOLD=5
SENSOR_NAME=honeypot-node-01
```

---

## ⚖️ Legal & Ethical Notice

This software is designed solely for defensive cybersecurity research, threat intelligence collection, authorized penetration testing simulation, and network hardening. Deploy only on networks, cloud instances, and infrastructure you own or have explicit authorization to monitor.

---

<div align="center">
  <b>Honeypot-System v2.0</b> • Engineered for Resilience, Threat Visibility, and Defense Automation.
</div>
