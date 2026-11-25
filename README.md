<div align="center">

# 🍯 Honeypot-System v2.0 Enterprise
### Autonomous Multi-Service Deception Grid & Real-Time Threat Intelligence Pipeline

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker Ready](https://img.shields.io/badge/docker-compose%20ready-2496ED.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1%20Mapped-red.svg?style=for-the-badge)](https://attack.mitre.org/)
[![STIX 2.1](https://img.shields.io/badge/Threat%20Intel-STIX%202.1-orange.svg?style=for-the-badge)](https://oasis-open.github.io/cti-documentation/)
[![Snort & Suricata](https://img.shields.io/badge/NIDS%20Signatures-Snort%20%7C%20Suricata-yellow.svg?style=for-the-badge)](https://suricata.io/)

<p align="center">
  <b>Production-Grade Deception Engineering & Autonomous SIEM/SOC Threat Pipeline.</b><br>
  Honeypot-System v2.0 Enterprise deploys medium-interaction decoys across <b>SSH (Stateful Linux VFS), HTTP, FTP, and Telnet</b> to trap automated botnets, credential stuffers, and zero-day exploit attempts (<b>Log4Shell, XML-RPC, Spring4Shell</b>). Features an autonomous <b>Threat Actor Profiling & Risk Scoring engine</b>, an interactive <b>MITRE ATT&CK Matrix Navigator</b>, and live automated threat intelligence distribution via <b>pfSense/OPNsense CIDR blocklists, Snort/Suricata NIDS rules, ArcSight CEF syslog, and OASIS STIX 2.1 bundles</b>.
</p>

[Quick Start](#-quick-start) •
[Architecture](#-system-architecture) •
[Decoy Matrix](#-decoy-services-matrix) •
[Threat Intelligence Pipeline](#-threat-intelligence-pipeline) •
[MITRE ATT&CK Matrix](#-mitre-attck-matrix) •
[SOC Dashboard](#-real-time-soc-dashboard) •
[API Reference](#-rest--websocket-api-reference)

---

</div>

## 🚀 Enterprise Architectural Features

- ⚡ **Pure Asynchronous Core:** Network listeners (HTTP, FTP, Telnet), database persistence (`aiosqlite`), and WebSocket broadcasts are non-blocking with per-connection socket failure isolation.
- 🐚 **Stateful Linux Virtual File System (VFS):** Interactive emulated Ubuntu TTY shell (`root@ubuntu-server-01:~#`) powered by Paramiko. Supports dynamic `cd`, `ls -la`, `cat`, `touch`, `mkdir`, `rm`, command redirection (`echo payload > /tmp/evil.sh`), and session keystroke replay.
- 🌐 **Multi-Surface Web Traps & Active Defense:**
  - Traps `/.env` cloud credentials, `/wp-login.php`, WordPress XML-RPC multicall attacks (`/xmlrpc.php`), and Spring Boot `/actuator/health`.
  - Intercepts **Log4j JNDI injection attempts** (`${jndi:ldap://...}`) across all headers and query parameters.
  - Neutralizes scrapers with **10-byte/sec streaming tarpits** and blasts scanner crawlers (`sqlmap`, `nikto`) with a safe **10MB gzip decompression bomb**.
- 🔬 **Threat Actor Profiler & Dynamic Risk Index:**
  - Classifies attacker signatures into botnet families (**Mirai**, **Gafgyt/BASHLITE**, **Log4j Weaponization**, **Mass Scanners**).
  - Algorithmic Threat Risk Score (`0–100`) based on vector weaponization, credential stuffing, and command sequence depth.
- 📡 **Multi-Standard Threat Intelligence Pipeline:**
  - `GET /api/v1/feed/firewall.txt`: Plain-text `<ip>/32` CIDR blocklist for pfSense, OPNsense, FortiOS, and iptables.
  - `GET /api/v1/feed/stix.json`: OASIS STIX 2.1 compliant JSON threat bundle.
  - `GET /api/v1/feed/snort.rules`: Automated Snort & Suricata NIDS rule signatures.
  - `GET /api/v1/feed/iocs.json`: Machine-readable IOC feed for OpenCTI, MISP, and Cortex XSOAR.
  - `GET /api/v1/feed/syslog.cef`: ArcSight Common Event Format (CEF) / RFC 5424 export.
- 🖥️ **Military-Grade SOC Radar Dashboard:**
  - Real-time dark Leaflet.js radar map with pulsating threat blips.
  - Interactive **MITRE ATT&CK Matrix Navigator** with live illuminated threat cells.
  - **Attacker Threat Dossier Modal:** Click any IP to inspect full activity timeline, targeted ports, credential spray list, and risk ratings.
  - In-browser retro CRT terminal keystroke playback modal.

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
   │ (Stateful VFS│  │ (Log4j, .env,│       │  (RFC 959    │       │  (RFC 854    │  │ (Tarpit &    │
   │ Pseudo-TTY)  │  │  XML-RPC)    │       │  ProFTPD)    │       │  Mirai IoT)  │  │  Gzip Bomb)  │
   └──────┬───────┘  └──────┬───────┘       └──────┬───────┘       └──────┬───────┘  └──────┬───────┘
          │                 │                      │                      │                 │
          └─────────────────┴──────────────────────┼──────────────────────┴─────────────────┘
                                                   │ Raw Payloads & Credentials
                                                   ▼
                                    ┌─────────────────────────────┐
                                    │    MITRE ATT&CK Engine      │
                                    │  - Heuristic Classification │
                                    │  - Botnet Fingerprinting    │
                                    │  - Risk Score (0-100)       │
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
          │  - MITRE Matrix Navigator   │                     │ - /feed/snort.rules (NIDS)  │
          │  - Threat Dossier Modal     │                     │ - /feed/iocs.json (OpenCTI) │
          │  - Keystroke Session Player │                     │ - /feed/syslog.cef (ArcSight)│
          └─────────────────────────────┘                     └─────────────────────────────┘
```

---

## ⚡ Quick Start

### 1. One-Click Deployment (Docker Compose)

Deploy the entire deception grid and SOC dashboard with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/yashwantraj147-eng/honeypot-system.git
cd honeypot-system

# Build and start all services in detached mode
docker compose up --build -d
```

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
| **SSH** | `22` / `2222` | `Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0)` | Brute-force auth, shell reconnaissance (`whoami`, `uname -a`, `cat /etc/passwd`, `wget`), file manipulation | Stateful in-memory Virtual File System (VFS), directory navigation (`cd`), file redirection (`echo > file`), keystroke recording |
| **HTTP** | `80` / `8080` | `nginx/1.22.1 (Ubuntu)` | `/.env` leaks, `/wp-login.php`, `/xmlrpc.php`, Log4j JNDI (`${jndi:...}`), Spring Actuator, directory traversal | 10 B/s streaming tarpit for scrapers; 10MB gzip bomb against scanner directory traversals |
| **FTP** | `21` / `2121` | `220 ProFTPD 1.3.5 Server (Ubuntu)` | Anonymous login, dictionary brute-force, `USER`/`PASS` harvesting | Harvests credentials, returns realistic `530 Login incorrect` error codes |
| **Telnet** | `23` / `2323` | `Ubuntu 22.04.3 LTS login:` | Mirai / BusyBox IoT botnets, default credential spraying (`root/xc3511`) | Negotiates RFC 854 IAC sequences, captures username/password combos |

---

## 🛡️ Threat Intelligence Pipeline

Honeypot-System v2.0 Enterprise automatically promotes malicious actors (`MALICIOUS_IP_THRESHOLD >= 5`) into 5 enterprise threat feeds:

### 1. Firewall Ingestion (`/api/v1/feed/firewall.txt`)
Plain-text CIDR blocklist (`<ip>/32\n`) for **pfSense**, **OPNsense**, **FortiOS**, and **iptables**.

### 2. SIEM & SOAR Integration (`/api/v1/feed/stix.json`)
Compliant with **OASIS STIX 2.1 Specification**. Direct ingestion into **Splunk Enterprise Security**, **Elastic Security**, and **Microsoft Sentinel**.

### 3. Automated NIDS Rules (`/api/v1/feed/snort.rules`)
Dynamically generated Snort & Suricata rule signatures:
```snort
alert ip 198.51.100.22 any -> $HOME_NET any (msg:"HONEYPOT-DETECTED Known Threat Actor [198.51.100.22]"; classtype:trojan-activity; sid:3900001; rev:1;)
```

### 4. Structured IOC Feed (`/api/v1/feed/iocs.json`)
JSON indicators for **MISP**, **OpenCTI**, and **Cortex XSOAR** with threat actor fingerprint, risk score, and defanged observables.

### 5. ArcSight CEF Syslog (`/api/v1/feed/syslog.cef`)
ArcSight Common Event Format export for enterprise SIEMs:
```cef
CEF:0|Honeypot-System|DeceptionGrid|2.0|T1190|Exploit Public-Facing Application|10|src=198.51.100.22 proto=HTTP cs1Label=Fingerprint cs1=Log4j Weaponization cn1Label=RiskScore cn1=85
```

---

## 🔍 MITRE ATT&CK Matrix

| Technique ID | Technique Name | Tactic | Trigger Patterns / Detection Logic |
| :--- | :--- | :--- | :--- |
| **T1110.001** | Password Guessing (Brute Force) | Credential Access | Rapid authentication attempts on SSH, Telnet, FTP, or HTTP `/wp-login.php`. |
| **T1110.003** | Password Spraying (Botnet Combos) | Credential Access | Known Mirai/Gafgyt default combos (`root/xc3511`, `vizxv`, `support`). |
| **T1059.004** | Unix Shell Execution | Execution | Shell invocations (`sh`, `bash`, `python`), chained commands (`&&`, `\|`, `;`). |
| **T1082** | System Information Discovery | Discovery | Commands including `uname -a`, `lscpu`, `df -h`, `cat /etc/*release`, `/actuator/health`. |
| **T1087.001** | Local Account Discovery | Discovery | Attacker commands `whoami`, `id`, `cat /etc/passwd`, `cat /etc/shadow`, `w`, `last`. |
| **T1105** | Ingress Tool Transfer | Command & Control | Download utilities: `wget`, `curl`, `tftp`, `sftp`, `busybox wget`, `scp`, `nc`. |
| **T1070.004** | Indicator Removal: File Deletion | Defense Evasion | Anti-forensic commands: `rm -rf`, `history -c`, `unset HISTFILE`, `shred`. |
| **T1046** | Network Service Discovery | Discovery | Scanning commands: `netstat`, `ss`, `nmap`, `arp -a`, `ifconfig`, `ip a`. |
| **T1190** | Exploit Public-Facing Application | Initial Access | Directory traversal (`../`), Log4Shell (`${jndi:...}`), XML-RPC multicalls, SQLi probes. |
| **T1552.001** | Credentials in Files | Credential Access | Probes against `/.env`, `/.env.local`, AWS secret patterns, config files. |

---

## 📊 Real-Time SOC Dashboard

1. **Global Cyber Deception Radar:** Interactive dark-mode world map (Leaflet.js) rendering real-time pulsating markers color-coded by Threat Risk Severity (Red = Critical, Orange = Elevated, Cyan = Low).
2. **Interactive MITRE ATT&CK Matrix Navigator:** Six tactic columns with dynamically illuminated cells that glow on active attack detection.
3. **Attacker Threat Dossier Modal:** Click any IP to open an interactive threat actor profile detailing targeted ports, observed credential spray history, threat fingerprints, and timeline.
4. **Terminal Session Keystroke Replayer:** In-browser retro CRT terminal modal with authentic typing animations, scanline effects, and playback controls.

---

## 🛠️ REST & WebSocket API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/` | `GET` | Serves the interactive dark-mode SOC dashboard |
| `/api/v1/health` | `GET` | Returns sensor health status and active port matrix |
| `/api/v1/stats` | `GET` | Aggregated intrusion counts, risk scores, botnet fingerprints, and MITRE distributions |
| `/api/v1/attacks/recent` | `GET` | Retrieve the latest 50 logged intrusion events |
| `/api/v1/attacker/{ip}` | `GET` | Detailed Threat Actor Dossier for an individual IP |
| `/api/v1/session/{id}/replay` | `GET` | Delivers raw keystroke and timing events from `recordings/` |
| `/api/v1/feed/firewall.txt` | `GET` | Plain-text CIDR blocklist for pfSense / OPNsense / iptables |
| `/api/v1/feed/stix.json` | `GET` | OASIS STIX 2.1 JSON threat intelligence bundle |
| `/api/v1/feed/snort.rules` | `GET` | Automated Snort / Suricata NIDS rule signatures |
| `/api/v1/feed/iocs.json` | `GET` | Structured IOC feed for MISP / OpenCTI |
| `/api/v1/feed/syslog.cef` | `GET` | ArcSight Common Event Format (CEF) syslog feed |
| `/ws/attacks` | `WebSocket` | Bi-directional streaming channel for real-time attack notifications |

---

## 🧪 Automated Attack Verification Suite

```bash
# Execute standalone test harness
python tests/test_harness.py

# Or run via pytest
pytest tests/test_harness.py -v
```

---

<div align="center">
  <b>Honeypot-System v2.0 Enterprise</b> • Engineered for Resilience, Threat Visibility, and Defense Automation.
</div>
