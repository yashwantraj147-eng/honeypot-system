# 🛡️ HoneypotNet — Multi-Service Honeypot System

> **Capture, analyse, and alert on attacker behaviour in real time.**

[![CI](https://github.com/yashwantraj147-eng/honeypot-system/actions/workflows/ci.yml/badge.svg)](https://github.com/yashwantraj147-eng/honeypot-system/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/Security-Policy-blue.svg)](SECURITY.md)

HoneypotNet deploys four emulated vulnerable services — **SSH, HTTP, FTP, and Telnet** — to attract malicious actors and record their actions: credentials attempted, commands executed, payloads uploaded, and scanner probes. A web-based admin dashboard provides filtering, searching, and exporting of captured telemetry.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: This software is provided strictly for **authorised security research, education, and defensive purposes**. Deploying a honeypot may have legal implications depending on your jurisdiction. You are solely responsible for ensuring your usage complies with all applicable laws and regulations.
>
> - Do **not** deploy on networks you do not own or have explicit written permission to monitor.
> - Do **not** use captured data to launch offensive actions.
> - Consult legal counsel before deploying in a production environment.

---

## 📁 Project Structure

```
honeypot-system/
├── main.py                     # Monolith launcher (all services in threads)
├── config.example.yaml         # Configuration template (copy to config.yaml)
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Unprivileged non-root container image
├── docker-compose.yml          # Multi-container orchestration
├── SECURITY.md                 # Vulnerability disclosure policy
├── LICENSE                     # MIT License
├── .gitignore
│
├── core/                       # Shared infrastructure
│   ├── config_loader.py        # YAML config singleton with .env injection
│   ├── logger.py               # SQLite central logger & indexing
│   ├── geoip.py                # ip-api.com geolocation
│   ├── threat_intel.py         # AbuseIPDB lookup
│   ├── alerting.py             # Email + Telegram alerts
│   ├── rate_limiter.py         # Per-IP sliding-window limiter
│   └── enrichment.py           # Geo + TI + DB + alert pipeline
│
├── honeypots/                  # Emulated vulnerable services
│   ├── ssh_honeypot.py         # Paramiko SSH server
│   ├── http_honeypot.py        # Flask HTTP trap
│   ├── ftp_honeypot.py         # Raw-socket FTP server
│   └── telnet_honeypot.py      # Raw-socket Telnet server
│
├── admin/                      # Web admin panel
│   ├── app.py                  # Flask dashboard app (rate limited & localhost bound)
│   └── templates/
│       ├── login.html
│       └── dashboard.html
│
└── tests/
    └── test_honeypots.py       # Comprehensive unit + integration test suite
```

---

## 🚀 Quick Start

### Option A — Run Locally (Development)

```bash
# 1. Clone and enter the project
git clone https://github.com/yashwantraj147-eng/honeypot-system.git
cd honeypot-system

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your admin password and secrets
export HONEYPOT_ADMIN_PASSWORD="YourStrongPasswordHere"
export HONEYPOT_SECRET_KEY="A_Random_64_Character_Secret"

# Optional: configure config.yaml from template
cp config.example.yaml config.yaml

# 5. Launch all services
python main.py
```

Services will start on their configured ports:

| Service  | Port | Binding Default |
|----------|------|-----------------|
| SSH      | 2222 | `0.0.0.0` (Public trap) |
| HTTP     | 8080 | `0.0.0.0` (Public trap) |
| FTP      | 2121 | `0.0.0.0` (Public trap) |
| Telnet   | 2323 | `0.0.0.0` (Public trap) |
| Admin UI | 5000 | `127.0.0.1` (Localhost only) |

### Option B — Docker Compose (Production)

```bash
# 1. Copy template and edit configuration
cp config.example.yaml config.yaml

# 2. Launch containerized services with non-root security context
docker-compose up -d --build

# 3. Tail logs
docker-compose logs -f
```

---

## 🖥️ Admin Dashboard

Navigate to `http://127.0.0.1:5000`. Authenticate with your username (`admin`) and the password configured via `HONEYPOT_ADMIN_PASSWORD` (or set in `config.yaml`). If no password was configured, a secure random one-time password is generated on startup and printed to the server logs.

**Security Enhancements:**
- **Localhost Bound**: The management console binds to `127.0.0.1` by default to prevent exposing management endpoints on the honeypot interface.
- **Brute-Force Rate Limiting**: The login endpoint locks out IP addresses that exceed 5 failed attempts within 5 minutes.
- **Timing-Safe Auth**: Uses `hmac.compare_digest` to mitigate timing side-channel attacks during credential verification.

---

## 🔔 Alerting

### Email (SMTP)
Set `alerting.email.enabled: true` in `config.yaml` and configure your SMTP server.

### Telegram Bot
Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` as environment variables or specify them in `config.yaml`. Alerts are rate-limited per attacker IP (`cooldown_seconds: 300`) to avoid notification spam.

---

## 🧪 Testing

```bash
# Run the complete test suite
python -m unittest tests/test_honeypots.py

# Or run with pytest
pytest tests/ -v
```

---

## 📜 Security & Vulnerability Disclosure

For vulnerability reports and responsible disclosure, please consult [SECURITY.md](SECURITY.md).

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for full details.
