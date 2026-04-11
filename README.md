# 🛡️ HoneypotNet — Multi-Service Honeypot System

> **Capture, analyse, and alert on attacker behaviour in real time.**

HoneypotNet deploys four emulated vulnerable services — **SSH, HTTP, FTP, and Telnet** — to attract malicious actors and record everything they do: credentials tried, commands executed, payloads uploaded, and scanner probes.  A web-based admin dashboard lets you filter, search, and export the captured data.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT**: This software is provided strictly for **authorised security research, education, and defensive purposes**.  Deploying a honeypot may have legal implications depending on your jurisdiction.  You are solely responsible for ensuring your usage complies with all applicable laws and regulations.
>
> - Do **not** deploy on networks you do not own or have explicit written permission to monitor.
> - Do **not** use captured data to launch offensive actions.
> - Consult legal counsel before deploying in a production environment.

---

## 📁 Project Structure

```
honeypot-system/
├── main.py                     # Monolith launcher (all services in threads)
├── config.yaml                 # Central configuration (API keys, ports, etc.)
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Monolith Docker image
├── docker-compose.yml          # Multi-container orchestration
├── .gitignore
│
├── core/                       # Shared infrastructure
│   ├── __init__.py
│   ├── config_loader.py        # YAML config singleton
│   ├── logger.py               # SQLite central logger
│   ├── geoip.py                # ip-api.com geolocation
│   ├── threat_intel.py         # AbuseIPDB lookup
│   ├── alerting.py             # Email + Telegram alerts
│   ├── rate_limiter.py         # Per-IP sliding-window limiter
│   └── enrichment.py           # Geo + TI + DB + alert in one call
│
├── honeypots/                  # Emulated vulnerable services
│   ├── __init__.py
│   ├── ssh_honeypot.py         # Paramiko SSH server
│   ├── http_honeypot.py        # Flask HTTP server
│   ├── ftp_honeypot.py         # Raw-socket FTP server
│   └── telnet_honeypot.py      # Raw-socket Telnet server
│
├── admin/                      # Web admin panel
│   ├── __init__.py
│   ├── app.py                  # Flask dashboard app
│   └── templates/
│       ├── login.html
│       └── dashboard.html
│
├── docker/                     # Per-service Dockerfiles
│   ├── Dockerfile.ssh
│   ├── Dockerfile.http
│   ├── Dockerfile.ftp
│   ├── Dockerfile.telnet
│   └── Dockerfile.admin
│
├── tests/
│   └── test_honeypots.py       # Unit + integration tests
│
├── data/                       # Runtime data (auto-created)
│   ├── honeypot.db             # SQLite database
│   ├── ssh_host_key            # Auto-generated RSA key
│   └── uploads/                # Files uploaded via HTTP honeypot
│
└── logs/                       # Rotating text log files
    └── honeypot.log
```

---

## 🚀 Quick Start

### Option A — Run Locally (Development)

```bash
# 1. Clone and enter the project
git clone <your-repo-url> && cd honeypot-system

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Edit configuration
cp config.yaml config.yaml.bak
# Edit config.yaml — set your AbuseIPDB key, Telegram bot token, etc.

# 5. Launch all services
python main.py
```

Services will start on the ports defined in `config.yaml`:

| Service  | Default Port |
|----------|-------------|
| SSH      | 2222        |
| HTTP     | 8080        |
| FTP      | 2121        |
| Telnet   | 2323        |
| Admin UI | 5000        |

### Option B — Docker Compose (Production)

```bash
# 1. Edit config.yaml with your API keys

# 2. Build and launch all containers
docker-compose up -d --build

# 3. Tail logs
docker-compose logs -f

# 4. Stop everything
docker-compose down
```

---

## 🖥️ Admin Dashboard

Navigate to `http://localhost:5000` and log in with the credentials from `config.yaml` (default: `admin` / `honeypot_admin_2024`).

**Features:**
- 📊 Summary cards (total events, unique IPs, per-service counts)
- 🔍 Filters by service, source IP, date range
- 📄 Paginated event table
- 📥 CSV export of filtered results
- 🌍 Geolocation data (country, city)
- ⚠️ AbuseIPDB confidence scores

---

## 🔔 Alerting

### Email (SMTP)

Set `alerting.email.enabled: true` in `config.yaml` and configure your SMTP server.  For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833).

### Telegram Bot

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token.
2. Get your chat ID by messaging [@userinfobot](https://t.me/userinfobot).
3. Set `alerting.telegram.enabled: true` and fill in `bot_token` + `chat_id`.

Alerts are **rate-limited per IP** (configurable `cooldown_seconds`) to prevent flooding.

---

## 🌍 Geolocation & Threat Intel

| Feature       | Provider      | Free Tier                |
|---------------|---------------|--------------------------|
| Geolocation   | ip-api.com    | 45 req/min, no key       |
| Threat Intel  | AbuseIPDB     | 1 000 checks/day (free)  |

Both modules cache results in-memory (LRU) to minimise API calls.

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=core --cov=honeypots --cov=admin
```

The test suite includes:
- **Unit tests** for the logger, geoIP, threat intel, rate limiter, and alerting modules
- **Integration tests** that start each honeypot on high ports and verify protocol behaviour
- **Admin dashboard tests** using Flask's test client

---

## 🛡️ Anti-Detection Features

- **Realistic banners**: SSH, FTP, and HTTP headers mimic real production software versions.
- **Believable shell**: SSH and Telnet return realistic responses to `id`, `uname`, `ls`, `cat /etc/passwd`, etc.
- **Fake directory listings**: FTP serves plausible file listings with enticing filenames (`database.sql`, `.htpasswd`).
- **Scanner traps**: HTTP honeypot exposes `/robots.txt` with "forbidden" paths, `.env`, `/phpmyadmin`, `/.git/config`.
- **Rate limiting**: Avoids appearing as a black-hole that accepts infinite connections.

---

## 📋 Configuration Reference

| Key                          | Description                              | Default                 |
|------------------------------|------------------------------------------|-------------------------|
| `general.database_path`      | SQLite file path                         | `data/honeypot.db`      |
| `general.log_level`          | Logging verbosity                        | `INFO`                  |
| `services.<svc>.port`        | Listening port for each honeypot         | See `config.yaml`       |
| `geoip.rate_limit_per_minute`| Max ip-api.com requests/min              | 45                      |
| `threat_intel.abuseipdb_api_key` | Your AbuseIPDB API key               | *(placeholder)*         |
| `alerting.cooldown_seconds`  | Min seconds between alerts per IP        | 300                     |
| `rate_limiting.max_connections`| Max conns/IP within the window          | 30                      |

---

## 📦 Database Schema

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,    -- ISO-8601 UTC
    src_ip      TEXT    NOT NULL,
    service     TEXT    NOT NULL,    -- ssh | http | ftp | telnet
    action      TEXT    NOT NULL,
    payload     TEXT,               -- JSON blob
    geo_country TEXT,
    geo_city    TEXT,
    geo_lat     REAL,
    geo_lon     REAL,
    abuse_score INTEGER DEFAULT -1
);
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a Pull Request

---

## 📜 License

This project is released under the **MIT License**.  See [LICENSE](LICENSE) for details.

---

*Built for defenders.  Stay safe.  🛡️*
