# Linux SSH Security Monitor

A high-performance, production-ready Linux SSH security monitoring and intrusion detection system built with Python 3.12+, FastAPI, systemd journald integration, SQLite (WAL mode), WebSocket alerts, and a real-time cybersecurity dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.12+](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)](https://www.python.org/)
[![Target: Debian/Ubuntu](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-orange.svg)](https://ubuntu.com/)

---

## 1. Architecture Overview

The system runs on Debian and Ubuntu Linux servers, continuously ingesting OpenSSH authentication logs directly from `systemd-journald` via `journalctl` in streaming follow mode (with zero busy loops and automatic crash recovery).

```
 ┌─────────────────────────────────────────────────────────────┐
 │                      Linux Operating System                 │
 │                                                             │
 │   OpenSSH Server (sshd/ssh.service)                         │
 │         │                                                   │
 │         ▼                                                   │
 │   systemd-journald                                          │
 └─────────┬───────────────────────────────────────────────────┘
           │
           │ journalctl -u ssh[d] -f -o json (safe subprocess)
           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │               SSH Security Monitor (app/)                   │
 │                                                             │
 │   ┌──────────────────────┐      ┌─────────────────────────┐ │
 │   │  Journal Collector   │ ───► │     SSH Log Parser      │ │
 │   └──────────────────────┘      └────────────┬────────────┘ │
 │                                              │              │
 │                                              ▼              │
 │   ┌──────────────────────┐      ┌─────────────────────────┐ │
 │   │   Detection Engine   │ ◄─── │ Normalized Security Ev. │ │
 │   │ (Rules 001 - 006)    │      └────────────┬────────────┘ │
 │   └──────────┬───────────┘                   │              │
 │              │ Alerts                        │ Events       │
 │              ▼                               ▼              │
 │   ┌──────────────────────┐      ┌─────────────────────────┐ │
 │   │    Alert Manager     │      │   SQLite Database (WAL) │ │
 │   └──────────┬───────────┘      │   events, alerts,       │ │
 │              │                  │   known_sources, users  │ │
 │              ▼                  └─────────────────────────┘ │
 │   ┌──────────────────────┐                   ▲              │
 │   │  WebSocket Manager   │                   │              │
 │   │  /ws/alerts          │                   │ Queries      │
 │   └──────────┬───────────┘                   │              │
 └──────────────┼───────────────────────────────┼──────────────┘
                │ Real-time                     │ REST API
                ▼                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │        Web Dashboard & Client Applications                  │
 │   (NOC UI, Live Event Stream, Alerts Triage, CLI Tool)      │
 └─────────────────────────────────────────────────────────────┘
```

### Key Architectural Safeguards
- **Event / Alert Separation**: An **Event** represents observed raw authentication activity. An **Alert** represents an actionable security detection. Events are never modified or purged when alerts fire.
- **Least Privilege Execution**: Runs under a dedicated unprivileged user (`sshmon`), accessing systemd journal logs via Linux supplementary group membership (`systemd-journal`). Root execution is disallowed in production.
- **Safe Subprocess Management**: Executes argument arrays directly through `asyncio.create_subprocess_exec` without `shell=True`, eliminating shell injection risks.
- **Bounded State & Memory**: Sliding detection windows automatically expire historical entries outside their time bounds, preventing unbounded memory growth.

---

## 2. Project Directory Tree

```
ssh-security-monitor/
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 001_initial_schema.py
├── alembic.ini
├── app/
│   ├── __init__.py
│   ├── main.py                     # FastAPI application & lifecycle
│   ├── config.py                   # Pydantic Settings & YAML loader
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py                 # JWT & bcrypt authentication
│   │   ├── routes_health.py        # /api/health & /api/config
│   │   ├── routes_events.py        # /api/events (filtering & pagination)
│   │   ├── routes_alerts.py        # /api/alerts (ack & resolve)
│   │   ├── routes_stats.py         # /api/statistics metrics
│   │   ├── routes_sources.py       # /api/sources known IP tracking
│   │   └── routes_maintenance.py   # /api/maintenance/cleanup
│   ├── collector/
│   │   ├── __init__.py
│   │   └── journal.py              # systemd journalctl streaming collector
│   ├── parser/
│   │   ├── __init__.py
│   │   └── ssh_parser.py           # IPv4/IPv6 OpenSSH message parser
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── engine.py               # Rule orchestration engine
│   │   └── rules.py                # RULE-001 through RULE-006 definitions
│   ├── database/
│   │   ├── __init__.py
│   │   ├── database.py             # SQLite WAL engine & session manager
│   │   └── models.py               # SQLAlchemy 2.x declarative models
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── manager.py              # Alert persistence & dispatch
│   ├── websocket/
│   │   ├── __init__.py
│   │   └── manager.py              # WebSocket connection manager
│   ├── services/
│   │   ├── __init__.py
│   │   └── monitor.py              # Central background orchestrator
│   └── cli/
│       ├── __init__.py
│       └── commands.py             # Typer / Rich CLI commands
├── frontend/
│   ├── index.html                  # Cyber NOC Web Dashboard
│   ├── css/
│   │   └── dashboard.css           # Responsive dark theme styling
│   └── js/
│       └── dashboard.js            # WebSocket client & REST binding
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # Pytest SQLite in-memory fixtures
│   ├── fixtures/
│   │   └── sample_auth_logs.json   # Synthetic OpenSSH log samples
│   ├── test_parser.py              # Parser unit tests
│   ├── test_detection.py           # Detection rule tests
│   ├── test_database.py            # SQLite operations & retention tests
│   ├── test_api.py                 # REST endpoints & auth tests
│   └── test_websocket.py           # WebSocket tests
├── systemd/
│   └── ssh-security-monitor.service # Hardened Linux service unit
├── scripts/
│   ├── install.sh                  # Automated Debian/Ubuntu installer
│   └── uninstall.sh                # Safe uninstaller (preserves data)
├── config.yaml                     # Application settings & thresholds
├── requirements.txt                # Python dependencies
├── pyproject.toml                  # Packaging & project metadata
├── .env.example                    # Template environment variables
├── README.md                       # Documentation
└── LICENSE                         # MIT License
```

---

## 3. Database Schema

Managed via SQLAlchemy 2.x and Alembic with SQLite configured in `WAL` mode (`PRAGMA journal_mode=WAL;`), `foreign_keys=ON`, and `busy_timeout=5000ms`.

### `events`
Stores every normalized SSH authentication attempt and session lifecycle event:
- `id`: Integer primary key (autoincrement)
- `timestamp`: DateTime with UTC timezone (Indexed)
- `event_type`: String (AUTH_FAILURE, AUTH_SUCCESS_PASSWORD, AUTH_SUCCESS_PUBLICKEY, INVALID_USER, SESSION_OPEN, SESSION_CLOSE, DISCONNECT, UNKNOWN_SSH_EVENT) (Indexed)
- `username`: String (Indexed)
- `source_ip`: String (IPv4 or IPv6) (Indexed)
- `source_port`: Integer
- `service`: String (default: `sshd`)
- `hostname`: String
- `raw_message`: Text
- `parser_confidence`: String (HIGH, MEDIUM, LOW)
- `created_at`: DateTime (UTC)
- **Composite Indexes**: `(timestamp, event_type)`, `(source_ip, timestamp)`

### `alerts`
Stores actionable alerts triggered by the detection engine:
- `id`: Integer primary key (autoincrement)
- `timestamp`: DateTime with UTC timezone (Indexed)
- `rule_id`: String (e.g. `RULE-001`) (Indexed)
- `alert_type`: String (Indexed)
- `severity`: String (CRITICAL, HIGH, MEDIUM, LOW, INFO) (Indexed)
- `source_ip`: String (Indexed)
- `username`: String
- `description`: Text
- `evidence`: JSON structured diagnostic data
- `status`: String (`active`, `acknowledged`, `resolved`) (Indexed)
- `created_at` / `updated_at`: DateTime (UTC)
- **Composite Indexes**: `(status, timestamp)`, `(source_ip, rule_id)`

### `known_sources`
Tracks distinct connecting IP addresses:
- `id`: Integer primary key
- `source_ip`: String (Unique index)
- `first_seen`: DateTime (UTC)
- `last_seen`: DateTime (UTC)
- `event_count`: Integer

### `users`
Administrative credentials for dashboard and API authentication:
- `id`: Integer primary key
- `username`: String (Unique index)
- `hashed_password`: String (bcrypt hashed)
- `is_active` / `is_admin`: Boolean

---

## 4. Detection Engine Rules

| Rule ID | Name | Default Condition | Severity | Cooldown |
| :--- | :--- | :--- | :--- | :--- |
| **RULE-001** | SSH Brute-Force Candidate | $\ge 5$ failed authentications from same IP in $120\text{s}$ | **HIGH** | $300\text{s}$ |
| **RULE-002** | Multiple Usernames Targeted | $\ge 3$ distinct usernames targeted from same IP in $180\text{s}$ | **HIGH** | $300\text{s}$ |
| **RULE-003** | Suspicious Auth Success | $\ge 3$ failures followed by accepted login from same IP in $300\text{s}$ | **CRITICAL** | $600\text{s}$ |
| **RULE-004** | Privileged Root Login | Successful login (password/pubkey) for user `root` | **MEDIUM** | $60\text{s}$ |
| **RULE-005** | New SSH Source | First connection attempt from an unseen remote IP address | **INFO** | $3600\text{s}$ |
| **RULE-006** | Auth Failure Burst | $\ge 15$ system-wide authentication failures in $60\text{s}$ | **CRITICAL** | $300\text{s}$ |

All rule thresholds, sliding window intervals, and severities are configurable via `config.yaml` or `.env`.

---

## 5. Automated Installation (Debian / Ubuntu)

Clone the repository on your target Debian 12 or Ubuntu 22.04 / 24.04 server:

```bash
git clone https://github.com/security/ssh-security-monitor.git
cd ssh-security-monitor

# Run automated installer as root
sudo ./scripts/install.sh
```

The installer will:
1. Verify OS and Python 3.12+ compatibility.
2. Create dedicated system user `sshmon` and add to group `systemd-journal`.
3. Create `/opt/ssh-security-monitor` and `/var/log/ssh-security-monitor`.
4. Create Python virtual environment and install dependencies.
5. Initialize the database schema via Alembic.
6. Generate a random JWT secret and initial administrator credentials.
7. Install, enable, and start `ssh-security-monitor.service`.

### Check Service Status
```bash
sudo systemctl status ssh-security-monitor
```

### Accessing Dashboard & API
- **Web Dashboard**: `http://<SERVER_IP>:8000/`
- **API Health Check**: `http://<SERVER_IP>:8000/api/health`
- **Swagger Documentation**: `http://<SERVER_IP>:8000/docs`

---

## 6. Development & Local Setup

To run locally for testing or development:

```bash
# 1. Clone repository
git clone https://github.com/security/ssh-security-monitor.git
cd ssh-security-monitor

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with test dependencies
pip install -r requirements.txt
pip install -e .

# 4. Copy environment file
cp .env.example .env

# 5. Initialize database & provision default admin
python -c "from app.database.database import init_db; init_db()"
ssh-monitor create-user --username admin --password adminpassword123!

# 6. Start development server
ssh-monitor start --host 127.0.0.1 --port 8000 --reload
```

---

## 7. Automated Testing

Run the automated test suite using `pytest`:

```bash
# Activate virtual environment
source .venv/bin/activate

# Run test suite
pytest
```

Tests verify:
- Safe log parsing for IPv4, IPv6, preauth drops, PAM sessions, and malformed strings.
- Rule threshold evaluation, sliding window time expiration, and alert deduplication.
- SQLite transactions, PRAGMA verification, and retention cleanup.
- REST API pagination, filtering, and JWT authentication.
- WebSocket ping/pong and alert broadcasting.

---

## 8. CLI Administration

The `ssh-monitor` CLI provides complete runtime diagnostics and control:

```bash
# Display system health & journal availability
ssh-monitor health

# Display database metrics summary
ssh-monitor status

# Verify parser extraction against built-in fixtures or custom log
ssh-monitor test-parser
ssh-monitor test-parser --line "Failed password for root from 1.2.3.4 port 22 ssh2"

# Simulate attack scenarios through the detection engine
ssh-monitor test-detection

# Inspect recent events stored in database
ssh-monitor events --limit 25 --type AUTH_FAILURE

# Inspect recent alerts
ssh-monitor alerts --limit 10 --status active

# Manually trigger retention cleanup
ssh-monitor cleanup --events-days 30 --alerts-days 90

# Create or reset an administrator account
ssh-monitor create-user --username admin
```

---

## 9. Security Considerations

1. **No Root Requirement**: The application runs under user `sshmon`. Access to `/run/log/journal` is granted exclusively via the `systemd-journal` group.
2. **Strict Systemd Hardening**:
   - `ProtectSystem=strict`
   - `ProtectHome=read-only`
   - `NoNewPrivileges=true`
   - `PrivateTmp=true`
3. **HTTP Security Headers**: Enforced across all endpoints:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: SAMEORIGIN`
   - `Strict-Transport-Security`
   - `Content-Security-Policy`
4. **Parameterized SQL Queries**: All queries execute through SQLAlchemy 2.0 ORM expressions. Raw SQL string concatenation is strictly avoided.
5. **Detection Only**: The application operates in detection-only mode. It does not manipulate `iptables`, `nftables`, or `ufw` directly.

---

## 10. Troubleshooting

### Issue: `journalctl binary not found` or `Permission Denied`
**Cause**: The service user lacks permissions to inspect journal logs.
**Solution**: Ensure the application user belongs to `systemd-journal`:
```bash
sudo usermod -aG systemd-journal sshmon
sudo systemctl restart ssh-security-monitor
```

### Issue: `database is locked`
**Cause**: SQLite file concurrency lock.
**Solution**: The application automatically sets `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;`. Verify your data directory resides on a standard local filesystem (ext4/xfs) and not an NFS share.

---

## 11. Production-Readiness Verification

- [x] Application starts and binds to configured host/port
- [x] SQLite initializes with WAL mode and proper indexes
- [x] Alembic migrations configured and executable
- [x] SSH journal collector streams with auto-recovery
- [x] SSH parser handles IPv4, IPv6, and malformed strings
- [x] Detection rules RULE-001 through RULE-006 implemented
- [x] Events and Alerts strictly separated
- [x] REST API endpoints support pagination and filtering
- [x] Authentication enforced with bcrypt and signed JWTs
- [x] WebSocket `/ws/alerts` broadcasts real-time updates
- [x] Lightweight NOC Web Dashboard rendered
- [x] CLI commands (`start`, `health`, `events`, `alerts`, `cleanup`)
- [x] Systemd service file with security hardening
- [x] Automated install/uninstall scripts
- [x] Full automated test suite passes (`pytest`)
- [x] Zero TODOs or placeholder function

Submission:
  Srivishnuvardhan P
  RCAS2025BDC005
