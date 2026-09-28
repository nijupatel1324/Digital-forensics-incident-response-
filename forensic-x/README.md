# 🔍 FORENSIC-X — Digital Forensics & Incident Response Platform

<div align="center">

![FORENSIC-X](https://img.shields.io/badge/FORENSIC--X-DFIR%20Platform-blue?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12+-green?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A professional, open-source Digital Forensics & Incident Response (DFIR) platform for authorized cybersecurity investigations.**

</div>

---

> ⚠️ **AUTHORIZED USE ONLY** — This platform is designed for authorized digital forensic investigations, incident response, and cybersecurity research on systems you own or have explicit permission to investigate. Never use it on systems without proper authorization.

---

## 📋 Features

| Module | Description |
|--------|-------------|
| 🔐 **Authentication** | JWT auth, Argon2 hashing, MFA, rate limiting, account lockout |
| 📁 **Case Management** | Full lifecycle case tracking with statuses, priorities, assignments |
| 🧪 **Evidence Management** | Register, store, and track digital evidence with full metadata |
| 🔒 **Evidence Integrity** | SHA-256 & SHA-512 hashing, tamper detection, integrity verification |
| ⛓️ **Chain of Custody** | Immutable audit trail for every evidence action |
| 🔬 **File Analysis** | Safe metadata extraction from authorized evidence files |
| 📊 **Log Analysis** | Parse Windows Event Logs, Linux auth logs, syslog, and more |
| 📅 **Timeline Engine** | Chronological event correlation and filtering |
| 🚨 **IOC Management** | Track IPs, domains, hashes, filenames, emails |
| ⚙️ **Detection Engine** | Configurable rule-based detection (brute-force, anomalies, etc.) |
| 📈 **Risk Scoring** | Transparent 0-100 risk scoring with contributing factors |
| 🔗 **Event Correlation** | Correlate events across users, IPs, files, processes, and cases |
| 🚒 **Incident Response** | Full IR workflow (Preparation → Lessons Learned) |
| ✅ **Task Management** | Assign and track investigation tasks |
| 📝 **Analyst Notes** | Per-case investigation notes with edit history |
| 📋 **Audit Logging** | Complete action audit trail with user, IP, timestamp |
| 📊 **SOC Dashboard** | Professional security dashboard with charts and metrics |
| 🔍 **Global Search** | Search across cases, evidence, IOCs, incidents, events |
| 📄 **Report Generator** | Generate PDF/HTML/JSON/CSV forensic reports |
| 🔑 **RBAC** | Role-based access: Administrator, Investigator, Responder, Auditor |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                    CLIENTS                       │
│         Browser (HTML/CSS/JS/Bootstrap)          │
└──────────────────────┬──────────────────────────┘
                       │ HTTPS
┌──────────────────────▼──────────────────────────┐
│                   NGINX                          │
│            Reverse Proxy / TLS                   │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│            FastAPI Application                   │
│   ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │
│   │  Auth   │ │  Cases  │ │    Evidence     │  │
│   │  RBAC   │ │  Tasks  │ │  Chain/Custody  │  │
│   └─────────┘ └─────────┘ └─────────────────┘  │
│   ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │
│   │Timeline │ │   IOCs  │ │   Detection     │  │
│   │ Engine  │ │   Mgmt  │ │    Engine       │  │
│   └─────────┘ └─────────┘ └─────────────────┘  │
│   ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │
│   │Incidents│ │ Reports │ │  Audit Logs     │  │
│   │   IR    │ │   PDF   │ │                 │  │
│   └─────────┘ └─────────┘ └─────────────────┘  │
└──────────────┬────────────────────┬─────────────┘
               │                    │
┌──────────────▼──────┐  ┌──────────▼────────────┐
│   PostgreSQL 16      │  │       Redis 7          │
│   Primary Database   │  │  Sessions/Cache/Limits │
└─────────────────────┘  └───────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend Framework** | FastAPI 0.115 + Python 3.12 |
| **ORM** | SQLAlchemy 2.0 (async) |
| **Database** | PostgreSQL 16 |
| **Cache / Rate Limit** | Redis 7 |
| **Migrations** | Alembic |
| **Auth** | JWT (python-jose) + Argon2 (passlib) |
| **MFA** | TOTP via pyotp |
| **Frontend** | HTML5 + Bootstrap 5 + Chart.js |
| **PDF Reports** | ReportLab / WeasyPrint |
| **Container** | Docker + Docker Compose |
| **Reverse Proxy** | Nginx 1.27 |
| **Testing** | pytest + pytest-asyncio + pytest-cov |
| **Logging** | structlog (JSON/console) |

---

## 📋 Prerequisites

### Windows

| Software | Minimum Version | Download |
|----------|----------------|---------|
| Python | 3.12+ | https://python.org |
| PostgreSQL | 16 | https://postgresql.org |
| Redis | 7 | https://redis.io (or use Docker) |
| Docker Desktop | Latest | https://docker.com |
| Git | 2.40+ | https://git-scm.com |

---

## 🚀 Quick Start (Local Development)

### 1. Clone the repository

```bash
git clone https://github.com/your-org/forensic-x.git
cd forensic-x
```

### 2. Create virtual environment

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Edit `.env` and update:
- `DATABASE_URL` — your PostgreSQL connection string
- `SECRET_KEY` — generate with: `python -c "import secrets; print(secrets.token_hex(32))"`
- `JWT_SECRET` — generate a second random key
- `ADMIN_EMAIL` and `ADMIN_PASSWORD`

### 5. Set up database

```bash
# Create PostgreSQL database
psql -U postgres -c "CREATE USER forensicx WITH PASSWORD 'your_password';"
psql -U postgres -c "CREATE DATABASE forensicx_db OWNER forensicx;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE forensicx_db TO forensicx;"

# Run migrations (Phase 2+)
alembic upgrade head

# Seed initial data (Phase 2+)
python scripts/seed_data.py
```

### 6. Run the application

```bash
python main.py
```

Or with uvicorn directly:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 7. Verify it's running

```
http://localhost:8000/              → Service info
http://localhost:8000/api/v1/health → Health check
http://localhost:8000/api/docs      → Swagger UI
```

---

## 🐳 Docker Setup

```bash
# Copy and edit environment file
copy .env.example .env

# Build and start all services
docker compose up --build

# Run in background
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f forensic-x-api

# Stop
docker compose down

# Stop and remove volumes (WARNING: deletes all data)
docker compose down -v
```

Services will be available at:
- **Platform**: http://localhost:80
- **API Docs**: http://localhost:80/api/docs
- **Health**: http://localhost:80/api/v1/health

---

## 🧪 Running Tests

```bash
# Activate virtual environment first
.\venv\Scripts\activate  # Windows

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_phase1_health.py -v

# Run with coverage report
pytest --cov=app --cov-report=html

# View coverage report
start htmlcov/index.html  # Windows
```

---

## 📁 Project Structure

```
forensic-x/
│
├── app/
│   ├── __init__.py
│   ├── main.py                 ← FastAPI app factory
│   ├── config.py               ← Settings (Pydantic)
│   │
│   ├── core/
│   │   ├── logging.py          ← Structured logging
│   │   └── security_headers.py ← OWASP headers middleware
│   │
│   ├── api/
│   │   └── v1/
│   │       ├── health.py       ← Health check endpoints
│   │       ├── auth.py         ← (Phase 3)
│   │       ├── cases.py        ← (Phase 4)
│   │       ├── evidence.py     ← (Phase 5)
│   │       └── ...
│   │
│   ├── db/
│   │   ├── base.py             ← SQLAlchemy Base
│   │   └── session.py          ← Async session factory
│   │
│   ├── auth/                   ← (Phase 3)
│   ├── users/                  ← (Phase 3)
│   ├── cases/                  ← (Phase 4)
│   ├── evidence/               ← (Phase 5)
│   ├── analysis/               ← (Phase 6-8)
│   ├── timeline/               ← (Phase 9)
│   ├── iocs/                   ← (Phase 10)
│   ├── detection/              ← (Phase 11)
│   ├── incidents/              ← (Phase 13)
│   ├── tasks/                  ← (Phase 13)
│   ├── reports/                ← (Phase 15)
│   ├── audit/                  ← (Phase 16)
│   │
│   ├── templates/              ← Jinja2 HTML templates
│   └── static/                 ← CSS, JS, images
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
│
├── sample_data/                ← Synthetic log files
├── scripts/                    ← Admin utilities
├── migrations/                 ← Alembic migrations
├── nginx/                      ← Nginx configuration
├── docs/                       ← Documentation
│
├── main.py                     ← Uvicorn entry point
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pytest.ini
├── .env.example
├── .gitignore
└── README.md
```

---

## 🔐 Security

- Passwords hashed with **Argon2** (winner of Password Hashing Competition)
- **JWT** tokens with configurable expiry
- **Rate limiting** on all endpoints (configurable)
- **Account lockout** after configurable failed attempts
- **OWASP security headers** on all responses
- **CORS** restricted to configured origins
- **TrustedHost** middleware prevents host-header injection
- **Parameterized queries** prevent SQL injection
- **File uploads** stored with random filenames outside web root
- **RBAC** enforced at API layer — never trust frontend alone
- **Audit logging** for all security-relevant actions

See [docs/security.md](docs/security.md) for the complete security guide.

---

## 📚 API Documentation

When running in development mode, Swagger UI is available at:

```
http://localhost:8000/api/docs
```

ReDoc alternative:

```
http://localhost:8000/api/redoc
```

---

## 🏗️ Development Phases

| Phase | Module | Status |
|-------|--------|--------|
| 1 | Project Architecture & Environment | ✅ Complete |
| 2 | Database Models & Migrations | 🔜 Next |
| 3 | Authentication & RBAC | 🔜 Pending |
| 4 | Case Management | 🔜 Pending |
| 5 | Evidence Management | 🔜 Pending |
| 6 | Hash Verification | 🔜 Pending |
| 7 | Chain of Custody | 🔜 Pending |
| 8 | Log Analysis | 🔜 Pending |
| 9 | Timeline Engine | 🔜 Pending |
| 10 | IOC Management | 🔜 Pending |
| 11 | Detection Engine | 🔜 Pending |
| 12 | Correlation | 🔜 Pending |
| 13 | Incident Response | 🔜 Pending |
| 14 | Dashboard | 🔜 Pending |
| 15 | Report Generation | 🔜 Pending |
| 16 | Security Hardening | 🔜 Pending |
| 17 | Testing | 🔜 Pending |
| 18 | Docker | 🔜 Pending |
| 19 | CI/CD | 🔜 Pending |
| 20 | Cloud Deployment | 🔜 Pending |

---

## ⚠️ Limitations

- Phase 1 does not include database connectivity (added in Phase 2)
- Evidence analysis is limited to metadata extraction — no file execution
- Threat intelligence requires external API keys
- Memory analysis requires additional forensic tools

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚖️ Legal & Ethical Notice

FORENSIC-X is designed exclusively for:

- **Authorized forensic investigations** on systems you own or have written permission to investigate
- **Incident response** within your organization or under formal engagement
- **Educational and research** purposes in authorized lab environments

**Never use this platform to:**
- Access systems without authorization
- Intercept communications without lawful authority
- Conduct offensive operations against third parties

Unauthorized access to computer systems is a criminal offense in most jurisdictions.
