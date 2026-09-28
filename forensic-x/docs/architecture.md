# FORENSIC-X — Architecture Documentation
# docs/architecture.md

## System Architecture

FORENSIC-X is a modular, layered web application following the clean architecture pattern.

## Layers

### Presentation Layer
- HTML/CSS/JavaScript frontend (Bootstrap 5 + Chart.js)
- Jinja2 server-side rendered templates
- Nginx reverse proxy

### API Layer
- FastAPI RESTful API (versioned at `/api/v1/`)
- Pydantic request/response validation
- JWT authentication middleware
- RBAC authorization middleware
- Rate limiting middleware

### Business Logic Layer
- Module-per-feature structure (cases, evidence, incidents, etc.)
- Service classes encapsulate business rules
- Detection engine and correlation logic

### Data Layer
- SQLAlchemy 2.0 async ORM
- PostgreSQL 16 primary database
- Redis 7 for sessions, rate limiting, caching
- File system for evidence storage

## Database Schema (planned — Phase 2)

```
users ──────────────┐
roles               │
permissions         │
                    │
cases ──────────────┤
case_users ─────────┤
evidence ───────────┤
evidence_hashes     │
chain_of_custody    │
events              │
timeline_events     │
iocs ───────────────┤
findings            │
detection_rules     │
incidents ──────────┤
incident_tasks      │
analyst_notes       │
reports             │
audit_logs ─────────┘
```

## Security Architecture

```
Request
  │
  ▼ TrustedHostMiddleware (host injection prevention)
  ▼ SecurityHeadersMiddleware (OWASP headers)
  ▼ CORSMiddleware (origin allowlist)
  ▼ SlowAPIMiddleware (rate limiting)
  ▼ JWT Authentication (verify token)
  ▼ RBAC Authorization (check permissions)
  ▼ Input Validation (Pydantic)
  ▼ Business Logic
  ▼ Parameterized DB Query
  ▼ Response (encoded output)
```

## Module Structure

Each feature module follows this pattern:

```
app/<module>/
├── __init__.py
├── models.py       ← SQLAlchemy ORM models
├── schemas.py      ← Pydantic request/response schemas
├── service.py      ← Business logic
├── repository.py   ← Database queries
└── router.py       ← FastAPI endpoints
```

## Evidence Storage

Evidence files are stored outside the web root:
- Path: `evidence_store/<case_id>/<random_uuid>.<extension>`
- Never served directly via URL
- Access controlled via API with auth check
- Original filenames stored in DB only
