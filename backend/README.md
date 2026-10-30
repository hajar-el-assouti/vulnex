# VULNEX — Backend

FastAPI backend for VULNEX: authentication, targets, scan orchestration,
scanning engines, findings and reports.

## Stack

- FastAPI + Pydantic
- PostgreSQL + SQLAlchemy 2 (async) + Alembic
- Redis (rate limiting, Celery broker)
- Celery worker + Celery beat
- httpx, dnspython, cryptography (scanning engines)
- reportlab + jinja2 (PDF/HTML reports)
- Docker Compose

## How a scan runs

1. The frontend sends `POST /api/v1/scans`.
2. FastAPI checks the session, target ownership and target
   authorization, then saves the scan as `PENDING` in PostgreSQL.
3. FastAPI puts the scan ID in Redis (`send_task`) and marks the scan
   `QUEUED`. If Redis is down, the scan stays `PENDING` and is retried
   later by a maintenance task.
4. A Celery worker picks up the ID, marks the scan `RUNNING`, runs each
   selected module in order and stores the results and findings.
5. The frontend polls `GET /api/v1/scans/{id}/status` until the scan
   reaches a terminal state.

Celery beat schedules the maintenance tasks (`app/tasks/maintenance.py`):
re-sending scans stuck in `PENDING`, and finalizing scans stuck in
`CANCELLING` after a worker crash.

## Scan modules

| Slug | What it does | Default |
| --- | --- | --- |
| `diagnostic` | Orchestration self-test, no network, no findings | enabled |
| `recon` | HTTP, headers, cookies, technologies, metadata files, DNS, SPF/DMARC/DKIM, RDAP, IP/ASN, TLS, external assets, API endpoints in the HTML, change history | enabled |
| `advanced_recon` | Authorized ports/services, deep TLS (versions, chain), passive WAF/CDN detection | enabled |
| `web_vuln_assessment` | Passive checks: security headers, cookies, CORS, HTTP methods, information disclosure, TLS config, injection surface, exposed API specs | enabled |
| `active_web_testing` | Non-destructive active checks: reflected XSS, SQL injection (differential), HTTP parameter handling, API error handling | **disabled** |
| `discovery_fuzzing` | Path discovery with a SecLists-based wordlist, soft-404 detection | **disabled** |

The two active modules are behind five independent gates: the module
must be enabled in the database, enabled by a deployment setting,
confirmed by the user for each scan, and the target must be in that
module's own lab allowlist. Every request is SSRF-validated and pinned
to the validated IP. See `app/core/config.py`.

## Project layout

```
app/
  main.py              FastAPI app, middleware, lifespan
  celery_app.py        Celery app and settings
  worker_main.py       Celery worker entry point
  core/                Settings, logging, errors, security, rate limiting, Redis
  db/                  Declarative base, async engine/session, cross-dialect types
  models/              SQLAlchemy models (one file per table)
  schemas/             Pydantic request/response schemas
  api/v1/endpoints/    HTTP routes
  services/            Business logic (scans, targets, findings, reports...)
  tasks/               Celery tasks and one ScanModule per engine
  engines/
    contracts.py       Interface every engine implements
    recon/             Recon and advanced recon engines and collectors
    web_vuln/          Passive vulnerability checks
    active_web_testing/ Active checks and IP-pinned HTTP client
    discovery_fuzzing/ Path discovery and wordlist
  security/            SSRF validation, network-scan authorization
alembic/               Migrations
```

## Data model

| Table | Purpose |
| --- | --- |
| `users` | Accounts (email, Argon2id password hash, role) |
| `sessions` | Server-side sessions (only the token hash is stored) |
| `targets` | Assets to scan; `is_authorized` gates every scan |
| `scan_modules` | Registry of engines |
| `scans` | One run against one target |
| `scan_module_runs` | Status, timing and result of each module in a scan |
| `scan_findings` | Findings with severity, confidence, evidence, remediation, status |
| `scan_events` | Append-only progress/audit log for a scan |
| `scan_profiles` | Saved module selections (built-in and per user) |
| `reports` | Generated PDF/HTML reports |

Every target has an `owner_id`, and every scan, finding and report is
reached through a target, so all queries are scoped to the current user.

`targets.is_authorized` is a recorded claim, not proof. A database
`CHECK` constraint requires a reference and a date whenever it is true,
`authorized_by_id` records who set it, and
`services/targets.py::ensure_target_is_authorized` checks it again
before every scan. Verifying the real-world authorization is a human
responsibility.

## API

All routes are under `/api/v1`. Private routes need a valid session;
routes that change data also need the CSRF header.

| Area | Routes |
| --- | --- |
| Health | `GET /health/live`, `GET /health/ready` |
| Auth | `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` |
| Targets | `POST/GET /targets`, `GET /targets/{id}`, `POST /targets/{id}/authorize` |
| Scans | `POST/GET /scans`, `GET /scans/{id}`, `GET /scans/{id}/status`, `GET /scans/{id}/events`, `POST /scans/{id}/cancel`, `POST /scans/{id}/rerun` |
| Modules & profiles | `GET /scan-modules`, `GET/POST /scan-profiles`, `DELETE /scan-profiles/{id}` |
| Findings | `GET /findings`, `GET /findings/{id}`, `PATCH /findings/{id}/status` |
| Reports | `POST/GET /reports`, `GET /reports/{id}`, `GET /reports/{id}/download` |
| Dashboard | `GET /dashboard/stats` |

Interactive docs: http://localhost:8000/docs

## Running with Docker Compose

```bash
cp .env.example .env
# Set a real POSTGRES_PASSWORD and SECRET_KEY. There are no defaults:
# the app refuses to start without them.
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

docker compose up --build
```

This starts PostgreSQL, Redis, the API, a Celery worker and Celery beat.
Postgres and Redis are not exposed to the host. The API runs
`alembic upgrade head` on startup and listens on `127.0.0.1:8000` only;
a real deployment would put a reverse proxy with TLS in front.

```bash
curl http://localhost:8000/api/v1/health/live    # process is up
curl http://localhost:8000/api/v1/health/ready   # database reachable (503 if not)
```

The worker and beat containers have CPU/RAM limits, no published ports,
`cap_drop: [ALL]` and `no-new-privileges`.

## Running locally without Docker

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Set POSTGRES_* to a running PostgreSQL, REDIS_URL to a running Redis,
# and SECRET_KEY.

alembic upgrade head
uvicorn app.main:app --reload --forwarded-allow-ips=""

# In two other terminals:
celery -A app.worker_main worker --loglevel=info --concurrency=2
celery -A app.worker_main beat --loglevel=info
```

`--forwarded-allow-ips=""` stops uvicorn from trusting
`X-Forwarded-For` from 127.0.0.1 by default, which would otherwise let a
client spoof the IP used for rate limiting.

## Migrations

The database URL comes from the app settings (`alembic/env.py`), never
from `alembic.ini`, so the same `.env` drives the app and migrations.

```bash
alembic revision --autogenerate -m "describe the change"   # review the file before applying
alembic upgrade head
alembic downgrade -1
```

## Security design

- **Passwords**: Argon2id (`argon2-cffi`), re-hashed automatically if
  the parameters are strengthened. Length 10–128, emails normalized.
- **Sessions**: server-side, not JWT. The client gets a random opaque
  token; only its SHA-256 hash is stored. Absolute lifetime
  (`SESSION_TTL_HOURS`, 12h) and idle timeout
  (`SESSION_IDLE_TIMEOUT_MINUTES`, 30 min). Logout revokes the current
  session.
- **Cookies**: `session_id` is HttpOnly, `SameSite=Lax`, and `Secure`
  outside development. `csrf_token` is readable by JavaScript so it can
  be sent back in a header.
- **CSRF**: double-submit cookie, and the token must match
  `HMAC-SHA256(SECRET_KEY, session_token_hash)` for the current session,
  so a token from another session is rejected.
- **Anti-enumeration**: unknown email, wrong password and inactive
  account return the same `401`, and a dummy Argon2 check keeps the
  response time the same.
- **Rate limiting**: Redis sliding window (atomic Lua script), shared
  across processes. Login: 5 attempts per 15 min per email and per IP.
  Registration: 10 per hour per IP. If Redis is down, auth returns 503
  by default (`RATE_LIMIT_FAIL_OPEN=false`).
- **Client IP**: `X-Forwarded-For` is ignored unless
  `TRUST_X_FORWARDED_FOR=true` and the connecting peer is in
  `TRUSTED_PROXIES`; then only the rightmost entry is used.
- **Security headers**: strict CSP for this JSON-only API
  (`default-src 'none'; frame-ancestors 'none'`), HSTS only outside
  development.
- **SSRF**: every outbound request validates the resolved IP and
  refuses loopback, private, link-local, multicast and reserved
  addresses. Redirects are followed manually and each hop is validated.
  Lab targets need an explicit `host:port` allowlist entry.
- **Active testing**: IP pinning (the request connects to the exact IP
  that was validated, with the original Host and TLS SNI), GET/HEAD/OPTIONS
  only, per-endpoint request budget, sequential requests, no destructive
  payloads.
- **Stored data**: cookie values and secrets are never stored; results
  are redacted and size-capped before being saved.
- **Reports**: never served as static files; every download re-checks
  ownership.

## Known limitations

- Target authorization is a recorded claim; there is no automatic proof
  of ownership (e.g. a DNS TXT record check).
- Reflected XSS detection doesn't run a browser, so findings stay at LOW
  confidence.
- The passive engines don't pin IPs, so a small DNS rebinding window
  remains for read-only requests. The active engines use IP pinning.
- The worker containers are not a full sandbox (no seccomp profile or
  network namespace restrictions).
- `discovery_fuzzing` only accepts the "quick" mode for now.
- The visual snapshot collector is not implemented (disabled by default).
