# NOC Intelligence Fusion Center Architecture

**Status:** Source-of-truth architecture guide
**Runtime:** FastAPI + Python workers + React/Vite
**Canonical documentation root:** `docs/`

## Purpose

The NOC Intelligence Fusion Center (IFC) collects cyber, infrastructure, physical, environmental, and vulnerability signals; normalizes them into a shared database; correlates infrastructure alerts; calculates risk; and presents the result through a browser dashboard, REST API, WebSocket updates, and email workflows.

This document describes the checked-in runtime. The authoritative implementation is the source tree, especially `src/api/main.py`, `src/scheduler.py`, `src/core/config.py`, `src/core/db.py`, and `docker-compose.yml`.

## Runtime Topology

```text
Browser
  | HTTP / WebSocket
  v
web:8501 or web-dev:5173
  | /api/v1 and /ws
  v
api:8101 --------------------+
  | REST, auth, WebSocket     |
  |                           v
  +---------------------- shared database
                              ^
worker ----------------------+
  | scheduled ingestion, scoring, briefs, escalation
  v
external feeds and SMTP

SolarWinds -> webhook:8100 -> shared database
```

## Deployable Services

| Service | Entrypoint | Port | Responsibility |
|---|---|---:|---|
| `api` | `uvicorn src.api.main:app --host 0.0.0.0 --port 8101` | 8101 | REST API, auth middleware, health/readiness, WebSocket endpoint |
| `worker` | `python -u src/scheduler.py` | none | Scheduled ingestion, enrichment, scoring, reports, maintenance, escalation |
| `webhook` | `python -u src/webhook_listener.py` | 8100 | SolarWinds webhook validation, normalization, and persistence |
| `web` | `web/Dockerfile` | host 8501 -> container 5173 | Production React build served by nginx |
| `web-dev` | Vite under the `dev` profile | 5173 | Development frontend with source mounts and HMR |

The API, worker, and webhook share `./data` as `/app/data`. SQLite is appropriate for a single-node deployment; use PostgreSQL for multi-instance or high-concurrency operation.

## Backend Boundaries

### API application

`src/api/main.py` creates the FastAPI application, installs `authentication_middleware`, configures CORS from `CORS_ORIGINS`, includes 14 routers, initializes the database during lifespan startup, and starts the 10-second WebSocket broadcaster. `/health` is a liveness response; `/ready` verifies a database query and returns `503` when the database is unavailable.

The router modules are `auth`, `dashboard`, `threat`, `regional`, `hunting`, `rca`, `aiops`, `logbook`, `reporting`, `settings`, `settings_admin` (mounted as `/admin`), `llm`, `email`, and `keyword_analysis`.

### Data access and compatibility modules

`src/services.py` is the central data-access and domain-service module used by routes and jobs. `src/services/` contains focused engines. `src/services/__init__.py` dynamically exposes the sibling `src/services.py` compatibility module; this is intentional and must not be “simplified” without checking all imports.

The API uses `src.core.db`; the scheduler imports the compatibility surface from `src.database`. Both resolve to the same SQLAlchemy-backed model/session system. The former Streamlit entrypoint and `src/ui/` tree have been removed; they are not Docker runtime entrypoints.

### Correlation and scoring

- `HybridScorer` combines configured keyword weights with the persisted ML model when available.
- `categorize_text` assigns article categories using the categorizer rules.
- `EnterpriseIOCExtractor` refangs and extracts indicators, validates IPs, and attaches context.
- `EnterpriseAIOpsEngine` maps devices into the ontology, clusters alerts by site, finds fleet outages, identifies patient zero, calculates root cause, and produces chronic insights.
- `src/utils/llm.py` handles context-window limits, chunking, map/reduce prompts, progress state, and brief assembly.

## Data Flow

### RSS and enrichment

1. `fetch_feeds` reads active `FeedSource` rows.
2. `fetch_all_feeds_chunked` downloads five feeds concurrently per chunk with a 15-second request timeout.
3. `parse_and_score_feed` rejects known links, scores title/summary text, categorizes it, and extracts IOCs for sufficiently relevant cyber articles.
4. `bulk_save_to_db` inserts each article in a nested transaction so one duplicate does not discard a batch.
5. `enrich_pending_articles` separately fetches full article content, limits stored content to 200,000 characters, and retries each item at most three times.
6. `deduplicate_articles` performs post-cycle cleanup.

### SolarWinds

`POST /webhook/solarwinds` accepts JSON, enforces body size and optional HMAC/timestamp checks, extracts fields from supported payload shapes, classifies the device, detects resolution language, and processes persistence in a FastAPI background task. The response is intentionally returned before the full correlation operation completes.

### Regional map

Workers cache hazard GeoJSON. The regional route compiles layers, view state, diagnostics, affected sites, and analytics. The response is positional: `[layers, viewState, diagnostics, toggled_affected, master_affected, analytics]`. Consumers must preserve this contract when changing either backend or frontend map code.

## Authentication and Authorization

The API middleware reads the session token supplied by the frontend client and attaches the authenticated user to protected requests. Login creates a database-backed session token; this is not JWT authentication. The WebSocket endpoint requires `?token=<session token>` and closes unauthenticated connections with code `1008`.

RBAC is represented by role page permissions, action permissions, and allowed site types. The frontend uses the same permission strings for navigation and controls, while sensitive backend operations use route-level checks. Important exact strings include `Action: Dispatch RCA Tickets`, `Action: Manage Site Maintenance`, `Tab: Settings -> Internal Assets`, and `Tab: Dashboards -> Unified Brief`.

## Database Lifecycle

`init_db()` calls `Base.metadata.create_all`, then applies additive migrations with guarded `ALTER TABLE` statements, creates indexes, seeds roles, optional users, feeds, keywords, and `SystemConfig`, and optionally seeds demo assets. Existing tables and columns are not dropped. Set `RESCORE_ON_STARTUP=true` only when an explicit startup rescore is acceptable.

SQLite startup enables WAL, `synchronous=NORMAL`, memory temp storage, a 16 MB cache, a 64 MB mmap, and a 30-second connection timeout. SQLite uses `NullPool`.

## Failure Isolation

- External fetch errors are logged and do not stop the scheduler loop.
- `run_threaded` limits concurrent jobs to two and prevents the same named job from overlapping.
- LLM brief generation stores progress by generation ID so the UI can poll and resume.
- Email failures are logged and do not roll back unrelated database work.
- API readiness fails closed when `SELECT 1` cannot execute.

## Source Reference

| Concern | Source |
|---|---|
| Settings and environment parsing | `src/core/config.py` |
| Engine/session/migrations/seeds | `src/core/db.py` |
| API lifecycle and WebSocket | `src/api/main.py`, `src/api/ws_manager.py` |
| Authentication middleware | `src/api/auth_guard.py` |
| Route handlers | `src/api/routes/*.py` |
| Services and DAL | `src/services.py`, `src/services/*.py` |
| Scheduler and intervals | `src/scheduler.py` |
| Webhook gateway | `src/webhook_listener.py` |
| React routing and providers | `web/src/App.tsx` |
| Container topology | `docker-compose.yml` |
