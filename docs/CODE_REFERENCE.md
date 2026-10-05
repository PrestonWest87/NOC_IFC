# Code and Function Reference

The detailed module pages live under `docs/reference/`. The current source-to-reference map is [reference/SOURCE_COVERAGE.md](reference/SOURCE_COVERAGE.md). Pages are organized by implementation boundary and are intended to answer four questions for every public or operational symbol: what it does, what it accepts, what it returns or changes, and what algorithm or dependency it uses.

## Backend Modules

| Area | Source | Reference |
|---|---|---|
| Configuration | `src/core/config.py` | `reference/core/config.md` |
| Core package | `src/core/__init__.py` | `reference/core/__init__.md` |
| Database lifecycle | `src/core/db.py` | `reference/core/db.md` |
| SQLite migrations | `src/core/migration_runner.py`, `alembic.ini`, `migrations/env.py`, `migrations/schema_v1.py`, `migrations/versions/*.py` | `reference/core/migration_runner.md`, `MIGRATION_COMPATIBILITY.md` |
| Bootstrap seeding | `src/core/bootstrap.py` | `reference/core/bootstrap.md` |
| Permission catalog | `src/core/permissions.py` | `reference/core/permissions.md` |
| Scheduler registry | `src/core/scheduler_registry.py` | `reference/core/scheduler_registry.md`, `SCHEDULER.md` |
| Persistent data/model paths | `src/core/paths.py` | `reference/core/paths.md` |
| Encrypted backups and restore | `src/core/backup_manager.py`, `src/core/restore_control.py`, `src/core/ui_restore.py` | `reference/core/backup_restore.md`, `MAINTENANCE.md` |
| Database compatibility surface | `src/database.py` | `reference/database_compat.md` |
| Model package | `src/models/__init__.py` | `reference/models/__init__.md` |
| API lifecycle/auth/health | `src/api/main.py`, `src/api/auth_guard.py` | `reference/api/main.md` |
| WebSocket manager | `src/api/ws_manager.py` | `reference/api/ws_manager.md` |
| API route handlers | `src/api/routes/*.py` | `reference/api/routes/` and `API.md` (operation coverage is checked against OpenAPI) |
| Data access and domain functions | `src/services.py` | `reference/services/services.md` |
| AIOps algorithms | `src/services/aiops_engine.py` | `reference/services/aiops_engine.md` |
| Article scoring | `src/services/logic.py` | `reference/services/logic.md` |
| Categorization | `src/services/categorizer.py` | `reference/services/categorizer.md` |
| IOC extraction | `src/services/ioc_extractor.py` | `reference/services/ioc_extractor.md` |
| LLM/map-reduce | `src/utils/llm.py` | `reference/utils/llm.md` |
| Email delivery | `src/utils/mailer.py` | `reference/utils/mailer.md` |
| Risk alerts | `src/utils/risk_alert.py` | `reference/utils/risk_alert.md` |
| Utility package | `src/utils/__init__.py` | `reference/utils/__init__.md` |
| Scheduler | `src/scheduler.py` | `SCHEDULER.md`, `reference/scheduler.md` |
| Workers | `src/workers/*.py` | `reference/workers/` |
| Webhook | `src/webhook_listener.py` | `WEBHOOK.md`, `reference/api/webhook_listener.md` |
| ML training | `src/train_model.py` | `reference/train_model.md` |

## Frontend Modules

| Area | Source | Reference |
|---|---|---|
| Application/router/providers | `web/src/App.tsx` | `reference/web/App.md` |
| Auth and API client | `web/src/utils/AuthContext.tsx`, `web/src/utils/api.ts` | `reference/web/utils/AuthContext.md`, `reference/web/utils/api.md` |
| Routing and permissions | `web/src/utils/routeConfig.ts`, `permissions.ts` | `FRONTEND.md`, `reference/web/utils/routeConfig.md`, `reference/web/utils/permissions.md` |
| Timezone and Markdown rendering | `web/src/utils/timezone.ts`, `web/src/components/MarkdownContent.tsx` | `reference/web/utils/timezone.md`, `reference/web/components/MarkdownContent.md` |
| Realtime hook | `web/src/hooks/useAIOpsWebSocket.ts` | `reference/web/hooks/useAIOpsWebSocket.md` |
| Pages | `web/src/pages/*.tsx` | `reference/web/pages/` |
| Components and theme | `web/src/components/*.tsx` | `reference/web/components/` |

## Legacy Boundary

The former Streamlit entrypoint and `src/ui/` tree have been removed. The active runtime is the FastAPI/React stack described in `ARCHITECTURE.md`.

## Documentation Quality Rule

When a function changes, update its nearest reference page and any affected flow/API/scheduler guide in the same change. Avoid copied line numbers, absolute workstation paths, undocumented environment variables, and claims about generated artifacts that are not checked into the repository.
