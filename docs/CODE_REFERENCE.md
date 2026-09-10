# Code and Function Reference

The detailed module pages live under `docs/reference/`. They are organized by implementation boundary and are intended to answer four questions for every public or operational symbol: what it does, what it accepts, what it returns or changes, and what algorithm or dependency it uses.

## Backend Modules

| Area | Source | Reference |
|---|---|---|
| Configuration | `src/core/config.py` | `reference/core/config.md` |
| Database lifecycle | `src/core/db.py` | `reference/core/db.md` |
| API lifecycle/auth/health | `src/api/main.py`, `src/api/auth_guard.py` | `reference/api/main.md` |
| WebSocket manager | `src/api/ws_manager.py` | `reference/api/ws_manager.md` |
| API route handlers | `src/api/routes/*.py` | `reference/api/routes/` |
| Data access and domain functions | `src/services.py` | `reference/services/services.md` |
| AIOps algorithms | `src/services/aiops_engine.py` | `reference/services/aiops_engine.md` |
| Article scoring | `src/services/logic.py` | `reference/services/logic.md` |
| Categorization | `src/services/categorizer.py` | `reference/services/categorizer.md` |
| IOC extraction | `src/services/ioc_extractor.py` | `reference/services/ioc_extractor.md` |
| LLM/map-reduce | `src/utils/llm.py` | `reference/utils/llm.md` |
| Email delivery | `src/utils/mailer.py` | `reference/utils/mailer.md` |
| Risk alerts | `src/utils/risk_alert.py` | `reference/utils/risk_alert.md` |
| Scheduler | `src/scheduler.py` | `SCHEDULER.md` |
| Workers | `src/workers/*.py` | `reference/workers/` |
| Webhook | `src/webhook_listener.py` | `WEBHOOK.md`, `reference/ui/webhook_listener.md` |

## Frontend Modules

| Area | Source | Reference |
|---|---|---|
| Application/router/providers | `web/src/App.tsx` | `reference/web/App.md` |
| Auth and API client | `web/src/utils/AuthContext.tsx`, `web/src/utils/api.ts` | `reference/web/utils/` |
| Routing and permissions | `web/src/utils/routeConfig.ts`, `permissions.ts` | `FRONTEND.md`, `reference/web/utils/permissions.md` |
| Realtime hook | `web/src/hooks/useAIOpsWebSocket.ts` | `reference/web/hooks/useAIOpsWebSocket.md` |
| Pages | `web/src/pages/*.tsx` | `reference/web/pages/` |
| Components and theme | `web/src/components/` | `reference/web/` |

## Legacy Boundary

`src/app.py`, `src/ui/`, and their pages are retained for historical compatibility. They are not the active Docker SPA runtime. Do not use their behavior as the contract for FastAPI or React changes.

## Documentation Quality Rule

When a function changes, update its nearest reference page and any affected flow/API/scheduler guide in the same change. Avoid copied line numbers, absolute workstation paths, undocumented environment variables, and claims about generated artifacts that are not checked into the repository.
