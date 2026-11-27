# Code and Function Reference

The detailed module pages live under `docs/reference/`. The current source-to-reference map is [reference/SOURCE_COVERAGE.md](reference/SOURCE_COVERAGE.md). Pages are organized by implementation boundary and are intended to answer four questions for every public or operational symbol: what it does, what it accepts, what it returns or changes, and what algorithm or dependency it uses.

## Backend Modules

| Area | Source | Reference |
|---|---|---|
| API controllers and OpenAPI | `src/NocIfc.Api/` | `API.md`, `README_DEV_C.md` |
| Application use cases | `src/NocIfc.Application/` | `README_DEV_C.md` and feature references |
| SQLite persistence and integrations | `src/NocIfc.Infrastructure/` | `DATABASE_SCHEMA.md`, `README_DEV_C.md` |
| Worker scheduler | `src/NocIfc.Worker/` | `SCHEDULER.md`, `README_DEV_C.md` |
| SolarWinds webhook | `src/NocIfc.Webhook/` | `WEBHOOK.md` |
| Shared permission contract | `contracts/permission_catalog.json` | `PERMISSIONS.md` |
| Host-side SQLite migration/bootstrap | `alembic.ini`, `migrations/`, `src/core/{config,db,migration_runner,bootstrap,permissions}.py`, `src/models/` | `MIGRATION_COMPATIBILITY.md`, `MAINTENANCE.md` |
| Host-side encrypted backup conversion/recovery | `tools/offline-python/`, `src/core/{backup_manager,restore_control,paths}.py` | `MAINTENANCE.md`, `reference/core/backup_restore.md` |
| Python/C# route comparison helper | `tools/offline-python/compare_api_routes.py` | `API.md` |

## Frontend Modules

| Area | Source | Reference |
|---|---|---|
| Application/router/providers | `web/src/App.tsx` | `reference/web/App.md` |
| Auth, API client, and CSV downloads | `web/src/utils/AuthContext.tsx`, `web/src/utils/api.ts`, `web/src/utils/csv.ts` | `reference/web/utils/AuthContext.md`, `reference/web/utils/api.md`, `reference/web/utils/csv.md` |
| Routing and permissions | `web/src/utils/routeConfig.ts`, `permissions.ts` | `FRONTEND.md`, `reference/web/utils/routeConfig.md`, `reference/web/utils/permissions.md` |
| Timezone and Markdown rendering | `web/src/utils/markdown.ts`, `web/src/utils/timezone.ts`, `web/src/components/MarkdownContent.tsx` | `reference/web/utils/timezone.md`, `reference/web/components/MarkdownContent.md` |
| Realtime hook | `web/src/hooks/useAIOpsWebSocket.ts` | `reference/web/hooks/useAIOpsWebSocket.md` |
| Pages | `web/src/pages/*.tsx` | `reference/web/pages/` |
| Components and theme | `web/src/components/*.tsx` | `reference/web/components/` |

## Legacy Boundary

The Python API, scheduler, webhook, workers, service layer, and root runtime manifests have been removed from `dev-c`. Python files remain only for host-side migration/bootstrap and backup maintenance; the active runtime is the C# stack described in `README_DEV_C.md` and `DEPLOYMENT.md`.

## Documentation Quality Rule

When a function changes, update its nearest reference page and any affected flow/API/scheduler guide in the same change. Avoid copied line numbers, absolute workstation paths, undocumented environment variables, and claims about generated artifacts that are not checked into the repository.
