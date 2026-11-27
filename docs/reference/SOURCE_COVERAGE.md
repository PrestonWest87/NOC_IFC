# Current Source Coverage and Historical References

This index maps active C# source and retained host-side Python tooling. Reference pages for removed Python runtime modules are historical behavior notes, not current source coverage.

## Backend

| Source area | Reference |
|---|---|
| `src/NocIfc.Api/` | `../API.md`, `../README_DEV_C.md` |
| `src/NocIfc.Application/` | `../README_DEV_C.md` and feature guides |
| `src/NocIfc.Infrastructure/` | `../DATABASE_SCHEMA.md`, `../README_DEV_C.md` |
| `src/NocIfc.Worker/` | `../SCHEDULER.md`, `../README_DEV_C.md` |
| `src/NocIfc.Webhook/` | `../WEBHOOK.md` |
| `contracts/permission_catalog.json` | `../PERMISSIONS.md` |
| `src/core/{config,db,migration_runner,bootstrap,permissions,paths,backup_manager,restore_control}.py`, `src/models/`, `migrations/` | `core/`, `models/`, `../MIGRATION_COMPATIBILITY.md`, `../MAINTENANCE.md` |
| `tools/offline-python/` | `../MAINTENANCE.md`, `../README_DEV_C.md` |

## Frontend

| Source area | Reference |
|---|---|
| `web/src/App.tsx` | `web/App.md` |
| `web/src/main.tsx` | `web/main.md` |
| `web/src/pages/*.tsx` | `web/pages/*.md` (one page per route component) |
| `web/src/pages/OperationalEmailPage.tsx` | `web/pages/OperationalEmailPage.md`, `../USER_GUIDE.md`, `../FRONTEND.md` |
| `web/src/components/*.tsx` | `web/components/*.md` (one page per component) |
| `web/src/hooks/*.ts` | `web/hooks/*.md` |
| `web/src/store/*.ts` | `web/store/*.md` |
| `web/src/utils/*.ts,*.tsx` | `web/utils/*.md` |
| `web/src/styles/*.css`, `web/src/themes/*.css` | `web/styles/*.md` |

## Reference Requirements

Each page should identify:

- Current source path, or an explicit historical label when the original source has been retired.
- Public classes, functions, handlers, or components.
- Inputs, defaults, validation, and outputs.
- Database reads/writes and external dependencies.
- Algorithms, thresholds, fallback behavior, and error handling.
- Permissions and side effects.
- Runtime configuration that changes behavior.

When a source symbol changes, update the associated reference page and any affected API, scheduler, flow, frontend, or operations guide in the same change.
