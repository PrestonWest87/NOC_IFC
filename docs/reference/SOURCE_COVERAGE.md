# Current Source Coverage

This index records the current source-to-reference mapping after the reference corpus audit. Source code is authoritative; this index prevents new runtime modules from being added without a corresponding detailed page.

## Backend

| Source area | Reference |
|---|---|
| `src/api/main.py` | `api/main.md` |
| `src/api/auth_guard.py` | `api/auth_guard.md` |
| `src/api/ws_manager.py` | `api/ws_manager.md` |
| `src/api/routes/*.py` | `api/routes/*.md` plus the complete method/path inventory in `../API.md` |
| `src/core/config.py` | `core/config.md` |
| `src/core/__init__.py` | `core/__init__.md` |
| `src/core/db.py` | `core/db.md` |
| `src/core/migration_runner.py`, `alembic.ini`, `migrations/env.py`, `migrations/schema_v1.py`, `migrations/versions/*.py` | `core/migration_runner.md`, `../MIGRATION_COMPATIBILITY.md`, `../DATABASE_SCHEMA.md` |
| `src/core/bootstrap.py` | `core/bootstrap.md` |
| `src/core/permissions.py` | `core/permissions.md`, `../API.md`, `../ARCHITECTURE.md` |
| `src/core/scheduler_registry.py` | `core/scheduler_registry.md`, `../SCHEDULER.md` |
| `src/core/paths.py` | `core/paths.md`, `train_model.md`, `services/logic.md` |
| `src/core/backup_manager.py` | `core/backup_restore.md`, `../MAINTENANCE.md`, `../API.md` |
| `src/core/restore_control.py`, `src/core/ui_restore.py` | `core/backup_restore.md`, `../MAINTENANCE.md` |
| `src/database.py` | `database_compat.md` |
| `src/models/schema.py` | `models/schema.md` |
| `src/models/__init__.py` | `models/__init__.md` |
| `src/services.py` | `services/services.md` |
| `src/services/__init__.py` | `services/services.__init__.md` |
| `src/services/aiops_engine.py` | `services/aiops_engine.md` |
| `src/services/categorizer.py` | `services/categorizer.md` |
| `src/services/ioc_extractor.py` | `services/ioc_extractor.md` |
| `src/services/logic.py` | `services/logic.md` |
| `src/utils/llm.py` | `utils/llm.md` |
| `src/utils/mailer.py` | `utils/mailer.md` |
| `src/utils/risk_alert.py` | `utils/risk_alert.md` |
| `src/utils/__init__.py` | `utils/__init__.md` |
| `src/scheduler.py` | `scheduler.md`, `../SCHEDULER.md` |
| `src/webhook_listener.py` | `api/webhook_listener.md`, `../WEBHOOK.md` |
| `src/train_model.py` | `train_model.md` |
| `src/workers/*.py` | `workers/*.md` |
| `scripts/restore_backup.py` | `core/backup_restore.md`, `../MAINTENANCE.md` |

## Frontend

| Source area | Reference |
|---|---|
| `web/src/App.tsx` | `web/App.md` |
| `web/src/main.tsx` | `web/main.md` |
| `web/src/pages/*.tsx` | `web/pages/*.md` (one page per route component) |
| `web/src/components/*.tsx` | `web/components/*.md` (one page per component) |
| `web/src/hooks/*.ts` | `web/hooks/*.md` |
| `web/src/store/*.ts` | `web/store/*.md` |
| `web/src/utils/*.ts,*.tsx` | `web/utils/*.md` |
| `web/src/styles/*.css`, `web/src/themes/*.css` | `web/styles/*.md` |

## Reference Requirements

Each page should identify:

- Current source path.
- Public classes, functions, handlers, or components.
- Inputs, defaults, validation, and outputs.
- Database reads/writes and external dependencies.
- Algorithms, thresholds, fallback behavior, and error handling.
- Permissions and side effects.
- Runtime configuration that changes behavior.

When a source symbol changes, update the associated reference page and any affected API, scheduler, flow, frontend, or operations guide in the same change.
