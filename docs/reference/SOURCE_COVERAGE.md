# Current Source Coverage

This index records the current source-to-reference mapping after the reference corpus audit. Source code is authoritative; this index prevents new runtime modules from being added without a corresponding detailed page.

## Backend

| Source area | Reference |
|---|---|
| `src/api/main.py` | `api/main.md` |
| `src/api/auth_guard.py` | `api/auth_guard.md` |
| `src/api/ws_manager.py` | `api/ws_manager.md` |
| `src/api/routes/*.py` | `api/routes/*.md` plus route-specific source corrections |
| `src/core/config.py` | `core/config.md` |
| `src/core/db.py` | `core/db.md` |
| `src/database.py` | `database_compat.md` |
| `src/models/schema.py` | `models/schema.md` |
| `src/services.py` | `services/services.md` |
| `src/services/__init__.py` | `services/services.__init__.md` |
| `src/services/aiops_engine.py` | `services/aiops_engine.md` |
| `src/services/categorizer.py` | `services/categorizer.md` |
| `src/services/ioc_extractor.py` | `services/ioc_extractor.md` |
| `src/services/logic.py` | `services/logic.md` |
| `src/utils/llm.py` | `utils/llm.md` |
| `src/utils/mailer.py` | `utils/mailer.md` |
| `src/utils/risk_alert.py` | `utils/risk_alert.md` |
| `src/scheduler.py` | `scheduler.md`, `../SCHEDULER.md` |
| `src/webhook_listener.py` | `api/webhook_listener.md`, `../WEBHOOK.md` |
| `src/train_model.py` | `train_model.md` |
| `src/workers/*.py` | `workers/*.md` |

## Frontend

| Source area | Reference |
|---|---|
| `web/src/App.tsx` | `web/App.md` |
| `web/src/main.tsx` | `web/main.md` |
| `web/src/pages/*.tsx` | `web/pages/*.md` |
| `web/src/components/*.tsx` | `web/components/*.md` |
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
