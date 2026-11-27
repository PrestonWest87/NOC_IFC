# Module Reference Corpus

This directory contains current C# references and historical Python implementation notes. It is part of the canonical `docs/` tree; the former top-level `Documentation/` directory no longer exists. Python API, scheduler, webhook, worker, and service source was removed from `dev-c`; only host-side migration/bootstrap and backup-maintenance modules remain executable.

## Coverage

- `api/`, `services/`, `utils/`, and `workers/`: historical Python behavior references; these runtimes are not present on `dev-c`.
- `scheduler.md`: historical Python scheduler behavior; current schedules are implemented in the C# Worker.
- `core/`: retained migration/bootstrap/backup modules plus historical notes for removed Python runtime helpers.
- [Migration compatibility](../MIGRATION_COMPATIBILITY.md): supported legacy SQLite upgrade shapes, additive changes, and fail-closed recovery behavior.
- `database_compat.md`: historical Python compatibility exports; removed from `dev-c`.
- `models/`: SQLAlchemy entities and relationships.
- `services/`: data access, scoring, categorization, IOC extraction, and AIOps algorithms.
- `utils/`: LLM, mail, risk-alert, and safe Markdown rendering.
- `workers/`: external feed workers and scheduled data integrations.
- `web/`: React pages, components, hooks, state, and utilities.
- `config/`: Docker, nginx, TypeScript, Vite, dependency, and environment-file notes.
- `scripts/`: historical script references. Current host-side migration, backup conversion, and restore commands are under `tools/offline-python/`.
- `SOURCE_COVERAGE.md`: Current source-to-reference coverage map and documentation requirements.

## Source-of-Truth Rule

These pages explain behavior and call chains, but executable source wins when a signature or default changes. Each page must use repository-relative paths and must identify inputs, outputs, side effects, error handling, and algorithmic decisions. High-level operational truth is maintained in `docs/ARCHITECTURE.md`, `docs/SCHEDULER.md`, `docs/OPERATIONS_REFERENCE.md`, and `docs/TROUBLESHOOTING.md`.
