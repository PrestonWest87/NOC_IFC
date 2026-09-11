# Module Reference Corpus

This directory is the detailed source-oriented reference corpus. It is part of the canonical `docs/` tree; the former top-level `Documentation/` directory no longer exists.

## Coverage

- `api/`: FastAPI lifecycle, WebSocket manager, authentication, and route handlers.
- `scheduler.md`: Scheduler functions, ingestion algorithms, retention, escalation, and ML retraining.
- `train_model.md`: Feedback-to-model training pipeline and artifact behavior.
- `api/webhook_listener.md`: SolarWinds gateway validation, normalization, and background processing.
- `core/`: settings, database sessions, migrations, and seed behavior.
- `database_compat.md`: active compatibility exports used by services and workers.
- `models/`: SQLAlchemy entities and relationships.
- `services/`: data access, scoring, categorization, IOC extraction, and AIOps algorithms.
- `utils/`: LLM, mail, and risk-alert behavior.
- `workers/`: external feed workers and scheduled data integrations.
- `web/`: React pages, components, hooks, state, and utilities.
- `config/`: Docker, nginx, TypeScript, Vite, dependency, and environment-file notes.
- `SOURCE_COVERAGE.md`: Current source-to-reference coverage map and documentation requirements.

## Source-of-Truth Rule

These pages explain behavior and call chains, but executable source wins when a signature or default changes. Each page must use repository-relative paths and must identify inputs, outputs, side effects, error handling, and algorithmic decisions. High-level operational truth is maintained in `docs/ARCHITECTURE.md`, `docs/SCHEDULER.md`, `docs/OPERATIONS_REFERENCE.md`, and `docs/TROUBLESHOOTING.md`.
