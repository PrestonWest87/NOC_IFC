# Module: `src.core.bootstrap`

`ensure_bootstrap_data(session_factory)` initializes application data after Alembic migrations. It is deliberately separate from schema creation and does not replace operator-edited rows.

## Seed behavior

- `_seed_roles_and_admin()` creates missing built-in roles, applies the one-time permission catalog conversion, and creates the first `admin` only when there are no users and `DEFAULT_ADMIN_PASSWORD` is non-empty.
- If a valid `DEFAULT_ADMIN_EMAIL` is configured, an existing email-less bootstrap admin can receive that trusted verified address. A matching pending initial recovery-email request is completed; conflicting addresses are not silently overwritten. The change is audited.
- `_seed_feeds()` inserts only missing rows from `DEFAULT_FEEDS` and leaves existing active state/names untouched.
- `_seed_keywords()` inserts only missing defaults and preserves existing weights.
- `_seed_demo_assets()` runs only when `DEMO_SEED_DATA=true`, and only seeds an inventory table when it is empty.
- Existing articles are rescored only when `RESCORE_ON_STARTUP` is truthy (`1`, `true`, or `yes`); default startup skips the corpus update.

Each bootstrap category handles/logs its own failure. A seed failure does not change the Alembic revision. Startup ordering is documented in `docs/reference/core/db.md`.
