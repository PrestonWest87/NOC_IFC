# SQLite Migration Compatibility and Safety

## Current behavior

The packaged migration head is `20261005_0003`. The API, worker, and webhook run pending Alembic revisions under a shared file lock before serving requests or starting jobs. A database already at head receives no schema DDL. A migration error stops startup; the application does not mark the failed revision as complete.

The initial adoption revision (`20261002_0001`) was designed for:

- An empty SQLite database: create the frozen baseline in `migrations/schema_v1.py`.
- A pre-Alembic application database: keep existing tables and rows, create missing baseline tables, add the historical columns in the revision's explicit compatibility map, add missing indexes, and run the listed one-time data conversions.
- A partially applied adoption: inspect objects and add only absent known objects so the revision can be retried.

Revision `20261002_0002` adds nullable `registration_invites.revoked_at` only when that column is absent. Revision `20261005_0003` adds non-null, false-default `solarwinds_alerts.needs_dispatch` only when absent, preserving all existing alert rows. None of the upgrade revisions drops or renames tables or columns.

## Data changes during adoption

The baseline revision performs these intentional backfills:

- Fill missing user `created_at` timestamps with the migration time.
- Fill missing `last_login_at` from a user's latest existing session, and fill missing `last_activity_at` from `last_login_at` when available.
- Mark old registration invitations with no email as used so they cannot be registered from.
- Convert numeric monitored-location priorities to the current `P1-Critical` through `P5-Planning` labels.

These updates do not remove existing rows. The legacy permission-catalog conversion runs separately during conditional bootstrap and is version-gated so operator-edited grants are not repeatedly rewritten.

## Compatibility limits and failure behavior

This is an additive upgrade for known application schemas, not an automatic repair for arbitrary hand-edited or severely incomplete databases. The adoption revision validates every frozen baseline table and column. If an existing table is missing a column without an explicit safe legacy definition, or if duplicate non-null normalized user emails prevent the unique index, startup fails with an error and the migration revision is not advanced. Existing application rows are left in place; the database may contain completed additive tables/columns from the failed attempt, which are inspected and reused on retry.

Before upgrading production, create and verify an encrypted full backup. Do not manually stamp `alembic_version`, delete columns, or treat a migration failure as a successful upgrade. Resolve the reported schema/data issue and restart the backend. Schema downgrade is not the rollback procedure; restore a verified pre-upgrade backup instead.

## Verification coverage

`tests/test_database_migrations.py` covers a populated pre-Alembic schema upgraded through all current revisions, preservation of existing user/article/site/invitation/alert records, false-default backfill for `needs_dispatch`, known partial-column upgrades, failure on an unsupported older schema without losing its row or recording success, duplicate-email failure, concurrent first startup, and no schema/data work on a second startup at head.

Run the focused suite with:

```bash
DATABASE_URL=sqlite:// python -m unittest tests.test_database_migrations -v
```
