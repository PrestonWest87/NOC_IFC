# SQLite Migration Compatibility and Safety

## Current behavior

The packaged migration head is `20261111_0012`. The API, worker, and webhook run pending Alembic revisions under a shared file lock before serving requests or starting jobs. A database already at head receives no schema DDL. A migration error stops startup; the application does not mark the failed revision as complete.

The initial adoption revision (`20261002_0001`) was designed for:

- An empty SQLite database: create the frozen baseline in `migrations/schema_v1.py`.
- A pre-Alembic application database: keep existing tables and rows, create missing baseline tables, add the historical columns in the revision's explicit compatibility map, add missing indexes, and run the listed one-time data conversions.
- A partially applied adoption: inspect objects and add only absent known objects so the revision can be retried.

Revision `20261002_0002` adds nullable `registration_invites.revoked_at` only when that column is absent. Revision `20261005_0003` adds non-null, false-default `solarwinds_alerts.needs_dispatch` only when absent, preserving all existing alert rows. Revision `20261005_0004` backfills `timeline_events.site_name` only for legacy Webhook/Alert rows whose generated alert format ends with an exact monitored-location name; unrecognized or ambiguous messages remain unscoped. Revision `20261013_0005` adds nullable `solarwinds_alerts.onpage_sent_at` to record successful paging without changing existing alert state. Revision `20261102_0006` adds the administrator-managed `monitored_location_contacts` table and site lookup index. Revision `20261103_0007` adds provider attempt/validator fields to `geojson_cache` and NWS CAP lifecycle fields to `regional_hazards`; pre-existing unverified rows receive status `unknown` and are not presented as verified active alerts. Revision `20261105_0008` adds nullable environment-override fields for alert destinations and Elastic integration plus a legacy-compatible LLM provider default. Revision `20261110_0009` creates the initial Operational Email tables. Revision `20261110_0010` adds administrator-managed signatures and nullable signature snapshot columns, and refreshes shipped template bodies only when they still exactly match prior defaults. Revision `20261111_0011` creates the Fiber/ONPAGE email contact and network-order/circuit tables without changing existing records. Revision `20261111_0012` refreshes shipped Operational Email subjects/bodies only when they exactly match prior defaults; administrator-customized text is preserved. The revisions do not drop or rename tables or columns.

## One-time data changes across revisions

The packaged revisions perform these intentional backfills:

- Fill missing user `created_at` timestamps with the migration time.
- Fill missing `last_login_at` from a user's latest existing session, and fill missing `last_activity_at` from `last_login_at` when available.
- Mark old registration invitations with no email as used so they cannot be registered from.
- Convert numeric monitored-location priorities to the current `P1-Critical` through `P5-Planning` labels.
- Backfill legacy webhook alert site names only when the generated message format and exact monitored-location suffix are both recognized (revision `20261005_0004`).
- Create the site-contact table and its location index without altering existing monitored-location rows (revision `20261102_0006`).
- Mark pre-lifecycle NWS hazard rows `unknown` while adding nullable CAP timestamps/references, coverage precision, and active/inactive lifecycle state (revision `20261103_0007`).
- Add nullable provider health/conditional-request fields to existing GeoJSON cache rows without replacing cached payloads (revision `20261103_0007`).
- Add nullable operational integration overrides and the default OpenAI-compatible provider field without rewriting existing settings (revision `20261105_0008`).

These updates do not remove existing rows. The legacy permission-catalog conversion runs separately during conditional bootstrap and is version-gated so operator-edited grants are not repeatedly rewritten.

## Compatibility limits and failure behavior

This is an additive upgrade for known application schemas, not an automatic repair for arbitrary hand-edited or severely incomplete databases. The adoption revision validates every frozen baseline table and column. If an existing table is missing a column without an explicit safe legacy definition, or if duplicate non-null normalized user emails prevent the unique index, startup fails with an error and the migration revision is not advanced. Existing application rows are left in place; the database may contain completed additive tables/columns from the failed attempt, which are inspected and reused on retry.

Before upgrading production, create and verify an encrypted full backup. Do not manually stamp `alembic_version`, delete columns, or treat a migration failure as a successful upgrade. Resolve the reported schema/data issue and restart the backend. Schema downgrade is not the rollback procedure; restore a verified pre-upgrade backup instead.

## Verification coverage

During implementation, local regression checks covered a populated pre-Alembic schema upgraded through all current revisions, preservation of user/article/site/invitation/alert records, the false default for `needs_dispatch`, a null default for `onpage_sent_at`, site-contact table creation, NWS lifecycle-column addition and legacy `unknown` status, scoped webhook-event backfill and rejection of unknown/unstructured sites, known partial-column upgrades, fail-closed handling of an unsupported older schema, duplicate-email failure, concurrent startup, and a no-work startup at head. The test suite is intentionally maintained locally and is not included in the Git repository.
