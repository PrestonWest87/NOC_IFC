# Route module: `src.api.routes.settings_admin`

Prefix: `/api/v1/admin`. The entire router has `Depends(require_admin)`: a built-in `admin`/`administrator` role is required, in addition to normal session authentication. New delegated user-management and application-settings operations use the separate `/user-admin` and `/application-settings` routers.

## Lists, scoring, feeds, and assets

| Method/path | Inputs and behavior |
|---|---|
| `GET /lists` | Returns keywords, feeds, and a sanitized legacy user list (`id`, username, role, full name only). |
| `POST /keywords/bulk?raw_text=...` | Newline-separated `word,weight`; missing/invalid/out-of-range weights fall back to 10. |
| `PATCH /keywords/{keyword_id}` | JSON `{weight}`; requires an integer 1–100, updates the database and reloads the scorer. |
| `DELETE /keywords/{keyword_id}` | Deletes a keyword record. |
| `POST /feeds/bulk?raw_text=...` | Newline-separated `url, name`; duplicate URLs are skipped. |
| `DELETE /feeds/{feed_id}` | Deletes a feed record. |
| `GET /ml-counts` | Returns positive, negative, and total labeled-article counts. |
| `POST /ml-retrain` | Synchronously calls `train()` and reloads the scorer; failures return an error result. The newer delegated route is `/application-settings/ml-retrain`. |
| `POST /assets/software` | JSON body `{ "csv_body": "..." }`; requires a `name` column and replaces the software-asset table. |
| `POST /assets/hardware` | JSON body `{ "csv_body": "..." }`; requires an `IP Address` column and replaces the hardware-asset table. |

`GET /roles`, `POST /roles`, and `PUT /roles/{name}` read/create/update role definitions. Role changes are validated by the service; the built-in administrator role cannot be edited through the update route. Delegated role management uses `/user-admin/roles` and `Action: Manage Roles`.

## Compatibility user, invitation, and location routes

| Method/path | Inputs and behavior |
|---|---|
| `POST /users` | Compatibility path for creating a display account; accepts username/password/role/full name and returns its user ID. |
| `POST /registration-invites` | Creates an email-required individual invitation; accepts username/email/role/optional `ttl_hours`, queues an email, and returns the registration URL. |
| `PUT /users/{username}/role` | JSON `{role}`; updates the role and revokes sessions. |
| `POST /users/{username}/reset-password` | JSON `{new_password}`; enforces 12+ characters, revokes sessions and outstanding reset tokens, and audits the action. |
| `GET /location` | Returns cached monitored locations (unscoped administrator view). |
| `GET /location/{location_id}/contacts` | Returns `{contacts:[...]}` for one site; contacts are separate from shared location payloads. |
| `PUT /location/{location_id}/contacts` | Administrator-only replacement with `{contacts:[{name,phone,email}]}`. Fields are optional; email and international-style phone values are validated, entries are trimmed, and fully blank rows are dropped. Maximum 50 contacts per site. |
| `PUT /email-contacts/fiber` | Replace up to 250 Fiber contacts with `{contacts:[{name,company,email,phone?}]}`; email is required, phone is optional, values are validated, and the saved count is audited. |
| `PUT /email-contacts/onpage` | Replace up to 250 ONPAGE department destinations with `{contacts:[{department,email}]}`; both fields are required and validated. |
| `POST /email-contacts/fiber/import` | Import `{csv_text,mode?}` with `name,company,email` and optional `phone` columns; merge-by-email is the default, or replace all rows. |
| `POST /email-contacts/onpage/import` | Import `{csv_text,mode?}` with `department,email` columns; merge-by-department is the default, or replace all rows. |
| `PUT /network-orders` | Replace up to 250 `{a_location,z_location,circuit_network_order_id,company}` reference rows. |
| `POST /network-orders/import` | Import `{csv_text,mode?}` with A location, Z location, Circuit/Network Order ID, and Company columns; merge-by-ID is the default, or replace all rows. |
| `POST /location/import?mode=add|upsert|replace` | JSON array of location objects. The route validates mode, returns `{status, mode, count}`, and clears the location cache. `replace` recreates the site list while preserving contacts for sites whose names remain in the imported list. |
| `PUT /location` | JSON array of edited location records; service updates rows by ID and clears the location cache. |

Monitored-site contact API responses and writes are administrator-only. These site contacts are not included in `GET /location`, `/settings/facilities`, regional, or AIOps site payloads; their email addresses appear as reference text only in automatic ONPAGE message bodies and are not used as recipients.

The Fiber, ONPAGE, and network-order directories are independent Settings reference data. Reads require their respective Settings tab grants; writes are administrator-only. Replacement preserves row order and records only counts in the audit trail.

The full role-aware individual/display-account workflow, invitation queue, recovery review, session revocation, and audit behavior is documented in [`routes/user_admin.md`](user_admin.md).

## Configuration compatibility route

`POST /config` accepts a JSON object and calls `save_global_config(..., allow_system_fields=False)`. It is administrator-only. The service allowlist includes user-editable application configuration; system-maintained brief/risk-state fields are removed from this path. Risk/application UI changes now use the narrower category endpoints, while administrator-only compatibility writes remain available.

`POST /config/test-email` accepts one validated recipient and sends a short message through the saved active SMTP profile. It uses the same sender selector as alerts, reports, recovery mail, and Operational Email; failures return HTTP 502 with a credential-safe message.

## Backup and restore

All endpoints in this group are administrator-only. Configure `BACKUP_ENCRYPTION_KEYS` and `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` before creating or staging packages.

| Method/path | Behavior |
|---|---|
| `GET /backups/status` | Returns encryption-configured flag, max bytes, and scheduled retention policy; never returns key material. |
| `GET /backups` | Lists encrypted `.nocbackup` package metadata. |
| `POST /backups` | Creates an authenticated encrypted SQLite online backup and includes the persistent model artifact when present. |
| `GET /backups/{backup_id}/download` | Streams the encrypted package with `Cache-Control: no-store`; normal Bearer auth or a short-lived scoped cookie is accepted. |
| `POST /backups/{backup_id}/download-link` | Verifies the package and returns a same-origin URL while setting a 60-second HttpOnly, path-scoped download cookie. |
| `DELETE /backups/{backup_id}` | Deletes manual or pre-restore safety packages. Scheduled packages are retention-managed and cannot be deleted here. |
| `GET /backups/staged` | Lists validated staged restore packages. |
| `POST /backups/staged` | Multipart form field `file`; validates encryption, manifest/checksums, archive layout, and SQLite integrity before staging. It does not restore. |
| `DELETE /backups/staged/{stage_id}` | Removes one staged package. |
| `POST /backups/staged/{stage_id}/restore` | Starts a UI-managed restore and returns 202 with a random `restore_id`. The API gates requests, closes WebSockets, waits for API/worker/webhook writers to drain, then migrates and atomically installs the package with rollback handling. |
| `POST /restore-status` | This capability endpoint is mounted at `/api/v1/restore-status`, outside the `/admin` prefix. It accepts `{restore_id}` and does not require a session because a successful restore revokes the initiating session. |

Restore invalidates restored sessions and outstanding invitation/reset/email-verification links, preserves request/audit history, and clears staged packages on success. The offline fallback is `scripts/restore_backup.py --maintenance-confirmed` after stopping all writers. See [`core/backup_restore.md`](../../core/backup_restore.md) and [`MAINTENANCE.md`](../../../MAINTENANCE.md).

## Legacy partial migration and destructive tools

| Method/path | Behavior |
|---|---|
| `GET /backup` | Four-collection legacy JSON backup: keywords, feeds, locations, aliases. |
| `POST /restore` | Adds missing records from that legacy JSON; not a database-file restore. |
| `GET /export-all` | Exports the 28 model classes in `ALL_MODELS`, including site contacts; may include password hashes/stored integrations and omits sessions, recovery state, failed-login records, audit, and scheduler config. |
| `POST /import-all` | Imports supported JSON tables; default replaces non-empty supported tables, body `{"_merge":true}` skips duplicate IDs. |
| `POST /upload-db` | Multipart `.db` file; reads the upload into memory and imports rows into the active database. It does not replace the active SQLite file. |
| `DELETE /record?model_name=...&record_id=...` | Deletes only service-allowlisted `Keyword`, `FeedSource`, `User`, `Role`, or `SavedReport` records. |
| `POST /nuke` | Calls a limited model allowlist: `CloudOutage`, `MonitoredLocation`, `Article`, `ExtractedIOC`, `FeedSource`, `Keyword`. It is not a full database reset. |
| `POST /nuke/crime` | Deletes crime incidents. |
| `POST /nuke/weather` | Deletes regional hazards and GeoJSON cache, resets site SPC risk. |
| `POST /maintenance` | Runs the scheduler's database-retention/SQLite-maintenance function synchronously. |

Create and verify an encrypted full backup before using any destructive or import tool. Legacy JSON and `.db` upload paths are partial migrations, not disaster-recovery restore.
