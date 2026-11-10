# Module: `src.core.operational_email`

Provides the persisted message/template service behind the Operational Email page and its worker schedule queue.

## Template catalog and defaults

`TEMPLATE_DEFINITIONS` declares six stable template keys, descriptions, fill-in fields, and capability limits:

| Key | Use | Special capability |
|---|---|---|
| `maintenance_notice` | Planned work, window, and impact | Eligible as a source for completion messages after successful delivery |
| `outage_dispatch` | Request field technician dispatch | — |
| `fiber_outage` | Fiber service interruption | BCC recipients |
| `after_hours_onpage` | Urgent after-hours acknowledgement and response | — |
| `morning_report` | Morning operations report | Bounded attachments |
| `maintenance_complete` | Close-out of planned maintenance | Requires a successfully sent maintenance-notice record |

`ensure_operational_email_templates(session_factory)` seeds missing rows without replacing administrator-edited defaults. Template placeholders use `{{field_name}}`; validation permits only field names declared for the selected template. `update_operational_email_template()` validates subject/body length, placeholders, recipients, and fiber-only BCC defaults, then records an account-audit event.

## Message validation and delivery

`normalize_recipient_list()` validates comma/semicolon-separated addresses and removes duplicates. `_normalize_fields()` enforces the selected template's allowed keys, required fields, and per-field bounds. `_normalize_attachments()` accepts no more than five files, 5 MiB each and 20 MiB combined; it sanitizes filenames and persists decoded bytes with the message snapshot.

`send_operational_email()` resolves defaults, validates recipients and fields, persists an `OperationalEmail` row plus attachment bytes, then calls `_attempt_delivery()`. Every attempt creates an immutable `OperationalEmailDelivery` snapshot with the global SMTP From address, recipient fields, rendered body, and attachment names. The shared mailer handles transport failures; both successful and failed outcomes remain visible in history.

`schedule_operational_email()` accepts one-time timezone-aware ISO timestamps or daily/weekly `America/Chicago` wall-clock schedules. `_next_recurrence()` calculates the next Central occurrence and stores it in UTC. `process_due_operational_emails()` atomically claims due rows, records one delivery per occurrence, advances recurring schedules, and leaves a visible failure state for unsuccessful one-time sends. `cancel_scheduled_operational_email()` cancels pending/recurring rows and refuses an in-flight send.

Maintenance completion requires `maintenance_notice_id` to refer to a maintenance-notice message with at least one successful delivery. Source fields and recipients can prefill the new message; the relationship is persisted as `parent_email_id`.

## Persistence and operational boundaries

The `operational_email_templates`, `operational_emails`, `operational_email_attachments`, and `operational_email_deliveries` tables are created by migration `20261110_0009`. Attachment bytes stay in SQLite so the queue survives restarts and is covered by the encrypted full-database backup. The worker's non-disableable one-minute registry job calls `process_due_operational_emails()`.

All HTTP operations require the `Operational Email` page grant. Administrator-only shared template changes are enforced by the route; send, schedule, cancellation, and history do not require separate action grants.
