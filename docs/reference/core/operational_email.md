# Module: `src.core.operational_email`

Provides the persisted message/template service behind the Operational Email page and its worker schedule queue.

## Template catalog and defaults

`TEMPLATE_DEFINITIONS` declares nine stable template keys, descriptions, fill-in fields, and capability limits:

| Key | Use | Special capability |
|---|---|---|
| `maintenance_notice` | Ticket title, site, planned work, start/end window, risk, disruption, and departmental impact | Maintenance times are date/time values; no Network Orders auto-fill |
| `fiber_maintenance_notice` | Ticket title, fiber work, MOP type, and Network Orders | Multi-select references fill A/Z, company, Fiber contact information, and BCC |
| `outage_dispatch` | Request field technician dispatch | — |
| `fiber_outage` | Fiber service interruption by Location/Network Orders | Network Orders fill A/Z/company/contact and matching Fiber contacts go to BCC; no Provider field |
| `fiber_outage_update` | Progress update to an outage ticket | Requires a successfully sent Fiber Outage source |
| `fiber_outage_resolution` | Service-restoration notice | Requires a successfully sent Fiber Outage source |
| `after_hours_onpage` | Urgent after-hours acknowledgement and response | ONPAGE contact multi-select; To recipients only |
| `morning_report` | Latest Global Dashboard shift analysis | Bounded attachments; source refreshed at delivery |
| `maintenance_complete` | Close-out of planned maintenance | Requires a successfully sent maintenance-notice record |

`ensure_operational_email_templates(session_factory)` seeds missing rows without replacing administrator-edited defaults. Template placeholders use `{{field_name}}`; validation permits only field names declared for the selected template. Maintenance risk is validated against `None`, `Low`, `Medium`, or `High`; disruption is selected from `Disruptive`, `Nondisruptive`, or `Possibly Disruptive`; planned maintenance start and expected-completion fields are date/time values. Timezone labels are set server-side to the current `CST`/`CDT` application abbreviation. BCC defaults and recipients are supported by every template except After-Hours ONPAGE, which is To-only. `update_operational_email_template()` validates subject/body length, placeholders, recipients, and the fixed Morning Report source body, then records an account-audit event.

Administrator-managed signatures have a unique name, plain-text content, active state, and optional default state. At most one active default is selected. Senders can use that default, choose another active signature, or explicitly send without a signature. Selected signature ID/name/content are captured when sending or scheduling, so later edits/deactivation do not alter a scheduled message.

## Message validation and delivery

`normalize_recipient_list()` validates comma/semicolon-separated addresses and removes duplicates. `_normalize_fields()` enforces the selected template's allowed keys, required fields, choices, date/time format, and per-field bounds. `get_operational_email_reference_data()` returns ordered Fiber/ONPAGE contacts and Network Orders to page-authorized composers. `_resolve_network_order_contacts()` validates selected record IDs, fills absent A/Z/Network Orders/company/contact text, and adds matching Fiber contact email addresses as BCC envelopes. `_normalize_attachments()` accepts no more than five files, 5 MiB each and 20 MiB combined; it sanitizes filenames and persists decoded bytes with the message snapshot.

`send_operational_email()` resolves defaults, linked source fields, and the selected signature; validates recipients/fields; persists an `OperationalEmail` row plus attachment bytes; then calls `_attempt_delivery()`. Every attempt creates an immutable `OperationalEmailDelivery` snapshot with the active provider (`smtp` or `gmail`), From address, To/Cc/Bcc envelope, selected signature name, rendered body, and attachment names. BCC is omitted from visible mail headers. The shared mailer handles transport failures; both successful and failed outcomes remain visible in history. Scheduled messages use the profile active at delivery time; completed history retains the provider used for that attempt.

`schedule_operational_email()` accepts one-time timezone-aware ISO timestamps or daily/weekly `America/Chicago` wall-clock schedules. `_next_recurrence()` calculates the next Central occurrence and stores it in UTC. `process_due_operational_emails()` atomically claims due rows, records one delivery per occurrence, advances recurring schedules, and leaves a visible failure state for unsuccessful one-time sends. Morning Report uses the most recent `SystemConfig.rolling_summary` at delivery time and sends it without report-date/window/title/executive-summary wrapping; the selected signature and attachments remain snapshotted. `cancel_scheduled_operational_email()` cancels pending/recurring rows and refuses an in-flight send.

Maintenance completion accepts its legacy `maintenance_notice_id` and current `source_email_id`; both require at least one successful maintenance-notice delivery. Fiber progress/resolution accepts `source_email_id` for a successfully delivered `fiber_outage` message. Source fields and recipients prefill the new message; each child stores a `parent_email_id` to the original source so multiple updates can share the same outage ticket.

## Persistence and operational boundaries

Migration `20261110_0009` creates the initial Operational Email tables; `20261110_0010` adds administrator-managed signatures/signature snapshots and safe shipped-default refreshes; `20261111_0011` adds the Fiber/ONPAGE contact and Network Order reference directories; `20261111_0012` refreshes untouched compose defaults for ticket title, risk/disruption, Network Orders, A/Z, and Location fields; `20261112_0013` adds the sender-provider snapshot column to delivery history. The `operational_email_templates`, `operational_email_signatures`, `operational_emails`, `operational_email_attachments`, and `operational_email_deliveries` tables persist this workflow. Attachment bytes stay in SQLite so the queue survives restarts and is covered by the encrypted full-database backup. The worker's non-disableable one-minute registry job calls `process_due_operational_emails()`.

All HTTP operations require the `Operational Email` page grant. Shared template defaults and signature management are administrator-only; send, schedule, cancellation, and history do not require separate action grants.
