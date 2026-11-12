# Route module: `src/api/routes/operational_email.py`

Mount prefix: `/api/v1/operational-email`. Every route has the blanket `Operational Email` page dependency. Shared-template changes and signature writes additionally require the built-in administrator role.

## Operations

| Method and route | Purpose |
|---|---|
| `GET /templates` | Return template definitions, saved defaults, global From address, and attachment bounds |
| `GET /reference-data` | Return Fiber/ONPAGE contacts and network-order/circuit rows for authorized composers |
| `PUT /templates/{template_key}` | Administrator-edit shared subject/body and To/Cc/Bcc defaults |
| `GET /signatures` | List active signatures and current default |
| `GET /signatures/manage` | Administrator-list all signatures, including inactive ones |
| `POST /signatures` | Administrator-create a shared signature |
| `PUT /signatures/{signature_id}` | Administrator-update a signature/default selection |
| `DELETE /signatures/{signature_id}` | Administrator-deactivate a signature without deleting history |
| `POST /send` | Validate, persist, and immediately deliver one template-based message |
| `POST /schedule` | Persist one-time, daily, or weekly message schedule and snapshot attachments |
| `GET /scheduled` | List pending, recurring, and processing schedules |
| `DELETE /scheduled/{email_id}` | Cancel a pending or recurring schedule |
| `GET /history` | List recent SMTP attempts without full bodies |
| `GET /history/{delivery_id}` | Retrieve an immutable message/recipient snapshot |
| `GET /maintenance-notices` | List successfully sent maintenance notifications for close-out |
| `GET /fiber-outages` | List successfully sent outage tickets for linked progress/resolution messages |

`ComposeOperationalEmailRequest` disallows unknown request fields and bounds subject/body/recipient/attachment input. The From address is never accepted from the request; the shared mailer uses `SystemConfig.smtp_sender`. `GET /signatures` returns active entries to page users; the admin-only `/signatures/manage` includes inactive entries. BCC is accepted by every template except After-Hours ONPAGE, which is To-only. Only Morning Report accepts attachments. Maintenance Complete can use the legacy `maintenance_notice_id` or `source_email_id`. Fiber progress/resolution requires a successfully sent fiber outage `source_email_id`. Signature name/content is snapshotted when a message or schedule is created. Morning Report reads the latest Global Dashboard shift analysis again at delivery time.
