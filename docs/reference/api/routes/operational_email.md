# Route module: `src/api/routes/operational_email.py`

Mount prefix: `/api/v1/operational-email`. Every route has the blanket `Operational Email` page dependency. Shared-template changes and signature writes additionally require the built-in administrator role.

## Operations

| Method and route | Purpose |
|---|---|
| `GET /templates` | Return template definitions, saved defaults, global From address, and attachment bounds |
| `GET /reference-data` | Return Fiber contacts and network-order/circuit rows; ONPAGE contacts are returned only with `include_onpage=true` for ONPAGE templates |
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

`ComposeOperationalEmailRequest` disallows unknown request fields and bounds subject/body/recipient/attachment input. The From address is never accepted from the request; the shared mailer uses the active SMTP profile. Fiber Maintenance, Fiber Outage, and follow-ups use Global From as To; Fiber contact selections and Network Orders auto-matches go to BCC. Fiber Outage ONPAGE sends directory-selected ONPAGE contacts to To and Global From on Cc; Network Orders do not auto-fill its BCC. Follow-ups accept either initial Fiber template as `source_email_id`, use Global From on To, omit ONPAGE recipients, and retain the source BCC list. After-Hours ONPAGE remains To-only. Only Morning Report accepts attachments. Maintenance Complete can use the legacy `maintenance_notice_id` or `source_email_id`. Signature name/content is snapshotted when a message or schedule is created. Morning Report reads the latest Global Dashboard shift analysis again at delivery time. Plain-text message line endings are normalized while paragraph spacing is preserved.
