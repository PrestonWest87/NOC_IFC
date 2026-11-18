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
| `POST /send` | Validate, persist, and immediately deliver a template-based message (one per company for Fiber Maintenance) |
| `POST /schedule` | Persist one-time, daily, or weekly schedules and snapshot attachments (one per company for Fiber Maintenance) |
| `GET /scheduled` | List pending, recurring, and processing schedules |
| `DELETE /scheduled/{email_id}` | Cancel a pending or recurring schedule |
| `GET /history` | List recent SMTP attempts without full bodies |
| `GET /history/{delivery_id}` | Retrieve an immutable message/recipient snapshot |
| `GET /maintenance-notices` | List successfully sent Maintenance and Fiber Maintenance notifications for close-out |
| `GET /fiber-outages` | List successfully sent outage tickets for linked progress/resolution messages |

`ComposeOperationalEmailRequest` disallows unknown request fields and bounds subject/body/recipient/attachment input. The From address is never accepted from the request; the shared mailer uses the active SMTP profile. Fiber Outage and linked follow-ups use Global From as To. Fiber Maintenance requires selected configured Network Order/Circuit records and a mapped Fiber contact for each selected company; it creates one message per company, puts that company's contacts in To, copies Global From on Cc, and renders only that company's circuits, A/Z locations, and contact details. Scheduled Fiber Maintenance creates one schedule per selected company. The entire selection is validated before any message is sent or scheduled. Its shared-template subject/message previews are read-only so company-specific output is rendered from the same placeholders. Fiber-contact BCC selection is available on Fiber Outage and Fiber Outage Resolution; linked messages retain the source BCC list. Fiber Outage requires a manually supplied nearest-crossroads Location and treats Network Orders/Circuit IDs as optional; selecting them does not fill Location. Pasting configured IDs into the Network Orders/Circuit IDs field selects matching records and fills their contact/A/Z data where applicable. Fiber Outage ONPAGE sends directory-selected ONPAGE contacts to To and Global From on Cc, with no Fiber-contact BCC selector. After-Hours ONPAGE remains To-only. Only Morning Report accepts attachments. Maintenance Complete accepts a successful Maintenance Notification or Fiber Maintenance Notification through `maintenance_notice_id` or `source_email_id`. Date/time values in Maintenance/Fiber Maintenance message bodies use `MM/DD/YY HH:MM AM/PM` with the active CST/CDT label. Signature name/content is snapshotted when a message or schedule is created. Morning Report reads the latest Global Dashboard shift analysis again at delivery time. Operational Email sends plain-text and preformatted HTML alternatives with preserved line breaks.
