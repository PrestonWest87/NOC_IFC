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
| `POST /send` | Validate, persist, and immediately deliver a template-based message (one per company for Fiber Maintenance and selected-circuit Fiber Outage) |
| `POST /schedule` | Persist one-time, daily, or weekly schedules and snapshot attachments (one per company for Fiber Maintenance and selected-circuit Fiber Outage) |
| `GET /scheduled` | List pending, recurring, and processing schedules |
| `DELETE /scheduled/{email_id}` | Cancel a pending or recurring schedule |
| `GET /history` | List recent delivery attempts without full bodies |
| `GET /history/{delivery_id}` | Retrieve an immutable message/recipient snapshot |
| `GET /maintenance-notices` | List successfully sent Maintenance and Fiber Maintenance notifications for Maintenance Start and Complete |
| `GET /fiber-outages` | List successfully sent outage tickets for linked progress/resolution messages |

`ComposeOperationalEmailRequest` disallows unknown request fields and bounds subject/body/recipient/attachment input. The From address is never accepted from the request; the shared mailer uses the active sender profile. Fiber Outage without configured circuits and single-message linked follow-ups use Global From as To. Selected-circuit Fiber Outage and Fiber Maintenance require a mapped Fiber email contact for each selected company and create one message per company, putting that company's mapped addresses in To and Global From in Cc. Fiber Maintenance also combines administrator default Cc with editable per-message Cc. Each message includes only that company's selected circuits and A/Z details, with each circuit ID paired with its A/Z locations. Scheduled sends use the same company split. The entire selection is validated before any message is sent or scheduled. Company-grouped subject/message previews are read-only and rendered per company from the shared template defaults. Fiber-contact BCC selection is available on Fiber Outage and Fiber Outage Resolution; mapped To contacts are not automatically copied to BCC, and manually entered BCC recipients carry into linked messages. A grouped source appears once in its selector; linked outage updates/resolutions and Fiber Maintenance Start/Complete notices fan out once for each source company with a successful delivery and retain that company's recipients/circuit subset. Fiber Outage requires a manually supplied nearest-crossroads Location and treats Network Orders/Circuit IDs as optional; selecting them does not fill Location or contact name/phone text fields. Fiber Outage ONPAGE sends directory-selected ONPAGE contacts to To and Global From on Cc, with no Fiber-contact BCC selector. After-Hours ONPAGE remains To-only. Only Morning Report accepts attachments.

Maintenance Start and Maintenance Complete accept a successfully sent Maintenance Notification or Fiber Maintenance Notification through `source_email_id`; Maintenance Complete also accepts legacy `maintenance_notice_id`. Linked messages inherit source operational fields and recipients, preserve source BCC, and combine source Cc with administrator defaults unless the sender explicitly edits Cc. A grouped Fiber Maintenance source creates one Start/Complete message per successfully delivered company. Planned maintenance-window values in message bodies use `MM/DD/YY HH:MM AM/PM` with the active CST/CDT label; other date/time fields use that format and include a timezone suffix only where their template includes one. Signature name/content is snapshotted when a message or schedule is created. Morning Report reads the latest Global Dashboard shift analysis again at delivery time. Operational Email sends plain-text and preformatted HTML alternatives with preserved line breaks.
