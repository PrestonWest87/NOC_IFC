# Route module: `src/api/routes/operational_email.py`

Mount prefix: `/api/v1/operational-email`. Every route has the blanket `Operational Email` page dependency. The shared-template `PUT` endpoint additionally requires the built-in administrator role.

## Operations

| Method and route | Purpose |
|---|---|
| `GET /templates` | Return template definitions, saved defaults, global From address, and attachment bounds |
| `PUT /templates/{template_key}` | Administrator-edit shared subject/body and To/Cc/Bcc defaults |
| `POST /send` | Validate, persist, and immediately deliver one template-based message |
| `POST /schedule` | Persist one-time, daily, or weekly message schedule and snapshot attachments |
| `GET /scheduled` | List pending, recurring, and processing schedules |
| `DELETE /scheduled/{email_id}` | Cancel a pending or recurring schedule |
| `GET /history` | List recent SMTP attempts without full bodies |
| `GET /history/{delivery_id}` | Retrieve an immutable message/recipient snapshot |
| `GET /maintenance-notices` | List successfully sent maintenance notifications for close-out |

`ComposeOperationalEmailRequest` disallows unknown request fields and bounds subject/body/recipient/attachment input. The From address is never accepted from the request; the shared mailer uses `SystemConfig.smtp_sender`. Only Fiber Outage accepts BCC, and only Morning Report accepts attachments. Maintenance Complete validates that its selected maintenance notice has a successful delivery.
