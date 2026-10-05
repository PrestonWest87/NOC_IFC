# Module: `src.api.routes.email`

Email sending routes. Prefix: `/api/v1/email`.

---

## Pydantic Models

### `SendEmailRequest`
| Field | Type | Default | Description |
|---|---|---|---|
| `to` | `str` | `""` | Recipient list, max 2,000 characters. |
| `subject` | `str` | `""` | Subject, max 200 characters. |
| `html_body` | `str` | `""` | HTML body, max 200,000 characters. |
| `attachments` | `list[EmailAttachment]` | empty list | Up to five base64-encoded attachments. |

`EmailAttachment` contains `filename` (max 120 chars), `content_type` (max 100 chars), and `content_base64` (max 7,000,000 chars).

### `BroadcastBriefRequest`

| Field | Type | Default |
|---|---|---|
| `email` | `str` | `""` |

---

## Endpoint: `POST /send`

### Purpose
Sends an HTML email via the configured SMTP mailer. Requires `Action: Send Email`.

### Parameters
| Parameter | Type               | Description                 |
|-----------|--------------------|-----------------------------|
| `req`     | `SendEmailRequest` | Email details (JSON body).  |

### Returns
```json
{
  "status": "ok" | "error",
  "message": "<description>"
}
```

### Raises
None.

### Flow
1. Calls `send_alert_email()` with `to` as recipient override, the HTML body, and decoded attachments.
2. Returns success or error based on the mailer's boolean result.

### Dependencies
- `src.utils.mailer.send_alert_email()`
## Current Source Surface

The module defines `EmailAttachment`, `SendEmailRequest`, and `BroadcastBriefRequest` models and exposes:

- `POST /send` for a permission-checked email request with optional base64 attachments.
- `POST /broadcast-brief` for the saved Unified Brief.
- `POST /broadcast-global-brief` for the saved Global Threat Brief.
- `POST /broadcast-internal-brief` for the saved Internal Asset Risk Brief.

Broadcast handlers require either the Global Dashboards or Reporting page plus `Action: Dispatch Exec Report`; they load the relevant saved brief and current internal-risk context before calling the shared mailer. SMTP configuration is read from `SystemConfig`.
