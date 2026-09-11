# Module: `src.api.routes.email`

Email sending routes. Prefix: `/api/v1/email`.

---

## Pydantic Models

### `SendEmailRequest`
| Field        | Type      | Default | Description                             |
|--------------|-----------|---------|-----------------------------------------|
| `subject`    | `str`     | `""`    | Email subject line.                     |
| `body`       | `str`     | `""`    | Email body content.                     |
| `recipients` | `str`     | `""`    | Comma-separated recipient addresses.    |
| `is_html`    | `bool`    | `False` | Whether the body contains HTML markup.  |

---

## Endpoint: `POST /send`

### Purpose
Sends an email via the configured SMTP mailer.

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
1. Validates that `recipients` is not empty; returns error if so.
2. Calls `send_alert_email()` with subject, body, recipient override, and HTML flag.
3. Returns success or error based on the boolean result.

### Dependencies
- `src.utils.mailer.send_alert_email()`
## Current Source Surface

The module defines `EmailAttachment`, `SendEmailRequest`, and `BroadcastBriefRequest` models and exposes:

- `POST /send` for a permission-checked email request with optional base64 attachments.
- `POST /broadcast-brief` for the saved Unified Brief.
- `POST /broadcast-global-brief` for the saved Global Threat Brief.
- `POST /broadcast-internal-brief` for the saved Internal Asset Risk Brief.

Broadcast handlers load the relevant brief and internal-risk context before calling the shared mailer. SMTP configuration is read from `SystemConfig`.
