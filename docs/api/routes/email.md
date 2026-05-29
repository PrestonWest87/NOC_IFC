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
