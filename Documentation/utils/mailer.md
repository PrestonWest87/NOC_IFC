# Module: `src/utils/mailer.py`

Email sending utility for the NOC Intelligence Fusion Center. Provides a single function to send alert emails via SMTP using system configuration stored in the database.

---

## Functions

---

### `send_alert_email`

**Purpose:** Send an alert email through the configured SMTP server using system settings from the database.

**Signature:**
```python
def send_alert_email(
    subject: str,
    body: str,
    recipient_override: str = None,
    is_html: bool = True
) -> tuple[bool, str]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `subject` | `str` | Email subject line (prefixed with `[NOC FUSION] ` automatically) |
| `body` | `str` | Email body content |
| `recipient_override` | `str \| None` | Optional override recipient email address; if `None`, uses `config.smtp_recipient` |
| `is_html` | `bool` | Whether to render the body as HTML; defaults to `True`. When enabled, performs lightweight Markdown-to-HTML conversion (line breaks, bold, headers) |

**Returns:**

| Type | Description |
|------|-------------|
| `tuple[bool, str]` | `(True, "Email sent successfully.")` on success; `(False, error_message)` on failure |

**Raises:** None (all exceptions are caught and returned as the error string)

**Flow:**
1. Opens a new database session via `SessionLocal()`
2. Queries the first `SystemConfig` row from the database
3. Validates preconditions:
   - Returns `(False, "SMTP is disabled in Settings.")` if `config` is `None` or `smtp_enabled` is falsy
   - Returns `(False, "SMTP configuration is incomplete...")` if `smtp_server`, `smtp_sender`, or resolved recipient are missing
4. Determines target recipient: `recipient_override` if provided, otherwise `config.smtp_recipient`
5. Constructs a `MIMEMultipart` email:
   - Sets `From`, `To`, and `Subject` headers (subject is prefixed with `[NOC FUSION] `)
6. If `is_html` is `True`:
   - Converts newlines to `<br>`, `**` to `<b>`, `##`/`###` to `<h2>`/`<h3>`
   - Attaches as `MIMEText` with `'html'` subtype
7. If `is_html` is `False`:
   - Attaches as `MIMEText` with `'plain'` subtype
8. Connects to SMTP server at `config.smtp_server:config.smtp_port`
9. Attempts `starttls()` (swallows exceptions if TLS is unavailable)
10. Logs in with `smtp_username`/`smtp_password` if both are configured
11. Sends the message via `server.send_message()`
12. Quits the server connection
13. Returns success tuple
14. On any `Exception`, returns `(False, str(exception))`
15. In the `finally` block, closes the database session

**Dependencies:**

| Dependency | Usage |
|------------|-------|
| `smtplib` | SMTP connection and email transmission |
| `email.mime.text.MIMEText` | MIME text payload creation |
| `email.mime.multipart.MIMEMultipart` | Multipart email container |
| `src.core.db.SessionLocal` | Database session factory |
| `src.models.schema.SystemConfig` | Database model for SMTP configuration |

---

## Configuration Requirements

The following fields must be set in the `SystemConfig` database table for email to function:

| Field | Description |
|-------|-------------|
| `smtp_enabled` | Boolean flag enabling/disabling SMTP |
| `smtp_server` | SMTP server hostname or IP address |
| `smtp_port` | SMTP server port (typically 25, 587, or 465) |
| `smtp_sender` | From email address |
| `smtp_recipient` | Default recipient email address (used when no override provided) |
| `smtp_username` | Optional SMTP authentication username |
| `smtp_password` | Optional SMTP authentication password |

---

## HTML Conversion Rules

When `is_html=True`, the function performs the following lightweight conversions:

| Input Pattern | Output |
|---------------|--------|
| `\n` | `<br>` |
| `**text**` | `<b>text</b>` |
| `## text` | `<h2>text</h2>` |
| `### text` | `<h3>text</h3>` |
