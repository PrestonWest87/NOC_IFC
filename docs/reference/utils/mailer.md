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
    is_html: bool = True,
    attachments=None,
    cc_override: str = None,
    bcc_override: str = None,
    subject_prefix: str = "[NOC FUSION]",
) -> tuple[bool, str]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `subject` | `str` | Email subject line; prefixed with `[NOC FUSION] ` by default |
| `body` | `str` | Email body content |
| `recipient_override` | `str \| None` | Optional override recipient email address; if `None`, uses `config.smtp_recipient` |
| `cc_override` | `str \| None` | Optional visible Cc recipients |
| `bcc_override` | `str \| None` | Optional hidden Bcc recipients, included only in the SMTP envelope |
| `is_html` | `bool` | Whether to render the body as HTML; defaults to `True`. When enabled, performs lightweight Markdown-to-HTML conversion (line breaks, bold, headers) |
| `attachments` | `list[dict] \| None` | Optional list of `{filename, content_type, content_base64}` objects. Filenames are reduced to a basename, base64 must validate, and each decoded attachment is limited to 5 MiB. The HTTP model allows at most five attachments. |
| `subject_prefix` | `str` | Prefix applied to the subject; use an empty string to preserve an exact subject for risk notifications. |

**Returns:**

| Type | Description |
|------|-------------|
| `tuple[bool, str]` | `(True, "Email sent successfully.")` on success; `(False, error_message)` on failure |

**Raises:** None (all exceptions are caught and returned as the error string)

**Flow:**
1. Opens a new database session via `SessionLocal()`
2. Queries the first `SystemConfig` row from the database
3. Resolves `SystemConfig.active_smtp_provider` through `src.core.email_settings.get_active_smtp_profile()`; the legacy `smtp` profile remains the default.
4. Validates the selected profile's enabled state, SMTP endpoint, From address, and recipient. The Gmail profile additionally requires a saved account and app password.
5. Determines target recipient: `recipient_override` if provided, otherwise the shared `smtp_recipient`.
6. Constructs a `MIMEMultipart` email:
   - Sets `From`, `To`, optional `Cc`, and `Subject` headers using `subject_prefix`
   - Resolves To/Cc/Bcc addresses into the SMTP envelope without adding a `Bcc` message header
7. If `is_html` is `True`:
   - Converts newlines to `<br>`, `**` to `<b>`, `##`/`###` to `<h2>`/`<h3>`
   - Attaches as `MIMEText` with `'html'` subtype
8. If `is_html` is `False`:
   - Attaches as `MIMEText` with `'plain'` subtype
9. Connects to the selected profile endpoint with a 10-second timeout and calls `starttls()`.
10. Logs in when both username and password are configured. Gmail uses `smtp.gmail.com:587`; copied app-password whitespace is removed before authentication.
11. Sends the message and closes the SMTP connection. BCC is included only in the envelope.
12. Returns `(True, "Email sent successfully.")` on success. Gmail authentication errors return an app-password-specific message without exposing credentials.
13. Closes the SMTP connection and database session in `finally`.

**Dependencies:**

| Dependency | Usage |
|------------|-------|
| `smtplib` | SMTP connection and email transmission |
| `email.mime.text.MIMEText` | MIME text payload creation |
| `email.mime.multipart.MIMEMultipart` | Multipart email container |
| `email.utils.getaddresses`, `email.utils.parseaddr` | Resolve envelope and sender addresses |
| `src.core.db.SessionLocal` | Database session factory |
| `src.models.schema.SystemConfig` | Database model for SMTP configuration |

`SystemConfig.active_smtp_provider` selects either the existing configurable relay (`smtp_*`) or the Gmail profile (`gmail_smtp_*`). Gmail host and port are fixed at `smtp.gmail.com:587`; both profiles use STARTTLS. The helper logs recipient counts rather than logging attachment contents. It does not guarantee SMTP server-side delivery beyond a successful `send_message()` call.

---

## Configuration Requirements

The following fields must be set in the `SystemConfig` database table for email to function:

| Field | Description |
|-------|-------------|
| `active_smtp_provider` | `smtp` or `gmail`; selects the profile for all outgoing IFC email |
| `smtp_enabled` | Enables the existing SMTP relay profile |
| `smtp_server` / `smtp_port` | Existing relay endpoint; StartTLS is used |
| `smtp_sender` | Existing relay From address |
| `smtp_recipient` | Default recipient email address (used when no override provided) |
| `smtp_username` | Optional SMTP authentication username |
| `smtp_password` | Optional SMTP authentication password |
| `gmail_smtp_enabled` | Enables the Gmail profile |
| `gmail_smtp_username` | Gmail or Google Workspace account address |
| `gmail_smtp_password` | Google App Password; required for Gmail SMTP authentication |
| `gmail_smtp_sender` | Optional Gmail From address; defaults to the account address |

---

## HTML Conversion Rules

When `is_html=True`, the function performs the following lightweight conversions:

| Input Pattern | Output |
|---------------|--------|
| `\n` | `<br>` |
| `**text**` | `<b>text</b>` |
| `## text` | `<h2>text</h2>` |
| `### text` | `<h3>text</h3>` |
