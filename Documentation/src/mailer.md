# Enterprise Architecture & Functional Specification: `src/mailer.py`

## 1. Executive Overview

The `src/mailer.py` module acts as the **Outbound Notification & Dispatch Engine** for the Intelligence Fusion Center (IFC). It provides a centralized, secure interface for transmitting critical alerts, automated AIOps forensic tickets, and Executive Situation Reports (SitReps) directly to the organization's existing email infrastructure.

It supports **unauthenticated internal SMTP relays**, optional TLS encryption, recipient overrides, and both HTML and plain-text email formats.

---

## 2. Configuration & Security Validation

### `send_alert_email(subject: str, body: str, recipient_override: str = None, is_html: bool = True)`

Before attempting any network connections, the function executes a strict validation check:
1. **Global Kill Switch:** Checks `config.smtp_enabled`. If disabled, instantly aborts.
2. **Configuration Completeness:** Verifies `smtp_server`, `smtp_sender`, and at least one recipient (override or default) are populated.

---

## 3. Algorithmic Processing

### Markdown Normalization
- `\n` → `<br>` (Line breaks)
- `**` → `<b>` (Bold text)
- `##` → `<h2>` (Section headers)
- `###` → `<h3>` (Sub-headers)

### MIME Construction
- Wraps HTML into `MIMEText(html_body, 'html')` when `is_html=True`
- Uses `MIMEMultipart()` container
- Prepends `[NOC FUSION]` to all subject lines

---

## 4. Execution & Fault Tolerance

1. **Connection:** Connects to `smtp_server:smtp_port`
2. **TLS (Optional):** Attempts `starttls()` but passes gracefully if the relay doesn't support it
3. **Authentication (Optional):** Only logs in if both `smtp_username` and `smtp_password` are configured
4. **Send:** Transmits the message and quits
5. **Error Handling:** All exceptions are caught and returned as `(False, str(e))`
6. **Cleanup:** `finally` block ensures `session.close()`

---

## 5. Complete Function Reference

| Function | Signature | Purpose |
|----------|-----------|---------|
| `send_alert_email` | `(subject, body, recipient_override, is_html) -> tuple` | Send email via configured SMTP |

---

## 6. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| smtplib | SMTP | https://docs.python.org/3/library/smtplib.html |
| email.mime | MIME | https://docs.python.org/3/library/email.mime.html |
