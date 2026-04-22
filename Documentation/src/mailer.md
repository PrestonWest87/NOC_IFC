# Enterprise Architecture & Functional Specification: `src/mailer.py`

## 1. Executive Overview

The `src/mailer.py` module acts as the **Outbound Notification & Dispatch Engine** for the Intelligence Fusion Center (IFC). It provides a centralized, secure interface for transmitting critical alerts, automated AIOps forensic tickets, and Executive Situation Reports (SitReps) directly to the organization's existing email or ITSM ingestion infrastructure.

By abstracting the SMTP logic into a dedicated worker function, the application ensures that all outbound communications share a uniform format, adhere to global configuration toggles, and handle network failures gracefully without crashing the main application thread.

---

## 2. Configuration & Security Validation

The module heavily relies on the `SystemConfig` database table to dictate its operational state. 

### `send_alert_email(subject: str, markdown_body: str)`
Before attempting any network connections, the function executes a strict, dual-layer validation check:
1.  **Global Kill Switch:** It checks `config.smtp_enabled`. If the administrator has toggled this off in the settings UI, the function instantly aborts and returns a safe `False` state.
2.  **Configuration Completeness Check:** It verifies that all required SMTP parameters are explicitly populated (`smtp_server`, `smtp_username`, `smtp_password`, `smtp_sender`, `smtp_recipient`). If any field is missing, it aborts, preventing malformed requests from throwing `SMTPException` errors.

---

## 3. Algorithmic Processing: Markdown Normalization

Because the IFC primarily operates in Markdown (due to its heavy reliance on LLM generation), but standard email clients require HTML for rich formatting, the mailer implements a lightweight translation step.

* **Regex-Free Translation:** Rather than importing heavy Markdown-to-HTML libraries, it utilizes a highly efficient string replacement chain:
  * `\n` $\rightarrow$ `<br>` (Line breaks)
  * `**` $\rightarrow$ `<b>` (Bold text)
  * `##` $\rightarrow$ `<h2>` (Section Headers)
  * `###` $\rightarrow$ `<h3>` (Sub-headers)
* **MIME Construction:** It wraps the translated HTML string into a `MIMEText(html_body, 'html')` payload and attaches it to a standard `MIMEMultipart()` container.
* **Subject Standardization:** To ensure IFC alerts bypass standard spam filters and trigger appropriate inbox rules for NOC operators, the system automatically prepends `[NOC FUSION]` to every outbound subject line.

---

## 4. Execution & Fault Tolerance

The transmission block is designed for secure, resilient delivery:
1.  **Connection & Encryption:** It connects to the specified `smtp_server` and `smtp_port` (typically 587 for modern mail servers). It immediately issues a `server.starttls()` command to upgrade the insecure connection to a secure TLS encrypted tunnel *before* transmitting any authentication credentials.
2.  **Authentication & Dispatch:** Logs in using the provided credentials and transmits the payload.
3.  **Error Handling:** The entire network transaction is wrapped in a `try...except` block. If the SMTP server rejects the connection, authentication fails, or a timeout occurs, the exception is caught, cast to a string, and returned as the second variable in a tuple: `(False, str(e))`. 
4.  **Database Integrity:** A `finally` block guarantees `session.close()`, ensuring that regardless of email success or failure, the transient database connection pool is released.

---

## 5. System Integration Context

Within the broader application architecture, this module is primarily leveraged by:
* **The AIOps Engine (`aiops_engine.py`):** When the deterministic correlation engine successfully clusters an outage and identifies the root cause, it dynamically generates an ITSM ticketing payload and calls `send_alert_email()` to dispatch the ticket to a service desk ingestion address (e.g., ServiceNow, Jira Service Management).
* **The Operational Dashboard (`app.py`):** Used in the "Global SitRep" and "Geospatial Analytics" tabs to allow human operators to manually broadcast AI-synthesized intelligence briefings to executive distribution lists with a single click.

---

## 6. Complete Function Reference

| Function | Signature | Purpose |
|----------|----------|---------|
| `send_alert_email` | `(subject, body, recipient_override, is_html) -> tuple` | Send email |

---

## 7. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| smtplib | SMTP | https://docs.python.org/3/library/smtplib.html |
| email.mime | MIME | https://docs.python.org/3/library/email.mime.html |
