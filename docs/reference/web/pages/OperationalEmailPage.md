# Page: Operational Email

**Source:** `web/src/pages/OperationalEmailPage.tsx`
**Route:** `#/operational-email`
**Permission:** `Operational Email`

The page provides Compose, Scheduled, Sent / History, and administrator-only Template Defaults panels. The page grant authorizes all ordinary page functions; shared template defaults are additionally restricted to administrators. Per-message recipients, subject, and body remain editable for all page users.

The six templates are Maintenance Notification, Outage — Request Technician Dispatch, Fiber Outage (BCC), After-Hours ONPAGE, Morning Report (attachments), and Maintenance Complete. Completion composition selects a successfully sent maintenance notification and preloads its stored fields/recipients.

One-time sends accept a Central date/time; daily and weekly schedules use `America/Chicago`. A previewable message snapshot, recipient lists, and attachment bytes are submitted to the backend; the queue persists in SQLite and is delivered by the worker. The sender is displayed from global SMTP settings and cannot be overridden by the page.

React Query loads templates and conditionally loads schedule/history data. 401/403 messages come from the shared API client; send, schedule, cancellation, and template-save results use accessible status/alert announcements.
