# Page: Operational Email

**Source:** `web/src/pages/OperationalEmailPage.tsx`
**Route:** `#/operational-email`
**Permission:** `Operational Email`

The page provides Compose, Scheduled, Sent / History, and administrator-only Template Defaults and Signatures panels. The page grant authorizes all ordinary page functions; shared defaults and signature administration are additionally restricted to administrators. Per-message recipients, subject, and body remain editable for all page users except the read-only live Morning Report body.

The nine templates are Maintenance Notification, Fiber Maintenance Notification, Outage — Request Technician Dispatch, Fiber Outage, Fiber Outage Follow-up, Fiber Outage Resolution, After-Hours ONPAGE, Morning Report, and Maintenance Complete. BCC is available except on To-only After-Hours ONPAGE. Fiber Maintenance and Fiber Outage can select multiple Network Orders to populate A/Z locations, company, Fiber contact details, and BCC recipients; the operational fields remain editable for manual/unlisted entries. Other templates offer directory contact selection alongside manual To/CC/BCC fields. After-Hours ONPAGE offers multi-select ONPAGE contacts for To. Fiber follow-up and resolution composition selects a successfully sent fiber outage ticket and preloads its stored fields/recipients. Maintenance Complete selects a successfully sent maintenance notification. Timezone fields are read-only and use the application’s current Central abbreviation.

Morning Report displays the latest Global Dashboard shift analysis and refreshes it before delivery; it omits report date/window/title and executive-summary wrapping. The optional selected signature is appended to the message and snapshotted with sent or scheduled content. One-time sends accept a Central date/time; daily and weekly schedules use `America/Chicago`. Message snapshots, recipient lists, signatures, and attachment bytes are persisted in SQLite and delivered by the worker. The sender is displayed from global SMTP settings and cannot be overridden by the page.

React Query loads templates, signatures, and conditionally loads maintenance/fiber source records, schedule, and history data. 401/403 messages come from the shared API client; send, schedule, cancellation, template-save, and signature-management results use accessible status/alert announcements.
