# Page: Operational Email

**Source:** `web/src/pages/OperationalEmailPage.tsx`
**Route:** `#/operational-email`
**Permission:** `Operational Email`

The page provides Compose, Scheduled, Sent / History, and administrator-only Template Defaults and Signatures panels. The page grant authorizes all ordinary page functions; shared defaults and signature administration are additionally restricted to administrators. Per-message recipients, subject, and body remain editable for all page users except the read-only live Morning Report body.

The ten templates include Maintenance Notification, Fiber Maintenance Notification, Outage — Request Technician Dispatch, Fiber Outage, Fiber Outage ONPAGE, Fiber Outage Follow-up, Fiber Outage Resolution, After-Hours ONPAGE, Morning Report, and Maintenance Complete. Fiber To defaults to the active Global From address; selected Fiber contacts go to BCC. After-Hours ONPAGE and Fiber Outage ONPAGE are the only templates that show ONPAGE contacts. Fiber Outage ONPAGE sends those contacts to To and the Global From address on Cc, without automatic Fiber BCC from Network Orders/Circuit IDs. Fiber follow-up and resolution messages omit ONPAGE To and inherit BCC from either initial Fiber template. Network Orders/Circuit IDs selections fill A/Z and contact fields; company mappings select matching Fiber contacts. Fiber Maintenance offers MOP Type choices (Demand, Standard, Emergency) and Expected impact; Maintenance Notification has the Department performing the change selector. Timezone values are automatic and hidden from the compose form.

Morning Report displays the latest Global Dashboard shift analysis and refreshes it before delivery; it omits report date/window/title and executive-summary wrapping. The optional selected signature is appended to the message and snapshotted with sent or scheduled content. One-time sends accept a Central date/time; daily and weekly schedules use `America/Chicago`. Message snapshots, recipient lists, signatures, and attachment bytes are persisted in SQLite and delivered by the worker. The sender is displayed from the global active SMTP profile and cannot be overridden by the page; delivery history records whether existing SMTP or Gmail was used.

React Query loads templates, signatures, and conditionally loads maintenance/fiber source records, schedule, and history data. 401/403 messages come from the shared API client; send, schedule, cancellation, template-save, and signature-management results use accessible status/alert announcements.
