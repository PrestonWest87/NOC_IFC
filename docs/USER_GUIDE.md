# NOC Intelligence Fusion Center — User Guide

This guide explains the current browser workspace. Available pages, tabs, site types, and actions depend on your assigned role. The API enforces those grants even when a control is visible in a stale browser session. See [Permissions](PERMISSIONS.md) for the exact keys.

## Sign in and account recovery

- Sign in with the username/password issued for your account. Sessions are database-backed and scoped to the current browser session.
- Individual accounts are created by email invitation; the invitee sets their password. Display accounts are administrator-created and may have no email.
- Password-reset requests are reviewed by a permitted user administrator. A reset email is sent only after approval and only when the account has a verified recovery address. Display and email-less accounts use administrator-assisted recovery.
- Recovery-email changes are reviewed first and then require mailbox verification. Individual accounts without a verified recovery email see a persistent prompt; display accounts are exempt.
- A `401` means the session is no longer valid and returns you to sign-in. A `403` means the session is still valid but the specific page/tab/action grant is missing; ask an administrator to update your role.

## Navigation

The sidebar contains up to ten pages: Global Dashboards, Threat Telemetry, Regional Grid, Threat Hunting & IOCs, AIOps RCA, Shift Logbook, Reporting & Briefings, Operational Email, Keyword Analysis, and Settings & Admin. The sidebar hides pages not granted to your account. Pages can also contain tabs that are separately permissioned.

## Global Dashboards (`#/`)

### Operational Dashboard

Shows 24-hour high-score article, CISA KEV, weather-hazard, and unresolved cloud-outage counts. The Threat Triage panel separates pinned from live articles; Infrastructure Status shows KEVs, cloud status, and hazards; AI Analysis shows the rolling shift handoff and authorized security-audit action. The subpanels rotate every ten seconds while Auto-Rotate is enabled.

Article actions include Pin/Unpin, +15 Score, Keep, Dismiss, and BLUF where the matching action grants are present. Keep/Dismiss writes analyst feedback; the first label on an article can adjust matched keyword weights. Pin/score/feedback actions require their corresponding grants.

### Global Risk

Displays the current external cyber/physical CIS posture, a 14-day score trend, scoring evidence, and the Global Threat Brief. The brief is generated daily at 02:00 Central by default and can be regenerated on demand with `Action: Generate Reports`. It combines OSINT, CISA KEVs, cloud/hazard context, and nearby headquarters-relative crime data. A brief is external-intelligence correlation, not evidence of an internal compromise.

### Internal Risk

Displays the latest asset-risk snapshot, hardware/software OSINT matches, score history, and the Internal Asset Risk Brief. Snapshot calculation runs every two hours by default; the manual calculation requires `Action: Generate Risk Snapshot`. The asset brief runs every three hours by default and requires `Action: Generate Reports` when started manually. If an asset-correlation batch or final LLM synthesis fails, IFC reports the generation error and retains the last successful brief rather than saving incomplete output; check AI settings and LLM endpoint connectivity before retrying.

### Unified Brief

Generates a combined cyber, physical, cloud, weather, crime, and internal-asset brief. Generation is asynchronous; its progress bar polls by generation ID, which is kept in the current browser session across SPA navigation. Broadcasting any saved dashboard brief requires `Action: Dispatch Exec Report` and valid SMTP configuration.

Risk-scoring controls are in **Settings > Application Settings**, not on the dashboard. See [Operations Reference](OPERATIONS_REFERENCE.md) for the current automatic schedule.

## Threat Telemetry (`#/threat-telemetry`)

### RSS Triage

Pinned, Live, Low, and Search sub-tabs provide article pagination and category/search filters. Opening an article can show full-content enrichment, matched keyword weights, and extracted IOCs. Pin, score boost, and feedback controls each require their own action grant. Manual feed fetch requires `Action: Manually Sync Data`.

The page's current category dropdown still contains some pre-renaming labels. The backend categorizer now emits `Cloud & IT Infrastructure`, `Physical Security & Crime`, and `Severe Weather & Natural Hazards`; exact legacy dropdown values may not match those rows. This source-level mismatch is recorded in the [audit](DOCUMENTATION_AUDIT.md#source-level-mismatches-surfaced-during-the-audit).

### CISA KEV

Browse the locally synchronized CISA Known Exploited Vulnerabilities records. Manual refresh requires the tab grant plus `Action: Manually Sync Data`.

### Cloud Services

Review active and resolved status-feed items. Provider status is polled from configured RSS/Atom feeds; scheduled sync runs every eight minutes by default. Manual sync requires the same manual-sync action.

### Perimeter Crime

Displays incidents from the Little Rock police CAD feed. Addresses are geocoded when possible and fallback locations are marked approximate. Incident distance and the perimeter notification threshold are measured from the Little Rock headquarters point, not from each monitored facility. The page offers a display radius filter and an authorized manual fetch.

## Regional Grid (`#/regional-grid`)

Six tabs provide a geospatial overlay, executive dashboard, deep hazard analytics, location matrix, weather-alert log, and Atmos Weather view. The local contiguous-US map loads state outlines and Arkansas-border county outlines before on-demand hazard layers. NWS alerts include Arkansas and the 50-mile outward strip in Louisiana, Texas, Mississippi, Missouri, Oklahoma, and Tennessee. The worker checks NWS once per minute; the map shows the last successful feed time and flags stale/errors.

Active NWS messages automatically leave active views at their CAP `Expires` time or when NWS updates/cancels them. The expected event-ending time is shown separately and does not clear an alert before its CAP expiry.

- Site markers are intersected with currently selected hazard geometry; filters control which data is shown.
- WFCA reported perimeters are distinct from FIRMS-derived estimated satellite footprints. Small fires at or below one acre are omitted when farther than one mile from monitored sites; alerts for those small fires use the same one-mile rule. Larger-fire proximity alerts use five miles.
- Atmos Weather can show a selected site's NWS forecast and save the signed-in user's weather-alert preferences.
- Manual hazard sync requires an eligible regional tab and `Action: Manually Sync Data`.

The map compiler returns a six-position response consumed by index. See [Architecture](ARCHITECTURE.md#regional-map) before changing map integrations.

## Threat Hunting & IOCs (`#/threat-hunting`)

### Live Global IOC Matrix

Shows extracted IPs, domains, URLs, hashes, CVEs, MITRE ATT&CK IDs, and other supported rules from recent articles. Filter by type, expand source articles, export CSV, or open supported external pivots.

### Deep Hunt & Detection Builder

Enter a search target and lookback range to search up to 30 stored articles. The UI displays up to 15 matches and builds a template detection package containing article excerpts, CVE-shaped strings, generic Splunk/Elastic query patterns, and a YARA stub. This package is generated in frontend code; it is not an LLM-authored or validated production detection rule. Review and test any query/rule in the target SIEM before operational use.

### Elastic SIEM Report

Displays locally cached high-severity Elasticsearch events. Manual cache sync requires `Action: Manually Sync Data`; AI triage requires the legacy `Action: Trigger AI Functions` grant and sends at most 50 bounded event records.

## AIOps RCA (`#/aiops-rca`)

The page has Active Board, Patterns, and Global tabs. Dashboard refresh defaults to ten seconds; root-cause analysis refresh defaults to sixty seconds. Both page and tab grants are needed, and server-side site-type scope filters locations, alerts, timeline events, and permitted mutations.

### Site health versus workflow

| Display | Meaning |
|---|---|
| Up / Clear (green) | No unresolved alert remains for the site. |
| Down / Action Required (red) | At least one unresolved alert remains without a later workflow label. |
| Needs Dispatch | An operator explicitly marked active alerts for dispatch. |
| Investigating | An authorized operator marked the active incident under investigation. |
| Ticket Dispatched | Current active site alerts are marked dispatched. |
| Under Maintenance | Separate blue outline/annotation with ETR/reason; it does not hide active alert colors or suppress escalation. |

Acknowledgement marks alerts correlated and removes them from the uncorrelated alert list, but it does not resolve their underlying status; the site remains operationally down while unresolved alerts exist. **Mark Site Up** resolves every unresolved alert for the site and clears stale Needs Dispatch/investigating state. It does not clear a maintenance window. Maintenance can be cleared from the site dialog even when no incident is active; expiry clears it after the ETR date ends in Central time.

Available controls are separately permissioned: RCA analysis, acknowledgement/Mark Site Up, dispatch/ticket email, investigation, and maintenance. An acknowledged alert is not the same as a resolved alert. The current map offsets co-located sites with connector spokes and does not use the earlier red alert pulse.

## Shift Logbook (`#/shift-logbook`)

Create notes with Morning, Afternoon, Evening, or No Shift; No Shift can take a custom date. Identity comes from the signed-in user and non-administrators cannot assign another role. Recent Entries is separate from History; History grants unlock the searchable/date-filtered explorer with day/week views. Administrators can export filtered, non-deleted records as CSV.

Entries are soft-deleted/restored through `is_deleted`; the API does not store a deletion reason. Cross-user changes require `Action: Manage Shift Logs`. Summary generation supports current shift/day and trailing-week scopes; end-of-day/week reports include all shifts and skip earlier generated rollups. The UI appends the report and labels source-only fallback output when LLM batches fail or exceed 30 seconds.

Auto-Draft reads scoped AIOps data and requires both AIOps page access and `Action: Run RCA Analysis`.

## Reporting & Briefings (`#/reporting`)

- **Daily Fusion Briefing:** generate/archive the previous local calendar day's report and optionally broadcast supplied content.
- **Custom Report Builder:** search article title/summary/full content, select matches or article IDs, provide an objective, then poll asynchronous generation. You can save or email the resulting report.
- **Shared Library:** list, open, and delete saved reports.

Generation requires `Action: Generate Reports`; report broadcasts, saving through the current report-builder route, and library deletion require `Action: Dispatch Exec Report`. Email recipient lists accept comma/semicolon-separated addresses, reject line breaks, and are limited to 20 addresses.

## Operational Email (`#/operational-email`)

The Operational Email page uses one page permission for composing, sending, scheduling/cancelling, and reviewing emails. Choose a template, fill in its operational fields, edit the message for the current send, and then send immediately or schedule once, daily, or weekly in America/Chicago. All templates support BCC, which is hidden from visible recipients. Event-time labels default to the application’s current Central abbreviation (`CST` or `CDT`).

- **Maintenance Notification** records planned work, a window, an expected impact of None/Low/Medium/High, and optional departmental impact. A completion message must select a successfully sent maintenance notification; its details and recipients are used to start the close-out message.
- **Fiber Maintenance Notification** records A/Z locations, circuit IDs, a maintenance window, expected impact, and optional departmental impact.
- **Outage — Request Technician Dispatch** describes service impact and the requested field response.
- **Fiber Outage** starts an outage ticket. **Fiber Outage Follow-up** can send repeat progress updates, and **Fiber Outage Resolution** sends a restoration notice; both remain linked to a previously sent fiber outage and inherit its details and recipients.
- **After-Hours ONPAGE** provides an urgent acknowledgement/request-for-response format.
- **Morning Report** sends the latest Global Dashboard shift analysis exactly as stored, without a date, window, title, or executive summary. The source is refreshed again when a scheduled message is delivered. It supports up to five attachments, 5 MiB each, with a 20 MiB combined limit.
- **Maintenance Complete** links the close-out to the selected sent maintenance notification.

Every message uses the single global From address configured in Settings > AI & SMTP. Administrators can edit shared template wording/recipient defaults and manage reusable signatures, including an optional default. Senders can choose that default, another active signature, or no signature. Signature content is snapshotted with sent and scheduled emails. Scheduled messages preserve their content and attachments; Morning Report alone refreshes its shift-analysis source at delivery. Delivery status and message details, including hidden BCC recipients, are available in Sent / History.

The page is not part of the default analyst role. Ask an administrator to grant the `Operational Email` page permission if you need access.

## Keyword Analysis (`#/keyword-analysis`)

Overview, keyword ranking, category breakdown, timeline, score distribution, and category/keyword cross-reference views explain persisted scoring data. This page requires the `Keyword Analysis` page permission. Corpus-wide recategorization requires the legacy `Action: Trigger AI Functions` grant and commits changed records in batches.

## Settings & Admin (`#/settings`)

The UI contains Profile, Theme, Facilities, Email Contacts, Network Orders & Circuits, Internal Assets, RSS Sources, ML Training, AI & SMTP, Application Settings, Users & Roles, Backup & Restore, and Danger Zone. Profile and Theme are self-service views once the Settings page is granted. The other sections use independent tab permissions; data changes require additional action permissions or the built-in administrator role.

### Email Contacts

Administrators maintain separate Fiber contacts (Name, Company, Email, Phone) and ONPAGE contacts (Department, Email). Rows can be edited directly or imported from separate CSV files. CSV import defaults to merging/updating matching records; choose Replace all rows to replace that directory with the file. A tab grant is required to read the directory; only administrators can save or import rows.

### Network Orders & Circuits

This tab stores circuit/network-order mappings with A location, Z location, Circuit/Network Order ID, and Company. Administrators can add, edit, remove, save, or import CSV files containing these columns. Import defaults to merging by Circuit/Network Order ID; Replace all rows is also available. A separate tab grant controls directory read access.

### Users & Roles

Invite an individual by email or create a display account separately. The directory shows account type, recovery-email state, role, status, last sign-in, and last activity. Authorized managers can edit profile/role/account type, disable/reactivate accounts, revoke sessions, resend/revoke invitations, and review reset/email-change requests. Role editors can only delegate grants and site types they themselves hold; administrator/elevated user-admin accounts are protected from delegated management.

### Application Settings

The page separates global URL/technology/ASN and failed-login alert settings, notification destinations and Elastic integration settings, risk scoring, and the dynamic scheduler. Application defaults and integration settings use `Action: Manage Application Settings`; risk scoring and scheduler timing retain their separate grants. Environment values are fallbacks until a database override is saved. A blank destination disables it, and “Reset to environment” removes saved overrides. Elastic API keys are write-only in the UI. Scheduler edits are range/type validated and the worker applies saved revisions within 30 seconds. Escalation and encrypted backup cannot be disabled.

In **Settings > AI & SMTP**, choose OpenAI-compatible, Ollama OpenAI-compatible, Ollama native, or vLLM. The connection test uses the selected provider’s API format. A saved API key is reused only with its saved provider; changing provider clears the old key unless you enter a replacement. Local model endpoints must be reachable from the API container; in Docker, use a service name or host gateway rather than the API container’s own `localhost`.

### Backup & Restore and Danger Zone

Full backup/restore and destructive controls are administrator-only in the UI. Encrypted `.nocbackup` packages include a consistent SQLite snapshot and the model artifact when present; `.env` is external. A UI restore pauses/drains API, worker, webhook, and WebSocket writers, validates/migrates the staged package, creates a pre-restore backup, atomically installs it with rollback handling, and invalidates restored sessions/links. JSON and `.db` tools are legacy partial imports/exports, not full backups. See [Maintenance](MAINTENANCE.md).

## Realtime behavior and safe interpretation

The authenticated WebSocket sends `dashboard_update` data every ten seconds when clients are connected. Client commands `INVESTIGATING_UPDATE` and `RCA_UPDATE` both require `Action: Dispatch RCA Tickets`; site updates are filtered by each recipient's site scope. Browser notifications may be requested for newly observed CRITICAL/HIGH AIOps alert IDs.

Risk tiers are ordered `GREEN < BLUE < YELLOW < ORANGE < RED`, with display names Low, Guarded, Elevated, High, and Severe. External OSINT/LLM correlations are situational awareness; they are not confirmation of a compromise. Verify relevant findings against internal telemetry and vendor advisories.

## Suggested shift routine

1. Review the Operational Dashboard, recent shift logs, and unresolved AIOps alerts.
2. Confirm the site's unresolved alert count before treating an acknowledgement as recovery.
3. Review current hazards, cloud events, and headquarters-relative local incidents.
4. Use scoped RCA/dispatch/maintenance actions only when authorized.
5. Record actions and handoff state in the logbook.
6. Generate and broadcast briefings only when appropriate permissions and SMTP are configured.
