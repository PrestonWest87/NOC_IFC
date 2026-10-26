# Trigger and Action Flows

This guide traces externally triggered, scheduled, browser-initiated, and WebSocket actions through the current implementation. REST route examples use router-relative suffixes; prepend `/api/v1` unless a full path is shown. The webhook and `/health`/`/ready` probes are outside that prefix. Exact route bodies/permissions are in [`API.md`](API.md); schedule defaults and bounds are in [`SCHEDULER.md`](SCHEDULER.md).

## 1. SolarWinds webhook

```text
SolarWinds sender
  -> POST :8100/webhook/solarwinds
  -> restore/body-size/HMAC/timestamp/JSON checks
  -> smart_extract + domain normalization + resolution-word detection
  -> HTTP 200 {status: accepted}
  -> FastAPI background task
       ├─ resolution: update unresolved same-node alerts + site-scoped timeline row
       └─ alert: insert SolarWindsAlert(raw payload) + site-scoped timeline row
  -> 1-minute escalation job / AIOps board / authenticated WebSocket
```

The success response confirms queueing only; it is not a persistence acknowledgment and is HTTP 200, not 202. See [`WEBHOOK.md`](WEBHOOK.md) for HMAC format and exact rejection codes.

## 2. Scheduler triggers

The single `worker` process registers 20 jobs from `JOB_REGISTRY`. It runs registry entries with `startup_run=true` during boot in four groups separated by 30-second pauses; scheduled callbacks use a two-thread executor and same-function non-overlap guard. On boot, enabled startup jobs can initiate external HTTP, email, LLM, and database work.

| Job | Default trigger | Main work |
|---|---|---|
| `tiered_alert_escalation` | Every 1 minute; starts on boot | Cluster active SolarWinds alerts; prepare site ticket and separate per-node on-page delivery |
| `rss_fetch` | Every 5 minutes; starts on boot | Fetch/score/categorize articles, extract eligible IOCs, persist, deduplicate |
| `article_enrichment` | Every 3 minutes | Extract full content for eligible captured articles |
| `maintenance_expiry` | Every 5 minutes; starts on boot | Clear maintenance after ETR date ends in Central time |
| `telemetry_sync` | Every 6 minutes; starts on boot | Run ORNL, RIPE, and IODA fetches concurrently |
| `elastic_sync` | Every 6 minutes; starts on boot | Import bounded high-severity Elastic events into the local cache |
| `regional_hazards` | Every 7 minutes; starts on boot | Refresh SPC/NWS/USGS/WFCA and evaluate earthquake/wildfire proximity |
| `cloud_outages` | Every 8 minutes; starts on boot | Fetch configured cloud status feeds |
| `crime_fetch` | Every 10 minutes; starts on boot | Fetch/geocode Little Rock CAD events and dispatch qualifying high-severity alerts |
| `database_maintenance` | Every 60 minutes | Retention, orphan IOC deletion, SQLite optimize/passive checkpoint |
| `internal_risk` | Every 2 hours; starts on boot | Calculate/store internal risk snapshot and check risk escalation |
| `rolling_summary` | Every 30 minutes | Generate/save rolling handoff summary |
| `internal_brief` | Every 3 hours; starts on boot | Generate/save internal asset-risk brief |
| `unified_brief` | Every 6 hours; starts on boot | Generate/save unified cyber/physical/internal brief and check global risk escalation |
| `cisa_kev` | Every 7 hours; starts on boot | Synchronize CISA KEV catalog |
| `global_brief` | Daily 02:00 Central; starts on boot | Generate/save US CI and global threat brief |
| `daily_fusion_report` | Daily 06:00 Central | Generate/save previous Central calendar day's Daily Fusion report |
| `daily_email_brief` | Daily 07:00 Central | Send the saved Unified Brief to `RISK_ALERT_RECIPIENTS` |
| `ml_retrain` | Sunday 02:00 Central | Train from feedback labels and reload scorer |
| `database_backup` | Sunday 00:00 Central | Create full encrypted backup; retain newest three scheduled packages |

`tiered_alert_escalation` is bounded to 1–5 minutes and cannot be disabled. `database_backup` cannot be disabled. Daily/weekly jobs remain on `America/Chicago`; other interval minima/maxima are in `SCHEDULER.md`.

## 3. Authentication, invitations, and recovery

### Login

```text
LoginPage -> POST /api/v1/auth/login -> bcrypt/session validation
  -> UserSession row + durable sign-in/activity timestamp
  -> public user/grants + opaque token
  -> sessionStorage(noc_user, noc_token)
  -> first granted page route
```

If enabled and correctly configured, failed attempts are stored for threshold-based alerting. The threshold is global across submitted usernames; one claimed alert window queues an email. Credentials are never included in the alert.

### Individual invitation and display account

- An authorized manager creates an email-bound individual invitation. The server stores a hashed, expiring single-use token; the mailer queues a registration URL. Registration validates the token, sets a 12+ character password, marks the invited email verified, creates a session, and returns the public user.
- An authorized manager creates a display account directly with an administrator-selected 12+ character password. Email is optional; the browser identifies this account type as exempt from recovery-email prompting.

### Recovery

```text
Forgot password -> generic POST /auth/request-password-reset
  -> identifier/IP rate limit + hashed evidence
  -> permitted reviewer queue/notification
  -> approve => single-use token emailed to verified recovery email
  -> POST /auth/reset-password => password update + revoke all sessions
```

Recovery-email changes follow a separate request → reviewer approval → mailbox verification flow. Request owners cannot approve their own recovery or reset request. Denials require a reason. Restores invalidate sessions and outstanding invitation/reset/email-verification links.

## 4. Article actions and threat-data refresh

| User action | API/service path | State change |
|---|---|---|
| Open article | `GET /threat/articles/{id}` | Reads article, persisted keyword weights, and related IOCs. |
| Pin/unpin | `POST /dashboard/articles/toggle-pin` -> `toggle_pin()` | Toggles shared `Article.is_pinned`. |
| Boost score | `POST /dashboard/articles/boost-score` -> `boost_score()` | Adds the requested amount, capped at 100. |
| Keep/dismiss | `POST /dashboard/articles/feedback` -> `change_status()` | Writes label 2/1; only a first label from 0 adjusts matched keyword weights. |
| Manually refresh RSS/KEV/cloud/crime | Corresponding `/threat/*` route | Calls the worker/service synchronously and returns before any separate scheduled run. |
| Manually sync Elastic | `/hunting/sync-elastic-cache` | Runs a bounded Elastic query; local `elastic_events` cache is refreshed. |

Each operation requires its workspace/tab and action grant. The threat-page category names and backend category outputs have a documented current mismatch; see [`DOCUMENTATION_AUDIT.md`](DOCUMENTATION_AUDIT.md#source-level-mismatches-surfaced-during-the-audit).

## 5. Brief and report actions

### Dashboard briefs

1. An authorized user starts unified/global/internal generation from its dashboard tab with `Action: Generate Reports`.
2. The route returns a generation ID and starts a tracked background thread.
3. The browser stores the ID in `sessionStorage` and polls the matching status route every two seconds.
4. On completion, the brief is saved to `SystemConfig`; the client refreshes saved brief data.
5. Email broadcast uses `/email/broadcast-*` and `Action: Dispatch Exec Report`.

Progress is an in-memory API-process record; a process restart can make an old generation ID return `unknown`.

### Custom and Daily Fusion reports

- Daily Fusion generation calls the LLM pipeline synchronously from the reporting route or the scheduled worker; the worker skips if the previous Central calendar day's row already exists.
- Custom report search uses OR matching across parsed terms; a user can select article IDs or use a target/lookback. Generation is asynchronous and reports progress/results from an in-memory store. Saving to the shared library and email broadcasting require the report-dispatch action.
- Recipient validation for report broadcasts rejects line breaks, validates address shape, and limits to 20 recipients.

## 6. AIOps response state machine

Operational health is based on unresolved alerts; acknowledgement/dispatch/workflow flags do not represent recovery.

```text
No unresolved site alerts -> Up / Clear (green)
Unresolved alert, no workflow state -> Down / Action Required (red)
Operator sets Needs Dispatch -> Needs Dispatch annotation
Operator investigates -> Investigating annotation
Operator completes ticket dispatch -> Ticket Dispatched annotation
Authorized Mark Site Up -> resolve every unresolved site alert, clear Needs Dispatch/investigating
Maintenance -> independent blue outline/ETR annotation; does not suppress alerts or escalation
```

| Action | Route and checks | Persistence / broadcast |
|---|---|---|
| Load Active Board | `GET /rca/dashboard`; AIOps page + Active Board | Returns alerts/events/grid/locations/investigation state and unresolved-alert counts, all scoped to permitted site types. |
| Run analysis | `POST /rca/analyze`; `Action: Run RCA Analysis` | Clusters visible alerts, calculates root causes/fleet events; chronic insight aggregate is returned only with all site types. |
| Investigate | `POST /rca/investigate`; `Action: Dispatch RCA Tickets` | Toggles process-local set; lost on API restart; broadcasts refresh. |
| Set Needs Dispatch | `POST /rca/needs-dispatch`; `Action: Dispatch RCA Tickets` | Persists the flag for active uncorrelated alerts; true requires at least one such alert. |
| Acknowledge | `POST /rca/acknowledge`; `Action: Acknowledge RCA Alerts` | Marks selected alerts correlated and records actor/time; they remain unresolved and counted for health. |
| Dispatch state | `POST /rca/dispatch`; `Action: Dispatch RCA Tickets` | Sets/clears alert workflow flag, clears Needs Dispatch, records actor/time, broadcasts refresh. |
| Generate/send ticket | `POST /rca/generate-ticket`, `POST /rca/send-ticket`; Dispatch RCA Tickets | Site/alert IDs are site-scope checked; email state changes to dispatched only after successful send. |
| Set/clear maintenance | `POST /rca/site-maintenance`; `Action: Manage Site Maintenance` | Persists `under_maintenance`, ETR date, reason, status actor/time; clearing nulls ETR/reason. |
| Mark Site Up | `POST /rca/resolve-site`; `Action: Acknowledge RCA Alerts` | Resolves all unresolved site alerts and clears investigation state. When alerts were resolved, records operator/status/timeline metadata; always broadcasts refresh. Maintenance remains separate. |

The server-side AIOps WebSocket requires the page and Active Board tab. Both accepted client commands (`INVESTIGATING_UPDATE`, `RCA_UPDATE`) require `Action: Dispatch RCA Tickets`; they do not replace the REST workflow endpoints.

## 7. Settings and scheduler changes

- Risk scoring writes use `/application-settings/risk-scoring` and `Action: Adjust Risk Scoring Overrides`.
- Global defaults/failed-login alert writes use `/application-settings` and `Action: Manage Application Settings`.
- Job schedules use `/application-settings/scheduler/jobs/{job_key}` and `Action: Manage Scheduler Settings`.
- The API validates job type, fixed interval units, interval bounds, Central timezone, time format, weekday, and non-disableable jobs. It increments `SystemConfig.scheduler_revision` and records an audit event.
- The worker polls every 30 seconds and rebuilds only registry-managed jobs when revision changes; active jobs are not interrupted.

## 8. Backup and restore triggers

```text
Admin creates encrypted backup -> SQLite online snapshot + model if present -> AES-GCM package
Admin stages upload -> authenticate/decrypt/check manifest/checksum/SQLite integrity -> keep staged
Admin starts restore -> maintenance marker -> drain API/worker/webhook -> close sockets
  -> validate + migrate staged DB -> pre-restore encrypted backup
  -> atomic database/model swap with rollback -> invalidate sessions/links -> clear staging
  -> refresh runtime caches/scorer -> report completion by restore capability ID
```

The offline CLI requires `--maintenance-confirmed` only after API, worker, and webhook writers are stopped. Environment secrets are not part of a full backup.

## 9. Scheduled notifications and external integrations

| Trigger | Destination/condition |
|---|---|
| Risk tier increases | `RISK_ALERT_RECIPIENTS`, only when prior tier is known, tier increases, SMTP is enabled, and the four-hour cooldown allows. |
| Earthquake proximity | `RISK_ALERT_RECIPIENTS`; USGS M≥2.5 within 50 miles of a monitored site. |
| Wildfire proximity | `NOC_NOTIFY_EMAIL`; 5 miles for ordinary fires, 1 mile for fires ≤1 acre, per-fire/site repeat tracking. |
| Perimeter crime | `CRIME_ALERT_SMS` (fallback `CRIME_ALERT_EMAIL`); severity text “High”, ≤0.4 miles from headquarters, not previously dispatched. |
| Escalation ticket/page | Remedyforce/NOC/ITNETWORK destinations; see [`ESCALATION.md`](ESCALATION.md) for wait, cooldown, and retry rules. |
| Daily email brief | `RISK_ALERT_RECIPIENTS` at 07:00 Central, if a saved unified brief exists. |

Email send paths depend on the `SystemConfig` SMTP settings; env recipients do not replace SMTP server/sender configuration.
