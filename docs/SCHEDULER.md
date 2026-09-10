# Scheduler and Background Jobs

The worker starts with `python -u src/scheduler.py`. Import-time initialization calls `init_db()`, then the `__main__` block registers jobs with the `schedule` library and runs a one-second polling loop.

## Current Schedule

Intervals below are the values in the scheduler source, not historical product targets.

| Job | Schedule | Function | Inputs and outputs |
|---|---|---|---|
| Tiered escalation | Every 1 minute | `job_tiered_alert_escalation` | Active `SolarWindsAlert`, weather/cloud/BGP context; sends ticket/notify/on-page mail and marks alerts |
| RSS capture | Every 5 minutes | `fetch_feeds` | Active `FeedSource`; writes scored `Article` and `ExtractedIOC` rows |
| Article enrichment | Every 3 minutes | `enrich_pending_articles` | Pending high-score articles; writes full content or failure state |
| Maintenance expiry | Every 5 minutes | `job_clear_expired_maintenance` | Site ETR state; clears expired maintenance and broadcasts `RCA_UPDATE` |
| Telemetry | Every 6 minutes | `run_telemetry_sync` | External telemetry; writes BGP and related records |
| Regional hazards | Every 7 minutes | `fetch_regional_hazards` | NWS/SPC/USGS and hazard feeds; updates cache and hazard records |
| Cloud outages | Every 8 minutes | `fetch_cloud_outages` | Provider status sources; updates `CloudOutage` |
| Crime | Every 10 minutes | `fetch_live_crimes` | Crime source; writes incidents and may alert |
| Database maintenance | Every 60 minutes | `run_database_maintenance` | Retention deletes, orphan cleanup, SQLite optimize/checkpoint |
| Internal risk | Every 2 hours | `job_internal_risk` | Asset/CVE/OSINT state; saves an `InternalRiskSnapshot` |
| Rolling summary | Every 30 minutes | `job_rolling_summary` | Shift data; saves an AI handoff summary |
| Internal brief | Every 3 hours | `job_internal_brief` | Asset snapshot and OSINT/CVE data; saves internal brief |
| Unified brief | Every 6 hours | `job_unified_brief` | Global physical/cyber context and internal snapshot; saves unified brief |
| CISA KEV | Every 7 hours | `fetch_cisa_kev` | CISA catalog; updates `CveItem` |
| Global brief | Daily at 02:00 | `job_global_brief` | Broad OSINT and physical context; saves global threat brief |
| ML retraining | Sunday at 02:00 | `job_retrain_ml` | Analyst feedback corpus; writes model and reloads scorer |
| Daily email | 07:00 `America/Chicago` | `job_daily_email_unified_brief` | Saved unified brief and risk context; sends to `RISK_ALERT_RECIPIENTS` |

## Execution Model

`run_threaded` submits work to a two-thread executor. A set protected by a lock prevents the same function name from running twice concurrently. Exceptions are logged, memory is sampled before and after each job, and the running marker is removed in `finally`.

The boot sequence runs four groups with 30-second pauses: (1) escalation, maintenance expiry, RSS; (2) KEV, regional hazards, cloud; (3) telemetry, crime, internal risk; (4) unified, global, and internal briefs.

Boot execution can create immediate outbound traffic and LLM work. Confirm environment recipients and API credentials before starting a production worker.

## Change Frequency

Edit the `schedule.every(...)` declarations in `src/scheduler.py`. Do not edit documentation values as a substitute. Preserve the non-overlap behavior and consider external API rate limits, database locks, LLM cost, and email volume before shortening an interval.

## Escalation Rules

The escalation job uses Central time business hours, Monday-Friday 06:00-20:00. It selects day-shift or after-hours rules, prioritizes higher-weight tiers, detects cascades, suppresses node flapping according to cooldown, and mutes a site for one hour after after-hours on-page. `REMEDYFORCE_TICKET_EMAIL` is required for the run to dispatch.
