# Scheduler and Background Jobs

The worker starts with `python -u src/scheduler.py`. It initializes the database, loads all 20 registered jobs, submits the startup-enabled subset, and runs a one-second `schedule.run_pending()` loop. The registry in `src/core/scheduler_registry.py` supplies defaults, bounds, schedule types, startup-run behavior, and the settings UI metadata.

## Current Schedule

Intervals below are the values in the scheduler source, not historical product targets.

| Job | Schedule | Function | Inputs and outputs |
|---|---|---|---|
| Tiered escalation | Every 1 minute | `job_tiered_alert_escalation` | Active `SolarWindsAlert`, weather/cloud/BGP context; site-level tickets, independently tracked node pages, and cooldown-aware retries |
| RSS capture | Every 5 minutes | `fetch_feeds` | Active `FeedSource`; writes scored `Article` and `ExtractedIOC` rows |
| Article enrichment | Every 3 minutes | `enrich_pending_articles` | Pending high-score articles; writes full content or failure state |
| Maintenance expiry | Every 5 minutes | `job_clear_expired_maintenance` | Site ETR date; clears after 23:59:59 America/Chicago on that date and broadcasts `RCA_UPDATE` |
| Telemetry | Every 6 minutes | `run_telemetry_sync` | ORNL power, RIPE BGP visibility, and IODA outages; writes `RegionalOutage`/`BgpAnomaly` |
| Elasticsearch cache | Every 6 minutes | `job_sync_elastic` | Queries configured Elasticsearch and stores high-severity events in `ElasticEvent` |
| Regional hazards | Every 7 minutes | `fetch_regional_hazards` | SPC/NWS/USGS/WFCA; updates cache/hazard records and may send earthquake/wildfire proximity alerts |
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
| Daily Fusion report | 06:00 `America/Chicago` | `run_daily_report` | Generates and stores the prior-day Daily Fusion report |
| Encrypted database backup | Sunday at 00:00 `America/Chicago` | `job_database_backup` | SQLite online snapshot of every table plus the trained model; authenticated encryption; retains the newest three scheduled packages |

## Execution Model

`run_threaded` submits work to a two-thread executor. A set protected by a lock prevents the same function name from running twice concurrently. Exceptions are logged, memory is sampled before and after each job, and the running marker is removed in `finally`.

The explicit startup-run policy runs only registry entries marked `startup_run`, in four groups with 30-second pauses: (1) escalation, maintenance expiry, RSS; (2) KEV, regional hazards, cloud; (3) telemetry, Elasticsearch, crime, internal risk; (4) unified, global, and internal briefs. Daily emails, the Daily Fusion report, ML retraining, and the weekly database backup wait for their scheduled times.

Boot execution can create immediate outbound traffic and LLM work. Confirm environment recipients and API credentials before starting a production worker.

## Registry bounds and startup policy

`validate_schedule()` rejects changed schedule types/units, out-of-range intervals, malformed `HH:MM` times, invalid weekdays, and timezones other than `America/Chicago`. Only escalation and encrypted backup are non-disableable.

| Job key | Allowed interval / calendar form | Startup run | Can disable |
|---|---|---:|---:|
| `tiered_alert_escalation` | 1–5 minutes | Yes | No |
| `rss_fetch` | 3–30 minutes | Yes | Yes |
| `article_enrichment` | 1–30 minutes | No | Yes |
| `maintenance_expiry` | 1–30 minutes | Yes | Yes |
| `telemetry_sync` | 3–60 minutes | Yes | Yes |
| `elastic_sync` | 5–120 minutes | Yes | Yes |
| `regional_hazards` | 5–60 minutes | Yes | Yes |
| `cloud_outages` | 5–60 minutes | Yes | Yes |
| `crime_fetch` | 5–60 minutes | Yes | Yes |
| `database_maintenance` | 15–240 minutes | No | Yes |
| `internal_risk` | 1–24 hours | Yes | Yes |
| `rolling_summary` | 15–360 minutes | No | Yes |
| `internal_brief` | 1–12 hours | Yes | Yes |
| `unified_brief` | 2–24 hours | Yes | Yes |
| `cisa_kev` | 4–24 hours | Yes | Yes |
| `global_brief` | Daily at `HH:MM` Central | Yes | Yes |
| `ml_retrain` | Any weekday at `HH:MM` Central | No | Yes |
| `daily_email_brief` | Daily at `HH:MM` Central | No | Yes |
| `daily_fusion_report` | Daily at `HH:MM` Central | No | Yes |
| `database_backup` | Any weekday at `HH:MM` Central | No | No |

The job's schedule type is fixed by its registry entry. Weekly entries accept Monday through Sunday; daily and weekly jobs use wall-clock time in `America/Chicago`.

## Change Frequency

Authorized users change schedules in Settings > Application Settings. The API validates each job against registry-specific minimum/maximum intervals and supported interval/daily/weekly formats. The worker polls the saved revision every 30 seconds and rebuilds only registry-managed jobs; an in-flight job is not interrupted and the per-job non-overlap guard remains active. Tiered escalation cannot be disabled and remains bounded to 1-5 minutes. The full database backup also cannot be disabled. Daily and weekly schedules use `America/Chicago`.

The older standalone `start_report_scheduler()` polling loop has been removed. Daily Fusion report generation is registered in the main job registry so it shares the same settings and reload path.

## Escalation Rules

The escalation job uses Central time business hours, Monday–Friday 06:00–20:00. It selects day-shift or after-hours rules using each alert's received timestamp, prioritizes higher-weight tiers, detects cascades, suppresses same-node flapping according to cooldown, and mutes routine after-hours site dispatch for one hour after a successful page. `REMEDYFORCE_TICKET_EMAIL` is required for escalation delivery; if it is missing, the function logs and skips that run without stopping the worker.
