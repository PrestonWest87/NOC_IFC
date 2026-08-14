## Background Scheduler (src/scheduler.py)
The master orchestrator running in the worker container. Uses the `schedule` library for timing and runs jobs in daemon threads via `run_threaded()`.

## Architecture
- Main loop: `while True: schedule.run_pending(); time.sleep(1)`
- Jobs run in `threading.Thread(daemon=True)` to prevent blocking
- Pre-loads HybridScorer at startup for efficiency
- Calls init_db() at import time

## Job Registry

| Job | Interval | Source File Function | Purpose |
|-----|----------|---------------------|---------|
| fetch_feeds | 15 min | scheduler.fetch_feeds | RSS ingestion |
| fetch_live_crimes | 3 min | crime_worker.fetch_live_crimes | Crime data |
| fetch_regional_hazards | 2 min | infra_worker.fetch_regional_hazards | NWS weather |
| fetch_cloud_outages | 5 min | cloud_worker.fetch_cloud_outages | Cloud status |
| run_telemetry_sync | 5 min | telemetry_worker.run_telemetry_sync | BGP/elastic |
| fetch_cisa_kev | 6 hours | cve_worker.fetch_cisa_kev | CISA KEV |
| job_internal_risk | 1 hour | scheduler.job_internal_risk | Internal CIS |
| job_unified_brief | 30 min | scheduler.job_unified_brief | AI brief |
| job_tiered_alert_escalation | 1 min | scheduler.job_tiered_alert_escalation | RCA dispatch |
| job_retrain_ml | Sunday 02:00 | scheduler.job_retrain_ml | ML training |
| run_database_maintenance | 60 min | scheduler.run_database_maintenance | Cleanup |
| job_daily_email_unified_brief | 07:00 CST | scheduler.job_daily_email_unified_brief | Email brief |

## Boot Sequence
On startup, runs all jobs immediately in sequence:
1. job_tiered_alert_escalation
2. fetch_cisa_kev
3. fetch_regional_hazards
4. fetch_cloud_outages
5. run_telemetry_sync
6. fetch_live_crimes
7. fetch_feeds
8. job_internal_risk
9. job_unified_brief

## Thread Safety
- Each job runs in its own daemon thread
- Jobs that need DB access create their own SessionLocal()
- Global _global_scorer is pre-loaded but force_reload_scorer() during ML retrain is atomic
- SQLAlchemy NullPool prevents connection contention

## Job Details

### fetch_feeds (RSS Ingestion)
Uses async/await with aiohttp for concurrent downloads. Chunks feeds in groups of 5. Parses with feedparser, scores with HybridScorer, extracts IOCs, saves in batches of 100, then deduplicates. GC.collect() after completion.

### job_tiered_alert_escalation
The most complex job. Queries unresolved alerts, clusters by site via AIOpsEngine, evaluates SLA rules per site, checks business hours, detects cascading, checks flapping cooldown, dispatches via SMTP. Runs every 60 seconds. (Full details in ESCALATION.md)

### job_unified_brief
Gathers data from InternalRiskSnapshot, RegionalHazard, crime data, and executive grid intel. Calls LLM for map-reduce generation. Saves to SystemConfig. Triggers risk_alert check.

### run_database_maintenance
Purges old data per retention policy: low-score articles >3d (unpinned), other articles >30d (unpinned), SolarWinds alerts >60d, hazards >48h, outages >12h, CVEs >7d, crimes >7d. Deduplicates articles. Runs SQLite PRAGMA optimize + WAL checkpoint.

## Logging
All jobs log via `log(message, source)` format: `[SOURCE] message`. Sources: SYSTEM, WORKER, EMAIL, CLEANUP, AI.

## Error Handling
Each job is wrapped in try/except. Errors are logged but never crash the main loop. The scheduler container runs indefinitely.
