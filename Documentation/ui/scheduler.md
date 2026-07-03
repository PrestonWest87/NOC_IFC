# Module: `src.scheduler.py`

Background task orchestrator for the NOC Intelligence Fusion Center. Manages 11 scheduled jobs using the `schedule` library with threaded execution.

---

## Overview

The scheduler runs as a standalone Python process in the `worker` Docker container (`python -u src/scheduler.py`). It starts all workers in a boot sequence, then enters a master event loop that checks for pending jobs every 1 second.

### Key Patterns
- **Threaded execution**: All jobs run via `run_threaded(job_func)` to prevent blocking the master loop.
- **Memory efficiency**: RSS feeds use chunked async fetching (5 concurrent feeds) with batch DB inserts (100 articles per batch).
- **GC**: Explicit `gc.collect()` after feed fetch cycles and database maintenance.
- **Pre-loaded scorer**: `HybridScorer` is loaded into memory at startup for performance.

---

## Boot Sequence

On container start, all jobs execute immediately in this order:
1. `job_tiered_alert_escalation` — Immediate RCA ticketing run
2. `fetch_cisa_kev` — CISA KEV catalog sync
3. `fetch_regional_hazards` — Weather/hazard data fetch
4. `fetch_cloud_outages` — Cloud provider status check
5. `run_telemetry_sync` — BGP/power/ISP telemetry
6. `fetch_live_crimes` — Crime feed fetch
7. `fetch_feeds` — RSS feed ingestion
8. `job_internal_risk` — Internal asset risk scoring
9. `job_unified_brief` — AI brief generation

---

## Job Schedule Reference

| Job | Interval | Function | Description |
|-----|----------|----------|-------------|
| RSS Feed Fetch | 15 min | `fetch_feeds(source="Scheduled")` | Poll configured RSS/Atom feeds. Downloads via aiohttp (chunked 5-at-a-time), parses via feedparser, scores via HybridScorer, extracts IOCs, saves in batches of 100. |
| Crime Feed | 3 min | `fetch_live_crimes` | Fetch geofenced law enforcement CAD data via ArcGIS geocoding. |
| Regional Hazards | 2 min | `fetch_regional_hazards` | Query NWS alerts (AR + OOS feeds), SPC day1/2/3 convective outlooks, USGS earthquakes (M0+). |
| Cloud Outages | 5 min | `fetch_cloud_outages` | Monitor 18+ cloud provider status feeds (AWS, GCP, Azure, Cisco, Cloudflare, GitHub, Slack, Zoom, Atlassian, Datadog, PagerDuty, Twilio, Okta, Zscaler, CrowdStrike, Mimecast). Filters non-US regions. |
| BGP / Telemetry | 5 min | `run_telemetry_sync` | Fetch ORNL ODIN power outage data, RIPE RIS BGP routing visibility, IODA ISP outage alerts. |
| CISA KEV Sync | 6 hours | `fetch_cisa_kev` | Mirror CISA Known Exploited Vulnerabilities catalog JSON. Compares by `cve_id`, inserts new records. |
| Internal Risk | 1 hour | `job_internal_risk` | Score internal hardware/software asset inventory against active CVEs. Generates CIS-compliant risk snapshot. |
| Unified Brief | 30 min | `job_unified_brief` | Generate LLM-synthesized executive intelligence brief. Gathers local telemetry, global intel, crime data, and sends to LLM for Map-Reduce narrative. |
| DB Maintenance | 60 min | `run_database_maintenance` | Purge stale telemetry, deduplicate articles (SequenceMatcher >85%), vacuum SQLite WAL. |
| ML Retrain | Sunday 02:00 | `job_retrain_ml` | Retrain `HybridScorer` from analyst feedback. Hot-reloads model weights into memory after training. |
| Tiered Alert Escalation | 1 min | `job_tiered_alert_escalation` | 24/7 RCA ticketing with P1-P5 SLA enforcement, business hours detection, and smart on-call paging. |
| Daily Email Brief | 07:00 CST | `job_daily_email_unified_brief` | Send the latest Unified Brief via SMTP to `RISK_ALERT_RECIPIENTS`. |

---

## Key Functions

### RSS Feed Ingestion (3-phase pipeline)

```
fetch_feeds()
  │
  ├── Phase 1: Download (async)
  │   └── fetch_all_feeds_chunked(feed_data, chunk_size=5)
  │       ├── fetch_single_feed(session, name, url) — aiohttp GET with 15s timeout
  │       └── Returns list of (name, content) tuples
  │
  ├── Phase 2: Parse & Score (sync)
  │   └── parse_and_score_feed(name, content, known_links)
  │       ├── feedparser.parse(content)
  │       ├── HybridScorer.score(full_text) — keyword + ML scoring
  │       ├── categorize_text(full_text) — 8-category regex classification
  │       ├── ioc_engine.extract(full_text) — IOC extraction (score >= 50 + Cyber category)
  │       └── Returns list of article data dicts
  │
  └── Phase 3: Bulk Save
      └── bulk_save_to_db(session, articles_data)
          ├── Batch size: 100 articles
          ├── Article + ExtractedIOC ORM creation
          ├── IntegrityError rollback for duplicates
          └── session.expunge_all() after batch
```

### Tiered Alert Escalation

`job_tiered_alert_escalation()` runs every 1 minute. See ARCHITECTURE.md section 8 for full SLA rules and dispatch paths.

Key components:
- `is_business_hours(dt_utc)` — Checks weekday (M-F) and time (0600-2000 CST)
- `get_tier(alert)` — Extracts P1-P5 tier from `Normalized_Alert_Level` or `Custom_Properties_Universal.Alert_Level`
- `is_node_on_cooldown(node_name, hours)` — Prevents repeat ticketing for flapping nodes
- Dual SLA dictionaries: `DAY_SHIFT_RULES` / `AFTER_HOURS_RULES`
- Cascade detection: Higher-priority alerts within a cluster override the dispatch target
- Site-level mute: `last_escalation_ticket` suppresses repeat onpages for 1 hour

### Database Maintenance

`run_database_maintenance()` runs every 60 minutes:

| Table / Operation | Retention | Action |
|-------------------|-----------|--------|
| Articles (score <= 0) | Immediate | Delete |
| Articles (not pinned, older than 14 days) | 14 days | Delete |
| SolarWindsAlerts (older than 60 days) | 60 days | Delete |
| RegionalHazards (older than 48 hours) | 48 hours | Delete |
| RegionalOutages (older than 12 hours) | 12 hours | Delete |
| BgpAnomalies (older than 12 hours) | 12 hours | Delete |
| CveItems (older than 7 days) | 7 days | Delete |
| CloudOutages (unresolved, older than 14 days) | 14 days | Delete |
| CloudOutages (updated older than 24 hours) | 24 hours | Delete |
| CrimeIncidents (older than 7 days) | 7 days | Delete |
| Orphaned IOCs | Immediate | Delete (article_id not in articles) |
| Article deduplication | Every cycle | Remove >85% title similarity within same source |
| SQLite optimization | Every cycle | PRAGMA optimize, WAL checkpoint truncate |

---

## Dependencies

### Internal Modules
- `src.services` — `generate_and_save_internal_risk_snapshot()`, `deduplicate_articles()`, `generate_rca_ticket_text()`
- `src.database` — All model classes, `SessionLocal`, `init_db()`
- `src.workers.cve_worker` — `fetch_cisa_kev()`
- `src.workers.infra_worker` — `fetch_regional_hazards()`
- `src.workers.cloud_worker` — `fetch_cloud_outages()`
- `src.workers.telemetry_worker` — `run_telemetry_sync()`
- `src.workers.crime_worker` — `fetch_live_crimes()`
- `src.workers.report_worker` — `start_report_scheduler()`
- `src.train_model` — `train()`
- `src.services.logic` — `get_scorer()`, `HybridScorer`
- `src.services.ioc_extractor` — `ioc_engine`
- `src.services.categorizer` — `categorize_text()`
- `src.services.aiops_engine` — `EnterpriseAIOpsEngine`
- `src.utils.mailer` — `send_alert_email()`
- `src.utils.llm` — `generate_unified_risk_brief()`
- `src.utils.risk_alert` — `check_and_alert()`

### External Libraries
- `schedule` — Job scheduling
- `feedparser` — RSS/Atom feed parsing
- `aiohttp` — Async HTTP feed downloads
- `requests` — Synchronous API calls
- `sqlalchemy` — ORM queries and maintenance
