# NOC Intelligence Fusion Center — Complete Architecture

## 1. High-Level Dependency Graph

```
                    ┌─────────────────────┐
                    │   webhook_listener   │  (FastAPI, port 8100)
                    │   (entry point #3)  │
                    └──────┬──────────────┘
                           │ calls
                           v
                    ┌─────────────────────┐
                    │     scheduler        │  (entry point #2, threaded)
                    │  (master loop)      │
                    └──┬───┬───┬───┬──────┘
                       │   │   │   │
         ┌─────────────┘   │   │   └──────────────┐
         v                 v   v                  v
   ┌──────────┐  ┌──────────────────┐  ┌──────────────────┐
   │ workers  │  │    services.py   │  │  train_model.py  │
   │ (6 files)│  │   (DAL layer)    │  │ (ML training)    │
   └──────────┘  └───────┬──────────┘  └──────────────────┘
                         │
             ┌───────────┼───────────┐
             v           v           v
       ┌──────────┐ ┌────────┐ ┌──────────┐
       │  llm.py  │ │mailer.py│ │risk_alert│
       └────┬─────┘ └────────┘ └──────────┘
            v
     ┌──────────────┐
     │   database   │  (leaf — no src/ imports)
     └──────────────┘

Entry points:
  app.py ──────→ calls services.py, llm.py, scheduler.fetch_feeds, database.init_db
  scheduler.py ──→ calls services.py, workers, llm.py, mailer.py, risk_alert.py
  webhook_listener.py ──→ calls database.py directly
```

---

## 2. Entry Points

### 2a. `app.py` — Streamlit UI (port 8501)

**Imports from `src/`:** `services`, `database.init_db`, `scheduler.fetch_feeds`, `llm.*`, `categorizer` (indirect via services)

**Functions defined in app.py:**

| Function | Called By | Purpose |
|----------|-----------|---------|
| `setup_database()` | module top-level (st.cache_resource) | Calls `init_db()` once |
| `force_db_migration()` | module top-level (st.cache_resource) | Also calls `init_db()` |
| `get_black_ops_state()` | module top-level | Easter egg state for "nick" user |
| `safe_rerun()` | multiple UI callbacks | Wrapper around `st.rerun()` |
| `check_cooldown(key, secs)` | UI button handlers | Rate-limits AI actions |
| `apply_cooldown(key)` | UI button handlers | Records cooldown timestamp |
| `format_local_time(utc_dt)` | various render functions | UTC → Central time string |
| `get_score_badge(score)` | article rendering | Returns emoji badge by score |
| `get_cat_icon(cat)` | article rendering | Returns emoji by category |
| `render_article_feed(feed_articles, key_prefix)` | RSS Triage tab | Renders article cards with action buttons |
| `show_cis_legend()` | Global Risk tab | Modal dialog with CIS level definitions |
| `md_to_html(md)` | (inline in Send button) | Markdown → HTML converter for email |

**`services.py` functions called from app.py:**

`get_user_by_token`, `get_all_roles`, `authenticate_user`, `get_user_by_username`, `get_cached_config`, `get_cached_locations`, `get_cached_geojson`, `get_filtered_notification_alerts`, `logout_user`, `update_user_profile`, `get_dashboard_metrics`, `get_pinned_articles`, `get_live_articles`, `get_cves`, `get_cloud_outages`, `get_hazards`, `get_executive_grid_intel`, `get_recent_crimes`, `get_historical_threat_scores`, `toggle_pin`, `boost_score`, `change_status`, `save_ai_bluf`, `save_global_config`, `generate_and_save_internal_risk_snapshot`, `SessionLocal`, `to_dotdict`, `get_cached_config`, `get_all_site_types`, `get_shift_logs`, `save_shift_log`, `set_site_maintenance`, `get_nws_forecast`, `force_fetch_crime_data`, `send_executive_report`, `get_all_daily_briefings`, `get_daily_briefing`, `save_daily_briefing`, `get_paginated_articles`, `get_user_weather_prefs`, `set_user_weather_prefs`, `get_active_wildfires`, `process_nws_alerts`, `get_weather_alerts_log`, `calculate_site_intersections`, `get_infrastructure_analytics`, `compile_regional_grid_map`, `_precompute_geo_matrix`, `import_locations`, `update_locations`, `nuke_crime_data`, `get_iocs`, `search_articles_for_hunting`, `get_osint_pivot_link`, `get_aiops_dashboard_data`, `clear_timeline_events`, `nuke_active_alerts`, `resolve_alert`, `acknowledge_cluster`, `generate_global_sitrep`, `search_articles`, `get_saved_reports`, `save_custom_report`, `get_all_roles`, `create_role`, `update_role`, `create_user`, `force_reset_pwd`, `update_user_role`, `add_bulk_keywords`, `add_bulk_feeds`, `delete_record`, `get_admin_lists`, `get_ml_counts`, `get_backup_data`, `restore_backup_data`, `recategorize_all_articles`, `nuke_tables`, `truncate_db_table`, `nuke_weather_data`, `build_crime_map_layers`, `build_aiops_map_layers`, `set_cluster_dispatch`, `dispatch_perimeter_crime_alerts`, `generate_daily_report_email_html`, `generate_unified_brief_email_html`, `generate_hazard_sitrep_html`, `generate_rca_ticket_text`, `generate_outlook_html_report`

**`llm.py` functions called from app.py:**

`generate_bluf`, `generate_rolling_summary`, `generate_daily_fusion_report`, `generate_executive_weather_brief`, `cross_reference_cves`, `build_custom_intel_report`, `generate_unified_risk_brief`, `generate_dynamic_scoring_report`, `call_llm`

**Database models accessed directly** (not via services): `User`, `CveItem`, `ElasticEvent`, `InternalRiskSnapshot` (via inline `SessionLocal()` blocks)

---

### 2b. `scheduler.py` — Background Orchestrator

**Imports from `src/`:** `services.generate_and_save_internal_risk_snapshot`, `database.*`, `cve_worker`, `infra_worker`, `cloud_worker`, `telemetry_worker`, `train_model.train`, `crime_worker.fetch_live_crimes`, `logic.get_scorer`, `llm.generate_unified_risk_brief`, `mailer.send_alert_email`, `aiops_engine.EnterpriseAIOpsEngine`, `risk_alert.check_and_alert`, `report_worker.start_report_scheduler`

**Functions defined in scheduler.py:**

| Function | Scheduled Interval | Purpose |
|----------|-------------------|---------|
| `log(message, source)` | — | Timestamped stdout logging |
| `fetch_single_feed(session, name, url)` | — | Async HTTP fetch for one RSS feed |
| `fetch_all_feeds_chunked(feed_data, chunk_size)` | — | Async concurrent feed downloader |
| `parse_and_score_feed(name, content, known_links)` | — | Parses RSS XML, scores, categorizes, extracts IOCs |
| `bulk_save_to_db(session, arts_data)` | — | Batch-inserts articles + IOCs |
| `fetch_feeds(source)` | every 15 min | Main RSS ingestion pipeline |
| `job_unified_brief()` | every 30 min | Generates Unified Risk Brief via LLM |
| `job_internal_risk()` | every 1 hour | Runs internal risk snapshot |
| `job_tiered_alert_escalation()` | every 1 min | 24/7 alert escalation + ticketing |
| `run_database_maintenance()` | every 60 min | Prunes old data, runs SQLite PRAGMAs |
| `job_retrain_ml()` | Sunday 02:00 | Retrains ML model, hot-reloads scorer |
| `run_threaded(job_func)` | — | Wrapper to run jobs in daemon threads |

**Key shared state in scheduler.py:**

- `_global_scorer` (module-level): Singleton `HybridScorer` instance pre-loaded at import time, hot-reloaded after ML retraining

**Workers called by scheduler:**

| Worker | Function Called | Interval |
|--------|----------------|----------|
| `crime_worker.py` | `fetch_live_crimes()` | 3 min |
| `cve_worker.py` | `fetch_cisa_kev()` | 6 hours |
| `infra_worker.py` | `fetch_regional_hazards()` | 2 min |
| `cloud_worker.py` | `fetch_cloud_outages()` | 5 min |
| `telemetry_worker.py` | `run_telemetry_sync()` | 5 min |
| `report_worker.py` | `start_report_scheduler()` | once at boot (thread) |

**Boot sequence** (in `if __name__ == "__main__"`): fires all workers once asynchronously via `run_threaded()`

---

### 2c. `webhook_listener.py` — FastAPI Gateway (port 8100)

**Imports from `src/`:** `database.SessionLocal`, `database.init_db`, `database.SolarWindsAlert`, `database.TimelineEvent`

**Functions defined:**

| Function | Called By | Purpose |
|----------|-----------|---------|
| `log(msg)` | internal | Timestamped logging |
| `classify_device(text, node_type_hint)` | `smart_extract` | Maps alert text to device class ontology |
| `smart_extract(payload)` | `process_payload_background` | Extracts structured fields from raw SolarWinds JSON |
| `process_payload_background(raw_payload)` | `receive_alert` (background) | Creates/updates SolarWindsAlert + TimelineEvent |
| `receive_alert(request, background_tasks)` | FastAPI POST `/webhook/solarwinds` | Entry point: queues payload for background processing |

**Endpoint:** `POST /webhook/solarwinds` → returns `{"status": "accepted"}`

---

## 3. Module Dependency Graph (All 23 Files)

```
                    ┌──────────────┐
                    │  database    │  ← leaf — no src/ imports
                    └──────┬───────┘
                           │
            ┌──────────────┼──────────────────┐
            │              │                  │
     ┌──────┴──────┐  ┌────┴─────┐  ┌────────┴────────┐
     │  services   │  │  logic   │  │  workers (6)    │
     │ (DAL layer) │  │(scorer)  │  │ crime_worker    │
     └──────┬──────┘  └────┬─────┘  │ cloud_worker    │
            │              │        │ cve_worker     │
            │              │        │ infra_worker   │
            │              │        │ telemetry_worker│
            │              │        └─────────────────┘
            │              │
     ┌──────┴──────┐  ┌────┴─────┐
     │    llm     │  │categorizer│
     └──────┬──────┘  └──────────┘
            │
     ┌──────┴──────┐
     │   mailer    │
     └─────────────┘

┌──────────────────────┐
│    risk_alert        │  ← imports database directly
└──────────────────────┘

┌──────────────────────┐
│    aiops_engine      │  ← imports database
└──────────────────────┘

┌──────────────────────┐
│   ioc_extractor      │  ← no src/ imports (pure)
└──────────────────────┘

┌──────────────────────┐
│   train_model        │  ← imports database
└──────────────────────┘

┌──────────────────────┐
│   report_worker      │  ← imports llm, database
└──────────────────────┘
```

---

## 4. Function-to-Function Call Chains

### 4a. RSS Ingestion Pipeline

```
scheduler.fetch_feeds()
  └─ scheduler.fetch_all_feeds_chunked()          [async]
       └─ scheduler.fetch_single_feed()           [async × N]
  └─ scheduler.parse_and_score_feed()
       └─ logic._global_scorer.score(text)        [HybridScorer]
       └─ categorizer.categorize_text(text)       [regex scoring]
       └─ ioc_extractor.ioc_engine.extract(text)  [if score≥50 & Cyber]
  └─ scheduler.bulk_save_to_db()
       └─ database.Article (SQLAlchemy INSERT)
       └─ database.ExtractedIOC (SQLAlchemy INSERT)
```

### 4b. Worker Functions

```
scheduler.fetch_live_crimes()       [every 3 min]
  └─ crime_worker.fetch_live_crimes()
       └─ crime_worker.geocode_address_arcgis()
       └─ crime_worker.calculate_distance()
       └─ services.dispatch_perimeter_crime_alerts()

scheduler.fetch_cisa_kev()          [every 6 hours]
  └─ cve_worker.fetch_cisa_kev()
       └─ database.CveItem (SQLAlchemy INSERT)

scheduler.fetch_regional_hazards()  [every 2 min]
  └─ infra_worker.fetch_regional_hazards()
       ├─ fetch_spc_outlooks() → save_geojson_to_db()
       ├─ fetch_nws_alerts_for_region("AR") → save_geojson_to_db() + RegionalHazard INSERT
       ├─ fetch_nws_alerts_for_region("OK,MS,MO") → same
       ├─ fetch_usgs_earthquakes("ar") → save_geojson_to_db()
       ├─ fetch_usgs_earthquakes("oos") → save_geojson_to_db()
       └─ check_earthquake_proximity()
            └─ risk_alert.send_alert() / build_eq_alert_email_body()

scheduler.fetch_cloud_outages()     [every 5 min]
  └─ cloud_worker.fetch_cloud_outages()
       └─ database.CloudOutage (SQLAlchemy INSERT/UPDATE)

scheduler.run_telemetry_sync()      [every 5 min]
  └─ telemetry_worker.run_telemetry_sync()
       ├─ fetch_ornl_odin_power() → RegionalOutage INSERT
       ├─ fetch_bgp_anomalies() → BgpAnomaly INSERT
       └─ fetch_ioda_isp_outages() → RegionalOutage INSERT
```

### 4c. Risk Calculation Chains

```
services.get_executive_grid_intel(active_nws_count, crimes)
  ├─ get_cached_config() → SystemConfig
  ├─ get_historical_threat_scores(14) → DailyThreatScore[]
  ├─ database.Article (query: 48h cyber/physical)
  ├─ database.CveItem (query: 48h)
  ├─ CIS scoring algorithm (c+l-s-n)
  └─ save_threat_score() → DailyThreatScore UPSERT

services.calculate_internal_cis_score(db_session)
  ├─ database.HardwareAsset, SoftwareAsset, Article, CveItem
  ├─ Inverted indexing + Double-Gatekeeper + Bi-Directional Proximity Regex
  └─ Returns annotated HW/SW lists + CIS score

services.generate_and_save_internal_risk_snapshot()
  └─ calculate_internal_cis_score()
  └─ database.InternalRiskSnapshot (INSERT)

scheduler.job_internal_risk()
  ├─ generate_and_save_internal_risk_snapshot()
  └─ risk_alert.check_and_alert(internal_risk=)

scheduler.job_unified_brief()
  ├─ services.get_executive_grid_intel()
  ├─ services.get_recent_crimes()
  ├─ llm.generate_unified_risk_brief()
  ├─ services.save_global_config()
  └─ risk_alert.check_and_alert(global_risk=)
```

### 4d. Alert Escalation Chain

```
scheduler.job_tiered_alert_escalation()  [every 1 min]
  ├─ database.SolarWindsAlert, MonitoredLocation, RegionalHazard, CloudOutage, BgpAnomaly
  ├─ aiops_engine.EnterpriseAIOpsEngine(db)
  │    └─ analyze_and_cluster(alerts) → {site: {alerts, metadata, domains, ...}}
  │         └─ _determine_patient_zero(alerts) → (p0_alert, scored_chain)
  ├─ ai_engine.calculate_root_cause(site, data, weather, cloud, bgp)
  │    └─ _get_domain(node_type, node_name, primary_comms)
  ├─ services.generate_rca_ticket_text()
  ├─ mailer.send_alert_email() [TICKET → REMEDYFORCE]
  ├─ mailer.send_alert_email() [NOTIFY → NOC]
  └─ mailer.send_alert_email() [ONPAGE → NOC or ITNETWORK]
```

### 4e. LLM Map-Reduce Pipeline

```
llm._map_reduce_summarize(items, formatter, map_prompt, reduce_prompt, config, chunk_size)
  ├─ [MAP] for each chunk: call_llm(sys=map_prompt, user=formatted_chunk)
  ├─ [REDUCE] if multiple summaries: call_llm(sys=reduce_prompt, user=joined)
  └─ returns final narrative string

Used by: generate_briefing, cross_reference_cves, generate_feed_overview,
         build_custom_intel_report, generate_daily_fusion_report,
         generate_aggregated_shift_summary, generate_dynamic_scoring_report

llm.generate_unified_risk_brief(session, global_intel, snapshot) — single-pass (no map-reduce)
llm.generate_rolling_summary(session) — single-pass, compresses 6h telemetry
llm.generate_bluf(article, session) — single-pass for one article
llm.generate_executive_weather_brief(analytics, p1_count, config) — single-pass
llm.generate_dynamic_scoring_report(session, intel) — uses map-reduce for cyber digest + single-pass master
llm.generate_siem_triage_summary(session, results) — single-pass
llm.generate_elastic_dsl(session, nl_query) — single-pass
llm.analyze_cascading_impacts(articles, session) — map-reduce
```

### 4f. Report Generation Chain

```
report_worker.start_report_scheduler()  [daemon thread]
  └─ (loop) → run_daily_report() at 06:00 CST
       └─ llm.generate_daily_fusion_report(session)
            ├─ 4x domain-specific map-reduce (Cyber, KEVs, Hazards, Cloud)
            └─ Master Editor single-pass → DailyBriefing INSERT
```

---

## 5. Shared / Global Variables

| Variable | Defined In | Type | Accessed By |
|----------|-----------|------|-------------|
| `GEO_CACHE` | `crime_worker.py:21` | `dict` | `geocode_address_arcgis()` |
| `CLOUD_FEEDS` | `cloud_worker.py:8` | `dict` | `fetch_cloud_outages()` |
| `COMPILED_CATEGORIES` | `categorizer.py:27` | `dict[str, Pattern]` | `categorize_text()` |
| `SPC_URLS` | `infra_worker.py:25` | `dict` | `fetch_spc_outlooks()` |
| `AR_COUNTY_COORDS` | `telemetry_worker.py:13` | `dict` | `fetch_ornl_odin_power()` |
| `USGS_BOUNDS` | `infra_worker.py:95` | `dict` | `fetch_usgs_earthquakes()` |
| `RISK_TIER_ORDER` | `risk_alert.py:21` | `list` | `get_tier_level()`, `is_increase()` |
| `CENTRAL_TZ` | `risk_alert.py:18` | `ZoneInfo` | `should_send_alert()`, `build_alert_email_body()`, `check_earthquake_proximity()` |
| `LOCAL_TZ` | `services.py:19` | `ZoneInfo` | All time formatting in services.py, `dispatch_perimeter_crime_alerts()` |
| `LOCAL_TZ` | `app.py:33` | `ZoneInfo` | `format_local_time()` |
| `LOCAL_TZ` | `llm.py:20` | `ZoneInfo` | `generate_aggregated_shift_summary()`, `generate_daily_fusion_report()` |
| `LOCAL_TZ` | `scheduler.py` (inline) | `ZoneInfo` | `log()`, `job_tiered_alert_escalation()` |
| `LOCAL_TZ` | `infra_worker.py:9` | `ZoneInfo` | `log_print()`, `check_earthquake_proximity()` |
| `LOCAL_TZ` | `report_worker.py:8` | `ZoneInfo` | `run_daily_report()`, `start_report_scheduler()` |
| `_global_scorer` | `scheduler.py:50` | `HybridScorer` | `parse_and_score_feed()`, `job_retrain_ml()` |
| `_SCORER_INSTANCE` | `logic.py:66` | `HybridScorer` | `get_scorer()`, `force_reload_scorer()` |
| `ioc_engine` | `ioc_extractor.py:173` | `EnterpriseIOCExtractor` | `parse_and_score_feed()`, `recategorize_all_articles()` |

---

## 6. Database Model Flows

### `User`
| Function | Operation |
|----------|-----------|
| `services.authenticate_user()` | Read (query by username), Update (session_token) |
| `services.get_user_by_token()` | Read (query by token) |
| `services.get_user_by_username()` | Read |
| `services.update_user_profile()` | Read + Update (full_name, job_title, contact_info, password) |
| `services.logout_user()` | Read + Update (session_token = None) |
| `services.create_user()` | Insert |
| `services.force_reset_pwd()` | Read + Update (password_hash, session_token) |
| `services.update_user_role()` | Read + Update (role, session_token) |
| `app.py` (inline) | Read + Update (default_shift) |
| `database.init_db()` | Seed (admin user) |

### `Role`
| Function | Operation |
|----------|-----------|
| `services.get_all_roles()` | Read (all) |
| `services.create_role()` | Insert |
| `services.update_role()` | Read + Update |
| `database.init_db()` | Seed (admin, analyst roles) |

### `Article`
| Function | Operation |
|----------|-----------|
| `services.get_dashboard_metrics()` | Read (count) |
| `services.get_pinned_articles()` | Read (pinned) |
| `services.get_live_articles()` | Read (score ≥ 50) |
| `services.toggle_pin()` | Read + Update (is_pinned) |
| `services.boost_score()` | Read + Update (score) |
| `services.change_status()` | Read + Update (human_feedback, Keyword.weights) |
| `services.save_ai_bluf()` | Read + Update (ai_bluf) |
| `services.get_executive_grid_intel()` | Read (48h cyber/physical) |
| `services.calculate_internal_cis_score()` | Read (30d) |
| `services.get_paginated_articles()` | Read (filtered, paginated) |
| `services.search_articles_for_hunting()` | Read (ILIKE search) |
| `services.search_articles()` | Read (ILIKE search) |
| `services.get_ml_counts()` | Read (count by feedback) |
| `services.recategorize_all_articles()` | Read + Update (category) |
| `services.nuke_tables()` | Delete |
| `scheduler.fetch_feeds()` → `bulk_save_to_db()` | Insert |
| `scheduler.run_database_maintenance()` | Delete (score ≤ 0, older than 14d) |
| `llm.generate_rolling_summary()` | Read (6h, score ≥ 50) |
| `llm.generate_daily_fusion_report()` | Read (yesterday) |
| `llm.generate_dynamic_scoring_report()` | Read (48h) |

### `CveItem`
| Function | Operation |
|----------|-----------|
| `services.get_dashboard_metrics()` | Read (count 24h) |
| `services.get_cves()` | Read (ordered by date_added) |
| `services.get_executive_grid_intel()` | Read (48h) |
| `services.calculate_internal_cis_score()` | Read (300 newest) |
| `cve_worker.fetch_cisa_kev()` | Insert (dedup by cve_id) |
| `scheduler.run_database_maintenance()` | Delete (older than 7d) |
| `llm.generate_dynamic_scoring_report()` | Read (48h) |

### `SolarWindsAlert`
| Function | Operation |
|----------|-----------|
| `webhook_listener.process_payload_background()` | Insert (new alert), Update (resolve existing) |
| `services.get_aiops_dashboard_data()` | Read (unresolved, uncorrelated) |
| `services.resolve_alert()` | Read + Update (status = Resolved) |
| `services.acknowledge_cluster()` | Read + Update (is_correlated = True) |
| `services.nuke_active_alerts()` | Delete (all) |
| `services.generate_global_sitrep()` | Read (uncorrelated, unresolved) |
| `scheduler.job_tiered_alert_escalation()` | Read (12h unresolved), Update (is_ticketed) |
| `scheduler.run_database_maintenance()` | Delete (older than 60d) |
| `aiops_engine.generate_chronic_insights()` | Read (60d) |

### `MonitoredLocation`
| Function | Operation |
|----------|-----------|
| `services.get_cached_locations()` | Read (all, cached) |
| `services.get_all_site_types()` | Read (distinct loc_type) |
| `services.import_locations()` | Insert (batch, dedup by name) |
| `services.update_locations()` | Read + Update (batch) |
| `services.set_site_maintenance()` | Read + Update (maintenance fields) |
| `services.nuke_tables()` | Delete |
| `scheduler.job_tiered_alert_escalation()` | Read (site metadata) |
| `infra_worker.check_earthquake_proximity()` | Read (sites with lat/lon) |
| `infra_worker.fetch_regional_hazards()` (indirect) | Read + Update (current_spc_risk) |

### `SystemConfig`
| Function | Operation |
|----------|-----------|
| `services.get_cached_config()` | Read (first row, cached) |
| `services.save_global_config()` | Read + Update / Insert |
| `risk_alert.update_tracked_risks()` | Read + Update (last_global_risk, last_internal_risk) |
| `risk_alert.should_send_alert()` | Read (last_risk_alert_time) |
| `risk_alert.update_last_alert_time()` | Read + Update (last_risk_alert_time) |
| `telemetry_worker.fetch_bgp_anomalies()` | Read (monitored_asns) |
| `telemetry_worker.fetch_ioda_isp_outages()` | Read (monitored_asns) |
| `database.init_db()` | Seed (first row with defaults) |

### `InternalRiskSnapshot`
| Function | Operation |
|----------|-----------|
| `services.generate_and_save_internal_risk_snapshot()` | Insert |
| `app.py` (inline) | Read (28 newest) |
| `scheduler.job_unified_brief()` | Read (latest) |
| `scheduler.job_internal_risk()` | (via generate_and_save) |

### `DailyThreatScore`
| Function | Operation |
|----------|-----------|
| `services.save_threat_score()` | UPSERT by record_date |
| `services.get_historical_threat_scores()` | Read (N days) |

### `CrimeIncident`
| Function | Operation |
|----------|-----------|
| `services.get_recent_crimes()` | Read (filtered, ordered) |
| `services.dispatch_perimeter_crime_alerts()` | Read + Update (is_alert_dispatched) |
| `services.nuke_crime_data()` | Delete (all) |
| `crime_worker.fetch_live_crimes()` | Insert (batch, dedup by id), Delete (stale > 7d) |
| `scheduler.run_database_maintenance()` | Delete (older than 7d) |

### `RegionalHazard`
| Function | Operation |
|----------|-----------|
| `services.get_dashboard_metrics()` | Read (count 24h) |
| `services.get_hazards()` | Read (ordered) |
| `services.nuke_weather_data()` | Delete (all) |
| `infra_worker.fetch_nws_alerts_for_region()` | Insert / Update (by hazard_id) |
| `scheduler.run_database_maintenance()` | Delete (older than 48h) |

### `CloudOutage`
| Function | Operation |
|----------|-----------|
| `services.get_dashboard_metrics()` | Read (count unresolved 24h) |
| `services.get_cloud_outages()` | Read (filtered) |
| `cloud_worker.fetch_cloud_outages()` | Insert / Update (is_resolved), Delete (resolved > 3d) |
| `scheduler.run_database_maintenance()` | Delete (older than 24h) |

### `BgpAnomaly`
| Function | Operation |
|----------|-----------|
| `telemetry_worker.fetch_bgp_anomalies()` | Insert (if not existing unresolved) |
| `scheduler.run_database_maintenance()` | Delete (older than 12h) |

### `GeoJsonCache`
| Function | Operation |
|----------|-----------|
| `services.get_cached_geojson()` | Read (all feed types) |
| `infra_worker.save_geojson_to_db()` | UPSERT by feed_name |
| `services.nuke_weather_data()` | Delete (all) |

### Other Models
| Model | Created By | Read By |
|-------|-----------|---------|
| `ExtractedIOC` | `scheduler.bulk_save_to_db()` | `services.get_iocs()` |
| `FeedSource` | `services.add_bulk_feeds()` | `scheduler.fetch_feeds()`, `services.get_admin_lists()` |
| `Keyword` | `services.add_bulk_keywords()` | `logic.HybridScorer.__init__()`, `services.get_admin_lists()` |
| `ShiftLogEntry` | `services.save_shift_log()` | `services.get_shift_logs()` |
| `DailyBriefing` | `report_worker.run_daily_report()`, `services.save_daily_briefing()` | `services.get_all_daily_briefings()`, `services.get_daily_briefing()` |
| `SavedReport` | `services.save_custom_report()` | `services.get_saved_reports()` |
| `RegionalOutage` | `telemetry_worker.fetch_ornl_odin_power()`, `telemetry_worker.fetch_ioda_isp_outages()` | `services.get_aiops_dashboard_data()` |
| `TimelineEvent` | `webhook_listener.process_payload_background()`, `services.resolve_alert()` | `services.get_aiops_dashboard_data()` |
| `ElasticEvent` | (external ingestion) | `app.py` (inline query) |
| `HardwareAsset` | (admin import) | `services.calculate_internal_cis_score()` |
| `SoftwareAsset` | (admin import) | `services.calculate_internal_cis_score()` |
| `UserWeatherPreference` | `services.set_user_weather_prefs()` | `services.get_user_weather_prefs()`, `services.get_filtered_notification_alerts()` |

---

## 7. Complete Function Inventory

### `src/database.py` (592 lines)
`init_db()`, `set_sqlite_pragma()`
**Models:** `User`, `Role`, `SavedReport`, `FeedSource`, `Keyword`, `SystemConfig`, `ShiftLogEntry`, `SoftwareAsset`, `HardwareAsset`, `InternalRiskSnapshot`, `Article`, `ExtractedIOC`, `CveItem`, `ElasticEvent`, `DailyBriefing`, `DailyThreatScore`, `RegionalHazard`, `RegionalOutage`, `CloudOutage`, `BgpAnomaly`, `SolarWindsAlert`, `TimelineEvent`, `MonitoredLocation`, `CrimeIncident`, `GeoJsonCache`, `UserWeatherPreference`

### `src/services.py` (2349 lines)
`to_dotdict()`, `to_dotdict_list()`, `central_now()`, `utc_now()`, `format_central()`, `get_cached_config()`, `get_cached_locations()`, `get_cached_geojson()`, `get_ar_counties_mapping()`, `get_regional_counties_mapping()`, `get_all_site_types()`, `set_cluster_dispatch()`, `get_shift_logs()`, `save_shift_log()`, `set_site_maintenance()`, `get_nws_forecast()`, `get_filtered_notification_alerts()`, `authenticate_user()`, `get_user_by_token()`, `get_user_by_username()`, `update_user_profile()`, `logout_user()`, `get_dashboard_metrics()`, `get_pinned_articles()`, `get_live_articles()`, `toggle_pin()`, `boost_score()`, `change_status()`, `save_ai_bluf()`, `get_recent_crimes()`, `force_fetch_crime_data()`, `get_historical_threat_scores()`, `save_threat_score()`, `get_executive_grid_intel()`, `calculate_internal_cis_score()`, `generate_and_save_internal_risk_snapshot()`, `generate_unified_brief_email_html()`, `native_md_to_html()` (nested), `generate_outlook_html_report()`, `send_executive_report()`, `get_all_daily_briefings()`, `get_daily_briefing()`, `save_daily_briefing()`, `generate_daily_report_email_html()`, `get_paginated_articles()`, `get_cves()`, `get_cloud_outages()`, `get_user_weather_prefs()`, `set_user_weather_prefs()`, `get_active_wildfires()`, `dispatch_perimeter_crime_alerts()`, `get_hazards()`, `process_nws_alerts()`, `get_weather_alerts_log()`, `_get_eq_severity()`, `calculate_site_intersections()`, `get_infrastructure_analytics()`, `generate_hazard_sitrep_html()`, `import_locations()`, `update_locations()`, `nuke_crime_data()`, `get_iocs()`, `search_articles_for_hunting()`, `get_osint_pivot_link()`, `get_aiops_dashboard_data()`, `clear_timeline_events()`, `nuke_active_alerts()`, `resolve_alert()`, `acknowledge_cluster()`, `save_alias()`, `generate_global_sitrep()`, `generate_rca_ticket_text()`, `search_articles()`, `get_saved_reports()`, `save_custom_report()`, `get_all_roles()`, `create_role()`, `update_role()`, `create_user()`, `force_reset_pwd()`, `update_user_role()`, `save_global_config()`, `add_bulk_keywords()`, `add_bulk_feeds()`, `delete_record()`, `get_admin_lists()`, `get_ml_counts()`, `get_backup_data()`, `restore_backup_data()`, `recategorize_all_articles()`, `nuke_tables()`, `truncate_db_table()`, `nuke_weather_data()`, `build_crime_map_layers()`, `build_aiops_map_layers()`, `_precompute_geo_matrix()`, `compile_regional_grid_map()`

### `src/scheduler.py` (659 lines)
`log()`, `fetch_single_feed()`, `fetch_all_feeds_chunked()`, `parse_and_score_feed()`, `bulk_save_to_db()`, `fetch_feeds()`, `job_unified_brief()`, `job_internal_risk()`, `job_tiered_alert_escalation()`, `is_business_hours()` (nested), `is_node_on_cooldown()` (nested), `get_tier()` (nested), `run_database_maintenance()`, `job_retrain_ml()`, `run_threaded()`

### `src/app.py` (3557 lines)
`setup_database()`, `get_black_ops_state()`, `safe_rerun()`, `check_cooldown()`, `force_db_migration()`, `apply_cooldown()`, `format_local_time()`, `get_score_badge()`, `get_cat_icon()`, `render_article_feed()`, `show_cis_legend()`, `md_to_html()` (inline)

### `src/llm.py` (636 lines)
`get_llm_config()`, `call_llm()`, `chunk_list()`, `truncate_text()`, `_map_reduce_summarize()`, `generate_bluf()`, `analyze_cascading_impacts()`, `generate_unified_risk_brief()`, `generate_aggregated_shift_summary()`, `generate_briefing()`, `cross_reference_cves()`, `generate_feed_overview()`, `generate_executive_weather_brief()`, `build_custom_intel_report()`, `generate_rolling_summary()`, `generate_dynamic_scoring_report()`, `generate_siem_triage_summary()`, `generate_elastic_dsl()`, `generate_daily_fusion_report()`

### `src/webhook_listener.py` (121 lines)
`log()`, `classify_device()`, `smart_extract()`, `process_payload_background()`, `receive_alert()`

### `src/aiops_engine.py` (421 lines)
`EnterpriseAIOpsEngine.__init__()`, `._get_domain()`, `._determine_patient_zero()`, `.identify_fleet_outages()`, `.generate_chronic_insights()`, `.calculate_root_cause()`, `.analyze_and_cluster()`

### `src/logic.py` (78 lines)
`HybridScorer.__init__()`, `.score()`, `get_scorer()`, `force_reload_scorer()`

### `src/categorizer.py` (53 lines)
`categorize_text()`

### `src/ioc_extractor.py` (173 lines)
`EnterpriseIOCExtractor.__init__()`, `._initialize_whitelists()`, `._compile_rulesets()`, `.refang_payload()`, `._is_valid_ip()`, `._get_context()`, `.extract()`

### `src/mailer.py` (53 lines)
`send_alert_email()`

### `src/risk_alert.py` (245 lines)
`get_tier_level()`, `is_increase()`, `get_alert_recipients()`, `get_smtp_config()`, `should_send_alert()`, `update_last_alert_time()`, `update_tracked_risks()`, `build_alert_email_body()`, `send_alert()`, `check_and_alert()`, `build_eq_alert_email_body()`

### `src/crime_worker.py` (258 lines)
`log()`, `calculate_distance()`, `geocode_address_arcgis()`, `fetch_live_crimes()`

### `src/cloud_worker.py` (217 lines)
`is_foreign_region()`, `extract_us_regions()`, `is_future_maintenance()`, `extract_service_name()`, `fetch_cloud_outages()`

### `src/infra_worker.py` (204 lines)
`log_print()`, `save_geojson_to_db()`, `fetch_spc_outlooks()`, `fetch_nws_alerts_for_region()`, `fetch_usgs_earthquakes()`, `haversine_distance()`, `check_earthquake_proximity()`, `fetch_regional_hazards()`

### `src/telemetry_worker.py` (145 lines)
`log_print()`, `fetch_ornl_odin_power()`, `fetch_bgp_anomalies()`, `fetch_ioda_isp_outages()`, `run_telemetry_sync()`

### `src/cve_worker.py` (52 lines)
`fetch_cisa_kev()`

### `src/train_model.py` (52 lines)
`train()`

### `src/report_worker.py` (53 lines)
`run_daily_report()`, `start_report_scheduler()`

---

## 8. Environment Variable Dependency Map

| Env Var | Used By | Purpose |
|---------|---------|---------|
| `DATABASE_URL` | `database.py:11` | SQLite or PostgreSQL connection string |
| `RISK_ALERT_RECIPIENTS` | `risk_alert.py:39` | Comma-separated emails for risk alerts |
| `REMEDYFORCE_TICKET_EMAIL` | `scheduler.py:297` | Ticket dispatch destination (P1-P5) |
| `NOC_NOTIFY_EMAIL` | `scheduler.py:298` | After-hours notification destination |
| `NOC_ONPAGE_EMAIL` | `scheduler.py:299` | NOC onpage destination (SWF devices) |
| `ITNETWORK_ONPAGE_EMAIL` | `scheduler.py:300` | IT Network onpage destination |
| `CRIME_ALERT_SMS` | `services.py:1322` | SMS/email for perimeter crime alerts |
| `CRIME_ALERT_EMAIL` | `services.py:1324` | Fallback for CRIME_ALERT_SMS |

---

## 9. Threading Model

```
scheduler.py (main thread)
  │
  ├─ run_threaded(fetch_feeds) ──────────→ worker thread
  ├─ run_threaded(fetch_live_crimes) ────→ worker thread
  ├─ run_threaded(fetch_regional_hazards) → worker thread
  ├─ run_threaded(fetch_cloud_outages) ──→ worker thread
  ├─ run_threaded(run_telemetry_sync) ───→ worker thread
  ├─ run_threaded(fetch_cisa_kev) ───────→ worker thread
  ├─ run_threaded(job_internal_risk) ────→ worker thread
  ├─ run_threaded(job_unified_brief) ────→ worker thread
  ├─ run_threaded(job_tiered_alert_escalation) → worker thread
  ├─ run_threaded(run_database_maintenance) → worker thread
  └─ run_threaded(job_retrain_ml) ───────→ worker thread

webhook_listener.py (uvicorn server)
  └─ background_tasks.add_task(process_payload_background) → FastAPI background thread

report_worker.py (dedicated thread)
  └─ threading.Thread(target=start_report_scheduler) → started by scheduler at boot

app.py (main thread, Streamlit)
  └─ All DB calls are sequential (single-threaded by Streamlit design)
```

**Concurrency note:** SQLite with WAL mode + `check_same_thread=False` + `timeout=30` allows concurrent reads but serializes writes. All scheduler worker threads share the same engine pool.
