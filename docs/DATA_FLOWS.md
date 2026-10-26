# Data Flows and Domain Pipelines

This document describes the data transformations implemented by the current source tree. Job frequencies/startup behavior are in [`SCHEDULER.md`](SCHEDULER.md); HTTP contracts are in [`API.md`](API.md).

## Runtime data path

```text
external feeds / webhook / API actions
              │
              ▼
       validation + normalization
              │
              ▼
       SQLite rows and caches
              │
       ┌──────┼─────────┐
       ▼      ▼         ▼
   scoring  correlation  reports/alerts
       └──────┼─────────┘
              ▼
      FastAPI, React, WebSocket, SMTP
```

API, worker, and webhook use one shared SQLite file on the `./data` volume. Migrations execute before normal service work. Full encrypted backups snapshot the SQLite file and persistent model artifact; environment secrets remain outside the package.

## 1. RSS ingestion, scoring, and article enrichment

**Entry point:** `src.scheduler.fetch_feeds()`; registry default every five minutes.
**Tables:** `feed_sources`, `articles`, `keywords`, `extracted_iocs`.

```text
active FeedSource rows
  -> known links published in prior 7 days
  -> aiohttp fetch in chunks of 5 (15 s/feed)
  -> parse each feed's entries
  -> HybridScorer(title + summary)
  -> categorizer(title + summary)
  -> IOC extraction when score >= 50 and category starts "Cyber"
  -> per-article nested-transaction insert
  -> 24-hour exact-link/title deduplication
  -> later full-content enrichment for score >= 40
```

`published_parsed` or `updated_parsed` is used for `published_date`; missing/invalid source time falls back to current UTC. Links already seen during the prior seven-day lookup and duplicate links within one feed are skipped. The database's unique `articles.link` constraint remains the final duplicate guard; article inserts use nested transactions so one integrity error does not discard the rest of the cycle. After each cycle, `deduplicate_articles()` compares recent exact links and RapidFuzz title ratios greater than 85 within source-domain, hour, and approximate title-length buckets.

Articles with score at least 40 start with enrichment status `pending`. The separate enrichment job selects pending/failed rows with fewer than three attempts, uses two fetch workers, stores at most 200,000 characters, and writes success/failure metadata. It is not part of the RSS request path.

### Hybrid article score

Keyword score is the sum of each configured keyword weight found as a lowercase substring. If the optional scikit-learn model exists, `predict_proba()` adjusts that score:

| Condition | Effect |
|---|---|
| Keep probability ≥0.75 and keyword score <50 | Raise score to at least 65 |
| Keep probability ≤0.25 and keyword score ≥50 | Reduce current score by 60% |
| Keep probability >0.50 and score >0 | Add `keep_probability * 10` |
| Final result | Cap at 100 |

An article is `is_bubbled` at score ≥45. IOC extraction uses a separate score ≥50 gate and a category prefix of `Cyber`. Keyword weights edited through the API are constrained to 1–100 and reload the in-process scorer. The optional model trains on `human_feedback=1` (noise) and `2` (keep), requires at least 10 labels, and is atomically written under the SQLite data directory.

### Category names and observed consumer mismatch

The current regex categorizer returns:

- `Cyber: Exploits & Vulns`
- `Cyber: Malware & Threats`
- `ICS/OT & SCADA`
- `Cloud & IT Infrastructure`
- `Physical Security & Crime`
- `Severe Weather & Natural Hazards`
- `Geopolitics & Policy`
- `AI & Emerging Tech`
- `Data Breach & Privacy`
- `General` when no pattern matches

There are nine non-General categories. **Compatibility mismatch:** the frontend category selector and parts of `get_executive_grid_intel()` still use the earlier labels `Cloud & IT Infra`, `Physical Security`, and `Severe Weather`; exact-match filters therefore do not treat the newer labels as aliases. The current code behavior and affected consumers are recorded in [`DOCUMENTATION_AUDIT.md`](DOCUMENTATION_AUDIT.md#source-level-mismatches-surfaced-during-the-audit).

## 2. IOC extraction and search

`EnterpriseIOCExtractor` URL-decodes/refangs text (`hxxp`, `[.]`, `(dot)`, and related forms), applies 21 compiled rules across Network, Host Artifacts, Actor Infrastructure, Cloud & DevOps, and Taxonomy, rejects configured benign domains and non-public IP addresses, normalizes selected value types, deduplicates, and attaches up to 45 characters on each side of a match. Persisted result fields are `Category`, `Type`, `Indicator`, and `Context` before database column mapping.

`get_iocs()` joins recent extraction records to source articles. Duplicate CVEs are grouped with multiple article sources; other indicators remain individual rows. Search parses space/comma/semicolon terms and quoted phrases, ORs terms across title/summary/full content, sorts deterministically, and caps article results at 30.

## 3. External Global CIS scoring

**Entry point:** `get_executive_grid_intel(active_warn_count, recent_crimes)`.
**Inputs:** previous 24 hours of articles and CISA KEV rows, recent grid-relevant crime rows, current hazard count, 14-day score history, and `SystemConfig` scoring fields.
**Output:** cyber/physical tiers and scores, unified tier, evidence, source rows, scoring mode, and applied overrides. Each run updates the current UTC `DailyThreatScore` row with the maximum cyber/physical points observed that day.

### Data selection and classification

- Cyber candidates require score ≥50 and exact membership in the implementation's cyber category list. High-level count claims must account for the category-label mismatch above.
- ICS/CISA advisories are inspected for source names and title terms, then tagged for critical vendor/KEV activity.
- Physical articles require a score ≥50, a local Arkansas/utility term, and a threat term; duplicate first-50-character titles are skipped.
- Local crime records passed to the grid are filtered to selected categories and the requested headquarters distance; this is not a per-monitored-site crime geofence.
- Crime records are grouped into persons/property/society buckets from title/category words for the CIS calculation.

### Score calculation

The 14-day cyber/physical historical means feed displayed baseline values. Non-zero `baseline_override_cyber`/`baseline_override_phys` values replace those means; absent history uses 20 and 25 respectively. These baseline fields are returned for posture context and are not added to the component score formula.

The service computes `C`, `L`, `P_C`, `P_L`, `S`, and `N`. Countermeasures are clamped to 1–5. The cyber and physical components are `(C + L) - (S + N)` and `(P_C + P_L) - (S + N)`. In `hybrid`, `global_risk_offset` is added to each component and scores are clamped to −8..+8. In `manual`, cyber/physical C/L overrides are used and clamped to 1–5. `auto` uses computed components. Risk buckets are GREEN (<−4), BLUE (−4..−2), YELLOW (−1..+2), ORANGE (+3..+5), RED (≥+6); the unified tier is the higher cyber/physical tier.

Important thresholds in the current source:

- Cyber lethality: any detected KEV-style ICS advisory -> 5; otherwise recent CVE count >10 -> 4, >5 -> 3, >0 -> 3; otherwise more than five qualifying cyber articles -> 2, else 1.
- Cyber criticality: critical ICS/utility targeting -> 5; any ICS advisory -> 4; APT/ransomware -> 4; more than three filtered cyber articles -> 3; else 2.
- Physical lethality: persons ≥5 or property ≥10 -> 5; persons ≥3 or property ≥6 -> 4; persons ≥1 or property ≥3 -> 3; total incidents ≥5 -> 2; else 1.
- Physical criticality: at least three filtered physical articles or weather weight ≥0.8 -> 5; at least one physical article or weather weight ≥0.4 -> 4; positive physical OSINT score -> 3; else 2.

## 4. Internal asset-risk pipeline

**Entry point:** `calculate_internal_cis_score(db_session)`.
**Sources:** all distinct hardware/software asset rows, articles from the last 30 days (maximum 500, score ≥40), and the 300 newest `CveItem` rows.
**Output:** risk score/tier, loaded and matching counts, sorted hardware/software match arrays, and applied auto/used C/L components.

1. Deduplicate hardware by non-empty IP and software by trimmed/case-folded name.
2. Build hardware/software match signatures from product, vendor, and version. Common-noun asset names use a ±100-character security-keyword proximity expression; acronym-collision filters suppress `apt`, `mac`, `surface`, and `office` false positives.
3. Gate article text by score ≥40 and at least one strong keyword or at least two weak keywords. Then use a trigger-token reverse index to reduce candidate regex scans. Each article contributes at most five matches; each CISA record contributes at most three.
4. Deduplicate match titles per asset. OSINT risk is `min(unique_match_count * 25, 100)`; global/critical unique titles feed aggregate counts.
5. Calculate auto lethality from critical/total unique OSINT-title counts and auto criticality from percent of deduplicated assets with matches. Compute `(C + L) - (S + N)`, apply `internal_risk_offset` only in hybrid mode, clamp −8..+8, and map to the shared risk buckets.

`generate_and_save_internal_risk_snapshot()` stores the result plus JSON hardware/software arrays and mirrors its tier to `SystemConfig.last_internal_risk`. The timer is every two hours by default; that cadence is independent of the on-demand endpoint.

## 5. LLM reports and progress

The LLM client uses an OpenAI-compatible `/chat/completions` endpoint configured in `SystemConfig`. Calls have a 300-second timeout and return `[WARN]` text on failure. The map/reduce implementation processes chunks sequentially, scales the base chunk size by model context, and may skip noise or the reduce step depending on caller options. Progress is stored in process memory, not a durable table.

| Report | Input window/shape | Persistence and default schedule |
|---|---|---|
| Unified brief | 24-hour cyber/physical data, recent KEVs/cloud/hazards/crimes, latest internal snapshot, top asset matches | `SystemConfig.unified_brief`; every 6 hours; asynchronous manual generation |
| Global threat brief | Up to 250 score-50+ articles, recent KEVs/cloud/hazards/crime; CI/APT keyword classification and US/global text classification | `SystemConfig.global_brief`; daily 02:00 Central; asynchronous manual generation |
| Internal asset-risk brief | Latest snapshot's hardware/software rows plus up to 200 recent KEVs | `SystemConfig.internal_brief`; every 3 hours; asynchronous manual generation; requires a snapshot |
| Rolling handoff | Last 24 hours; up to 15 score-50+ articles, 20 hazards, 15 cloud records | `SystemConfig.rolling_summary`; every 30 minutes |
| Daily Fusion | Previous America/Chicago calendar day; articles score ≥80 (max 15), KEVs (20), hazards (15), cloud rows (15) | `daily_briefings`; daily at 06:00 Central; final LLM failure returns a domain-summary fallback |
| Custom intelligence report | Selected IDs or up to 30 OR-matched articles; title/summary/full content fed to source-evidence prompt | In-memory generation status/results; user explicitly saves to `saved_reports` |
| Shift handoff summary | Up to 200 non-deleted filtered logs; untrusted source text | Returned to UI and optionally appended as a log; 30-second wrapper timeout uses deterministic fallback |

The global-threat assembler classifies map outputs into CI sectors, actors, CVEs, and US/global groups in Python; it skips the reduce request and may use one final LLM call for the BLUF. The internal brief is an LLM analysis of stored asset correlations, not a replacement for deterministic score calculation. The unified brief adds OSINT-correlation and AI-generated-content disclaimers.

## 6. Webhook, AIOps, and notifications

### SolarWinds

`POST /webhook/solarwinds` validates body size and optional HMAC/timestamp replay controls, extracts supported fields, then schedules background persistence. The current route returns HTTP 200 with an accepted body, not HTTP 202. A resolution marks unresolved alerts for the node as Resolved; a new event writes a `SolarWindsAlert` and a site-scoped timeline row. AIOps clustering and scheduled escalation run after persistence.

### AIOps

`EnterpriseAIOpsEngine` groups alerts by site, maps normalized domain hints (`PRIMARY_INTERNET` input becomes canonical `INTERNET`), ranks patient zero by domain/severity/time, finds provider clusters at five or more sites by default, and calculates root cause from the cluster plus cloud/BGP/weather context. Current `RegionalHazard` schema has no geometry columns; root-cause weather matching uses district/site text against `location` under the normal persisted model.

Acknowledgement (`is_correlated`) and dispatch are workflow flags, not recovery. `get_aiops_active_issue_counts()` counts all unresolved alerts, including acknowledged/correlated alerts. The site dialog's Mark Site Up action resolves all unresolved site alerts, clears Needs Dispatch, records the operator, and broadcasts a refresh. Maintenance is separate and is not an escalation filter.

### Risk, earthquake, wildfire, and crime notifications

- `risk_alert.check_and_alert()` sends only on a tier increase from a known prior tier, uses `RISK_ALERT_RECIPIENTS`, and applies a four-hour shared cooldown. If no recipients exist, it updates tracked levels without sending.
- Earthquake proximity examines magnitude ≥2.5 events within 50 miles of monitored locations and keeps alerted IDs in `SystemConfig`.
- Wildfire proximity defaults to five miles from a site/perimeter. A fire at or below one acre uses a one-mile site threshold; per-fire/site distance state supports a re-alert when the fire moves at least 0.5 mile closer.
- Perimeter crime delivery selects only rows with distance ≤0.4 miles from headquarters, severity text containing `High`, and `is_alert_dispatched=false`; it sends an SMS-friendly email through the configured gateway address.

## 7. Regional weather, fire, and telemetry

`fetch_regional_hazards()` starts SPC, NWS Arkansas, NWS nearby out-of-state, and two USGS queries in a four-worker executor. NWS responses are cached as GeoJSON and upserted into `regional_hazards`. USGS requests cover the last seven days with minimum magnitude 2.0; proximity email checks use a separate 2.5 threshold. After those feeds complete, the worker runs wildfire proximity alerting.

Wildfire map data comes from WFCA WFS incidents/perimeters and recent FIRMS footprint features. The request uses a regional bounding box and filters incidents to non-stale active wildfires in the Arkansas operating-area county union. Perimeter and footprint GeoJSON are unioned by normalized IRWIN ID. Satellite footprints are estimates, not official perimeters. Fires ≤1 acre farther than one mile from every monitored site are omitted from the map and the small-fire notification set.

`run_telemetry_sync()` concurrently runs three providers: ORNL ODIN county power outages, RIPE routing visibility for configured ASNs, and IODA ISP outage alerts. Elasticsearch is **not** part of this telemetry job; it has a separate `elastic_sync` job every six minutes.

## 8. Cloud, KEV, Elastic, and crime workers

| Worker | Source/processing | Stored state |
|---|---|---|
| CISA KEV | Fetches the CISA JSON catalog, batch-loads known CVE IDs, inserts only new records | `cve_items` |
| Cloud | Fetches configured provider RSS/Atom feeds with up to five concurrent requests, considers up to 15 recent entries/provider, skips future maintenance and foreign-only entries, and marks matching reports resolved | `cloud_outages` |
| Elastic | Searches non-hidden indices for recent high severity (`log.level` or ECS `event.severity`), uses bounded scroll pages, index-qualifies IDs, normalizes ECS fields | `elastic_events` |
| Little Rock crime | POSTs to Little Rock CAD, uses ArcGIS geocoding with bounded in-memory LRU, generates an incident ID, classifies category/severity, writes in batches of 100, and purges >7-day records | `crime_incidents` |

All worker data freshness depends on upstream provider availability. Empty/no-new-data results can be normal and are distinct from API readiness.

## 9. Retention and full backup

The `database_maintenance` job runs every 60 minutes by default. It deletes old rows using the exact windows in [`MAINTENANCE.md`](MAINTENANCE.md#scheduled-maintenance-and-retention), cleans orphaned IOCs, expires recovery records, then attempts SQLite `PRAGMA optimize` and a passive WAL checkpoint. Article deduplication also runs after each RSS cycle.

The encrypted backup job is weekly Sunday 00:00 Central, cannot be disabled, and keeps the newest three scheduled packages. Manual/pre-restore safety backups use separate retention. Backup/restore uses the SQLite online backup API, versioned manifest, checksums, AES-256-GCM chunk authentication, persistent model artifact, restore migration, maintenance drain, atomic installation, and rollback. `.env` is not included.

## Known wire contracts

- `POST /regional/compile-map` returns `[processed_geo, {}, diagnostics, toggled_affected_sites, master_affected_sites, analytics]`; indices are consumed by the frontend.
- REST permission failures are structured 403 responses and do not invalidate a session; 401 is an authentication failure.
- WebSocket `dashboard_update` is user-scoped and sent every ten seconds while a connected authorized AIOps Active Board client exists.
