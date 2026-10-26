# Services and Domain Logic

This guide describes the current backend service boundaries. Source code is authoritative for exact implementation details; detailed module pages are linked throughout and indexed in [`reference/SOURCE_COVERAGE.md`](reference/SOURCE_COVERAGE.md).

## Runtime boundaries

```text
FastAPI routes ─────────┐
Worker scheduler ───────┼──> src.services.py (data access/domain operations) ──> SQLite
Webhook gateway ────────┘                     │
                                               ├── src/services/logic.py
                                               ├── src/services/categorizer.py
                                               ├── src/services/ioc_extractor.py
                                               ├── src/services/aiops_engine.py
                                               └── src/utils/{llm,mailer,risk_alert}.py
```

`src/services/__init__.py` dynamically loads the sibling `src/services.py` file as `src.services` while retaining package search paths for `logic`, `categorizer`, `ioc_extractor`, and `aiops_engine`. This compatibility layout is intentional. `src.database` is a compatibility re-export of `src.core.db` and `src.models.schema`; it is not a second database implementation.

## Domain module map

| Module | Responsibility | Detailed reference |
|---|---|---|
| `src/services.py` | Central data-access, scoring orchestration, account/recovery, site-scope, regional analytics, reporting, and compatibility operations | [`reference/services/services.md`](reference/services/services.md) |
| `src/services/logic.py` | Keyword-plus-ML article score and lazy scorer reload | [`reference/services/logic.md`](reference/services/logic.md) |
| `src/services/categorizer.py` | Regex categorization of article title/summary/full text | [`reference/services/categorizer.md`](reference/services/categorizer.md) |
| `src/services/ioc_extractor.py` | Defanged indicator normalization, extraction, public-IP/domain filters, and context | [`reference/services/ioc_extractor.md`](reference/services/ioc_extractor.md) |
| `src/services/aiops_engine.py` | SolarWinds alert clustering, canonical infrastructure domains, patient-zero ranking, fleet detection, root cause, and 60-day insights | [`reference/services/aiops_engine.md`](reference/services/aiops_engine.md) |
| `src/utils/llm.py` | OpenAI-compatible chat completion, context lookup, map/reduce reports, and progress state | [`reference/utils/llm.md`](reference/utils/llm.md) |
| `src/utils/mailer.py` | SMTP message formatting, attachments, STARTTLS, and delivery result | [`reference/utils/mailer.md`](reference/utils/mailer.md) |
| `src/utils/risk_alert.py` | Risk-tier increase detection, a shared four-hour send cooldown, and earthquake email formatting | [`reference/utils/risk_alert.md`](reference/utils/risk_alert.md) |
| `src/train_model.py` | Feedback-labeled TF-IDF/logistic-regression model and atomic artifact replacement | [`reference/train_model.md`](reference/train_model.md) |
| `src/workers/*.py` | CISA KEV, regional hazards, cloud status, telemetry, crime, Elastic cache, and Daily Fusion inputs | [`reference/README.md`](reference/README.md) |
| `src/scheduler.py` | Registered job execution, schedule reload, retention, escalation, and periodic model/brief jobs | [`SCHEDULER.md`](SCHEDULER.md), [`reference/scheduler.md`](reference/scheduler.md) |

## Scoring and article enrichment

### Article capture

`src/scheduler.py:fetch_feeds()` loads active feeds, builds a seven-day link set, downloads up to five feeds concurrently per chunk (15-second request timeout), then processes feed entries sequentially. Scoring and categorization use title plus summary. Article persistence uses one nested transaction per article so a duplicate does not discard unrelated rows. Full-content extraction is a separate job: it selects score-40-or-higher articles with fewer than three attempts, uses two fetch threads, and stores at most 200,000 characters.

### Hybrid scoring

`HybridScorer.score()` adds each matched keyword's configured weight. If a model exists, it predicts the probability for the `keep` class:

- `keep_prob >= 0.75` and keyword score below 50 sets the score to at least 65.
- `keep_prob <= 0.25` and keyword score at least 50 applies a 60% reduction.
- `keep_prob > 0.50` with a positive score adds `keep_prob * 10` points.
- The final score is capped at 100. Missing model files leave keyword-only scoring active.

The persisted feedback mapping is `0=neutral`, `1=dismiss/noise`, `2=keep/important`. The first transition from neutral to a label adjusts each matched keyword by one point (floor 1 for a dismissal); later feedback updates do not repeat that adjustment. Manual keyword changes require weights 1–100 and reload the in-process scorer.

### Current category and IOC contracts

The categorizer emits exactly these nine labels: `Cyber: Exploits & Vulns`, `Cyber: Malware & Threats`, `ICS/OT & SCADA`, `Cloud & IT Infrastructure`, `Physical Security & Crime`, `Severe Weather & Natural Hazards`, `Geopolitics & Policy`, `AI & Emerging Tech`, and `Data Breach & Privacy`; unmatched text returns `General`.

The extractor compiles 21 types in five categories: Network (IPv4, IPv6, URL, Domain, Email, ASN), Host Artifacts (SHA256, SHA1, MD5, Registry Key, Windows Path, Linux Path), Actor Infrastructure (BTC Wallet, XMR Wallet, Discord C2, Telegram C2), Cloud & DevOps (AWS API Key, AWS S3 Bucket, Azure Blob), and Taxonomy (CVE, MITRE ATT&CK). IOC results use `Category`, `Type`, `Indicator`, and `Context`; each side of the match can include a 45-character context window. Public/private/loopback/multicast/link-local/reserved IPs and the configured exact benign-domain list are excluded.

**Observed compatibility mismatch:** the current categorizer labels differ from some exact labels still used in `get_executive_grid_intel()` and `ThreatTelemetryPage.tsx`. The matching consequences are recorded in [`DOCUMENTATION_AUDIT.md`](DOCUMENTATION_AUDIT.md); this documentation does not imply those source comparisons have been changed.

## Composite Intelligence Score

`get_executive_grid_intel(active_warn_count, recent_crimes)` evaluates the preceding 24 hours of articles and CISA KEVs, classifies local crime reports into FBI UCR-style persons/property/society groups, and produces cyber, physical, and unified risk fields. A 14-day score history supplies average baselines; non-zero `baseline_override_cyber`/`baseline_override_phys` values override those displayed baselines.

The algorithm derives cyber criticality/lethality and physical criticality/lethality from the activity counts, then computes `(C + L) - (S + N)`, clamped to −8..+8. The exact thresholds and evidence strings are in `get_executive_grid_intel()` and `docs/DATA_FLOWS.md`. `auto` uses computed values; `manual` uses the C/L overrides; `hybrid` uses computed values and adds the bounded global offset. The same global offset is applied to both cyber and physical totals in hybrid mode. Tier ranges are GREEN below −4, BLUE −4..−2, YELLOW −1..+2, ORANGE +3..+5, and RED +6..+8. The unified tier is the higher of cyber and physical. Daily score rows retain the highest point value observed for that UTC date.

`calculate_internal_cis_score()` deduplicates hardware by IP and software by normalized name, examines up to 500 articles from the last 30 days with score at least 40 and up to 300 latest KEV records, gates article text on strong/weak cyber keywords, then uses token-indexed asset matching with exact/version/proximity rules. Each distinct matching intel title contributes 25 points to that asset's OSINT risk, capped at 100. It derives internal C/L values from critical/global matches and percentage of assets at risk, subtracts system/network countermeasures, applies the internal offset only in hybrid mode, clamps to −8..+8, and maps to the same risk tiers. Snapshots persist sorted hardware/software match data as JSON.

## AIOps correlation and operational state

`EnterpriseAIOpsEngine` canonical domains are `INTERNET`, `COMMS_EQUIPMENT`, `POWER_SUPPLIES`, `RTU`, `SCADA`, `COMPUTE`, `FACILITIES`, plus `UNKNOWN_DOMAIN`. `PRIMARY_INTERNET` is normalized to `INTERNET` for compatibility. Patient zero is ranked using domain tier, status/packet-loss severity, and a capped time penalty. Fleet events group affected sites by primary communications provider and require at least five sites by default.

Root-cause results combine domain spread, fleet provider matches, cloud-provider names, BGP ASN/provider matches, alert level, and weather records. Current persisted `RegionalHazard` rows have no geometry columns, so the normal weather correlation path matches the site's district/name against the hazard's location text. Chronic insights query 60 days of alert records and return Python lists plus recommendation text; they are not an ML forecast.

Site health and workflow are separate:

- Acknowledging marks alerts correlated and records the actor/time; it does not resolve them. The site remains operationally down until unresolved alert records are resolved.
- `Needs Dispatch` is a separately persisted alert workflow flag.
- Mark Site Up resolves every unresolved alert for the site, clears Needs Dispatch and investigating state, records the action, and leaves maintenance fields separate.
- Maintenance is an annotation with ETR and reason. Its expiry job clears it after the end of the ETR date in America/Chicago; maintenance itself is not an escalation suppression rule.

## Regional data, reporting, and operations

- `src/workers/infra_worker.py` concurrently fetches SPC outlooks, Arkansas/nearby NWS alerts, and USGS GeoJSON, then performs earthquake/wildfire proximity notification work. The regional route precomputes Shapely intersections and returns `[processed_geo, {}, diagnostics, toggled_affected_sites, master_affected_sites, analytics]`.
- `get_active_wildfires()` uses WFCA WFS incident/perimeter data and recent FIRMS satellite footprints. Footprints are explicitly estimates and remain separate from official perimeters.
- `src/workers/telemetry_worker.py` runs ORNL ODIN, RIPE routing visibility, and IODA ISP outage work concurrently. Elastic ingestion is a separate `elastic_sync` registry job.
- `src/workers/crime_worker.py` consumes Little Rock CAD data, geocodes addresses, measures distance from the Little Rock headquarters point, and stores deduplicated rows. Perimeter notification thresholds are also headquarters-relative.
- `src/utils/llm.py` stores report progress in process memory keyed by generation ID; API routes expose it while that process remains alive. LLM output is not a durable transaction with database writes.
- Full backup/restore is implemented under `src/core/backup_manager.py`, `restore_control.py`, and `ui_restore.py`, not as an ORM export. See [`MAINTENANCE.md`](MAINTENANCE.md).

## Caching and transaction boundaries

`TTLCache` is an in-process dictionary cache with timestamp-based eviction; it is not a distributed cache and is not protected by a lock. Route/worker mutations explicitly clear caches where required. Most service functions own and close their own `SessionLocal()` session; selected functions accept a caller-owned SQLAlchemy session (for example `calculate_internal_cis_score(db_session)`). Follow each function's actual ownership contract when reusing it.

The service module reference contains detailed signatures, parameters, returns, side effects, and data dependencies. Keep it aligned with source changes rather than copying old function descriptions forward.
