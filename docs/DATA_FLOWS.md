# NOC Intelligence Fusion Center — Data Flow Reference

> Enterprise-grade documentation of all internal data pipelines, scheduling cadences,
> scoring algorithms, and inter-service data contracts.

---

## Table of Contents

1. [RSS Feed Ingestion Pipeline](#1-rss-feed-ingestion-pipeline)
2. [CIS Scoring Pipeline (Executive Grid Intel)](#2-cis-scoring-pipeline-executive-grid-intel)
3. [Internal Risk Assessment Pipeline](#3-internal-risk-assessment-pipeline)
4. [Unified Brief Generation Pipeline](#4-unified-brief-generation-pipeline)
5. [SolarWinds Alert Ingestion Pipeline](#5-solarwinds-alert-ingestion-pipeline)
6. [AIOps Correlation Pipeline](#6-aiops-correlation-pipeline)
7. [Risk Alert Pipeline](#7-risk-alert-pipeline)
8. [Weather/Telemetry Ingestion Pipeline](#8-weathertelemetry-ingestion-pipeline)
9. [Supporting Sub-Pipelines](#9-supporting-sub-pipelines)

---

## 1. RSS Feed Ingestion Pipeline

**Trigger:** Scheduler, every 15 minutes
**Source files:** `src/scheduler.py:56-216`, `src/services/logic.py`, `src/services/categorizer.py`, `src/services/ioc_extractor.py`

### Overview

The RSS pipeline is the primary OSINT ingestion mechanism. It pulls intelligence feeds from
configurable sources, scores each article via a hybrid ML + keyword engine, categorizes
content, extracts IOCs from high-value cyber articles, persists everything to the database,
and deduplicates stale entries.

### ASCII Flow Diagram

```
                         ┌──────────────────────────────────────┐
                         │   SCHEDULER (every 15 minutes)       │
                         └──────────────┬───────────────────────┘
                                        │
                                        ▼
                         ┌──────────────────────────────────────┐
                         │  fetch_feeds(source="Scheduled")     │
                         │  src/scheduler.py:176                │
                         └──────────────┬───────────────────────┘
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
            ▼                           ▼                           ▼
   ┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
   │  Query FeedSource│        │  Load 7-day     │        │  Pre-load       │
   │  (active feeds) │        │  known_links    │        │  HybridScorer   │
   │  DB: feed_sources│        │  (dedup gate)   │        │  in memory      │
   └────────┬────────┘        └────────┬────────┘        └────────┬────────┘
            │                           │                           │
            └───────────┬───────────────┘                           │
                        ▼                                           │
           ┌────────────────────────┐                               │
           │  Phase 1: Async Fetch  │                               │
           │  fetch_all_feeds_      │                               │
           │  chunked()             │                               │
           │  chunk_size=5          │                               │
           │  aiohttp.ClientSession │                               │
           │  0.1s inter-chunk delay│                               │
           └───────────┬────────────┘                               │
                       │                                            │
                       ▼                                            │
           ┌────────────────────────────────────────────┐           │
           │  Phase 2: Sequential Processing (per feed) │           │
           │                                            │           │
           │  ┌──────────────────────────────────────┐  │           │
           │  │  feedparser.parse(content)            │  │           │
           │  │  → iterate feed.entries               │  │           │
           │  └──────────────┬───────────────────────┘  │           │
           │                 │                          │           │
           │                 ▼                          │           │
           │  ┌──────────────────────────────────────┐  │           │
           │  │  Dedup gate: skip if link in          │  │           │
           │  │  known_links or seen_in_batch         │  │           │
           │  └──────────────┬───────────────────────┘  │           │
           │                 │                          │           │
           │                 ▼                          │           │
           │  ┌──────────────────────────────────────┐  │           │
           │  │  HybridScorer.score(text)             │◄─┘           │
           │  │  → keyword_score + ML boost/penalty   │              │
           │  │  → returns (score, reasons)           │              │
           │  └──────────────┬───────────────────────┘              │
           │                 │                                      │
           │                 ▼                                      │
           │  ┌──────────────────────────────────────┐              │
           │  │  categorize_text(full_text)            │              │
           │  │  → regex match against 8 categories   │              │
           │  │  → returns category string            │              │
           │  └──────────────┬───────────────────────┘              │
           │                 │                                      │
           │                 ▼                                      │
           │  ┌──────────────────────────────────────┐              │
           │  │  IOC Extraction Gate                  │              │
           │  │  IF score >= 50 AND category starts   │              │
           │  │  with "Cyber":                        │              │
           │  │    ioc_engine.extract(full_text)      │              │
           │  │  ELSE: extracted_iocs = []            │              │
           │  └──────────────┬───────────────────────┘              │
           │                 │                                      │
           │                 ▼                                      │
           │  ┌──────────────────────────────────────┐              │
           │  │  Mark is_bubbled = (score >= 45)      │              │
           │  └──────────────┬───────────────────────┘              │
           │                 │                                      │
           └─────────────────┼──────────────────────────────────────┘
                             │
                             ▼
           ┌─────────────────────────────────────────────┐
           │  bulk_save_to_db(db_session, arts_data)     │
           │  src/scheduler.py:121                       │
           │                                             │
           │  batch_size = 100                           │
           │  → db_session.add_all(batch)                │
           │  → db_session.flush()                       │
           │  → Persist ExtractedIOC records per article  │
           │  → db_session.commit()                      │
           │  → IntegrityError → rollback (dedup)        │
           └──────────────────┬──────────────────────────┘
                              │
                              ▼
           ┌─────────────────────────────────────────────┐
           │  deduplicate_articles(session)               │
           │  src/services/__init__.py                   │
           │                                             │
           │  → Exact link match within same source      │
           │  → Title similarity > 0.85 (same source)    │
           └─────────────────────────────────────────────┘
```

### Scoring Details

The `HybridScorer` (`src/services/logic.py:9-62`) combines two signal sources:

| Signal | Weight | Description |
|--------|--------|-------------|
| Keyword match | Accumulative | Each matched keyword adds its DB-stored weight to the score |
| ML model boost | +10 to +65 | If `keep_prob >= 0.75` and score < 50, AI boost to 65 |
| ML noise penalty | -60% | If `keep_prob <= 0.25` and score >= 50, penalty applied |
| ML synergy bonus | +0-10 | If `keep_prob > 0.50` and score > 0 |

**Thresholds:**

| Threshold | Value | Effect |
|-----------|-------|--------|
| Bubble alert | `score >= 45` | Article flagged for executive dashboard bubble |
| IOC extraction | `score >= 50` AND `category.startswith("Cyber")` | IOC patterns extracted |
| Article retention | `score > 0` | Score-0 articles deleted during maintenance |

### IOC Extraction Engine

The `EnterpriseIOCExtractor` (`src/services/ioc_extractor.py:9-150`) runs compiled regex
rule sets across 5 categories with a 45-character context window:

| Category | Indicator Types |
|----------|-----------------|
| Network | IPv4, IPv6, URL, Domain, Email, ASN |
| Host Artifacts | SHA256, SHA1, MD5, Registry Key, Windows Path, Linux Path |
| Actor Infrastructure | BTC Wallet, XMR Wallet, Discord C2, Telegram C2 |
| Cloud & DevOps | AWS API Key, AWS S3 Bucket, Azure Blob |
| Taxonomy | CVE, MITRE ATT&CK |

Whitelists exclude known-good domains (google.com, github.com, etc.) and IPs (8.8.8.8, etc.).

### Deduplication Rules

- **Exact link match:** Same URL within the 7-day window
- **Title similarity > 0.85:** Same source, near-identical titles (fuzzy match)
- **Batch-level dedup:** `seen_in_batch` set prevents duplicate entries within a single fetch cycle
- **Post-fetch cleanup:** `deduplicate_articles()` runs after every feed cycle

---

## 2. CIS Scoring Pipeline (Executive Grid Intel)

**Trigger:** Called by `job_unified_brief()` every 30 minutes and on-demand via API
**Source files:** `src/services.py:613-884`, `src/scheduler.py:218-248`

### Overview

The CIS (Cybersecurity & Infrastructure Security) Scoring Pipeline computes a unified
threat posture for the executive grid. It ingests 24-hour telemetry across cyber articles,
CVEs, ICS advisories, physical crime data, and weather hazards, then applies the CIS
Alert Level Framework (Green → Red) with auto/manual/hybrid scoring modes.

### ASCII Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CIS SCORING PIPELINE                              │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Step 1: Configuration                                        │ │
│  │  get_cached_config() → TTLCache(300s)                         │ │
│  │  → scoring_mode: auto | manual | hybrid                       │ │
│  │  → sys_countermeasures (default 3, range 1-5)                 │ │
│  │  → net_countermeasures (default 3, range 1-5)                 │ │
│  │  → override columns: cyber_criticality_override, etc.         │ │
│  └──────────────────────────┬─────────────────────────────────────┘ │
│                             │                                       │
│  ┌──────────────────────────┴─────────────────────────────────────┐ │
│  │  Step 2: Query 24h Telemetry                                  │ │
│  │                                                                │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐ │ │
│  │  │ Cyber Articles   │  │ CVEs (CISA KEV) │  │ ICS Advisories │ │ │
│  │  │ score >= 50      │  │ last 24h        │  │ ICS/CISA src   │ │ │
│  │  │ cyber categories │  │                 │  │ critical vendor│ │ │
│  │  └─────────────────┘  └─────────────────┘  └────────────────┘ │ │
│  │                                                                │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐ │ │
│  │  │ Physical Arts    │  │ Crime Incidents  │  │ Weather Alerts │ │ │
│  │  │ score >= 50      │  │ last 24h        │  │ RegionalHazard │ │ │
│  │  │ phys categories  │  │ grid_only=True  │  │ count          │ │ │
│  │  └─────────────────┘  └─────────────────┘  └────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                             │                                       │
│                             ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Step 3: FBI UCR Crime Classification                         │ │
│  │                                                                │ │
│  │  Violence keywords → "Crimes Against Persons"                 │ │
│  │  Trespass/narcotics → "Crimes Against Society"                │ │
│  │  Vandalism/theft    → "Crimes Against Property"               │ │
│  └──────────────────────────┬─────────────────────────────────────┘ │
│                             │                                       │
│                             ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Step 4: Auto-Compute Cyber C + L                             │ │
│  │                                                                │ │
│  │  LETHALITY (auto_l):                                          │ │
│  │    KEV active        → 5                                      │ │
│  │    CVE count > 10    → 4                                      │ │
│  │    CVE count > 5     → 3                                      │ │
│  │    CVE count > 0     → 3                                      │ │
│  │    Cyber arts > 5    → 2                                      │ │
│  │    Otherwise         → 1                                      │ │
│  │                                                                │ │
│  │  CRITICALITY (auto_c):                                        │ │
│  │    Critical ICS/Util → 5                                      │ │
│  │    Any ICS advisory  → 4                                      │ │
│  │    APT/Ransomware    → 4                                      │ │
│  │    Cyber arts > 3    → 3                                      │ │
│  │    Otherwise         → 2                                      │ │
│  └──────────────────────────┬─────────────────────────────────────┘ │
│                             │                                       │
│                             ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Step 5: Auto-Compute Physical P_C + P_L                      │ │
│  │                                                                │ │
│  │  P_L (physical lethality):                                    │ │
│  │    Persons >= 5 or Property >= 10 → 5                         │ │
│  │    Persons >= 3 or Property >= 6  → 4                         │ │
│  │    Persons >= 1 or Property >= 3  → 3                         │ │
│  │    Total crimes >= 5              → 2                         │ │
│  │    Otherwise                      → 1                         │ │
│  │                                                                │ │
│  │  P_C (physical criticality):                                  │ │
│  │    Phys arts >= 3 or weather >= 80% → 5                       │ │
│  │    Phys arts >= 1 or weather >= 40% → 4                       │ │
│  │    OSINT phys score > 0             → 3                       │ │
│  │    Otherwise                        → 2                       │ │
│  └──────────────────────────┬─────────────────────────────────────┘ │
│                             │                                       │
│                             ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Step 6: Scoring Mode Dispatch                                │ │
│  │                                                                │ │
│  │  AUTO:     Use all auto-computed values                       │ │
│  │  MANUAL:   Read override columns from SystemConfig            │ │
│  │  HYBRID:   Auto-computed + global_risk_offset adjustment      │ │
│  │                                                                │ │
│  │  CIS_Cyber = (C + L) - (S + N)                               │ │
│  │  CIS_Phys  = (P_C + P_L) - (S + N)                           │ │
│  │                                                                │ │
│  │  S = sys_countermeasures (clamped 1-5)                        │ │
│  │  N = net_countermeasures (clamped 1-5)                        │ │
│  │                                                                │ │
│  │  Score clamped to [-8, +8]                                    │ │
│  └──────────────────────────┬─────────────────────────────────────┘ │
│                             │                                       │
│                             ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Step 7: Map to CIS Alert Level                               │ │
│  │                                                                │ │
│  │   Score >= +6  ──►  RED    (Severe)                           │ │
│  │   Score >= +3  ──►  ORANGE (High)                             │ │
│  │   Score >= -1  ──►  YELLOW (Elevated)                         │ │
│  │   Score >= -4  ──►  BLUE   (Guarded)                          │ │
│  │   Score <  -4  ──►  GREEN  (Low)                              │ │
│  │                                                                │ │
│  │  Unified Risk = MAX(cyber_tier, physical_tier)                │ │
│  │                                                                │ │
│  │  → save_threat_score() → DailyThreatScore table               │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Output: {                                                          │
│    "unified_risk": "RED"|"ORANGE"|"YELLOW"|"BLUE"|"GREEN",         │
│    "cyber_score": ..., "physical_score": ...,                      │
│    "cis_cyber_score": int, "cis_phys_score": int,                  │
│    "evidence_log": [...],                                          │
│    "scoring_mode": "auto"|"manual"|"hybrid",                       │
│    "applied_overrides": { "cyber_criticality": {auto, used}, ... } │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Scoring Mode Comparison

| Mode | C / L / P_C / P_L Source | Offset Applied | Override Columns Used |
|------|--------------------------|----------------|----------------------|
| `auto` | Fully algorithmic | No | No |
| `manual` | Operator-entered values | No | `cyber_criticality_override`, `cyber_lethality_override`, `physical_criticality_override`, `physical_lethality_override` |
| `hybrid` | Auto-computed + `global_risk_offset` | Yes (+/- N) | No |

### Evidence Log

Every scoring run produces an `evidence_log` array containing human-readable justifications
for each scoring decision. This is rendered in the frontend Global Risk dashboard and
appended to the Unified Brief.

---

## 3. Internal Risk Assessment Pipeline

**Trigger:** Scheduler, every 60 minutes
**Source files:** `src/services.py:886-1243`

### Overview

The Internal Risk Assessment correlates the organization's hardware and software asset
inventory against live OSINT threat intelligence and the CISA KEV catalog. It uses a
5-phase pipeline with an inverted index for O(C × avg_triggers) correlation performance
and a double-gatekeeper keyword security filter to eliminate noise.

### ASCII Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│               INTERNAL RISK ASSESSMENT PIPELINE                      │
│               Trigger: Every 60 minutes                              │
│                                                                      │
│  ════════════════════════════════════════════════════════════════════ │
│  PHASE 1: Engine Rules & Signature Compilation                      │
│  ════════════════════════════════════════════════════════════════════ │
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌────────────────────┐   │
│  │ HW Assets    │     │ SW Assets    │     │ Stop-word Filter   │   │
│  │ from DB      │     │ from DB      │     │ (12 words: "and",  │   │
│  │              │     │              │     │  "the", "for", ...)│   │
│  └──────┬───────┘     └──────┬───────┘     └────────────────────┘   │
│         │                     │                                      │
│         ▼                     ▼                                      │
│  ┌──────────────────────────────────────────┐                       │
│  │  Per asset:                              │                       │
│  │  1. Deduplicate (IP for HW, name for SW)│                       │
│  │  2. Extract trigger_token (longest word  │                       │
│  │     not in STOP_WORDS or IGNORE_LIST)    │                       │
│  │  3. Build compiled regex signatures      │                       │
│  │     - Common nouns: proximity check      │                       │
│  │       (100-char window to security kw)   │                       │
│  │     - Named products: exact match        │                       │
│  │     - With version: versioned match      │                       │
│  │  4. Handle acronym collisions (apt, mac, │                       │
│  │     surface, office) via context regex   │                       │
│  └──────────────────────────────────────────┘                       │
│                                                                      │
│  ════════════════════════════════════════════════════════════════════ │
│  PHASE 2: Inverted Indexing (Double-Gatekeeper)                     │
│  ════════════════════════════════════════════════════════════════════ │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  For each article (score >= 40):                             │    │
│  │    text_blob = title + summary                               │    │
│  │    word_set  = tokenized (2+ chars, lowercase)               │    │
│  │                                                              │    │
│  │    ┌─────────────────────────────────────────────────────┐   │    │
│  │    │  DOUBLE-GATEKEEPER SECURITY FILTER                  │   │    │
│  │    │                                                     │   │    │
│  │    │  STRONG keywords (13): vulnerability, cve, malware, │   │    │
│  │    │    ransomware, phishing, zero-day, exploit, rce,    │   │    │
│  │    │    ddos, cyber, hacked, botnet                       │   │    │
│  │    │                                                     │   │    │
│  │    │  WEAK keywords (7): breach, patch, flaw, leak, bug, │   │    │
│  │    │    actor, bypass                                     │   │    │
│  │    │                                                     │   │    │
│  │    │  GATE: strong_hits > 0  OR  weak_hits >= 2          │   │    │
│  │    │  → PASS: article enters correlation engine           │   │    │
│  │    │  → FAIL: article discarded (noise)                   │   │    │
│  │    └─────────────────────────────────────────────────────┘   │    │
│  │                                                              │    │
│  │  Similarly for CVE index (CISA KEV entries, last 300)       │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ════════════════════════════════════════════════════════════════════ │
│  PHASE 3: Reverse-Indexed Batch Correlation Scan                    │
│  ════════════════════════════════════════════════════════════════════ │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  Build reverse index: trigger_token → [asset_map, ...]      │    │
│  │                                                              │    │
│  │  1. ARTICLE SCAN: O(C × avg_triggers)                       │    │
│  │     For each article's word_set ∩ trigger_to_assets keys:   │    │
│  │       For each candidate asset:                              │    │
│  │         Check acronym collision regex                        │    │
│  │         Execute compiled exact/proximity regex               │    │
│  │         If match: append to asset.matches[] (cap 5/article) │    │
│  │                                                              │    │
│  │  2. CVE SCAN: O(CVEs × avg_triggers)                        │    │
│  │     For each CVE's word_set + vendor ∩ trigger keys:         │    │
│  │       HW assets: vendor+product cross-check                 │    │
│  │       SW assets: compiled regex match                        │    │
│  │       Cap 3 matches per CVE                                  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ════════════════════════════════════════════════════════════════════ │
│  PHASE 4: Posture Reconstruction                                    │
│  ════════════════════════════════════════════════════════════════════ │
│                                                                      │
│  For each asset with matches:                                        │
│    → Deduplicate intel titles                                        │
│    → Compute OSINT Risk Score = min(match_count × 25, 100)          │
│    → Annotate HW: identifier, IP, OS, risk score                    │
│    → Annotate SW: name, risk score, risk_level (HIGH/MEDIUM/LOW)    │
│    → Track global_osint_titles, global_critical_titles               │
│                                                                      │
│  ════════════════════════════════════════════════════════════════════ │
│  PHASE 5: CIS Risk Calculation                                      │
│  ════════════════════════════════════════════════════════════════════ │
│                                                                      │
│  auto_lethality:                                                     │
│    critical_osint > 10 → 5 │ critical_osint > 5 → 4                │
│    critical_osint > 2  → 3 │ critical_osint > 0 → 3                │
│    total_osint > 10    → 2 │ otherwise          → 1                │
│                                                                      │
│  auto_criticality:                                                   │
│    percent_at_risk > 30% → 5 │ percent_at_risk > 20% → 4           │
│    percent_at_risk > 10% → 3 │ percent_at_risk > 5%  → 2           │
│    otherwise              → 1                                       │
│                                                                      │
│  Internal CIS Score = (C + L) - (S + N)                             │
│  Clamped to [-8, +8]                                                 │
│                                                                      │
│  → save InternalRiskSnapshot to DB                                   │
└──────────────────────────────────────────────────────────────────────┘
```

### Keyword Security Filter Detail

The double-gatekeeper mechanism prevents false positives from common English words:

```
  Article Text: "Whales are breaching in the Pacific Ocean"
    strong_hits: 0 (no "vulnerability", "cve", etc.)
    weak_hits:   1 ("breaching" ≠ "breach"; only "breach" matches)
    Result:      BLOCKED (need strong >= 1 OR weak >= 2)

  Article Text: "Critical flaw in Fortinet firmware allows breach"
    strong_hits: 0
    weak_hits:   2 ("flaw" + "breach")
    Result:      PASSED
```

---

## 4. Unified Brief Generation Pipeline

**Trigger:** Scheduler, every 30 minutes; on-demand via API
**Source files:** `src/utils/llm.py:257-434`, `src/scheduler.py:218-248`

### Overview

The Unified Brief pipeline generates an executive-level OSINT risk digest by gathering
telemetry from all subsystems, running map-reduce summarization through an LLM, and
producing a structured Markdown report with mandatory OSINT correlation disclaimers.

### ASCII Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                 UNIFIED BRIEF GENERATION PIPELINE                        │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Stage 1: GATHERING (0%)                                         │  │
│  │                                                                    │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │  │
│  │  │ Internal      │  │ NWS Hazards  │  │ Crime Incidents        │  │  │
│  │  │ Risk Snapshot │  │ RegionalHaz. │  │ get_recent_crimes()    │  │  │
│  │  │ (latest)      │  │ (count)      │  │ (grid_only, 24h)       │  │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────┬─────────────┘  │  │
│  │         │                 │                      │                 │  │
│  │         ▼                 ▼                      ▼                 │  │
│  │  ┌──────────────────────────────────────────────────────────┐     │  │
│  │  │  get_executive_grid_intel(active_nws, crime_data)        │     │  │
│  │  │  → Returns: unified_risk, cyber/phys scores,             │     │  │
│  │  │    raw_cyber_articles[], raw_phys_articles[]              │     │  │
│  │  └──────────────────────────┬───────────────────────────────┘     │  │
│  │                             │                                     │  │
│  │  Additionally queried:                                             │  │
│  │  - CveItem (last 24h, limit 200)                                 │  │
│  │  - CloudOutage (last 24h, limit 20)                              │  │
│  │  - HW/SW assets (from InternalRiskSnapshot JSON)                 │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Stage 2: CYBER MAP-REDUCE (1-49%)                               │  │
│  │                                                                    │  │
│  │  Payload: cyber_arts (150) + CISA KEVs + cloud outages           │  │
│  │                                                                    │  │
│  │  ┌──────────────┐  chunk_size = 15 × context_scale              │  │
│  │  │ MAP: Per chunk│  → Extract factual data points                 │  │
│  │  │ LLM call     │  → Strict bullet points, no embellishment      │  │
│  │  └──────┬───────┘                                                │  │
│  │         │                                                         │  │
│  │         ▼                                                         │  │
│  │  ┌──────────────┐                                                 │  │
│  │  │ REDUCE:      │  → Compile exhaustive cyber digest              │  │
│  │  │ All summaries│  → Preserve CVE IDs, actor names, vendors      │  │
│  │  │ → 1 summary  │                                                 │  │
│  │  └──────────────┘                                                 │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Stage 3: PHYSICAL MAP-REDUCE (50-99%)                           │  │
│  │                                                                    │  │
│  │  Payload: phys_arts (100) + weather hazards + perimeter crimes    │  │
│  │                                                                    │  │
│  │  Same map-reduce pattern as cyber:                                │  │
│  │  chunk_size = 15 × context_scale                                  │  │
│  │  → Categorize: Weather/Geospatial Hazards + Local Perimeter       │  │
│  │  → Retain exact distances, locations, severity, FBI categories    │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Stage 4: SYNTHESIZING (99%)                                      │  │
│  │                                                                    │  │
│  │  Compiled intel block assembled:                                   │  │
│  │  ┌──────────────────────────────────────────────────────────┐     │  │
│  │  │  === MACRO THREAT POSTURE ===                            │     │  │
│  │  │  === DEEP CYBER OSINT DIGEST ===                         │     │  │
│  │  │  === DEEP PHYSICAL OSINT DIGEST ===                      │     │  │
│  │  │  === INTERNAL ASSET EXPOSURE ===                         │     │  │
│  │  │    --- HARDWARE --- / --- SOFTWARE ---                   │     │  │
│  │  │    --- DEDUPLICATED VULNERABILITY REFERENCES ---         │     │  │
│  │  └──────────────────────────────────────────────────────────┘     │  │
│  │                                                                    │  │
│  │  Master LLM call (temperature=0.5) with structured prompt:       │  │
│  │  → Executive OSINT Summary (BLUF)                                │  │
│  │  → Internal Asset Threat Correlations                            │  │
│  │  → Global Cyber & Cloud Threat Landscape                         │  │
│  │  → Physical, Weather & Perimeter Posture                         │  │
│  │  → Strategic Recommendations                                     │  │
│  │                                                                    │  │
│  │  + Mandatory disclaimers appended:                                │  │
│  │    - OSINT Correlation Disclaimer                                 │  │
│  │    - AI-Generated Content Disclaimer                              │  │
│  └─────────────────────────────┬─────────────────────────────────────┘  │
│                                │                                        │
│                                ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Stage 5: COMPLETE (100%)                                        │  │
│  │                                                                    │  │
│  │  → save_global_config({"unified_brief": markdown})               │  │
│  │  → SystemConfig.unified_brief column updated                     │  │
│  │  → Frontend polls /brief-generation-status every 2s              │  │
│  │  → sessionStorage persists generation_id across SPA navigation   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Progress Tracking

The pipeline exposes real-time progress to the frontend via an in-memory store:

```
BriefProgressStore (thread-safe dict):
  {
    "generation_id": {
      "stage":           "gathering"|"cyber_map"|"phys_map"|"synthesizing"|"complete",
      "message":         "Processing cyber intelligence (150 items)...",
      "total_items":     150,
      "processed_items": 45,
      "percent":         31,
      "error":           None
    }
  }
```

| Stage | Percent Range | Description |
|-------|---------------|-------------|
| `gathering` | 0% | Querying DB for telemetry |
| `cyber_map` | 1-49% | Map-reduce per chunk on cyber payload |
| `phys_map` | 50-99% | Map-reduce per chunk on physical payload |
| `synthesizing` | 99% | Final LLM synthesis call |
| `complete` | 100% | Brief saved, ready for retrieval |

### Map-Reduce Details

| Parameter | Value | Notes |
|-----------|-------|-------|
| `chunk_size` | 15 | Base; scaled by `ctx / 128000` for model context window |
| Map temperature | 0.1 | Factual extraction, minimal creativity |
| Reduce temperature | 0.2 | Compiling summaries, low creativity |
| Synthesis temperature | 0.5 | Executive narrative, moderate creativity |
| Max tokens | `min(ctx // 2, 8192)` | Auto-calculated from context window |

---

## 5. SolarWinds Alert Ingestion Pipeline

**Trigger:** HTTP POST webhook (event-driven)
**Source files:** `src/webhook_listener.py:1-135`, `src/services/aiops_engine.py:13-66`

### Overview

The webhook listener receives SolarWinds alert payloads on port 8100, normalizes the
data via `smart_extract()`, classifies devices into the 7-domain ontology, handles
alert resolution (auto-resolving active alerts), creates database records, and hands
off to the scheduler's tiered escalation engine.

### ASCII Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│              SOLARWINDS WEBHOOK INGESTION PIPELINE                     │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  POST /webhook/solarwinds (port 8100)                           │  │
│  │  FastAPI + BackgroundTasks                                       │  │
│  │  → Returns {"status": "accepted"} immediately                   │  │
│  │  → Actual processing in background thread                       │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  smart_extract(payload)                                          │  │
│  │  src/webhook_listener.py:37                                      │  │
│  │                                                                  │  │
│  │  Normalize from 3 payload sections:                              │  │
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ │  │
│  │  │ Node_Details (ND)│ │Performance_Metrics│ │Custom_Properties │ │  │
│  │  │  - NodeName      │ │  - PercentLoss   │ │  - Site          │ │  │
│  │  │  - IP_Address    │ │  - CPULoad       │ │  - District      │ │  │
│  │  │  - StatusDesc    │ │                  │ │  - Primary_Comms │ │  │
│  │  │  - MachineType   │ │                  │ │  - Alert_Level   │ │  │
│  │  └──────────────────┘ └──────────────────┘ └──────────────────┘ │  │
│  │                                                                  │  │
│  │  Output: {                                                       │  │
│  │    node_name, ip_address, severity, alert_level,                │  │
│  │    event_type, status, is_resolution, device_type,              │  │
│  │    event_category, site_group, primary_comms, secondary_comms   │  │
│  │  }                                                               │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│              ┌──────────────┴──────────────┐                           │
│              │                             │                           │
│              ▼                             ▼                           │
│  ┌───────────────────────┐     ┌───────────────────────┐              │
│  │  Resolution Detection │     │  New Alert Processing  │              │
│  │  Keywords: resolved,  │     │                        │              │
│  │  up, ok, clear,       │     │  classify_device()     │              │
│  │  operational,         │     │  → 7-domain ontology   │              │
│  │  recovered            │     │  → text fingerprinting │              │
│  └──────────┬────────────┘     └──────────┬────────────┘              │
│             │                              │                           │
│             ▼                              ▼                           │
│  ┌───────────────────────┐     ┌───────────────────────┐              │
│  │  Find active alerts   │     │  Create               │              │
│  │  for node_name        │     │  SolarWindsAlert      │              │
│  │  → Set status=Resolved│     │  TimelineEvent        │              │
│  │  → Set resolved_at    │     │                       │              │
│  │  → TimelineEvent:     │     │  is_correlated=False  │              │
│  │    "Resolution"       │     │  (pending AIOps)      │              │
│  └───────────────────────┘     └──────────┬────────────┘              │
│                                            │                           │
│                                            ▼                           │
│                              ┌───────────────────────┐                 │
│                              │  Scheduler handoff    │                 │
│                              │  job_tiered_alert_    │                 │
│                              │  escalation (1 min)   │                 │
│                              └───────────────────────┘                 │
└────────────────────────────────────────────────────────────────────────┘
```

### 7-Domain Device Ontology

The `classify_device()` function maps incoming device types to one of 7 operational
domains via text fingerprinting:

| Domain | Device Types / Fingerprints |
|--------|---------------------------|
| `PRIMARY_INTERNET` | VSAT, Cellular, SD-WAN, Modem, Radio, ISP, Internet |
| `COMMS_EQUIPMENT` | Router, Switch, Firewall, ASA, Palo, Fortigate, Meraki, Nexus, Catalyst, WLC |
| `POWER_SUPPLIES` | UPS, PDU, ATS, Battery, Generator, HVAC, DC Power Supply, DC Controller |
| `RTU` | RTU, NTEST RTU |
| `SCADA` | Sub Equipment, Plant Equipment, Meter Point, I/O, Member Equipment, SCADA, PLC, Relay, SEL- |
| `COMPUTE` | VM Host, VM Server, Physical Machine, Storage, ESXi, SAN, NAS |
| `FACILITIES` | Access Control Panel, Door Controller, IP Camera, HVAC |

### Resolution Detection

```python
res_indicators = ['resolved', 'up', 'ok', 'clear', 'operational', 'recovered']
# Matched via word-boundary regex against status + description
```

When a resolution is detected, all active (non-Resolved) alerts for the same `node_name`
are auto-closed with `resolved_at = datetime.utcnow()`.

---

## 6. AIOps Correlation Pipeline

**Trigger:** Scheduler, every 1 minute (`job_tiered_alert_escalation`)
**Source files:** `src/services/aiops_engine.py:1-402`, `src/scheduler.py:382-647`

### Overview

The AIOps correlation engine is the system's primary RCA (Root Cause Analysis) mechanism.
It clusters active SolarWinds alerts by mapped location, determines the "patient zero"
for each incident cluster via topology-severity-time scoring, identifies fleet-wide
outages, generates chronic instability insights, calculates root cause through a 7-stage
correlation chain, and dispatches RCA tickets with dual-SLA escalation logic.

### ASCII Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    AIOPS CORRELATION PIPELINE                            │
│                    Trigger: Every 1 minute                               │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 1: Data Acquisition                                       │  │
│  │                                                                    │  │
│  │  Query: SolarWindsAlert WHERE status != 'Resolved'                │  │
│  │         AND received_at >= (now - 12 hours)                       │  │
│  │  Query: RegionalHazard (all active)                               │  │
│  │  Query: CloudOutage (is_resolved = False)                         │  │
│  │  Query: BgpAnomaly (is_resolved = False)                          │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 2: Clustering (analyze_and_cluster)                        │  │
│  │  src/services/aiops_engine.py:346                                 │  │
│  │                                                                    │  │
│  │  For each alert:                                                  │  │
│  │    site = Custom_Properties.Site OR mapped_location OR "Unknown"  │  │
│  │    → Group into incidents[site] = {                                │  │
│  │        alerts[], site_metadata, domains_affected,                 │  │
│  │        dependency_chain[], avg_loss[], avg_cpu[], ips[],          │  │
│  │        max_alert_level, latest_alert                              │  │
│  │      }                                                            │  │
│  │                                                                    │  │
│  │  For each site cluster:                                           │  │
│  │    → _determine_patient_zero(alerts)                              │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 3: Patient Zero Determination                              │  │
│  │  src/services/aiops_engine.py:68                                  │  │
│  │                                                                    │  │
│  │  For each alert in cluster:                                       │  │
│  │    domain = _get_domain(node_type, node_name, primary_comms)     │  │
│  │    tier = TIER_RANKING[domain]  (1=highest priority)             │  │
│  │                                                                    │  │
│  │    ┌─────────────────────────────────────────────────────────┐    │  │
│  │    │  topo_score  = (9 - tier) × 2000                       │    │  │
│  │    │  sev_score   = DOWN/100%=1000 | CRITICAL/>50%=500     │    │  │
│  │    │                WARNING=100    | else=0                  │    │  │
│  │    │  time_penalty = min(time_offset_seconds, 200)          │    │  │
│  │    │                                                         │    │  │
│  │    │  final_score = topo_score + sev_score - time_penalty    │    │  │
│  │    └─────────────────────────────────────────────────────────┘    │  │
│  │                                                                    │  │
│  │  Winner (highest score) = patient_zero alert                      │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 4: Fleet Outage Detection                                 │  │
│  │  src/services/aiops_engine.py:119                                │  │
│  │                                                                    │  │
│  │  Group sites by primary_coms provider                             │  │
│  │  IF provider has >= 5 affected sites AND provider != "Unknown":  │  │
│  │    → Flag as "Regional Provider Outage" (CRITICAL)               │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 5: Chronic Insights (60-day history)                       │  │
│  │  src/services/aiops_engine.py:139                                │  │
│  │                                                                    │  │
│  │  Query: SolarWindsAlert last 60 days                              │  │
│  │  → DataFrame: node_name, device_type, site                       │  │
│  │  → Top 15 flapping nodes by incident count                       │  │
│  │  → Top 10 sites by incident count                                │  │
│  │  → CRITICAL FLAP if top node > 5 incidents                       │  │
│  │  → REGIONAL DEGRADATION if top site > 15 incidents               │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 6: 7-Stage RCA Correlation Chain                          │  │
│  │  src/services/aiops_engine.py:204                                │  │
│  │                                                                    │  │
│  │  ┌──────┬────────────────────────────────────┬──────────────────┐ │  │
│  │  │ Rank │ Correlation Source                  │ Score Bonus      │ │  │
│  │  ├──────┼────────────────────────────────────┼──────────────────┤ │  │
│  │  │  1   │ Fleet/Regional Provider Outage     │ +100             │ │  │
│  │  │  2   │ Cloud Provider Dependency Failure  │ +85              │ │  │
│  │  │  3   │ BGP Routing Anomaly                │ +75              │ │  │
│  │  │  4   │ Power/Environmental Failure        │ +60              │ │  │
│  │  │  5   │ Transport/Comms Severed            │ +50              │ │  │
│  │  │  6   │ Weather Geospatial Intersection    │ +40 to +55       │ │  │
│  │  │  7   │ SCADA/OT Isolated Failure          │ +30              │ │  │
│  │  └──────┴────────────────────────────────────┴──────────────────┘ │  │
│  │                                                                    │  │
│  │  Weather geospatial scoring:                                      │  │
│  │    District name match           → +40                            │  │
│  │    Haversine distance ≤ radius   → +55                            │  │
│  │                                                                    │  │
│  │  Additional:                                                      │  │
│  │    Multi-domain cascade         → +20                             │  │
│  │    Native alert level 1         → +50                             │  │
│  │                                                                    │  │
│  │  Total score capped at 100                                        │  │
│  └──────────────────────────┬───────────────────────────────────────┘  │
│                             │                                          │
│                             ▼                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Phase 7: Tiered Escalation & Dispatch                           │  │
│  │  src/scheduler.py:382-647                                        │  │
│  │                                                                    │  │
│  │  ┌──────────────────────────────────────────────────────────────┐ │  │
│  │  │  DUAL SLA DICTIONARIES                                       │ │  │
│  │  │                                                              │ │  │
│  │  │  DAY SHIFT (M-F 0600-2000 Central)                          │ │  │
│  │  │  ┌───────┬──────┬──────────┬────────┬──────────────────┐   │ │  │
│  │  │  │ Tier  │ Wait │ SLA      │ Weight │ On-Page           │   │ │  │
│  │  │  ├───────┼──────┼──────────┼────────┼──────────────────┤   │ │  │
│  │  │  │ P1-Hi │ 0min │ 1 Hour   │ 70     │ No                │   │ │  │
│  │  │  │ P1-Lo │ 0min │ 4 Hours  │ 60     │ No                │   │ │  │
│  │  │  │ P2-Hi │ 10mn │ 2.5 Hrs  │ 50     │ No                │   │ │  │
│  │  │  │ P2-Lo │ 10mn │ 4 Hours  │ 40     │ No                │   │ │  │
│  │  │  │ P3    │ 10mn │ 8 Hours  │ 30     │ No                │   │ │  │
│  │  │  │ P4    │ 10mn │ 24 Hours │ 20     │ No                │   │ │  │
│  │  │  │ P5    │ 10mn │ 72 Hours │ 10     │ No                │   │ │  │
│  │  │  └───────┴──────┴──────────┴────────┴──────────────────┘   │ │  │
│  │  │                                                              │ │  │
│  │  │  AFTER HOURS (Nights/Weekends)                               │ │  │
│  │  │  ┌───────┬──────┬──────────┬────────┬──────────────────┐   │ │  │
│  │  │  │ Tier  │ Wait │ SLA      │ Weight │ On-Page           │   │ │  │
│  │  │  ├───────┼──────┼──────────┼────────┼──────────────────┤   │ │  │
│  │  │  │ P1-Hi │ 0min │ 1 Hour   │ 70     │ YES (IT Network)  │   │ │  │
│  │  │  │ P1-Lo │ 45mn │ 4 Hours  │ 60     │ YES (IT Network)  │   │ │  │
│  │  │  │ P2-Hi │ 30mn │ 2.5 Hrs  │ 50     │ No                │   │ │  │
│  │  │  │ P2-Lo │ 45mn │ 4 Hours  │ 40     │ No                │   │ │  │
│  │  │  │ P3    │ 45mn │ 8 Hours  │ 30     │ No                │   │ │  │
│  │  │  │ P4    │ 60mn │ 24 Hours │ 20     │ No                │   │ │  │
│  │  │  │ P5    │ 120m │ 72 Hours │ 10     │ No                │   │ │  │
│  │  │  └───────┴──────┴──────────┴────────┴──────────────────┘   │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  │                                                                    │  │
│  │  Dispatch Flow:                                                   │  │
│  │  1. Sort undispatched alerts by received_at                      │  │
│  │  2. Determine highest-weight tier (cascade detection)            │  │
│  │  3. Check node cooldown (flapping detection)                     │  │
│  │  4. Check site-level onpage mute (1h after last onpage)         │  │
│  │  5. Wait period elapsed?                                         │  │
│  │  6. Day shift:  → Remedyforce ticket email only                  │  │
│  │     After hours: → Ticket + NOC Notification + On-Page           │  │
│  │  7. Mark all cluster alerts as is_ticketed=True                  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

### Business Hours Logic

```
Business Hours = Monday-Friday, 0600-2000 America/Chicago
After Hours   = All other times (nights, weekends)

Day shift ticket recipients:    REMEDYFORCE_TICKET_EMAIL only
After hours ticket recipients:  REMEDYFORCE_TICKET_EMAIL
                                + NOC_NOTIFY_EMAIL
                                + NOC_ONPAGE_EMAIL (SWF devices)
                                + ITNETWORK_ONPAGE_EMAIL (non-SWF)
```

### Flapping Detection

A node is considered "flapping" if it has a ticketed alert within the cooldown window:

```
Cooldown hours:
  P1-Hi: 1 hour
  P1-Lo: 1 hour
  P2-Hi through P5: 5 hours
```

When a node is on cooldown, the entire cluster is muted and all alerts marked as ticketed.

### Site-Level On-Page Mute

After an on-page is dispatched for a site, no further on-pages are sent for that site
for 1 hour (`loc.last_escalation_ticket`). The cluster is still ticketed, but the
on-page step is suppressed.

---

## 7. Risk Alert Pipeline

**Trigger:** Called after `job_unified_brief()` and `job_internal_risk()` complete
**Source files:** `src/utils/risk_alert.py:1-242`, `src/scheduler.py:247-263`

### Overview

The Risk Alert pipeline monitors for risk-level *increases* across both the Global
(CIS) and Internal risk dimensions. When an increase is detected and the 4-hour cooldown
has elapsed, it constructs a plain-text email and dispatches it to configured recipients.

### ASCII Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                    RISK ALERT PIPELINE                                │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Entry Points:                                                 │  │
│  │  - job_unified_brief()  → check_and_alert(global_risk=...)    │  │
│  │  - job_internal_risk()  → check_and_alert(internal_risk=...)  │  │
│  └──────────────────────────┬─────────────────────────────────────┘  │
│                             │                                        │
│                             ▼                                        │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  check_and_alert(global_risk, internal_risk)                  │  │
│  │  src/utils/risk_alert.py:156                                  │  │
│  │                                                                │  │
│  │  1. Read previous tracked risks from SystemConfig:            │  │
│  │     previous_global   = config.last_global_risk               │  │
│  │     previous_internal = config.last_internal_risk             │  │
│  │                                                                │  │
│  │  2. Detect increases:                                         │  │
│  │     global_change   = is_increase(prev_global, curr_global)  │  │
│  │     internal_change = is_increase(prev_int, curr_int)        │  │
│  │                                                                │  │
│  │     RISK_TIER_ORDER = ["GREEN","BLUE","YELLOW","ORANGE","RED"]│  │
│  │     Increase = new tier index > old tier index                │  │
│  │                                                                │  │
│  │  3. No increase detected?                                     │  │
│  │     → update_tracked_risks() and return                       │  │
│  │                                                                │  │
│  │  4. Check 4-hour cooldown:                                    │  │
│  │     should_send_alert()                                       │  │
│  │     → Compares now vs config.last_risk_alert_time             │  │
│  │     → If < 4 hours: skip alert, update risks only             │  │
│  │                                                                │  │
│  │  5. Build email:                                              │  │
│  │     get_alert_recipients() ← RISK_ALERT_RECIPIENTS env var   │  │
│  │     build_alert_email_body() → plain text                    │  │
│  │                                                                │  │
│  │  6. Dispatch:                                                 │  │
│  │     send_alert(recipients, subject, body)                     │  │
│  │     → SMTP via SystemConfig settings                         │  │
│  │                                                                │  │
│  │  7. Post-dispatch:                                            │  │
│  │     update_tracked_risks()                                    │  │
│  │     update_last_alert_time()                                  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  Email Format:                                                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Subject: "NOC Risk Alert: Global Risk ORANGE"                │  │
│  │                                                                │  │
│  │  NOC Intelligence Fusion Center - Risk Level Change Alert     │  │
│  │  ==================================================           │  │
│  │                                                                │  │
│  │  GLOBAL RISK INCREASED:                                       │  │
│  │    Previous: YELLOW                                           │  │
│  │    Current:  ORANGE                                           │  │
│  │                                                                │  │
│  │  --------------------------------------------------           │  │
│  │  CURRENT STATE:                                               │  │
│  │    Global Risk:   ORANGE                                      │  │
│  │    Internal Risk: YELLOW                                      │  │
│  │                                                                │  │
│  │  Time: 2026-07-15 14:30:00 CDT                              │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

### Risk Tier Hierarchy

```
GREEN (Low)  <  BLUE (Guarded)  <  YELLOW (Elevated)  <  ORANGE (High)  <  RED (Severe)
    idx=0           idx=1              idx=2                 idx=3              idx=4
```

An increase is strictly: `tier_index(current) > tier_index(previous)`.

---

## 8. Weather/Telemetry Ingestion Pipeline

**Trigger:** Scheduler, every 2 minutes (hazards), 5 minutes (cloud/telemetry)
**Source files:** `src/workers/infra_worker.py:1-235`, `src/workers/cloud_worker.py:1-206`, `src/workers/telemetry_worker.py:1-144`, `src/workers/crime_worker.py:1-154`

### Overview

This pipeline continuously ingests weather hazards from NWS/SPC, cloud service outage
feeds, ISP/BGP telemetry, power grid outages, earthquake proximity monitoring, and
local crime dispatch data. Each sub-pipeline runs independently on its own schedule.

### ASCII Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│              WEATHER / TELEMETRY INGESTION PIPELINE                          │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════════ │
│  SUB-PIPELINE A: Regional Hazards (every 2 minutes)                        │
│  ════════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  fetch_regional_hazards()                                                    │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  ┌──────────────────┐                                                 │  │
│  │  │ SPC Outlooks     │  3 GeoJSON feeds (Day 1/2/3)                   │  │
│  │  │ spc.noaa.gov     │  → save to GeoJsonCache (spc_day1/2/3)         │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐                                                 │  │
│  │  │ NWS Alerts (AR)  │  api.weather.gov/alerts?area=AR                │  │
│  │  │                  │  → GeoJsonCache (nws_ar)                       │  │
│  │  │                  │  → RegionalHazard records (dedup by hazard_id)  │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐                                                 │  │
│  │  │ NWS Alerts (OOS) │  api.weather.gov/alerts?area=OK,MS,MO          │  │
│  │  │                  │  → GeoJsonCache (nws_oos)                      │  │
│  │  │                  │  → RegionalHazard records                       │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐                                                 │  │
│  │  │ USGS Earthquakes │  earthquake.usgs.gov (AR bounds)               │  │
│  │  │ (AR region)      │  → GeoJsonCache (usgs_ar)                      │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐                                                 │  │
│  │  │ USGS Earthquakes │  earthquake.usgs.gov (OOS bounds)              │  │
│  │  │ (OOS region)     │  → GeoJsonCache (usgs_oos)                     │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────────────────────────────────────────────────┐     │  │
│  │  │ Earthquake Proximity Check                                   │     │  │
│  │  │ check_earthquake_proximity(equake_data, distance_miles=50)  │     │  │
│  │  │                                                              │     │  │
│  │  │ For each earthquake (mag >= 2.5):                            │     │  │
│  │  │   For each MonitoredLocation with lat/lon:                   │     │  │
│  │  │     haversine_distance(eq, site)                             │     │  │
│  │  │     IF distance <= 50 miles:                                 │     │  │
│  │  │       → Add to new_alerts[]                                 │     │  │
│  │  │                                                              │     │  │
│  │  │ If new_alerts exist:                                        │     │  │
│  │  │   → build_eq_alert_email_body()                             │     │  │
│  │  │   → send_alert() to RISK_ALERT_RECIPIENTS                   │     │  │
│  │  │   → Persist alerted_eq_ids (dedup, never re-alert same eq)  │     │  │
│  │  └──────────────────────────────────────────────────────────────┘     │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════════ │
│  SUB-PIPELINE B: Cloud Outages (every 5 minutes)                           │
│  ════════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  fetch_cloud_outages()                                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  18 providers monitored:                                               │  │
│  │  AWS, Google Cloud, Azure, Cisco (Umbrella/Webex/Meraki),             │  │
│  │  Cloudflare, GitHub, Slack, Zoom, Atlassian, Datadog,                 │  │
│  │  PagerDuty, Twilio, Okta, Zscaler, CrowdStrike, Mimecast             │  │
│  │                                                                        │  │
│  │  Per provider RSS/Atom feed:                                          │  │
│  │    → Parse with feedparser                                            │  │
│  │    → Filter: future maintenance, foreign regions, >7 days old         │  │
│  │    → Extract US regions from title/description                        │  │
│  │    → Detect resolution keywords                                       │  │
│  │    → Save CloudOutage or mark resolved                                │  │
│  │    → Purge resolved entries > 3 days old                              │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════════ │
│  SUB-PIPELINE C: Telemetry Sync (every 5 minutes)                          │
│  ════════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  run_telemetry_sync()                                                        │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  ┌──────────────────┐  ORNL ODIN Power Grid                          │  │
│  │  │ Power Outages    │  → RegionalOutage records (customers_out > 100) │  │
│  │  │ (Arkansas)       │  → Estimated radius = 10 + (out_count / 1000)  │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐  RIPEstat Routing Status                       │  │
│  │  │ BGP Anomalies    │  → BgpAnomaly records (risk_score > 0.5)      │  │
│  │  │ (per ASN)        │  → Monitored ASNs from SystemConfig            │  │
│  │  └──────────────────┘                                                 │  │
│  │                                                                        │  │
│  │  ┌──────────────────┐  IODA Internet Outage Detection               │  │
│  │  │ ISP Outages      │  → RegionalOutage records (ISP type)          │  │
│  │  │ (AR + ASN)       │  → Checks both region=US-AR and ASN-level     │  │
│  │  └──────────────────┘                                                 │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════════ │
│  SUB-PIPELINE D: Crime Data (every 3 minutes)                              │
│  ════════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  fetch_live_crimes()                                                         │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  Source: Little Rock CAD dispatches (POST web.littlerock.state.ar.us) │  │
│  │                                                                        │  │
│  │  Per dispatch entry:                                                   │  │
│  │    → Geocode address via ArcGIS (with cache + fallback)               │  │
│  │    → Haversine distance from HQ (34.6755, -92.3235)                  │  │
│  │    → Classify severity by keyword:                                   │  │
│  │        ARSON/EXPLOSIVE/SHOOTING → Critical Infrastructure Threat      │  │
│  │        THEFT/BURGLARY/ROBBERY   → Asset/Copper Theft Risk            │  │
│  │        ASSAULT/BATTERY/WEAPON    → Violent Proximity Threat           │  │
│  │        VANDALISM/TRESPASS        → Perimeter Breach/Vandalism        │  │
│  │        Otherwise                 → General Police Activity            │  │
│  │                                                                        │  │
│  │  → CrimeIncident records (batch=100, dedup by composite ID)          │  │
│  │  → Purge entries > 7 days old                                         │  │
│  │  → dispatch_perimeter_crime_alerts() if new high-severity             │  │
│  │    (distance <= 0.4 miles → SMS-friendly alert)                       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════════ │
│  SUB-PIPELINE E: CISA KEV (every 6 hours)                                  │
│  ════════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  fetch_cisa_kev()                                                            │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │  Source: CISA Known Exploited Vulnerabilities JSON                    │  │
│  │  → CveItem records (dedup by cve_id)                                  │  │
│  │  Fields: cve_id, vendor, product, vulnerability_name, description,    │  │
│  │          required_action, due_date                                     │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Site Intersection Calculation

The `calculate_site_intersections()` function (`src/services.py:1867-1913`) determines
which monitored sites are affected by active weather hazards:

```
For each hazard polygon:
  → Pre-compute bounding box (minx, miny, maxx, maxy)

For each monitored site (Lat, Lon):
  → Bounding box pre-check (fast float comparison)
  → Shapely point.within(polygon) (precise, only if bbox passes)
  → Add to master_affected_sites (always) and toggled_affected_sites (if UI toggle on)
```

### Cache Refresh Cadence

| Data Source | Cache Key | TTL |
|-------------|-----------|-----|
| SPC Outlooks | `spc_day1`, `spc_day2`, `spc_day3` | 2 min (re-fetched) |
| NWS Alerts (AR) | `nws_ar` | 2 min |
| NWS Alerts (OOS) | `nws_oos` | 2 min |
| USGS Earthquakes | `usgs_ar`, `usgs_oos` | 2 min |
| GeoJSON Cache (all) | `GeoJsonCache.feed_name` | In-DB, overwritten each cycle |

---

## 9. Supporting Sub-Pipelines

### 9.1 Database Maintenance (every 60 minutes)

**Source:** `src/scheduler.py:329-376`

```
run_database_maintenance()
  ├── deduplicate_articles()
  ├── Delete articles: score <= 0.0
  ├── Delete low-score articles: older than 3 days AND not pinned
  ├── Delete other articles: older than 30 days AND not pinned
  ├── Delete SolarWindsAlert: older than 60 days
  ├── Delete RegionalHazard: older than 48 hours
  ├── Delete RegionalOutage: older than 12 hours
  ├── Delete BgpAnomaly: older than 12 hours
  ├── Delete CveItem: older than 7 days
  ├── Delete CloudOutage: older than 24 hours (or 14 days if unresolved)
  ├── Delete CrimeIncident: older than 7 days
  ├── Delete orphaned ExtractedIOCs
  ├── PRAGMA optimize (SQLite)
  └── PRAGMA wal_checkpoint(TRUNCATE) (SQLite)
```

### 9.2 ML Model Retraining (weekly, Sunday 02:00)

**Source:** `src/scheduler.py:654-666`

```
job_retrain_ml()
  ├── train() → src/train_model.py
  │     → Trains new model → saves to src/ml_model.pkl
  └── Hot-reload: _global_scorer = get_scorer()
        → Loads new model weights into memory
```

### 9.3 Daily Email Brief (07:00 Central)

**Source:** `src/scheduler.py:266-322`

```
job_daily_email_unified_brief()
  ├── Read SystemConfig.unified_brief (latest)
  ├── Gather internal risk level
  ├── Gather global intel
  ├── generate_unified_brief_email_html()
  │     → Risk tier banners (Unified/Global/Internal)
  │     → OSINT Correlation + AI-Generated disclaimers
  │     → Cyber Security Director attribution line
  └── send_alert_email() to RISK_ALERT_RECIPIENTS
```

---

## Appendix: Scheduler Job Registry

| Job | Interval | Function | Thread Safety |
|-----|----------|----------|---------------|
| RSS Feed Fetch | 15 min | `fetch_feeds()` | Threaded |
| Crime Fetch | 3 min | `fetch_live_crimes()` | Threaded |
| Regional Hazards | 2 min | `fetch_regional_hazards()` | Threaded |
| Cloud Outages | 5 min | `fetch_cloud_outages()` | Threaded |
| CISA KEV | 6 hours | `fetch_cisa_kev()` | Threaded |
| Internal Risk | 1 hour | `job_internal_risk()` | Threaded |
| Unified Brief | 30 min | `job_unified_brief()` | Threaded |
| DB Maintenance | 60 min | `run_database_maintenance()` | Threaded |
| ML Retrain | Sunday 02:00 | `job_retrain_ml()` | Threaded |
| Tiered Escalation | 1 min | `job_tiered_alert_escalation()` | Threaded |
| Telemetry Sync | 5 min | `run_telemetry_sync()` | Threaded |
| Daily Email Brief | 07:00 CST | `job_daily_email_unified_brief()` | Threaded |

All scheduled jobs are wrapped in `run_threaded()` which spawns a daemon thread, preventing
slow external API calls from blocking the master schedule loop.

---

## Appendix: Database Tables Referenced

| Table | Primary Pipeline | Purpose |
|-------|-----------------|---------|
| `articles` | RSS Ingestion | OSINT articles with score, category, keywords |
| `feed_sources` | RSS Ingestion | Configurable RSS feed URLs (7 active) |
| `keywords` | RSS Ingestion | Keyword weights for HybridScorer |
| `extracted_iocs` | RSS Ingestion | IOCs extracted from cyber articles |
| `daily_threat_scores` | CIS Scoring | Historical CIS scores for baseline calculation |
| `system_config` | All | Global config: scoring mode, overrides, SMTP, LLM |
| `hardware_assets` | Internal Risk | Hardware inventory for OSINT correlation |
| `software_assets` | Internal Risk | Software inventory for OSINT correlation |
| `internal_risk_snapshots` | Internal Risk | Periodic internal CIS risk snapshots |
| `solar_wind_alerts` | Webhook/AIOps | SolarWinds alert records |
| `timeline_events` | Webhook | Event log for alert lifecycle |
| `monitored_locations` | AIOps/Regional | Facility geospatial registry |
| `regional_hazards` | Weather | NWS hazard records |
| `geojson_cache` | Weather | Cached GeoJSON layers (SPC, NWS, USGS) |
| `cloud_outages` | Cloud Worker | Cloud provider outage records |
| `regional_outages` | Telemetry | ISP/power outage records |
| `bgp_anomalies` | Telemetry | BGP routing anomaly records |
| `cve_items` | CISA KEV | Known Exploited Vulnerabilities |
| `crime_incidents` | Crime Worker | Local crime dispatch records |
| `users` | Auth | User accounts and session tokens |
| `roles` | Auth | RBAC role definitions |
| `saved_reports` | Reporting | User-saved reports |
| `daily_briefings` | Reporting | Daily fusion reports |
| `shift_log_entries` | Logbook | Shift log records |
| `node_aliases` | AIOps | Node name normalization |
| `user_weather_preferences` | Weather | Per-user weather alert preferences |
