# Module: `src/ui/pages/threat_telemetry.py`

## Overview

Unified Threat Telemetry page renderer. Provides four permission-gated tabs: RSS Triage (pinned, live, low-scored, and searchable article feeds with pagination), Exploits (CISA KEV database viewer), Cloud Services (active and historical cloud outage tracking by provider), and Perimeter Crime (geofenced crime incident map and log around headquarters).

---

## Function: `render_threat_telemetry()`

**Purpose:** Renders the complete Threat Telemetry page with up to 4 permission-gated tabs.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions. Builds tab list based on allowed actions.

2. **Tab: RSS Triage**:
   - "Force Fetch Feeds" button (60s cooldown, requires `can_sync`): calls `fetch_feeds(source="User Force")`.
   - Category filter selectbox (All, Cyber exploits/vulns, malware, ICS/OT, cloud, physical security, severe weather, geopolitics, AI, general).
   - **Nested Function: `handle_pagination(feed_id, q_type, pg_size, s_term=None, m_score=0)`**:
     - Manages per-feed page state in session state.
     - Calls `svc.get_paginated_articles()` with type, category filter, page number, page size, search term, and minimum score.
     - Renders "Previous"/"Next" pagination controls with page counter and total display.
     - Calls `render_article_feed()` from state_manager for the article items.
   - Four sub-tabs:
     - **Pinned**: paginated pinned articles (page size 10).
     - **Live**: paginated live/scored articles (page size 20).
     - **Low**: paginated low-scored articles (page size 20).
     - **Search**: search term input, minimum score number input, items per page select (10/20/50). Calls pagination with search parameters.

3. **Tab: Exploits (KEV)**:
   - "Sync CISA KEV" button (60s cooldown, requires `can_sync`): calls `fetch_cisa_kev()`.
   - Iterates last 50 CVEs from 30 days and renders each as an expander with CVE ID, vendor/product, vulnerability name, and description.

4. **Tab: Cloud Services**:
   - "Sync Cloud Status" button (60s cooldown, requires `can_sync`): calls `fetch_cloud_outages()`.
   - Fetches active cloud outages and filters out upcoming maintenance windows (checks for maintenance keywords and date formats).
   - If active outages exist, creates per-provider tabs.
   - Each provider tab lists outages with expanders showing service, update time, title link, and description.
   - "View Historical / Resolved Incidents" expander: shows resolved outages from the last 100 records.

5. **Tab: Perimeter Crime**:
   - Geofence radius selectbox (1, 3, 5, 10 miles).
   - "Force Fetch LRPD" button: calls `svc.force_fetch_crime_data()`.
   - Queries recent crimes via `svc.get_recent_crimes()`.
   - If coordinate data missing, prompts terminal side-run.
   - Builds crime map layers via `svc.build_crime_map_layers()` and renders with pydeck.
   - Map zoom adjusts based on radius (15.5 for 1mi, 13.5 for 3mi, 12.0 for 5+mi).
   - Raw incident log DataFrame with `on_select="rerun"` for single-row selection.
   - On row selection, recenters map and adds a red highlight scatterplot layer at the selected crime location.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | Crime data DataFrame |
| `pydeck` | Crime map visualization |
| `src.services` | Data access layer |
| `src.scheduler.fetch_feeds` | Feed fetch trigger |
| `src.workers.cve_worker.fetch_cisa_kev` | CISA KEV sync |
| `src.workers.cloud_worker.fetch_cloud_outages` | Cloud outage sync |
| `src.ui.state_manager` | Safe rerun, cooldowns, time formatting, `render_article_feed`, permissions |
