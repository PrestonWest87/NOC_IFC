# Module: `src/ui/pages/threat_hunting.py`

## Overview

Active Threat Hunting and Detection Engineering page renderer. Provides three permission-gated tabs: Live Global IOC Matrix (filterable IOC table with OSINT pivot links and CSV export), Deep Hunt and Detection Builder (LLM-assisted threat hunting with YARA/SIEM query generation), and Elastic SIEM Report (rolling cache dashboard, live Elastic hunt, and AI-powered natural language to Elastic DSL query builder).

---

## Function: `render_threat_hunting()`

**Purpose:** Renders the complete Threat Hunting page with up to 3 permission-gated tabs.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions, system config, AI-enabled flag. Builds tab list based on allowed actions.

2. **Tab: Live Global IOC Matrix**:
   - Queries IOCs from last 72 hours via `svc.get_iocs(days_back=3)`.
   - Enriches each IOC with an OSINT pivot URL via `svc.get_osint_pivot_link()`.
   - Renders DataFrame with multi-select type filter (default: IPv4, SHA256, Domain, CVE, MITRE ATT&CK).
   - Column config with link columns for Source Article and OSINT Pivot (displayed as "Open Tool").
   - "Export Hunting Targets (CSV)" download button (excludes OSINT Pivot column).

3. **Tab: Deep Hunt & Detection Builder**:
   - "Targeted LLM Deep Hunt & Detection Engine" form:
     - Target entity text input.
     - Historical depth slider (7-90 days).
   - "Compile Detection Package" button (60s cooldown, requires AI enabled):
     - Searches articles via `svc.search_articles_for_hunting()`.
     - If articles found, builds context string with title, source, and summary.
     - Calls `call_llm()` with system prompt requesting: Threat Overview & MITRE TTPs, Known Vulnerabilities & Infrastructure, Splunk/SIEM Hunt Queries, YARA Detection Stub.
     - Renders result with reference intel article links.

4. **Tab: Elastic SIEM Report**:
   - Three subtabs: "Rolling Cache (Fast)", "Live Hunt (API)", "AI Query Builder".
   - **Rolling Cache**:
     - "Sync Local Cache" button: calls `sync_elastic_telemetry()` and `purge_stale_elastic_data()`.
     - Displays local Elastic events from last 24 hours.
     - KPI metrics: Local High/Crit Alerts, Unique Threat IPs, Critical Density percentage.
     - Data table sorted by time descending.
   - **Live Hunt**:
     - Target index selectbox (common log indices), result limit, quick keyword search.
     - "Execute Live Hunt" button: builds query_string or match_all query, calls `execute_live_query()`.
     - Flattens nested Elasticsearch source fields into flat results DataFrame.
     - "AI Triage & Summarize Results" button: calls `generate_siem_triage_summary()`.
   - **AI Query Builder**:
     - Natural language text area describing the hunt criteria.
     - "Generate Query" button: calls `generate_elastic_dsl()` to translate intent to Elasticsearch JSON DSL.
     - Displays generated JSON in a code block with instructions for Kibana or API use.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | IOC DataFrame, Elastic results DataFrame |
| `plotly.express` | (imported, used in the Rolling Cache section) |
| `src.services` | Data access layer |
| `src.utils.llm` | `call_llm`, `generate_siem_triage_summary`, `generate_elastic_dsl` |
| `src.workers.elastic_worker` | `sync_elastic_telemetry`, `purge_stale_elastic_data`, `execute_live_query` |
| `src.database.ElasticEvent` | Local SIEM cache query |
| `src.ui.state_manager` | Safe rerun, cooldowns, permissions, timezone |
