# Module: `src/ui/pages/global_dashboards.py`

## Overview

Global NOC Dashboards page renderer for the Streamlit UI. Provides four dashboard tabs: Operational Dashboard (threat triage, infrastructure status, AI analysis), Global Risk (Executive Grid Threat Matrix with CIS threat level scoring, 14-day trend, dispatchable intelligence reports), Internal Risk (asset posture dashboard with OSINT correlation), and Unified Brief (AI-generated executive brief with email broadcast).

---

## Function: `render_global_dashboards()`

**Purpose:** Renders the complete Global Dashboards page with all four tab panels: Operational, Global Risk, Internal Risk, and Unified Brief.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads system config, AI-enabled flag, permission flags. Renders sidebar refresh rate selector (Off/10s/1m/5m) with `st_autorefresh`.

2. **Tab: Operational Dashboard** (`dash_tabs[0]`):
   - Displays 4 KPI metrics (High-Threat RSS, Active KEVs, Hazards, Cloud Outages) in columns.
   - **Threat Triage panel** (`auto_rotate` support): Two-column layout.
     - Left: Pinned intel articles with score badges, links, AI BLUFs.
     - Right: Live feed (top 15 scored articles).
   - **Infrastructure Status panel**: Three columns.
     - CISA KEVs (top 15 with NVD links).
     - Active cloud outages by provider.
     - Regional hazards with severity icons.
   - **AI Analysis panel**: Two columns.
     - Left: AI Shift Briefing with auto-regeneration (30-min cache), force refresh button (120s cooldown).
     - Right: Security Auditor - scans internal assets against 30-day KEVs using cross-reference LLM call.

3. **Tab: Global Risk** (`dash_tabs[1]`):
   - **CIS Threat Level Legend** dialog accessible via button.
   - **Executive Grid Threat Matrix**: Calculates unified risk posture using `get_executive_grid_intel()` with SIEM penalty injection.
   - Displays large color-coded threat posture banner (GREEN through RED).
   - 14-day CIS Alert Level trend chart (line chart, cyber vs physical scores).
   - Color-coded risk level reference strip.
   - **Physical & Perimeter section**: Risk level, brief, contributing physical intelligence expander, recent crime incidents.
   - **Cyber & SCADA section**: Risk level, brief, CIS macroscopic variables expander with evidence log, contributing cyber intelligence expander.
   - **Dynamic Scoring Overview**: "Generate Scoring Rationale" button (60s cooldown) calls `generate_dynamic_scoring_report()`. Displays warning if posture changed since generation.
   - **Dispatch Intelligence Report**: Email input + "Send AI Scoring Report" button. Converts scoring report markdown to HTML with inline color styling and dispatches via `send_alert_email()`.

4. **Tab: Internal Risk** (`dash_tabs[2]`):
   - "Force Generate" button for admin (30s cooldown).
   - Loads last 28 `InternalRiskSnapshot` records.
   - Displays internal posture banner with CIS risk level, score, total assets analyzed.
   - KPI metrics: total asset footprint, total OSINT correlations, critical OSINT hits.
   - Historical threat trend line chart.
   - **Hardware Assets** expander: data table of at-risk hardware with OSINT matches.
   - **Software Assets** expander: data table of at-risk software.

5. **Tab: Unified Brief** (`dash_tabs[3]`):
   - Displays "Force Refresh Brief" button (60s cooldown). On click, gathers global intel + internal risk, calls `generate_unified_risk_brief()`, saves to config.
   - Shows latest brief with timestamp in bordered container.
   - **Broadcast Executive Brief**: Email input + "Transmit Brief" button. Converts brief to formatted HTML with risk color coding and dispatches via `send_alert_email()`.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | Chart data formatting |
| `pydeck` | (imported, not used in this file) |
| `streamlit_autorefresh` | Auto-refresh interval |
| `src.services` | Data access layer |
| `src.utils.llm` | `generate_rolling_summary`, `cross_reference_cves`, `call_llm`, `generate_executive_weather_brief`, `generate_unified_risk_brief`, `generate_dynamic_scoring_report` |
| `src.ui.state_manager` | `safe_rerun`, `check_cooldown`, `apply_cooldown`, `format_local_time`, `get_score_badge`, `get_cat_icon`, `get_permission_flags`, `LOCAL_TZ` |
| `src.utils.mailer.send_alert_email` | Email dispatch |
| `src.database` | `InternalRiskSnapshot`, `CveItem`, `ElasticEvent` |
