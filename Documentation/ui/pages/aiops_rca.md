# Module: `src/ui/pages/aiops_rca.py`

## Overview

AIOps Root Cause Analysis page renderer. Provides a live correlation board with map visualization, a predictive analytics panel for chronic degradation detection, and a global correlation engine for multi-domain causal analysis. Integrates with the `EnterpriseAIOpsEngine` for alert clustering, root cause calculation, and fleet outage detection.

---

## Function: `render_aiops_rca()`

**Purpose:** Renders the complete AIOps RCA page with three permission-gated tabs: Active Board, Patterns (Predictive Analytics), and Global (Global Correlation).

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions, system config, black ops state. Instantiates `EnterpriseAIOpsEngine` with `svc.SessionLocal`. Builds tab list based on allowed actions.

2. **Tab: Active Board**:
   - Live 5s polling toggle with `st_autorefresh`.
   - Loads dashboard data: alerts, timeline events, grid via `svc.get_aiops_dashboard_data()`.
   - Right column (1/4): Event Log - displays timeline events with local time formatting and unicode cleanup.
   - Left column (3/4):
     - **Overlays**: Loads locations, filters by allowed site types.
     - **Black Ops: Operation Dean**: If active for current user, simulates cascading failures adding fake alerts at 2 sites per minute.
     - Map visualization via `svc.build_aiops_map_layers()` rendered with pydeck.
     - **Correlation** section:
       - Queries active weather, cloud, BGP, and uncorrelated SolarWinds alerts.
       - Runs `ai_engine.analyze_and_cluster()` to group alerts by site.
       - Runs `ai_engine.identify_fleet_outages()` to detect global carrier events.
       - For fleet events, renders a red banner with provider and affected sites count.
       - For each site cluster, calls `calculate_root_cause()` and renders:
         - Priority/site header with root cause warning text.
         - Patient Zero detection (suspected origin node or "Indeterminate").
         - Maintenance banner if site is under maintenance.
         - "Ticket Dispatched" checkbox (gated by `can_dispatch_rca` permission).
         - "Draft & Dispatch Ticket" expander: RCA text area with editable ticket body, fixed recipient list, dispatch button via `send_alert_email()`.
         - "Acknowledge Incident & Clear Board" button (gated by `can_dispatch_rca`).
         - Maintenance Controls expander (gated by `can_manage_maint`): status selectbox, ETR date input, reason textarea, save button calling `svc.set_site_maintenance()`.

3. **Tab: Patterns**:
   - "Run Deep Analysis" button (60s cooldown).
   - Calls `ai_engine.generate_chronic_insights()`.
   - Left column: Top Offending Nodes DataFrame (high-frequency flapping devices).
   - Right column: Infrastructure Hotspots DataFrame (chronically unstable sites).
   - AI Predictive Maintenance Forecast section with results display (string, DataFrame, or list).

4. **Tab: Global**:
   - "Run Global Correlation" button (60s cooldown).
   - Calls `svc.generate_global_sitrep(sys_config)`.
   - Displays result in bordered container.
   - "Broadcast SitRep" button: dispatches via `send_alert_email()`.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | DataFrames |
| `pydeck` | Map layers |
| `streamlit_autorefresh` | Live polling |
| `src.services` | Data access layer |
| `src.services.aiops_engine.EnterpriseAIOpsEngine` | Alert clustering, RCA, fleet detection, chronic insights |
| `src.utils.mailer.send_alert_email` | Ticket/SitRep dispatch |
| `src.ui.state_manager` | Safe rerun, cooldowns, permissions, black ops state, timezone |
| `src.database` | `RegionalHazard`, `CloudOutage`, `BgpAnomaly`, `SolarWindsAlert` |
