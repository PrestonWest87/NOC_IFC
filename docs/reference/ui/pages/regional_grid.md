# Module: `src/ui/pages/regional_grid.py`

## Overview

Regional Grid and Hazard Analytics page renderer. Provides geospatial map overlay with SPC convective outlooks, NWS warnings, watches, fire weather, wildfires, and earthquakes. Includes tabbed views for Executive Dashboard (KPIs, AI weather brief, Plotly visualizations, email broadcast), Deep Hazard Analytics (intersectional dataset, sitrep broadcast), Location Matrix, Weather Alerts Log (NWS alert details with deep dive), and Atmos Weather (alert preferences, 7-day forecast, SPC outlooks, live radar).

---

## Function: `render_regional_grid()`

**Purpose:** Renders the complete Regional Grid page with up to 6 permission-gated tabs.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions, system config, AI-enabled flag. Provides "Sync Regional Telemetry" button (60s cooldown) that calls `fetch_regional_hazards()` and clears GeoJSON cache.
2. Loads cached locations (filtered by `allowed_site_types`) and builds a pandas DataFrame with id, name, type, district, priority, risk, lat, lon.
3. Loads GeoJSON data: SPC D1/D2/D3, AR warnings, OOS warnings, USGS AR/OOS.
4. Builds tab list based on allowed actions (up to 6 tabs).

5. **Tab: Geospatial Overlay**:
   - Left control panel (1/5 width):
     - Master Layers toggles: Radar Overlay, Animated Panel, SPC Convective, Warnings (AR), Watches (AR), Out-of-State, Fire Weather, Wildfires, Earthquakes.
     - Fire Desk Legend when relevant layers active.
     - Hazard Isolation multi-select filter by active event types.
     - Facility Filters: type and priority multi-select.
   - Right map area (4/5 width):
     - Pydeck chart with `compile_regional_grid_map()` layers.
     - Optional animated radar panel with RainViewer iframe alongside the map.
     - "Sites Impacted" table sorted by priority.

6. **Tab: Executive Dashboard**:
   - KPI row: Total Tracked Assets, Assets in Active Risk Zones (with % exposure), Critical P1 Assets at Risk, Highest Regional Risk.
   - AI Executive Weather Briefing: "Generate Briefing" button calls `generate_executive_weather_brief()`, displays result.
   - Three Plotly visualizations:
     - SPC Risk pie chart (color-coded by risk level).
     - NWS Alerts pie chart (color-coded by alert type).
     - At-Risk Assets by District bar chart.
   - Broadcast Executive SitRep form:
     - Email recipient input, optional analyst notes.
     - "Transmit Report" button: builds HTML bar charts for SPC/NWS distributions, combines with KPIs + AI brief + analyst notes, dispatches via `send_alert_email()`.
   - Raw Matrices expander: priority, district, and type risk matrices.

7. **Tab: Deep Hazard Analytics**:
   - KPI row: Total Sites Impacted, Critical P1 Impacts, High P2 Impacts, Unique Hazards.
   - Complete intersectional dataset DataFrame (sorted by priority, severity, site).
   - Broadcast Executive HTML SitRep: generates hazard sitrep HTML and dispatches via email.

8. **Tab: Location Matrix**:
   - Displays all tracked locations with SPC convective outlooks overlay (minus geospatial columns).
   - Sortable by risk and priority.

9. **Tab: Weather Alerts Log**:
   - Comprehensive NWS alerts table with event, severity, affected area, expires, headline.
   - Deep Dive Inspection: selectbox to choose an alert and view full details including event type, affected zones, severity, certainty, effective/expires times, NWS description, and actionable instructions.

10. **Tab: Atmos Weather**:
    - Browser notification enable button with JavaScript.
    - Alert Preferences form: multi-select for NWS event types, saves via `set_user_weather_prefs()`.
    - Active Watched Alerts: displays filtered notifications matching user preferences.
    - Site-Specific 7-Day Forecast: selectbox for monitored facility, renders up to 14 forecast periods with icons, temperatures, wind, and detailed descriptions.
    - Predictive Convective Outlooks (SPC): Day 1/2/3 tabs rendering GeoJSON layers with risk color coding.
    - Live Atmospheric Radar: embedded Windy.com radar iframe.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | DataFrames |
| `pydeck` | Map layers |
| `streamlit.components.v1` | HTML/iframe embedding |
| `plotly.express`, `plotly.graph_objects` | Charts (Executive Dashboard) |
| `src.services` | Data access layer |
| `src.utils.llm.generate_executive_weather_brief` | AI weather briefing |
| `src.ui.state_manager` | Safe rerun, cooldowns, time formatting, permissions, timezone |
| `src.workers.infra_worker.fetch_regional_hazards` | Telemetry sync |
| `src.utils.mailer.send_alert_email` | Email dispatch |
