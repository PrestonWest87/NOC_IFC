# Enterprise Architecture & Functional Specification: `src/app.py`

## 1. Executive Overview

The `src/app.py` module serves as the **Primary Presentation and Controller Layer** for the Intelligence Fusion Center (IFC). Built on the Streamlit framework, it acts as the interactive frontend for Network Operations Center (NOC) personnel.

In its latest architectural iteration, this module has undergone a major refactoring to enforce a strict **Service-Oriented Architecture (SOA) pattern**. It explicitly bans direct database Model imports (e.g., SQLAlchemy ORM models), delegating all data persistence, querying, and mutation to the dedicated intermediate `src.services` layer. Furthermore, it introduces robust UI debouncing to protect backend systems from rate-limit exhaustion and integrates advanced PyDeck geospatial rendering for executive and kinetic intelligence.

---

## 2. Core Architecture: The Service Layer & State Management

### 2.1 Separation of Concerns (Controller vs. Model)
The updated architecture imports `src.services as svc` and exclusively uses its abstracted functions. 
* **Architectural Benefit:** This decoupling ensures that `app.py` only handles DOM rendering, session states, and layout. By relying on the `DotDict` patterns established in `services.py`, the frontend avoids fatal `DetachedInstanceError` exceptions during asynchronous re-renders.

### 2.2 UI Debouncing & Rate Limiting (The Cooldown Engine)
The application integrates a custom rate-limiting mechanism to protect expensive backend processes (like LLM generation, forced RSS syncing, or API polling) from accidental user spam.
* **Execution:** Utilizes `check_cooldown(key, cooldown_seconds)` to evaluate the `st.session_state` timestamp against the current time.
* **Tactile Feedback:** When `apply_cooldown(key)` is triggered, buttons automatically disable themselves and dynamically change their labels (e.g., from "Generate Report" to "⏳ Generating..."), providing immediate visual feedback to the operator.

### 2.3 Auto-Refresh Timers
The module leverages the `streamlit_autorefresh` library to create autonomous "Wall Monitor" modes.
* **Operational Dashboard:** Configurable to refresh every 1, 2, or 5 minutes, rotating sequentially through its internal sub-panels.
* **AIOps RCA:** Configurable to sync live network telemetry every 5, 10, or 30 seconds.

---

## 3. Initialization, Authentication & RBAC

### 3.1 Authentication Lifecycle
* **Persistent Sessions:** The application integrates `CookieController` to set and retrieve a `noc_session_token` with a 30-day expiration (`max_age=30*86400`). 
* **Login Flow:** If no valid cookie exists, the app halts execution (`st.stop()`) and renders a login form. Upon successful authentication via `svc.authenticate_user()`, the token is minted and the UI rerenders.

### 3.2 Granular Role-Based Access Control (RBAC)
Permissions are explicitly defined via descriptive string arrays (`ALL_POSSIBLE_PAGES` and `ALL_POSSIBLE_ACTIONS`).
* **Admin Override:** If a user possesses the "admin" role, they are forcefully granted all possible pages and actions.
* **Dynamic Action Gates:** Boolean variables (e.g., `can_pin`, `can_train`, `can_trigger_ai`) are evaluated on every page load to dynamically disable or hide specific UI buttons based on the user's assigned role.

---

## 4. Module Specifications (Page Routing)

The application utilizes `st.sidebar.radio` to route operators between 9 distinct operational modules.

### 4.1 Operational Dashboard (HUD)
* **Metrics Header:** Displays 24-hour KPIs for RSS volume, KEVs, physical hazards, and cloud outages.
* **Auto-Rotating Panels:** Cycles between "Threat Triage" (Pinned/Live feeds), "Infrastructure Status" (Active Cloud/Regional/CVE data), and "AI Analysis".
* **AI Security Auditor:** Features an on-demand LLM scanner that cross-references the internal `sys_config.tech_stack` against the last 30 days of the CISA KEV catalog.

### 4.2 Executive Dashboard
* **Unified Threat Posture:** Aggregates real-time localized crime, cyber OSINT, and physical hazards into a single high-level risk score (HIGH, MEDIUM, LOW).
* **Telemetry Expander:** Specifically filters geopolitical noise, displaying only OSINT relevant to the Bulk Electric System (BES).
* **Broadcast Engine:** Provides a one-click interface to generate and dispatch an inline-CSS HTML email designed for Microsoft Outlook.

### 4.3 Daily Fusion Report
* **Historical Archive:** Analysts can utilize a dropdown (`st.selectbox`) to select and view any historical Daily Briefing from the database archive.
* **Generation & Transmission:** Contains UI flows to trigger the `generate_daily_fusion_report` map-reduce LLM pipeline and transmit the resulting markdown as a formatted HTML email.

### 4.4 Crime Intelligence
* **Geospatial Geofencing:** Renders a 3D `pydeck_chart` centered on HQ. 
* **Campus Boundary:** Implements a hardcoded `campus_boundary` coordinate array to draw a precise, user-defined `PolygonLayer` over the facility footprint, overlaying recent LRPD incidents via a `ScatterplotLayer`.

### 4.5 Threat Telemetry
A deeply technical tab partitioned by RBAC sub-tabs.
* **RSS Triage:** Implements advanced pagination logic (`handle_pagination`) to gracefully render thousands of threat articles across "Pinned", "Live", "Low", and "Search" sub-tabs.
* **Regional Grid & Fire Desk:** * **Map Controls:** Offers granular toggles for Radar, SPC Convective, Warnings, Watches, and the Fire Desk (NWS Red Flag & NIFC Active Wildfires).
    * **Map Rendering:** Combines `TileLayer` for radar, `GeoJsonLayer` for weather polygons, and `ScatterplotLayer` for NIFC fires (with radius scaling by acreage) and NOC locations. Features a live animated precipitation loop via a `components.html` iframe.
    * **Hazard Analytics:** Displays real-time DataFrames cross-tabulating NOC Facility Priority vs. Active Hazard Types.

### 4.6 Threat Hunting & IOCs
* **Global IOC Matrix:** Displays a dataframe of Extracted IOCs (IPv4, SHA256, CVE) and utilizes `st.column_config.LinkColumn` to generate hyperlinked "OSINT Pivots" to VirusTotal and Shodan.
* **Deep Hunt Builder:** Takes a target entity (e.g., "Volt Typhoon"), queries historical telemetry up to 90 days back, and instructs the LLM to generate custom Splunk/SIEM queries and YARA rules.

### 4.7 AIOps RCA (Root Cause Analysis)
* **Active Board:** Renders an auto-focusing PyDeck map of alerting locations. Calculates correlation clusters and provides a "Draft & Dispatch Ticket" text area pre-configured to email `remedyforceworkflow@aecc.com` and `noc@aecc.com`.
* **Predictive Analytics:** Executes deep Pandas aggregations to highlight specific nodes experiencing state-flapping and sites suffering from chronic instability.

### 4.8 Report Center & Settings
* **Report Builder:** A multi-select interface allowing analysts to aggregate database articles into a custom LLM Map-Reduce pipeline, saving the output to the `Shared Library`.
* **Settings & Admin:** The control plane containing six sub-tabs:
    * **Users & Roles:** Create users, edit granular `ALL_POSSIBLE_ACTIONS` for custom roles, and force password resets.
    * **Backup & Restore:** Generates and imports master JSON backups containing keywords, feeds, and locations.
    * **Danger Zone:** Houses destructive tools to run the Garbage Collector, purge cloud telemetry, recategorize legacy articles, or trigger a full database factory reset.
