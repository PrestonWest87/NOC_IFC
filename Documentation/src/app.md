# Enterprise Architecture & Functional Specification: `src/app.py` *(Updated)*

## 1. Executive Overview

The `src/app.py` module serves as the **Primary Presentation and Controller Layer** for the Intelligence Fusion Center (IFC). Built on the Streamlit framework, it acts as the interactive frontend for Network Operations Center (NOC) personnel.

In its latest architectural iteration, this module has undergone a major refactoring to implement a strict **Service-Oriented Architecture (SOA) pattern**. It explicitly bans direct database Model imports (SQLAlchemy ORM), delegating all data persistence, querying, and mutation to a dedicated intermediate `services.py` layer. Furthermore, it introduces robust UI debouncing to protect backend systems from rate-limit exhaustion and integrates new executive-level and kinetic intelligence modules.

---

## 2. Core Architecture: The Service Layer Abstraction

### 2.1 Separation of Concerns (Controller vs. Model)
Previously, `app.py` tightly coupled the User Interface with the database by directly executing `session.query(Model)` commands. The updated architecture imports `src.services as svc` and explicitly prohibits direct database model imports.
* **Architectural Benefit:** This decoupling ensures that `app.py` only handles UI DOM rendering and user session states. Database logic, connection pooling, and error handling are centralized in `services.py`. If the backend transitions from SQLite/PostgreSQL to a completely different data store or REST API, the `app.py` file remains entirely untouched.

### 2.2 UI Debouncing & Rate Limiting (The Cooldown Engine)
The application integrates a custom rate-limiting mechanism to protect expensive backend processes (like LLM generation, external API syncing, or complex PyDeck map rendering) from accidental user spam or impatient multi-clicking.
* **`check_cooldown(key, cooldown_seconds)`**: Evaluates the Streamlit `session_state` timestamp against the current time.
* **`apply_cooldown(key)`**: Sets the lock.
* **Implementation:** Applied to high-latency buttons (e.g., "🔄 Sync CISA KEV", "🤖 Generate Yesterday's Report"). While cooling down, buttons automatically disable themselves and change their label to "⏳ Syncing..." or "⏳ Generating...", providing immediate tactile feedback to the operator.

---

## 3. Initialization, Authentication & RBAC

### 3.1 Authentication Lifecycle
* **Cookie Controller:** The app uses `CookieController` to check for an existing `noc_session_token`.
* **Service Delegation:** Auth requests are passed to `svc.authenticate_user(username, password)`. Upon success, a token is minted, stored in the browser cookie (30-day expiration), and the session is refreshed.

### 3.2 Granular Role-Based Access Control (RBAC)
The permission arrays have been overhauled into highly descriptive, human-readable matrices that dictate exactly what an operator can see and do.
* **`ALL_POSSIBLE_PAGES`**: Dictates top-level sidebar navigation (e.g., `"🌐 Operational Dashboard"`, `"📊 Executive Dashboard"`).
* **`ALL_POSSIBLE_ACTIONS`**: Dictates granular tab-level visibility and specific interactive functions (e.g., `"Action: Dispatch Exec Report"`, `"Tab: Threat Telemetry -> RSS Triage"`).

---

## 4. Module Specifications (Page Routing)

The application utilizes `st.sidebar.radio` to route operators between nine distinct modules, automatically hiding modules the current user's `Role` does not possess permissions for.

### 4.1 🌐 Operational Dashboard (HUD)
* **Metrics Header:** Fetches top-level 24-hour KPIs via `svc.get_dashboard_metrics()`.
* **Auto-Rotation:** Uses `st_autorefresh` and modular arithmetic to cycle the view between "Threat Triage", "Infrastructure Status", and "AI Analysis" for hands-free SOC wall-monitor viewing.
* **AI Security Auditor:** Cross-references the local `SystemConfig.tech_stack` against the active CISA KEV catalog using an LLM prompt.

### 4.2 📊 Executive Dashboard (New)
A synthesized command dashboard explicitly targeting executive leadership and high-level incident management.
* **Unified Threat Posture:** Aggregates real-time kinetic telemetry (crimes within 1 mile), cyber OSINT (48-hour pipeline), and physical hazard grids into an overarching risk score (HIGH/MEDIUM/LOW).
* **HTML Outlook Broadcast:** Enables one-click translation of the dashboard into a sanitized, boardroom-ready Outlook HTML email dispatched directly via the `src.mailer` integration.

### 4.3 📰 Daily Fusion Report
* **Historical Archive:** Operators can generate the previous day's report or use a dropdown (`st.selectbox`) to select and view any historical Daily Briefing from the database archive fetched via `svc.get_all_daily_briefings()`.
* **Broadcast Integration:** Includes a dedicated UI block to transmit the synthesized Markdown report natively as HTML to specific mailing lists.

### 4.4 🚨 Crime Intelligence (New)
Provides a hyper-localized view of kinetic threats near physical assets.
* **Geospatial Rendering:** Uses `pydeck` (pdk) to map a highly specific user-defined geo-polygon (Campus Boundary) and overlays kinetic incidents (assaults, theft, arson) fetched from the Little Rock Open Data API.
* **Data Transparency:** Provides raw incident logs strictly filtered by distance (`distance_miles < 1.0`), ensuring operators aren't overwhelmed by generic city-wide noise.

### 4.5 📡 Threat Telemetry
A deeply technical tab governed by granular "Tab" RBAC permissions.
* **RSS Triage:** Implements advanced UI pagination (`svc.get_paginated_articles()`) to gracefully render thousands of threat articles without crashing the browser DOM. Includes sub-tabs for Pinned, Live, Low Threat, and Deep Search.
* **Exploits (KEV) & Cloud Services:** Interfaces for viewing and forcing syncs of external vulnerability catalogs and SaaS outages.
* **Regional Grid & Fire Desk:** * **Map Rendering:** Renders a live 3D map overlaid with SPC Convective Outlooks and NWS weather alerts.
    * **Fire Weather Expansion:** Integrates dynamic layers for NWS Red Flag Warnings, Fire Weather Watches, and NIFC Active Wildfires with acreage-based radius scaling.
    * **Hazard Analytics:** Displays real-time matrices cross-tabulating NOC Facility Priority vs. Active Hazard Types.

### 4.6 🎯 Threat Hunting & IOCs
* **Global IOC Matrix:** Displays Indicators of Compromise extracted via background workers. Dynamically injects hyperlinked "OSINT Pivots" based on artifact type (e.g., routing SHA256 hashes to VirusTotal, IPv4 addresses to Shodan).
* **Deep Hunt Builder:** Takes a target entity (e.g., "Volt Typhoon"), queries historical telemetry via `svc.search_articles_for_hunting()`, and instructs the LLM to generate custom YARA rules and SIEM queries.

### 4.7 ⚡ AIOps RCA (Root Cause Analysis)
The Enterprise correlation frontend interfacing with `EnterpriseAIOpsEngine`.
* **Active Incident Board:** Displays an auto-focusing PyDeck map calculating the geographic "Blast Radius" of active network alarms overlapping with physical environmental grids.
* **Correlation Engine:** Renders the AI-calculated Root Cause, Cascade Time, and Patient Zero. Provides an editable text area to review the forensic ticket before dispatching it to an ITSM system.
* **Predictive Analytics:** Executes Pandas aggregations to highlight Cellular micro-blips, chronic hardware reboots, and VSAT rain fade susceptibility.

### 4.8 📑 Report Center
* **Report Builder:** A unified multi-select interface allowing analysts to aggregate specific database articles into a context window and trigger an LLM Map-Reduce pipeline (`build_custom_intel_report`) to generate highly technical, bespoke intelligence reports.

### 4.9 ⚙️ Settings & Admin
The administrative control plane.
* **Configurations:** UIs to manage weighted Keywords, RSS Feeds, LLM System prompts/API keys, and global SMTP settings.
* **Danger Zone:** Features destructive tools leveraging generic service commands (e.g., `svc.nuke_tables(["MonitoredLocation"])`) to securely wipe historical state, run PostgreSQL/SQLite database vacuuming routines, or trigger NLP recategorization scripts.
