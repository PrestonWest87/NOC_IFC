# Enterprise Architecture & Functional Specification: `src/app.py`

## 1. Executive Overview

The `src/app.py` module serves as the **Primary Presentation and Controller Layer** for the Intelligence Fusion Center (IFC). Built on the Streamlit framework, it acts as the interactive frontend for Network Operations Center (NOC) personnel.

In its latest architectural iteration, this module has undergone a major refactoring to enforce a strict **Service-Oriented Architecture (SOA) pattern**. It explicitly bans direct database Model imports (e.g., SQLAlchemy ORM models), delegating all data persistence, querying, and mutation to the dedicated intermediate `src.services` layer. Furthermore, it introduces robust UI debouncing to protect backend systems, a cookie-persistent dynamic theming engine, advanced PyDeck/Plotly visual analytics, and an integrated AI-driven Shift Logbook.

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
* **Global Dashboards:** Configurable to refresh every 10 seconds, 1 minute, or 5 minutes. Includes a native "Auto-Rotate" toggle that cycles sequentially through internal sub-panels on each refresh interval.
* **AIOps RCA:** Implements a dedicated 5-second polling loop to actively monitor telemetry and grid health.

### 2.4 Dynamic UI Theming Engine
Introduces a cookie-persistent CSS injection engine to allow operator-specific aesthetic customization.
* **Themes Available:** Standard, NOC Terminal, High Contrast (Dark), Cyberpunk, Solarized Dark, and Midnight Ocean.
* **Execution:** Theme selections are saved to the browser via `CookieController` (`noc_theme_[user]`) for 30-day persistence. The system overrides Streamlit's base styling with aggressive custom CSS logic upon rendering.

---

## 3. Initialization, Authentication & RBAC

### 3.1 Authentication Lifecycle
* **Persistent Sessions:** The application integrates `CookieController` to set and retrieve a `noc_session_token` with a 30-day expiration (`max_age=30*86400`). 
* **Login Flow:** If no valid cookie exists, the app halts execution (`st.stop()`) and renders a login form. Upon successful authentication via `svc.authenticate_user()`, the token is minted and the UI rerenders.

### 3.2 Granular Role-Based Access Control (RBAC)
Permissions are explicitly defined via descriptive string arrays (`ALL_POSSIBLE_PAGES` and `ALL_POSSIBLE_ACTIONS`).
* **Admin Override:** If a user possesses the "admin" role, they are forcefully granted all possible pages and actions.
* **Dynamic Action Gates:** Boolean variables (e.g., `can_pin`, `can_trigger_ai`, `can_sync`) are evaluated on every page load to dynamically disable or hide specific UI buttons based on the user's assigned role. 

---

## 4. Module Specifications (Page Routing)

The application utilizes `st.sidebar.radio` to route operators between 8 distinct operational modules based on their allowed pages.

### 4.1 Global Dashboards
* **Operational Dashboard:** Displays top-level 24-hour KPIs. Houses auto-rotating panels for "Threat Triage" (Pinned/Live intel), "Infrastructure Status" (Active Cloud Outages, CVEs, Hazards), and an "AI Analysis" panel featuring an LLM-powered rolling summary and Security Auditor for the defined tech stack.
* **Executive Matrix:** A strategic dashboard implementing the official MS-ISAC / CIS Alert Levels (-8 to +8 mapped to GREEN, BLUE, YELLOW, ORANGE, RED).
    * Evaluates live unified threat posture (Cyber + Physical) against a dynamically generated 14-Day Threat Deviation Trend (visualized via a pandas line chart).
    * Features a macroscopic evidence log and an AI generator that synthesizes scoring rationale into a broadcast-ready HTML email.

### 4.2 Threat Telemetry
A deeply technical tab partitioned by RBAC sub-tabs.
* **RSS Triage:** Implements advanced pagination logic to gracefully render thousands of threat articles across "Pinned", "Live", "Low", and "Search" sub-tabs.
* **Exploits (KEV) & Cloud Services:** Manual synchronization interfaces for the CISA database and active IaaS/SaaS outages.
* **Perimeter Crime:** Renders a 3D PyDeck map of localized LRPD dispatch data geofenced around HQ, capable of dynamic radius filtering (1, 3, 5, or 10 miles).

### 4.3 Regional Grid
* **Map Controls & Geospatial Overlay:** Deep integration with PyDeck to overlay NOC facilities with active SPC Convective outlooks, NWS Warnings/Watches, NIFC Active Wildfires, and Live Radar loops via iframe components.
* **Executive Dashboard:** Uses Plotly pie and bar charts to present critical infrastructure exposure by District, Priority, and Threat Type, along with an AI Meteorological Briefing generator.
* **Analytics & Alerts Log:** Provides matrix dataframes of facility intersections and deep-dive inspection windows into explicit NWS action instructions.

### 4.4 Threat Hunting & IOCs
* **Global IOC Matrix:** Displays a dataframe of Extracted IOCs (IPv4, SHA256, CVE) and utilizes `st.column_config.LinkColumn` to generate hyperlinked "OSINT Pivots" to VirusTotal and Shodan.
* **Deep Hunt Builder:** Takes a target entity (e.g., "Volt Typhoon"), queries historical telemetry up to 90 days back, and instructs the LLM to generate custom Splunk/SIEM queries, MITRE mappings, and YARA rules.

### 4.5 AIOps RCA (Root Cause Analysis)
* **Active Board:** Renders an auto-focusing PyDeck map of alerting locations. Integrates new **TOC/NOC Maintenance Controls** (for silencing and scheduling ETRs on facilities) and a robust **Ticket Dispatch System** that drafts LLM correlation narratives direct to RemedyForce.
* **Predictive Analytics:** Executes deep Pandas aggregations to highlight specific nodes experiencing state-flapping and sites suffering from chronic instability.
* **Global Correlation Engine:** Deterministically graphs causal links between external global intelligence and internal network telemetry drops.

### 4.6 Shift Logbook (NEW MODULE)
A highly requested tactical tool replacing external notepads, heavily reliant on AI Map-Reduce.
* **Active Incident Entry:** Analysts can input manual updates or utilize the "Auto-Draft Active Outages" engine, which polls the `AIOps Engine` to calculate the exact duration and suspected "Patient Zero" of active offline sites.
* **Handoff Generation:** Synthesizes the running day's log into a concise 2-3 paragraph end-of-shift report for oncoming personnel.
* **Aggregated Executive Summaries:** Allows operators to target specific organizational roles (e.g., Network Analysts) and run deep LLM analyses summarizing historical logs across an entire "Current Week" or "Current Month."
* **Log Explorer:** A dynamic day/week calendar interface featuring soft-delete auditing, modal expansions, and an Admin CSV export utility.

### 4.7 Reporting & Briefings
* **Daily Fusion Report:** An archive of automated AI-synthesized situational reports covering Cyber, Physical, and Cloud telemetry, natively converting Markdown into HTML for broad enterprise email distribution.
* **Report Builder & Shared Library:** A multi-select interface allowing analysts to manually aggregate specific database articles into a custom LLM pipeline, saving the output to an organizational directory.

### 4.8 Settings & Admin
The control plane containing seven sub-tabs:
* **Facilities, RSS Sources, ML Training:** General database mutation, data import/export, and neural weight re-calibration interfaces.
* **AI & SMTP:** Manages LLM endpoints, tech stack inputs, and custom baseline overrides for the Executive Threat Matrix.
* **Users & Roles:** Granular RBAC controls allowing admins to craft custom roles mapped to specific pages and UI actions.
* **Danger Zone:** Houses destructive tools to run the Garbage Collector, clear crime/weather telemetry arrays, or trigger full factory database resets. 
* **Black Ops:** Undocumented simulation tools (Operation: Nick and Operation: Dean) used strictly for training simulations and cascading failure mock drills.
