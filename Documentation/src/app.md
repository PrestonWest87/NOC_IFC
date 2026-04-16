# Enterprise Architecture & Functional Specification: `src/app.py`

## 1. Executive Overview

The `src/app.py` module serves as the **Primary Presentation and Controller Layer** for the Intelligence Fusion Center (IFC). Built on the Streamlit framework, it acts as the interactive frontend for Network Operations Center (NOC) personnel.

In its latest architectural iteration, this module enforces a strict **Service-Oriented Architecture (SOA) pattern**. It explicitly bans direct database Model imports for data mutation, delegating transactions to the dedicated `src.services` layer. Furthermore, it introduces robust UI debouncing, a cookie-persistent dynamic theming engine, advanced PyDeck geospatial rendering, a comprehensive internal asset tracking dashboard, and an integrated AI-driven Shift Logbook.

---

## 2. Core Architecture: The Service Layer & State Management

### 2.1 Separation of Concerns (Controller vs. Model)
The application architecture imports `src.services as svc` and heavily relies on its abstracted `DotDict` returns. 
* **Architectural Benefit:** This decoupling ensures that `app.py` only handles DOM rendering, session states, and layout execution, completely sidestepping fatal `DetachedInstanceError` exceptions during asynchronous Streamlit re-renders.

### 2.2 UI Debouncing & Rate Limiting (The Cooldown Engine)
The application integrates a custom rate-limiting mechanism (`check_cooldown` and `apply_cooldown`) to protect expensive backend processes (like LLM generation, RSS syncing, or API polling) from accidental user spam. Buttons automatically disable themselves and dynamically change their labels (e.g., from "Generate Report" to "⏳ Generating...") during cooldown windows.

### 2.3 Auto-Refresh Timers
The module leverages the `streamlit_autorefresh` library to create autonomous "Wall Monitor" modes.
* **Global Dashboards:** Configurable to refresh every 10 seconds, 1 minute, or 5 minutes, featuring an auto-rotate toggle that cycles sequentially through internal sub-panels.
* **AIOps RCA:** Implements a dedicated 5-second polling loop to actively monitor real-time infrastructure telemetry and event logs.

### 2.4 Dynamic UI Theming Engine
Introduces a cookie-persistent CSS injection engine to allow operator-specific aesthetic customization without altering global states.
* **Themes Available:** Standard, NOC Terminal, High Contrast (Dark), Cyberpunk, Solarized Dark, and Midnight Ocean.
* **Execution:** Theme selections are saved to the browser via `CookieController` (`noc_theme_[user]`) for 30-day persistence. The system overrides Streamlit's base styling with aggressive custom CSS logic upon rendering.

---

## 3. Initialization, Authentication & RBAC

### 3.1 Authentication Lifecycle
* **Persistent Sessions:** The application integrates `CookieController` to set and retrieve a `noc_session_token` with a 30-day expiration. 
* **Login Flow:** If no valid cookie exists, the app halts execution (`st.stop()`) and renders a login form. Upon successful authentication, the token is minted, and the UI rerenders.

### 3.2 Granular Role-Based Access Control (RBAC)
Permissions are explicitly defined via descriptive string arrays (`ALL_POSSIBLE_PAGES` and `ALL_POSSIBLE_ACTIONS`).
* **Dynamic Action Gates:** Boolean variables (e.g., `can_pin`, `can_trigger_ai`, `can_sync`) dynamically disable or hide UI buttons based on the user's assigned role.
* **Site Type Restrictions:** Custom roles can now be geographically or operationally restricted to specific `allowed_site_types`, automatically filtering the AIOps active board and Regional Grid maps to only show authorized facilities.

---

## 4. Module Specifications (Page Routing)

The application utilizes `st.sidebar.radio` to route operators between 8 distinct operational modules based on their allowed pages.

### 4.1 Global Dashboards
* **Operational Dashboard:** Displays top-level 24-hour KPIs. Houses auto-rotating panels for "Threat Triage" (Pinned/Live intel), "Infrastructure Status" (Active Cloud Outages, CVEs, Hazards), and an "AI Analysis" panel featuring an LLM-powered rolling summary and Security Auditor.
* **Global Risk (Executive Matrix):** Evaluates live unified threat posture (Cyber + Physical) against a 14-Day Baseline Deviation Trend utilizing the MS-ISAC/CIS Alert Framework (GREEN to RED). Features an interactive PyDeck map of localized perimeter crimes and a one-click HTML email dispatch engine.
* **Internal Risk (Asset Posture):** A new dedicated dashboard that tracks the organization's hardware and software footprint against active OSINT threats, producing a localized CIS risk score and highlighting critical asset exposures.
* **Unified Brief:** Generates a high-level executive narrative synthesizing both Global OSINT and Internal Risk, automatically updating every two hours.

### 4.2 Threat Telemetry
* **RSS Triage:** Implements advanced pagination logic to gracefully render thousands of threat articles across "Pinned", "Live", "Low", and "Search" sub-tabs.
* **Exploits (KEV) & Cloud Services:** Manual synchronization interfaces for the CISA database and active IaaS/SaaS outages.
* **Perimeter Crime:** Renders a 3D PyDeck map of localized LRPD dispatch data geofenced around HQ. Features dynamic radius filtering (1, 3, 5, or 10 miles) and interactive row-selection that auto-zooms and highlights specific crimes on the map.

### 4.3 Regional Grid
* **Geospatial Map:** Deep integration with PyDeck to overlay NOC facilities with active SPC Convective outlooks, NWS Warnings/Watches, NIFC Active Wildfires, and NWS Red Flag warnings. Includes an embedded live animated precipitation radar iframe.
* **Executive Dashboard & Analytics:** Uses Plotly pie and bar charts to present critical infrastructure exposure by District, Priority, and Threat Type, along with an AI Meteorological Briefing generator.

### 4.4 Threat Hunting & IOCs
* **Live Global IOC Matrix:** Displays extracted IOCs (IPv4, SHA256, CVE) with hyperlinked "OSINT Pivots" to external tools like VirusTotal and Shodan, fully exportable to CSV.
* **Deep Hunt Builder:** Takes a target entity (e.g., "Volt Typhoon"), queries historical telemetry, and instructs the LLM to generate custom Splunk/SIEM queries, MITRE mappings, and YARA rules.

### 4.5 AIOps RCA (Root Cause Analysis)
* **Active Board:** Renders an auto-focusing PyDeck map of alerting locations. Integrates **Global Fleet Event Detection** (warning of massive carrier/ISP outages) and **TOC/NOC Maintenance Controls**. Features a ticket dispatch system that drafts LLM correlation narratives direct to RemedyForce.
* **Predictive Analytics:** Executes Pandas aggregations to highlight specific nodes experiencing state-flapping and sites suffering from chronic instability over 60-day historical periods.
* **Global Correlation:** Deterministically graphs causal links between external global intelligence and internal network telemetry drops.

### 4.6 Shift Logbook (NEW)
A highly requested tactical tool replacing external notepads, heavily reliant on AI Map-Reduce.
* **Active Incident Entry:** Analysts log manual updates or utilize the "Auto-Draft Active Outages" engine, which polls the AIOps Engine to automatically format and insert active down-times into the log.
* **Persistent Daily Summaries:** Generates automated "End of Morning" and "End of Day" handoff reports using the LLM. Admins can run retroactive EOD reports for missed days.
* **Aggregated Executive Summaries:** Allows operators to target specific organizational roles (e.g., Network Analysts) and run deep LLM Map-Reduce analyses summarizing historical logs across an entire "Current Week" or "Current Month."
* **Log Explorer:** A dynamic day/week calendar interface featuring soft-delete auditing, modal expansions, and an Admin CSV export utility.

### 4.7 Reporting & Briefings
* **Daily Fusion Report:** An archive of automated AI-synthesized situational reports covering Cyber, Physical, and Cloud telemetry, natively converting Markdown into HTML for enterprise email distribution.
* **Report Builder & Shared Library:** A multi-select interface allowing analysts to manually aggregate database articles into a custom LLM pipeline, saving the output to an organizational directory.

### 4.8 Settings & Admin
The control plane containing eight sub-tabs:
* **Facilities & Internal Assets:** Bulk JSON/CSV importers to manage Monitored Locations, Hardware tracking, and Software footprints.
* **RSS Sources & ML Training:** General database mutation and neural weight re-calibration interfaces.
* **AI & SMTP:** Manages LLM endpoints, tech stack inputs, mail servers, and custom baseline overrides for the Executive Threat Matrix.
* **Users & Roles:** Granular RBAC controls allowing admins to craft custom roles mapped to specific pages, UI actions, and authorized facility types.
* **Danger Zone:** Houses destructive tools to run the Garbage Collector, clear crime/weather telemetry arrays, or trigger full factory database resets. 
* **Black Ops:** Undocumented operational tools (*Operation: Nick* and *Operation: Dean*) used for targeted screen locks or cascading failure mock drills.**
