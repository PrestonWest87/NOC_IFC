# Enterprise Architecture & Algorithmic Specification: `src/aiops_engine.py`

## 1. Executive Overview

The `src/aiops_engine.py` file is the analytical core—the "brain"—of the NOC Intelligence Fusion Center. It houses the `EnterpriseAIOpsEngine` class, which is responsible for ingesting raw, non-uniform telemetry (like SolarWinds webhooks) and transforming it into deterministic, correlated incidents. 

This engine bridges the gap between traditional IT monitoring and external situational awareness. It performs real-time Machine Learning (ML) node mapping, ontological root-cause calculation (factoring in weather, cloud outages, and BGP anomalies), and automated ITSM ticket dispatching. Furthermore, it includes a predictive analytics module to detect chronic, long-term degradation patterns before they result in catastrophic failure.

---

## 2. Core Engine Initialization

### `EnterpriseAIOpsEngine` Class
The engine is instantiated with an active database session (`SessionLocal`).
* **`__init__(self, db_session)`**: Binds the database session and immediately loads the active dictionary of learned aliases into memory for rapid cross-referencing.
* **`_load_aliases(self)`**: Queries the `NodeAlias` database table to build an internal dictionary (`self.aliases`) mapping known raw node patterns to formal `MonitoredLocation` names.

---

## 3. The Node Mapping Pipeline

Raw monitoring alerts often contain messy, inconsistent device names (e.g., `FW-AR-LIT-01` vs. `Little Rock Firewall`). The engine uses a robust, 5-stage pipeline to sanitize and map these strings to physical database locations.

### `map_node_to_location(self, raw_node_name, raw_payload)`
This function executes the following waterfall logic:

1.  **Exact Match**: Checks if the `raw_node_name` directly matches a known `MonitoredLocation` name in the database.
2.  **Verified Alias Match**: Consults the in-memory `self.aliases` dictionary. If a verified alias exists for the raw string, it maps it instantly.
3.  **Heuristic / Regex Matching**: Applies predefined business-logic regex patterns (e.g., looking for `-AR-` to imply Arkansas) to catch obvious nomenclature standards.
4.  **Machine Learning Prediction (Scikit-Learn)**: If deterministic methods fail, it attempts to load `src/ml_model.pkl` (a trained Random Forest/TF-IDF pipeline) via `predict_alias()`. The ML model guesses the location based on historical data context and returns a `predicted_loc` and `confidence_score`. 
    * *Feedback Loop:* The engine automatically writes this ML guess into the `NodeAlias` table as unverified (`is_verified=False`), allowing human operators to review and confirm it in the UI later.
5.  **Fallback**: If all methods fail, the node is flagged as `"Unmapped"` for manual intervention.

---

## 4. Ontological Incident Correlation & Root Cause Analysis

Once nodes are mapped to physical sites, the engine clusters individual alerts into macro-incidents and calculates causation.

### `analyze_and_cluster(self, active_alerts)`
* **Functionality**: Groups an array of raw `SolarWindsAlert` objects by their `mapped_location`.
* **Metadata Extraction**: For each site, it builds a metadata dictionary containing:
    * The total number of downed nodes.
    * A list of the specific device names affected.
    * The distinct network domains affected (e.g., separating `NETWORK_ACCESS` switches from `SD-WAN` routers) based on the `event_category` of the alerts.

### `calculate_root_cause(self, site_name, site_data, active_weather, active_cloud, active_bgp)`
This is the master algorithm for determining *why* a site failed and *how bad* the failure is. It returns seven distinct metrics:

1.  **Patient Zero Detection (`p0`)**: Sorts all alerts at the site chronologically to identify the exact device that failed first.
2.  **Cascade Duration (`cascade_time`)**: Calculates the time differential (in seconds/minutes) between Patient Zero failing and the most recent node failing. This reveals whether a failure was instantaneous (e.g., a power cut) or a slow degradation (e.g., a spanning-tree loop).
3.  **Blast Radius (`blast_radius`)**: 
    * If the failure spans multiple network domains, it is flagged as a **"Cross-Subnet Cascade"**.
    * If contained to one domain, it is an **"Isolated Domain Segment"**.
4.  **External Factor Overlay (The "Evidence" Array)**:
    * *Weather/Grid*: Checks if the `site_name` intersects with any active `RegionalHazard` or `RegionalOutage` geometry.
    * *Cloud*: Scans the raw payload of the alerts to see if it mentions down APIs matching active `CloudOutage` providers.
    * *BGP*: Checks if the payload implicates specific ASNs currently tracked in the `BgpAnomaly` table.
5.  **Priority Calculation Matrix (`priority`)**:
    * **P1 - CRITICAL**: Requires $\ge$ 3 down nodes AND crosses multiple network domains.
    * **P2 - HIGH**: Multiple nodes down, but isolated to a single domain.
    * **P3 - MODERATE**: Single node isolation.
6.  **Root Cause & Confidence Synthesis**: Generates a finalized string (e.g., `"Environmental Overwhelm (Severe Weather Context)"`) and assigns a confidence percentage (e.g., `95%` if weather correlates, `70%` if purely internal infrastructure cascade).

---

## 5. ITSM Integration & Dispatch

### `generate_itsm_payload(...)`
* **Functionality**: Takes the structured data from the Root Cause algorithm and compiles it into a highly readable, standardized plaintext/Markdown template.
* **Structure**: The payload includes an Incident Dispatch header (Priority, Blast Radius, Cascade Duration, Site Address), an AI Forensic Analysis block (Root Cause & Evidence), and an Affected Infrastructure Inventory grouped by domain.

### `send_to_ticketing_system(self, sys_config, title, payload)`
* **Functionality**: The dispatch mechanism. Currently, it utilizes the `send_alert_email` function from `src.mailer` to transmit the generated payload to an ITSM ingestion email address (defined in `SystemConfig.smtp_recipient`). It returns a success boolean and status message.

---

## 6. Predictive Analytics & Chronic Pattern Recognition

This module shifts the engine from *reactive* correlation to *proactive* analytics, querying historical databases to find micro-failures that humans miss.

### `generate_chronic_insights(self, days_back=30)`
Queries the `SolarWindsAlert` and `TimelineEvent` tables over the specified lookback period to generate three Pandas DataFrames:

1.  **Cellular Micro-Blips (`flap_df`)**:
    * *Algorithm*: Identifies alerts where the `device_type` is Cellular/LTE and the time difference between the alert creation (`received_at`) and resolution (`resolved_at`) is less than 5 minutes.
    * *Output*: Aggregates counts of these "blips" per node, highlighting circuits that are chronically unstable (flapping) but resolve too quickly for human NOC operators to ticket.
2.  **VSAT Environmental Vulnerability (`vsat_df`)**:
    * *Algorithm*: Isolates alerts for VSAT/Satellite connections. It attempts to cross-reference the timestamps of these outages with historical `RegionalHazard` data for the specific site.
    * *Output*: Generates a `Vulnerability_Score` out of 100. A high score indicates a satellite dish that is highly susceptible to minor rain fade and requires physical realignment or a terrestrial backup circuit.
3.  **Chronic Hardware Reboots (`reboot_df`)**:
    * *Algorithm*: Counts instances where the same physical node alerts for "Unexpected Reboot" or purely logical down/up states sequentially.
    * *Output*: Highlights specific devices experiencing recurring hardware instability, indicating failing internal components (e.g., bad RAM or power supplies) before a hard crash.
