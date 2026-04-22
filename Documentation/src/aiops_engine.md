# Enterprise Architecture & Algorithmic Specification: `src/aiops_engine.py`

## 1. Executive Overview

The `src/aiops_engine.py` file is the analytical core—the "brain"—of the NOC Intelligence Fusion Center. It houses the `EnterpriseAIOpsEngine` class, which is responsible for ingesting raw, non-uniform telemetry (like SolarWinds alerts) and transforming it into deterministic, multi-domain correlated incidents. 

In its current architectural iteration, this engine utilizes a **Topological Ontology Model** with **Structural Dominance Tiering**. It calculates root cause by evaluating the hierarchical dependencies of physical infrastructure and dynamically cross-referencing those failures against external situational awareness grids (Severe Weather, Global BGP anomalies, Cloud Provider outages, and Regional Fleet Outages). Furthermore, it includes a robust predictive analytics module utilizing Pandas to detect chronic, long-term degradation patterns over a 60-day baseline before they result in catastrophic failure.

---

## 2. Infrastructure Ontology & Dependency Hierarchy

To accurately determine cascading failures, the engine must understand the physical and logical realities of network architecture. It accomplishes this via hardcoded ontological mappings and a strict tiering system.

### `ONTOLOGY` & `TIER_RANKING`
The engine categorizes arbitrary device strings (e.g., "Lanolinx-switch" or "VSAT Modem") into six foundational infrastructure domains. Replacing the legacy weight system, each domain is now assigned a `TIER_RANKING` from 1 to 6, where a *lower number indicates higher structural authority*. 

* **Tier 1: POWER_ENV:** UPS, Generators, HVAC, PDU. *(If power dies, everything dies).*
* **Tier 2: TRANSPORT_CORE:** Routers, DWDM, Firewalls, Service Providers, VSAT Modems, Radios. *(If transport dies, the site is isolated).*
* **Tier 3: NETWORK_ACCESS:** Switches, Fabric Interconnects, Wireless Controllers, Access Points.
* **Tier 4: COMPUTE_STORAGE:** VM Hosts, Physical Servers, SANs, NTP Servers.
* **Tier 5: SCADA_OT:** RTUs, Plant Equipment, Meters, I/O.
* **Tier 5: FACILITIES_IOT:** IP Cameras, Access Control Panels, Intercoms.
* **Tier 6: UNKNOWN_DOMAIN:** Any unrecognized device type.

---

## 3. Incident Clustering & The "Patient Zero" Algorithm

Raw monitoring platforms often trigger "alert storms" where a single failure generates dozens of downstream alerts. The engine suppresses this noise by clustering alerts and mathematically isolating the origin node.

### `analyze_and_cluster(self, active_alerts)`
* **Functionality:** Ingests an array of active alerts and groups them by `site_name` (extracted from custom properties or mapped aliases).
* **Metadata Extraction:** For each site cluster, it safely extracts and calculates aggregate telemetry, heavily guarded against `KeyError` and `TypeError` exceptions:
    * Averages CPU Load and Packet Loss (`avg_cpu`, `avg_loss`).
    * Tracks all unique IP addresses involved to determine if the failure spans multiple VLANs (calculating the "Blast Radius").
    * Computes a "Cascade Delay" by comparing the timestamp of Patient Zero to the most recent alert in the cluster.

### `_determine_patient_zero(self, alerts)`
**The Supreme Patient Zero Algorithm:** Traditional monitoring relies purely on timestamps to find the root cause, which fails due to varied SNMP/WMI polling cycles. This algorithm bypasses the "polling cycle trap" using a newly updated weighted scoring matrix:
1.  **Topological Score:** Calculated mathematically as `(7 - tier) * 2000`. A Tier 1 Power device inherently scores 12,000, vastly outranking a Tier 5 IP Camera (4,000).
2.  **Severity Score:** Hard "Down" states, 100% packet loss, or "offline" categories add 1000 points. "Critical" states or >50% loss add 500 points. "Warning" states add 100 points.
3.  **Time Offset Penalty:** Acts as a micro-tiebreaker within the *same* tier. Subtracts points based on the seconds elapsed since the very first alert in the cluster, capped at a maximum penalty of 200 points. 
* *Result:* Structural topology securely outweighs minor polling delays, guaranteeing the true foundational failure is always identified as Patient Zero.

---

## 4. Multi-Domain Root Cause Analysis (RCA)

Once Patient Zero is identified, the engine executes deterministic correlation against external intelligence grids.

### `calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events)`
This master algorithm evaluates the clustered data against distinct correlation tiers. It returns a definitive cause, an Evidence Log, a Blast Radius, Patient Zero, and the Cascade Delay.

1.  **Dependency Cascade (Score: +20):** Base penalty added if the incident spans multiple infrastructure domains.
2.  **Fleet / Regional Carrier Correlation (Score: +100):** *NEW.* Uses `identify_fleet_outages` to detect if 5 or more sites sharing the same primary communications provider go down simultaneously. Overrides local diagnostics to declare a "Regional Carrier Outage."
3.  **Cloud / Upstream Correlation (Score: +85):** Scans the raw payload against active global `CloudOutage` objects. Attributes failure to upstream SaaS/IaaS providers if a match is found.
4.  **BGP / Routing Correlation (Score: +75):** If the failure resides in the `TRANSPORT_CORE`, the engine checks the site's carrier ASNs against global `BgpAnomaly` events.
5.  **Hardware / Topological Heuristics (Score: +30 to +60):** If no external digital factors align, it evaluates the internal domain of Patient Zero:
    * *POWER_ENV:* "Catastrophic Facilities/Power Failure" (+60)
    * *TRANSPORT_CORE (>80% Loss or Down):* "Site Isolation" (+50)
    * *SCADA_OT:* "Isolated OT/SCADA Telemetry Failure" (+30)
6.  **Geospatial Weather / Grid Correlation (Score: +40 to +55):** Uses the Haversine formula (`math.asin(math.sqrt(...))`) to calculate the exact distance in miles between the site and active regional hazards. If the site is within the storm's radius, it is escalated to a "Direct Kinetic Impact."
7.  **Policy Override (Score: +50):** Automatically escalates incidents explicitly flagged with `Alert_Level = 1` by the native monitoring tool.

---

## 5. Predictive Analytics & Chronic Pattern Recognition

This module shifts the engine from *reactive* correlation to *proactive* analytics, moving to a heavy 60-day historical window.

### `generate_chronic_insights(self)`
Queries historical `SolarWindsAlert` records over the last 60 days, aggressively filtering out resolved messages to focus strictly on degradation events. It utilizes Pandas DataFrames to return three targeted operational intelligence reports:

1.  **Top Offending Nodes (`f` DataFrame):** Aggregates and returns the top 15 specific physical devices experiencing the highest volume of chronic failures or flapping states.
2.  **Infrastructure Hotspots (`v` DataFrame):** Aggregates and returns the top 10 physical facility sites experiencing the highest overall volume of IT incidents, exposing localized power or transport instability.
3.  **AI Predictive Maintenance Forecast (`r` list):** An automated insights engine that flags nodes with >5 incidents a week as "CRITICAL FLAP DETECTED" or sites with >15 incidents as "REGIONAL DEGRADATION", generating explicit, actionable recommendations for field technicians (e.g., circuit testing, power conditioning checks).

---

## 6. Complete Function Reference

### Class: EnterpriseAIOpsEngine

| Method | Signature | Purpose |
|-------|----------|---------|
| `__init__` | `(self, db_session)` | Initialize session |
| `_get_domain` | `(self, node_type) -> str` | Get domain from node type |
| `_determine_patient_zero` | `(self, alerts) -> dict` | Determine root alert |
| `identify_fleet_outages` | `(self, incidents, threshold) -> list` | Detect fleet outages |
| `generate_chronic_insights` | `(self) -> dict` | Chronic analytics |
| `calculate_root_cause` | `(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events) -> dict` | Root cause analysis |
| `analyze_and_cluster` | `(self, active_alerts) -> dict` | Cluster alerts |

### Constants

| Constant | Type | Description |
|----------|-----|-------------|
| `ONTOLOGY` | `dict` | Device type ontology (6 domains) |
| `TIER_RANKING` | `dict` | Domain priority ranking |

---

## 7. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| pandas | Data processing | https://pandas.pydata.org/ |
| math | Calculations | https://docs.python.org/3/library/math.html |
| ipaddress | IP validation | https://docs.python.org/3/library/ipaddress.html |
