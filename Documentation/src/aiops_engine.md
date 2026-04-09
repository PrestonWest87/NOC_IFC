# Enterprise Architecture & Algorithmic Specification: `src/aiops_engine.py`

## 1. Executive Overview

The `src/aiops_engine.py` file is the analytical core—the "brain"—of the NOC Intelligence Fusion Center. It houses the `EnterpriseAIOpsEngine` class, which is responsible for ingesting raw, non-uniform telemetry (like SolarWinds alerts) and transforming it into deterministic, multi-domain correlated incidents. 

In its current architectural iteration, this engine has evolved from simple time-based clustering to a **Topological Ontology Model**. It calculates root cause by evaluating the hierarchical dependencies of physical infrastructure and dynamically cross-referencing those failures against external situational awareness grids (Severe Weather, Global BGP anomalies, and Cloud Provider outages). Furthermore, it includes a predictive analytics module utilizing Pandas to detect chronic, long-term degradation patterns before they result in catastrophic failure.

---

## 2. Infrastructure Ontology & Dependency Hierarchy

To accurately determine cascading failures, the engine must understand the physical and logical realities of network architecture. It accomplishes this via hardcoded ontological mappings.

### `ONTOLOGY` & `DOMAIN_WEIGHTS`
The engine categorizes arbitrary device strings (e.g., "Lanolinx-switch" or "VSAT Modem") into six foundational infrastructure domains. Each domain is assigned a topological weight representing its criticality to the site's survival. If a high-weight domain fails, it inherently causes the failure of lower-weight domains.

* **POWER_ENV (Weight: 100):** UPS, Generators, HVAC. *(If power dies, everything dies).*
* **TRANSPORT_CORE (Weight: 80):** Routers, DWDM, Firewalls, Service Providers, VSAT Modems, Radios. *(If transport dies, the site is isolated).*
* **NETWORK_ACCESS (Weight: 60):** Switches, Fabric Interconnects, Wireless Controllers, Access Points.
* **COMPUTE_STORAGE (Weight: 40):** VM Hosts, Physical Servers, SANs, NTP Servers.
* **SCADA_OT (Weight: 20):** RTUs, Plant Equipment, Meters, I/O.
* **FACILITIES_IOT (Weight: 20):** IP Cameras, Access Control Panels, Intercoms.

---

## 3. Incident Clustering & The "Patient Zero" Algorithm

Raw monitoring platforms often trigger "alert storms" where a single failure generates dozens of downstream alerts. The engine suppresses this noise by clustering alerts and mathematically isolating the origin node.

### `analyze_and_cluster(self, active_alerts)`
* **Functionality:** Ingests an array of active alerts and groups them by `site_name` (extracted from custom properties or mapped aliases).
* **Metadata Extraction:** For each site cluster, it calculates aggregate telemetry:
    * Averages CPU Load and Packet Loss (`avg_cpu`, `avg_loss`).
    * Tracks all unique IP addresses involved to determine if the failure spans multiple VLANs via `_analyze_subnets()` (calculating the "Blast Radius").
    * Compiles a breakdown of affected device types and domains.

### `_determine_patient_zero(self, alerts)`
**The Supreme Patient Zero Algorithm:** Traditional monitoring relies purely on timestamps to find the root cause. This fails due to varied SNMP/WMI polling cycles (a server might alert 2 minutes before the router that actually caused the outage). This algorithm bypasses the "polling cycle trap" using a weighted scoring matrix. It forces all alerts—even isolated single events—through this loop to ensure perfectly consistent data structures:
1.  **Topological Score:** `DOMAIN_WEIGHT * 1000`. (A core router inherently outranks a server).
2.  **Severity Score:** Hard "Down" states or 100% packet loss add 500 points. "Warning" states add 100 points.
3.  **Time Offset Penalty:** Subtracts points based on the seconds elapsed since the very first alert in the cluster, capped at 200 points. 
* *Result:* A foundational node (like a Router) that alerts 3 minutes late will correctly outrank a downstream node (like an IP Camera) that alerted immediately.

---

## 4. Multi-Domain Root Cause Analysis (RCA)

Once the Patient Zero is identified, the engine executes deterministic correlation against external intelligence grids.

### `calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp)`
This master algorithm evaluates the clustered data against distinct correlation tiers and scoring mechanisms. It returns a definitive cause, an Evidence Log, a Blast Radius, and an Incident Priority (P1/P2/P3).

1.  **Dependency Cascade (Score: +20):** If the incident spans multiple infrastructure domains, a baseline penalty is added to account for the widespread downstream isolation.
2.  **Cloud / Upstream Correlation (Score: +85):** Scans the raw payload and node names against active global `CloudOutage` objects. If a node relies on a degraded SaaS/IaaS provider, the outage is attributed externally.
3.  **BGP / Routing Correlation (Score: +75):** If the failure resides in the `TRANSPORT_CORE` domain, the engine checks the site's primary/secondary carrier ASNs against active global `BgpAnomaly` events.
4.  **Hardware / Domain Heuristics (Score: Variable):** If no external digital factors align, it evaluates the internal domain of Patient Zero:
    * *POWER_ENV:* "Catastrophic Facilities/Power Failure" (+60)
    * *TRANSPORT_CORE (>80% Loss):* "WAN Isolation" (+50)
    * *SCADA_OT:* "Isolated OT/SCADA Telemetry Failure" (+30)
    * *COMPUTE_STORAGE (>90% CPU):* "Resource Exhaustion" (+30)
    * *NETWORK_ACCESS (Single Subnet):* "Localized Access Layer Failure" (+20)
5.  **Geospatial Weather / Grid Correlation (Score: +40 to +55):** Uses the Haversine formula (`math.asin(math.sqrt(...))`) to calculate the exact distance in miles between the site's database latitude/longitude and the epicenter of active regional hazards (e.g., Tornado Warnings, NIFC Wildfires). If the distance is within the hazard radius, the failure is upgraded to a "Direct Kinetic Impact".
6.  **Policy Override (Score: +50):** If the native monitoring tool explicitly flagged the alert payload with an `Alert_Level` of 1, the engine forcefully weights the incident to guarantee a critical escalation.

---

## 5. Predictive Analytics & Chronic Pattern Recognition

This module shifts the engine from *reactive* correlation to *proactive* analytics. By executing heavy Pandas DataFrame aggregations against the historical database, it identifies degrading hardware before catastrophic failure occurs.

### `generate_chronic_insights(self, days_back=30)`
Queries historical events dynamically via the engine's generic `alert_model` (defaulting to `SolarWindsAlert`) over a specified lookback period to generate three distinct operational intelligence reports:

1.  **Cellular Micro-Blips (`flap_summary`):**
    * *Algorithm:* Isolates alerts where the primary/secondary comms involve "Cellular" or "LTE" and the total duration of the outage is strictly `> 0` and `< 5.0` minutes.
    * *Output:* Highlights circuits that are chronically state-flapping. These rapid connections/disconnections often resolve too quickly for human operators to notice or ticket, but indicate failing carrier signal strength.
2.  **VSAT Environmental Vulnerability (`vsat_summary`):**
    * *Algorithm:* Aggregates total outage events specifically targeting nodes utilizing VSAT/Satellite transport.
    * *Output:* Generates a `Vulnerability_Score` out of 100. High-scoring sites represent satellite arrays highly susceptible to minor environmental shifts (rain fade), indicating a need for physical dish realignment or terrestrial fallback provisioning.
3.  **Chronic Hardware Reboots (`reboot_summary`):**
    * *Algorithm:* Filters the historical event payload for strings matching `reboot`, `crash`, or `unexpected`.
    * *Output:* Identifies specific physical devices experiencing recurring, uncommanded state resets—a primary indicator of failing internal hardware (e.g., degraded RAM, failing power supply) preceding a total device death.
