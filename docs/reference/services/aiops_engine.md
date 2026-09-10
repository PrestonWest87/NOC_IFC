# Enterprise AIOps Engine Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services/aiops_engine.py`

The `EnterpriseAIOpsEngine` class provides root cause analysis, incident clustering, fleet outage detection, and chronic instability insights for the NOC's infrastructure monitoring.

---

## Class: `EnterpriseAIOpsEngine`

**Purpose:** Core AIOps correlation engine that analyzes SolarWinds alerts, determines root cause by topology domain, detects fleet/provider-level outages, and generates chronic instability insights.

### Constants

#### `ONTOLOGY` (dict)
Maps topology domains to their component device types:
- `PRIMARY_INTERNET` -- VSAT, Cellular, Radio, SD-WAN, Modem
- `COMMS_EQUIPMENT` -- Router, Switch, Firewall, Lanolinx-switch, Fabric Interconnect
- `POWER_SUPPLIES` -- UPS, Generator, DC Power Supply, PDU, PDS, DC Controller
- `RTU` -- RTU, NTEST RTU
- `SCADA` -- Sub Equipment, Plant Equipment, Meter Point, I/O, Member Equipment, SCADA
- `COMPUTE` -- VM Host, VM Server, Physical Machine, Storage
- `FACILITIES` -- Access Control Panel, Door Controller, IP Camera, HVAC

#### `TIER_RANKING` (dict)
Maps domains to criticality tiers (1 = highest criticality):
- `POWER_SUPPLIES`: 1
- `PRIMARY_INTERNET`: 2
- `COMMS_EQUIPMENT`: 3
- `COMPUTE`: 4
- `RTU`: 5
- `SCADA`: 6
- `FACILITIES`: 7
- `UNKNOWN_DOMAIN`: 8

---

### `__init__(self, session_factory=None)`

**Purpose:** Initializes the engine with an optional custom session factory.

**Parameters:**
- `session_factory` (callable | None) -- Factory function for database sessions. Defaults to `SessionLocal` if not provided.

---

### `_get_domain(self, node_type, node_name="", primary_comms="") -> str`

**Purpose:** Classifies a network node into a topology domain based on type, name, and primary communications.

**Parameters:**
- `node_type` (str) -- Device type from alert payload
- `node_name` (str) -- Node/device name (default: "")
- `primary_comms` (str) -- Primary communication method (default: "")

**Returns:** `str` -- One of: "PRIMARY_INTERNET", "POWER_SUPPLIES", "COMMS_EQUIPMENT", "RTU", "SCADA", or "UNKNOWN_DOMAIN".

**Flow:** Normalizes input to lowercase. Checks for keywords in order: VSAT/cellular/sd-wan/modem -> POWER_SUPPLIES -> router/switch/firewall (with internet check) -> RTU -> SCADA -> falls back to ONTOLOGY matching -> UNKNOWN_DOMAIN.

---

### `_determine_patient_zero(self, alerts) -> tuple`

**Purpose:** Identifies the earliest/causal alert (patient zero) by scoring each alert on topology tier, severity, and timing.

**Parameters:**
- `alerts` (list[SolarWindsAlert]) -- List of related alerts for a site

**Returns:** `tuple[SolarWindsAlert | None, list[dict]]` -- `(patient_zero_alert, scored_alert_chain)`

**Flow:**
1. Captures all valid received times; sets earliest as baseline
2. For each alert, extracts node_type, node_name, primary_comms from raw_payload
3. Determines domain via `_get_domain()`
4. Computes topo_score = `(9 - tier) * 2000`
5. Computes severity score based on status/event_category/loss
6. Applies time penalty (min of time offset in seconds, capped at 200)
7. final_score = topo_score + sev_score - time_penalty
8. Returns highest-scoring alert as patient zero, all scored alerts as dependency chain

---

### `identify_fleet_outages(self, incidents, threshold=5) -> list[dict]`

**Purpose:** Detects provider-level fleet outages when multiple sites share a communications provider.

**Parameters:**
- `incidents` (dict) -- Site-keyed incident dictionary from `analyze_and_cluster()`
- `threshold` (int) -- Minimum sites affected to qualify as fleet outage (default: 5)

**Returns:** `list[dict]` -- Fleet events with provider, affected_sites, event_type, severity.

**Flow:** Groups sites by primary_coms provider. If any provider appears in >= threshold sites with PRIMARY_INTERNET or COMMS_EQUIPMENT domain failures, flags as CRITICAL fleet event.

---

### `generate_chronic_insights(self) -> tuple`

**Purpose:** Analyzes 60 days of alert history to detect chronic node flapping and regional degradation hotspots.

**Returns:** `tuple[list | None, list | None, list | None]` -- `(top_nodes_json, top_sites_json, recommendation_texts)` or `(None, None, None)` if no data.

**Dependencies:** `pandas`, `SolarWindsAlert`, `SessionLocal`

**Flow:**
1. Queries all alerts in the last 60 days
2. Excludes resolved alerts
3. Builds DataFrame of node_name, device_type, site
4. Counts incidents per node, merges metadata
5. Counts incidents per site (excluding Unknown)
6. Generates recommendations: critical flapping flag if top node has >5 incidents; regional degradation flag if top site has >15 incidents
7. Returns JSON-serialized top 15 nodes, top 10 sites, and recommendation texts

---

### `calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events=[]) -> tuple`

**Purpose:** Determines root cause, severity score, and priority for a site incident cluster.

**Parameters:**
- `site_name` (str) -- Site name
- `data` (dict) -- Incident cluster data from `analyze_and_cluster()`
- `active_weather` (list[RegionalHazard]) -- Active weather hazards
- `active_cloud` (list[CloudOutage]) -- Active cloud outages
- `active_bgp` (list[BgpAnomaly]) -- Active BGP anomalies
- `fleet_events` (list) -- Fleet outage events (default: [])

**Returns:** `tuple[str, int, str, list, str, str, str]` -- `(cause, score, priority_str, evidence_log, blast_radius, patient_zero_name, cascade_delay_str)`

**Flow:**
1. Extracts metadata, domains, avg loss, avg CPU from cluster data
2. If patient_zero is None, returns "Indeterminate Failure"
3. If multiple domains affected, scores +20 for dependency cascade
4. Checks fleet events: if site in fleet outage, scores +100
5. Checks cloud correlation: matches alert node_name/payload against active cloud providers
6. Checks BGP correlation: matches ASN against site's primary/secondary comms
7. If no external correlation found, evaluates by patient_zero domain:
   - POWER_SUPPLIES: catastrophic power failure
   - PRIMARY_INTERNET/COMMS_EQUIPMENT: transport outage or congestion
   - SCADA/RTU: isolated OT telemetry failure
   - Other: generalized infrastructure degradation
8. Checks maintenance mode: auto-clears expired ETR
9. Geospatial weather correlation: calculates haversine distance to hazard epicenters
10. Applies alert level override (Level 1 = +50 policy override)
11. Maps max_alert_level to P1-P5 priority with SLA times
12. Returns cause, capped score (max 100), priority string, evidence log, blast radius, patient zero, cascade delay

---

### `analyze_and_cluster(self, active_alerts) -> dict`

**Purpose:** Groups active alerts by site and enriches them with topology metadata for root cause analysis.

**Parameters:**
- `active_alerts` (list[SolarWindsAlert]) -- List of active un-correlated alerts

**Returns:** `dict` -- Site-keyed incident clusters with:
 - `alerts` -- All alerts for the site
 - `site_metadata` -- primary_coms, secondary_coms, district
 - `domains_affected` -- Set of topology domains involved
 - `dependency_chain` -- Scored alert chain from `_determine_patient_zero`
 - `avg_loss` -- List of packet loss percentages
 - `avg_cpu` -- List of CPU load percentages
 - `ips` -- List of IP addresses
 - `max_alert_level` -- Minimum (most critical) alert level
 - `latest_alert` -- Most recent alert by received_at
 - `patient_zero` -- Identified causal alert

**Flow:**
1. Iterates all alerts; groups by site (from Custom_Properties_Universal.Site or mapped_location)
2. Accumulates performance metrics (PercentLoss, CPULoad), IPs, alert levels
3. For each site cluster, calls `_determine_patient_zero()` to identify causal alert and build scored dependency chain
4. Collects unique domains affected from the scored chain
