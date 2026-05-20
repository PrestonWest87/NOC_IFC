# Enterprise Architecture & Algorithmic Specification: `src/aiops_engine.py`

## 1. Executive Overview

The `src/aiops_engine.py` file is the analytical core—the "brain"—of the NOC Intelligence Fusion Center. It houses the `EnterpriseAIOpsEngine` class, which is responsible for ingesting raw, non-uniform telemetry (like SolarWinds alerts) and transforming it into deterministic, multi-domain correlated incidents.

It utilizes a **Topological Ontology Model** with **Structural Dominance Tiering**. It calculates root cause by evaluating the hierarchical dependencies of physical infrastructure and dynamically cross-referencing those failures against external situational awareness grids (Severe Weather, Global BGP anomalies, Cloud Provider outages, and Regional Fleet Outages). It includes a robust predictive analytics module utilizing Pandas to detect chronic, long-term degradation patterns over a 60-day baseline.

---

## 2. Infrastructure Ontology & Dependency Hierarchy

### `ONTOLOGY` — 7 Domains

| Domain | Device Types |
|--------|-------------|
| POWER_SUPPLIES | UPS, Generator, DC Power Supply, PDU, PDS, DC Controller |
| PRIMARY_INTERNET | VSAT, Cellular, Radio, SD-WAN, Modem |
| COMMS_EQUIPMENT | Router, Switch, Firewall, Lanolinx-switch, Fabric Interconnect |
| COMPUTE | VM Host, VM Server, Physical Machine, Storage |
| RTU | RTU, NTEST RTU |
| SCADA | Sub Equipment, Plant Equipment, Meter Point, I/O, Member Equipment |
| FACILITIES | Access Control Panel, Door Controller, IP Camera, HVAC |

### `TIER_RANKING` (Lower Number = Higher Authority)

| Tier | Domain | Points Base |
|------|--------|-------------|
| 1 | POWER_SUPPLIES | 16,000 |
| 2 | PRIMARY_INTERNET | 14,000 |
| 3 | COMMS_EQUIPMENT | 12,000 |
| 4 | COMPUTE | 10,000 |
| 5 | RTU | 8,000 |
| 6 | SCADA | 6,000 |
| 7 | FACILITIES | 4,000 |
| 8 | UNKNOWN_DOMAIN | 2,000 |

### `_get_domain(node_type, node_name, primary_comms)`
Determines infrastructure domain via explicit keyword matching and ontology lookup. Differentiates Internet routers from internal comms routers using `primary_comms` context.

---

## 3. Incident Clustering & "Patient Zero" Algorithm

### `analyze_and_cluster(self, active_alerts)`
Ingests an array of active alerts and groups them by `site_name`. For each site cluster it extracts:
- Average CPU Load and Packet Loss
- All unique IP addresses involved
- Maximum alert level (extracted via regex from `Normalized_Alert_Level`, `Alert_Level`, or `severity`)
- Latest alert timestamp for cascade delay calculation

### `_determine_patient_zero(self, alerts)`
**The Supreme Patient Zero Algorithm** uses a weighted scoring matrix:
1. **Topological Score:** `(9 - tier) * 2000`. A Tier 1 Power device scores 16,000 vs. a Tier 7 Facilities device scoring 4,000.
2. **Severity Score:** Down/offline = 1000, Critical >50% loss = 500, Warning = 100
3. **Time Offset Penalty:** Micro-tiebreaker within same tier, capped at 200 points

---

## 4. Fleet Outage Detection

### `identify_fleet_outages(self, incidents, threshold=5)`
Detects carrier outages across multiple sites. If 5+ sites sharing the same primary communications provider experience failures in `PRIMARY_INTERNET` or `COMMS_EQUIPMENT` domains, a `Regional Provider Outage` event is generated.

---

## 5. Multi-Domain Root Cause Analysis (RCA)

### `calculate_root_cause(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events)`
Evaluates clustered data against distinct correlation tiers:

1. **Fleet Correlation (+100):** Regional carrier outage detected
2. **Cloud Correlation (+85):** Node depends on a provider experiencing known outage
3. **BGP Correlation (+75):** Transport provider has active routing anomaly
4. **Hardware Heuristics (+30 to +60):** Structural cause based on Patient Zero domain
5. **Geospatial Weather (+40 to +55):** Haversine distance calculation to active hazards
6. **Policy Override (+50):** Native Alert Level 1 detected
7. **Maintenance Auto-Clear:** Expired maintenance windows are automatically cleared

**SLA Priority Mapping:**
| Max Alert Level | Priority | SLA |
|-----------------|----------|-----|
| 1 | P1 - CRITICAL | 15 Minutes |
| 2 | P2 - HIGH | 1 Hour |
| 3 | P3 - MODERATE | 4 Hours |
| 4 | P4 - LOW | 24 Hours |
| 5 | P5 - PLANNING | Best Effort |

Returns: `(cause, score, priority, evidence_log, blast_radius, p0_node, cascade_str)`

---

## 6. Predictive Analytics & Chronic Pattern Recognition

### `generate_chronic_insights(self)`
Queries historical `SolarWindsAlert` records over the last **60 days**, filtering out resolved messages. Uses Pandas DataFrames to return:

1. **Top Offending Nodes:** Top 15 physical devices with highest failure volume
2. **Infrastructure Hotspots:** Top 10 facilities with highest incident volume
3. **Predictive Maintenance Forecast:** Automated insights flagging nodes with >5 incidents/week as "CRITICAL FLAP DETECTED" or sites with >15 incidents as "REGIONAL DEGRADATION"

---

## 7. Complete Function Reference

### Class: `EnterpriseAIOpsEngine`

| Method | Signature | Purpose |
|--------|-----------|---------|
| `__init__` | `(self, db_session)` | Initialize with database session |
| `_get_domain` | `(self, node_type, node_name, primary_comms) -> str` | Get infrastructure domain |
| `_determine_patient_zero` | `(self, alerts) -> tuple` | Determine root cause alert |
| `identify_fleet_outages` | `(self, incidents, threshold) -> list` | Detect regional carrier outages |
| `generate_chronic_insights` | `(self) -> tuple` | 60-day predictive analytics |
| `calculate_root_cause` | `(self, site_name, data, active_weather, active_cloud, active_bgp, fleet_events) -> tuple` | Multi-domain root cause analysis |
| `analyze_and_cluster` | `(self, active_alerts) -> dict` | Cluster alerts by site |

---

## 8. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| pandas | Data processing | https://pandas.pydata.org/ |
| math | Haversine calculations | https://docs.python.org/3/library/math.html |
| ipaddress | IP validation | https://docs.python.org/3/library/ipaddress.html |
