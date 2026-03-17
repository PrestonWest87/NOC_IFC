# Enterprise Architecture & Functional Specification: `src/telemetry_worker.py`

## 1. Executive Overview

The `src/telemetry_worker.py` module acts as the **Multi-Domain Infrastructure Telemetry Engine** for the Intelligence Fusion Center. While the `cloud_worker` handles SaaS/IaaS and the `infra_worker` handles meteorology, this worker sits at the critical intersection of the **Physical Power Grid** and **Core Internet Routing**.

It autonomously polls highly specialized, academic, and government APIs to detect regional power outages, BGP (Border Gateway Protocol) route leaks, and broad ISP degradation. By translating macro-level infrastructure failures into localized geospatial data, the AIOps engine can definitively prove if a sudden cluster of downed routers is due to a regional blackout rather than an internal network misconfiguration.

---

## 2. Core Data Sources & Upstream APIs

The worker aggregates telemetry from three distinct, authoritative external ecosystems:

1.  **ORNL ODIN (Oak Ridge National Laboratory):**
    * **Focus:** Real-time county-level electrical grid status.
    * **Data:** Customers without power, segmented by Arkansas counties.
2.  **RIPE Network Coordination Centre (RIPE Stat):**
    * **Focus:** Global BGP routing visibility and anomalies.
    * **Data:** IPv4 routing risk scores for specific Autonomous System Numbers (ASNs) managed by the organization.
3.  **IODA (Internet Outage Detection and Analysis - Georgia Tech):**
    * **Focus:** Macro-level ISP degradation and internet blackouts.
    * **Data:** Active control-plane and data-plane drops for specific geographic regions (US-AR) and ASNs.

---

## 3. Algorithmic Processing & Sub-Modules

The module is divided into three distinct polling functions, each managing its own database transaction lifecycle.

### 3.1 Power Grid Telemetry: `fetch_ornl_odin_power()`
* **Target Scope:** Queries the ODIN API specifically refined for `state:Arkansas`.
* **State Management:** Drops all existing records where `provider == "ORNL ODIN"` to prevent ghost outages, ensuring the database strictly mirrors the live grid.
* **Heuristic Thresholding:** Ignores micro-outages. It only commits records where `customers_out > 100`.
* **Geospatial Translation Engine:**
    * The ODIN API provides county names, not coordinates. The worker utilizes a hardcoded dictionary (`AR_COUNTY_COORDS`) to map strings (e.g., `"PULASKI"`) to central latitude/longitude points.
    * **Dynamic Radius Math:** It calculates the spatial impact zone (`est_radius`) dynamically based on outage severity: $10.0 + (\text{out\_count} / 1000)$. A 500-person outage generates a localized 10.5km blast radius, while a 50,000-person blackout generates a massive 60km blast radius, allowing the AIOps spatial engine to accurately envelop affected NOC sites.

### 3.2 BGP Routing Anomalies: `fetch_bgp_anomalies()`
* **Target Scope:** Reads the dynamic `monitored_asns` string (e.g., "AS701, AS7922") from the `SystemConfig` table.
* **Risk Evaluation:** Queries the RIPE Stat API for the current IPv4 routing visibility of each ASN.
* **Thresholding:** Extracts the calculated `risk` score. If the score exceeds an arbitrary instability threshold (`> 0.5`), it generates an unresolved `BgpAnomaly` record. This alerts NOC engineers to upstream BGP route leaks or peering drops that are outside their direct administrative control.

### 3.3 ISP Degradation: `fetch_ioda_isp_outages()`
* **Temporal Scoping:** Calculates Unix Epoch timestamps to strictly request alerts triggered within the last 12 hours (`now_epoch - (12 * 3600)`).
* **Dual-Vector Polling:**
    1.  *Regional Vector:* Queries IODA for all alerts within the ISO-3166-2 boundary for Arkansas (`US-AR`).
    2.  *ASN Vector:* Queries IODA for global alerts impacting the organization's specific `monitored_asns`.
* **Geospatial Anchoring:** Because macro-ISP outages don't have exact GPS coordinates, the worker drops a central anchor point (Little Rock, AR: `34.8, -92.2`) and assigns a massive `radius_km` (200km to 300km). This mathematical net guarantees that any monitored site within the state will spatially intersect with the outage during AIOps correlation.

---

## 4. Execution & Transactional Integrity

### `run_telemetry_sync()`
* **Execution Strategy:** The master wrapper function executes the three sub-modules sequentially.
* **Connection Isolation:** Unlike earlier iterations of the codebase that passed a global `session` object down the call chain, this worker enforces strict **Database Session Independence**. Each function opens its own `SessionLocal()`, executes its API calls, commits its data, and closes the session. 
* **Benefit:** If the RIPE API times out, it triggers a `session.rollback()` strictly isolated to the BGP module. The ODIN Power records that were already processed remain perfectly intact, preventing a single API failure from poisoning the entire telemetry ingestion cycle.

---

## 5. System Integration Context

Within the broader Intelligence Fusion Center ecosystem:
* **The Global Scheduler (`scheduler.py`):** Invokes `run_telemetry_sync()` every **5 minutes**. This high-frequency polling ensures the NOC detects power cuts and routing drops almost instantly.
* **The AIOps Engine (`aiops_engine.py`):** These records are the final piece of the ontological puzzle. The engine passes active `RegionalOutage` and `BgpAnomaly` records into `calculate_root_cause()`. If a router drops offline and intersects with an ODIN power blast radius, the AI automatically correlates the event as "Facility Power Loss" rather than a hardware fault, entirely eliminating manual diagnostic time.
