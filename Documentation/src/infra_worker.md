# Enterprise Architecture & Functional Specification: `src/infra_worker.py`

## 1. Executive Overview

The `src/infra_worker.py` module serves as the **Physical Infrastructure & Environmental Telemetry Engine** for the Intelligence Fusion Center. Unlike traditional IT monitoring tools that focus purely on digital packet loss, this worker actively monitors the physical world. 

It ingests live meteorological data from government APIs and utilizes advanced geospatial mathematics (via the `shapely` library) to calculate deterministic intersections between active severe weather polygons and the exact latitude/longitude coordinates of tracked NOC facilities. This provides the AIOps engine with the localized environmental context needed to diagnose physical layer failures (e.g., fiber cuts from tornadoes, VSAT rain fade).

---

## 2. Core Data Sources & Upstream APIs

The worker relies on authoritative, high-availability feeds from the National Oceanic and Atmospheric Administration (NOAA) and the National Weather Service (NWS).

### 2.1 Storm Prediction Center (SPC) Convective Outlooks
* **Endpoint:** `https://www.spc.noaa.gov/products/outlook/day1otlk_cat.lyr.geojson`
* **Format:** GeoJSON
* **Purpose:** Provides macro-level, day-of risk polygons for severe thunderstorms and tornadoes across the continental United States.

### 2.2 NWS Active Warnings API
* **Endpoint:** `https://api.weather.gov/alerts/active?area=AR,OK,MS,MO`
* **Format:** Custom NWS JSON (CAP - Common Alerting Protocol)
* **Purpose:** Provides hyper-local, active warnings (e.g., Flash Flood Warnings, Tornado Warnings) specifically filtered to the organization's primary operational footprint (Arkansas, Oklahoma, Mississippi, Missouri).

---

## 3. Geospatial Processing Engine: `fetch_spc_outlooks(session)`

This function acts as the spatial intersection calculator. It is computationally intense, bridging static IT asset management with dynamic weather tracking.

### 3.1 Data Preparation & Compilation
1.  **GeoJSON Ingestion:** Downloads the latest SPC Day 1 outlook and extracts the `features` array.
2.  **Risk Hierarchy:** Establishes a numerical weighting system (`risk_levels`) to evaluate overlapping polygons (e.g., HIGH=6, TSTM=1). This ensures that if a site sits on the border of a "Slight" and "Enhanced" risk zone, the engine appropriately inherits the higher "Enhanced" threat model.
3.  **Polygon Pre-compilation:** Iterates through the GeoJSON features and converts the raw coordinate arrays into formal `shapely.geometry.shape()` polygon objects, storing them in memory for rapid iteration.

### 3.2 The Intersection Algorithm (Point-in-Polygon)
1.  **Location Retrieval:** Queries the `MonitoredLocation` database table to retrieve the specific latitude and longitude of every tracked site.
2.  **Spatial Math (`shapely`):** For each site, it creates a Shapely `Point(lon, lat)`. *Note: Shapely strictly requires coordinates in (Longitude, Latitude) order, unlike standard mapping formats.*
3.  **Overlap Detection:** It evaluates `point.within(poly)` against every pre-compiled SPC polygon.
4.  **Database Update:** If an intersection is detected and the risk level exceeds the site's current recorded baseline, it updates the `current_spc_risk` property for that specific `MonitoredLocation` and commits the changes to the database.

---

## 4. Regional Threat Ingestion: `fetch_nws_warnings(session)`

This function manages the active, tactical threat board by tracking immediate hazards (e.g., "Tornado Warning issued for Pulaski County").

### 4.1 Ingestion & Idempotency logic
1.  **Payload Extraction:** Hits the NWS API and parses the JSON response.
2.  **UUID Fallback:** Attempts to extract the official NWS `id` for the hazard. If the NWS API fails to provide one, it generates a `uuid.uuid4()` to ensure database constraints are met.
3.  **Upsert Mechanism:** * **Check:** Queries the `RegionalHazard` table for an existing `hazard_id`.
    * **Update:** If the warning is already tracked, it simply updates the `updated_at` timestamp, preventing database bloat.
    * **Insert:** If it is a newly issued warning, it instantiates a new `RegionalHazard` object, extracting the `event` (Hazard Type), `severity`, `headline` (Title), and `areaDesc` (Location).

---

## 5. System Integration & Lifecycle

### `fetch_regional_hazards()`
This is the master wrapper function that initializes the database session (`SessionLocal`), executes both the tactical (NWS) and macro (SPC) environmental sweeps, and safely closes the database connection in a `finally` block to prevent memory/connection leaks.

### Macro-Architecture Context
Within the IFC ecosystem, this telemetry data is consumed by:
* **The UI (Regional Grid Tab):** In `app.py`, the `MonitoredLocation` records are plotted onto the PyDeck 3D map. The `current_spc_risk` dynamically alters the color and status of the NOC sites on the dashboard.
* **The AIOps Engine (`aiops_engine.py`):** When a SolarWinds node goes down, the engine queries the `RegionalHazard` table. If the failed node's mapped location overlaps with an active environmental hazard, the AI natively correlates the outage to "Severe Weather Hazards" rather than an internal misconfiguration.
