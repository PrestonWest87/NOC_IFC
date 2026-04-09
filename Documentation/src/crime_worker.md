# Enterprise Architecture & Functional Specification: `src/crime_worker.py`

## 1. Executive Overview

The `src/crime_worker.py` module serves as the **Kinetic Intelligence Ingestion Daemon** for the Intelligence Fusion Center. Operating as a standalone background worker, it autonomously polls local law enforcement Computer-Aided Dispatch (CAD) APIs—specifically targeting the Little Rock, AR metropolitan area—to detect physical threats in real-time.

The engine parses raw police dispatch JSON, mathematically calculates the geographic proximity of incidents to the Network Operations Center (NOC) Headquarters, categorizes the events into enterprise threat matrices, and persists the data for the Executive Dashboard and PyDeck 3D mapping modules.

---

## 2. Core Architecture: Geospatial Processing

Because raw police dispatch feeds often provide unstructured street addresses rather than precise coordinates, the module implements a robust, multi-tier geocoding and distance calculation engine.

### 2.1 ArcGIS Geocoding & Memory Caching
* **`geocode_address_arcgis(address, hq_lat, hq_lon, region)`:** Acts as the primary location resolver. It cleans the raw address string (e.g., standardizing block numbers and intersections) and queries the ArcGIS World Geocoding REST API.
* **API Optimization (`GEO_CACHE`):** To prevent rate-limiting and accelerate processing, the function maintains an in-memory dictionary cache of previously resolved addresses during its execution cycle. 
* **The "Donut of Uncertainty" Fallback:** If the ArcGIS API fails, times out, or cannot resolve a highly obscure address, the engine executes a mathematical fallback. It generates a random radial offset (between 0.009 and 0.018 degrees) and a random angle from the HQ coordinates. This ensures the incident is still plotted on the UI map with an `(Approx Loc)` flag, preventing a total loss of situational awareness due to API failure.

### 2.2 Haversine Distance Calculation
* **`calculate_distance(lat1, lon1, lat2, lon2)`:** Utilizes the Great-Circle Haversine formula to calculate the exact distance in miles between the NOC Headquarters and the geocoded crime incident. This precise metric is later used by the frontend to trigger geofenced perimeter alerts (e.g., 1-mile vs. 5-mile radius).

---

## 3. Threat Triage & Ingestion Pipeline

### `fetch_live_crimes()`
This is the primary execution loop of the daemon. It establishes a secure connection to the municipal CAD event endpoint and processes the payload through a strict triage pipeline.

**Algorithmic Flow:**
1. **Temporal Filtering:** Establishes a strict 7-day (168-hour) rolling window. Any dispatch payload older than this threshold is immediately discarded to save compute cycles.
2. **Deterministic Deduplication:** Law enforcement APIs frequently update the same dispatch ticket multiple times. To prevent database duplication, the engine generates a deterministic identifier (`inc_id`) using an MD5 hash of the location string combined with the dispatch timestamp.
3. **Heuristic Categorization:** Raw police dispatch codes are translated into Enterprise Security classifications using keyword arrays:
    * *Critical Infrastructure Threat (Critical):* Arson, Explosives, Sabotage.
    * *Asset/Copper Theft Risk (High):* Burglary, Robbery, Theft.
    * *Violent Proximity Threat (High):* Assault, Homicide, Weapons.
    * *Perimeter Breach/Vandalism (Medium):* Trespassing, Prowlers, Vandalism.
    * *General Police Activity (Low):* Routine traffic stops or non-violent disturbances.

---

## 4. Database Persistence & Lifecycle Management

Once an incident is geocoded, scored, and deduplicated, it interacts with the underlying SQLAlchemy models.

* **Insertion (`CrimeIncident`):** The enriched incident—complete with its calculated distance, severity, and normalized coordinates—is committed to the `CrimeIncident` SQLite table.
* **Autonomous Garbage Collection:** To prevent the SQLite database from bloating over time, the worker executes an automatic purge at the end of every polling cycle. It runs a `DELETE` query dropping all `CrimeIncident` records where the timestamp is older than the 7-day threshold. This ensures the application footprint remains lightweight and edge-deployable.
