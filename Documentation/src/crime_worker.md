# Enterprise Architecture & Functional Specification: `src/crime_worker.py`

## 1. Executive Overview

The `src/crime_worker.py` module serves as the **Kinetic Intelligence Ingestion Daemon** for the Intelligence Fusion Center. Operating as a standalone background worker, it autonomously polls local law enforcement Computer-Aided Dispatch (CAD) APIs—specifically targeting the Little Rock, AR metropolitan area—to detect physical and kinetic threats in real-time.

Because standard IT alerting tools lack visibility into the physical environment, this engine bridges the gap by translating raw police dispatch JSON into actionable enterprise security metrics. It mathematically calculates the geographic proximity of incidents to the Network Operations Center (NOC) Headquarters, categorizes the events into structured threat matrices, and persists the data for the Executive Dashboard and PyDeck 3D perimeter mapping modules.

---

## 2. Core Architecture: Geospatial Processing

Raw police dispatch feeds often provide unstructured street addresses or block numbers rather than precise latitudinal and longitudinal coordinates. To render this data on a precise UI map, the module implements a robust, fault-tolerant geocoding engine.

### 2.1 ArcGIS Geocoding & Memory Caching
* **`geocode_address_arcgis(address, hq_lat, hq_lon, region)`:** Acts as the primary location resolver. It aggressively cleans the raw address string (e.g., standardizing block numbers and intersections) and queries the ArcGIS World Geocoding REST API.
* **API Optimization (`GEO_CACHE`):** To prevent rate-limiting and accelerate processing cycles, the function maintains an in-memory dictionary cache of previously resolved addresses. If a specific address is dispatched multiple times, the engine bypasses the external API completely.
* **The "Donut of Uncertainty" Fallback:** If the ArcGIS API fails, times out, or cannot resolve a highly obscure address, the engine executes a mathematical fallback. It generates a random radial offset (between 0.009 and 0.018 degrees) and a random angle from the HQ coordinates. This ensures the incident is still plotted on the UI map with an `(Approx Loc)` flag, preventing a total loss of situational awareness due to third-party API failure.

### 2.2 Haversine Distance Calculation
* **`calculate_distance(lat1, lon1, lat2, lon2)`:** Utilizes the precise Great-Circle Haversine formula to calculate the exact distance in miles between the NOC Headquarters and the geocoded crime incident. This mathematically precise metric is stored in the database and utilized by the frontend to trigger strict geofenced perimeter alerts (e.g., 1-mile vs. 5-mile radius).

---

## 3. Threat Triage & Ingestion Pipeline

### `fetch_live_crimes()`
This is the primary execution loop of the daemon. It establishes a secure connection to the municipal CAD event endpoint and processes the payload through a strict triage pipeline.

**Algorithmic Flow:**
1. **Temporal Filtering:** Establishes a strict 7-day (168-hour) rolling window. Any dispatch payload older than this threshold is immediately discarded to save compute cycles and database I/O.
2. **Deterministic Deduplication:** Law enforcement APIs frequently update the same dispatch ticket multiple times (e.g., upgrading an Assault to a Homicide). To prevent database duplication, the engine generates a deterministic identifier (`inc_id`) using an MD5 hash of the location string combined with the dispatch timestamp.
3. **Heuristic Categorization:** Raw police dispatch codes are translated into Enterprise Security classifications using keyword arrays. This maps civic events directly into the Executive Dashboard's threat scoring model:
    * *Critical Infrastructure Threat (Critical):* Arson, Explosives, Sabotage, Terror.
    * *Asset/Copper Theft Risk (High):* Burglary, Robbery, Theft, Breaking & Entering.
    * *Violent Proximity Threat (High):* Assault, Battery, Homicide, Weapons.
    * *Perimeter Breach/Vandalism (Medium):* Trespassing, Prowlers, Vandalism.
    * *General Police Activity (Low):* Routine traffic stops or non-violent disturbances.

---

## 4. Database Persistence & Lifecycle Management

Once an incident is geocoded, scored, and deduplicated, it interacts with the underlying SQLAlchemy models.

* **Insertion (`CrimeIncident`):** The enriched incident—complete with its calculated Haversine distance, enterprise severity score, and normalized coordinates—is committed to the `CrimeIncident` SQLite table.
* **Autonomous Garbage Collection:** To prevent the SQLite database from bloating over time, the worker executes an automatic purge at the end of every polling cycle. It runs a `DELETE` query dropping all `CrimeIncident` records where the timestamp is older than the 7-day threshold. This ensures the application footprint remains lightweight and edge-deployable.

---

## 5. Complete Function Reference

| Function | Signature | Purpose |
|----------|----------|---------|
| `calculate_distance` | `(lat1, lon1, lat2, lon2) -> float` | Haversine distance in miles |
| `geocode_address_arcgis` | `(address, hq_lat, hq_lon, region) -> tuple` | ArcGIS geocoding with fallback |
| `fetch_live_crimes` | `() -> int` | Main fetch loop, returns count |

### Constants

| Constant | Type | Description |
|----------|-----|-------------|
| `GEO_CACHE` | `dict` | In-memory geocoding cache |

---

## 6. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| ArcGIS Geocoding | Address → Lat/Lon | https://developers.arcgis.com/ |
| Requests | HTTP client | https://docs.python-requests.org/ |
| math | Distance calculations | https://docs.python.org/3/library/math.html |
