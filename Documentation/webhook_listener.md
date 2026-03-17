# Enterprise Architecture & Functional Specification: `src/webhook_listener.py`

## 1. Executive Overview

The `src/webhook_listener.py` module functions as the **High-Velocity Ingestion Gateway** for the Intelligence Fusion Center (IFC). Built on the asynchronous **FastAPI** framework, it provides a dedicated REST API endpoint designed to receive, parse, and normalize live telemetry webhooks from external Network Management Systems (NMS) and IT Service Management (ITSM) platforms, specifically tuned for SolarWinds.

This module acts as the crucial translation layer between traditional, isolated IT monitoring tools and the IFC's advanced AIOps correlation engine. It rapidly converts unstructured JSON payloads into standardized database objects, enabling the system to track incidents and recoveries in real-time.

---

## 2. API Architecture & Endpoint Configuration

### The Ingestion Route: `POST /webhook/solarwinds`
* **Framework:** Utilizes FastAPI, running on a Uvicorn ASGI server (`port=8100`, `host="0.0.0.0"`).
* **Dependency Injection:** Uses `Depends(get_db)` to securely manage SQLAlchemy session lifecycles per request, ensuring that high-volume webhook bursts do not exhaust the database connection pool.
* **Asynchronous Handling:** The route is defined as `async def` and uses `await request.json()`, allowing the gateway to accept thousands of concurrent webhooks without blocking the main event loop.

---

## 3. Data Extraction & Normalization

External webhooks are notoriously inconsistent. The `smart_extract(payload: dict)` function acts as a fault-tolerant parsing engine to standardize incoming data.

### 3.1 Direct Schema Mapping
It attempts to extract critical entities using the `.get()` method, targeting known SolarWinds variable schemas:
* `DisplayName` $\rightarrow$ `node_name`
* `Alert Name` / `check` $\rightarrow$ `event_type`
* `Node Type` $\rightarrow$ `device_type`
* `Site` $\rightarrow$ `site_group`

### 3.2 Automated Resolution Detection
The engine analyzes the raw status description. It converts the string to lowercase and checks it against a lexicon of recovery indicators: `['resolved', 'up', 'ok', 'clear', 'operational', 'recovered']`.
* If a match is found, it dynamically flips the `is_resolution` boolean to `True`, signaling the database to close the incident rather than open a new one.

### 3.3 Failsafe Regex Extraction
If the payload is malformed and fails to provide a structured `IP Address` field, the function converts the entire JSON payload into a flat string and applies an IPv4 Regular Expression to rescue the IP data.

---

## 4. Heuristic Device Classification

### `classify_device(text_corpus, node_type_hint)`
To perform accurate blast-radius calculations, the AIOps engine needs to know *what* type of device failed. If SolarWinds fails to provide a definitive `Node Type`, this function employs a heuristic fingerprinting dictionary against the node's name and alert text.

* **Firewall:** Triggers on `fw`, `asa`, `palo`, `fortigate`, `meraki mx`.
* **Router:** Triggers on `rtr`, `asr`, `gateway`, `sd-wan`.
* **Switch:** Triggers on `sw`, `nexus`, `catalyst`, `idf`, `mdf`.
* **Power/UPS:** Triggers on `ups`, `pdu`, `battery`, `generator`.

*Benefit:* Even if a node is poorly named (e.g., `NYC-Bldg4-MDF`), the system accurately categorizes it as a Switch.

---

## 5. Geospatial & Alias Mapping

### `resolve_location_mapping(node_name, sw_site_hint, db)`
For the physical environment correlation (Weather/Power grids) to work, logical network nodes must be tied to physical `MonitoredLocation` entities.

1.  **Primary Override (The Hint):** If the SolarWinds webhook includes a populated "Site" custom property, the system trusts this as the absolute source of truth and instantly maps it.
2.  **Secondary Fallback (Alias Match):** If the explicit site is missing, the engine sanitizes the node name (stripping FQDN suffixes) and queries the `NodeAlias` ML-translation table.
3.  **Tertiary Fallback (Fuzzy Matching):** *(Present in earlier iterations of the function)* Uses the `rapidfuzz` library to calculate the Levenshtein distance between the raw node name and all known NOC sites, automatically generating new `NodeAlias` records if the confidence score exceeds 70%.

---

## 6. The Transaction Lifecycle (State Management)

Once the data is normalized and mapped, the `receive_alert` route determines the database transaction path.

### Path A: Incident Resolution (Recovery)
* **Trigger:** `parsed["is_resolution"] == True`
* **Action:** Queries the `SolarWindsAlert` table for all active, unresolved alerts matching the `node_name`. 
* **Update:** Iterates through the active alerts, changing their status to `'Resolved'` and appending the current `resolved_at` UTC timestamp.
* **Audit:** Writes a green recovery message to the `TimelineEvent` table for the live UI dashboard.

### Path B: New Incident Creation (Degradation)
* **Trigger:** Standard alert payload.
* **Action:** Instantiates a new `SolarWindsAlert` ORM object.
* **Critical Handoff:**
    * Saves the absolute `raw_payload` (JSON) to the database. This allows the LLM AIOps engine to perform deep forensic analysis on the raw metrics later.
    * Strictly sets `is_correlated = False`. This acts as a flag for the backend `aiops_engine.py` daemon, alerting it that a new, raw incident requires root-cause processing.
* **Audit:** Writes a red degradation message to the `TimelineEvent` table.
