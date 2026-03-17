# Enterprise Architecture & Functional Specification: `src/cve_worker.py`

## 1. Executive Overview

The `src/cve_worker.py` module functions as the **Vulnerability Intelligence Synchronizer** for the Intelligence Fusion Center. It is a dedicated backend worker script responsible for automatically ingesting and maintaining a localized copy of the **CISA Known Exploited Vulnerabilities (KEV)** catalog. 

By maintaining a synchronized local database of these high-priority vulnerabilities, the application can perform rapid, offline cross-referencing against the organization's internal technology stack (via the AI Security Auditor) without constantly querying external government APIs.

---

## 2. Data Source & Ingestion Mechanics

### The CISA KEV Feed
The worker relies on the authoritative JSON data feed provided by the U.S. Cybersecurity and Infrastructure Security Agency (CISA):
* **Endpoint:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
* **Format:** Standardized JSON containing an array of actively exploited vulnerabilities.

### Request Configuration
* **Timeouts:** The `requests.get()` call is strictly capped at `timeout=30` seconds. This prevents the worker thread from hanging indefinitely if the CISA infrastructure experiences degradation or routing issues.
* **Status Validation:** Uses `response.raise_for_status()` to instantly fail and trigger the exception handling block if a non-200 HTTP status code is returned.

---

## 3. Algorithmic Processing & Normalization

### `fetch_cisa_kev()`
This is the core operational loop of the worker. It is designed to be **idempotent**, meaning it can be run repeatedly without duplicating data or corrupting the database.

**Execution Logic:**
1.  **Payload Extraction:** Isolates the `vulnerabilities` array from the parsed JSON payload.
2.  **Deduplication (Existence Check):** Before processing any data, it queries the local database: `session.query(CveItem).filter_by(cve_id=cve_id).first()`. If the CVE ID (e.g., `CVE-2024-1234`) already exists locally, the loop skips the entry entirely.
3.  **Date Normalization:** CISA provides dates as `YYYY-MM-DD` strings. The script parses this into a native Python `datetime` object (`datetime.strptime(date_added_str, '%Y-%m-%d')`). If the date is missing, it safely falls back to `datetime.utcnow()`.
4.  **ORM Object Instantiation:** Maps the JSON schema to the localized `CveItem` SQLAlchemy model, utilizing `.get()` with safe defaults (`'Unknown'`) to prevent `KeyError` exceptions on malformed upstream data. 
    * *Mapped Fields:* `cve_id`, `vendor`, `product`, `vulnerability_name`, `date_added`, `description`, `required_action`, `due_date`.

---

## 4. Execution & Transactional Integrity

* **Atomic Transactions:** The worker operates within a single database transaction. All new `CveItem` objects are staged in memory (`session.add(new_cve)`). If the entire payload processes successfully, a single `session.commit()` persists the data to disk.
* **Failure State Handling:** If a network failure, JSON parsing error, or database integrity violation occurs, the `except Exception as e:` block catches it, logs the exact failure point, and immediately fires `session.rollback()`. This ensures no partial or corrupted data is saved.
* **Graceful Termination:** The `finally: session.close()` block guarantees that the database connection pool is returned, preventing connection leaks regardless of success or failure.

---

## 5. System Integration Context

Within the broader architecture, this module is executed by:
* **The Global Scheduler (`src/scheduler.py`)**: Runs this script on a predefined chronological loop (e.g., daily or hourly) to ensure the NOC is always aware of zero-day additions to the KEV catalog.
* **User Manual Override (`app.py`)**: Can be forcefully triggered by NOC Operators clicking the "Sync CISA KEV" button in the Threat Telemetry module, bypassing the scheduler for immediate updates.
* **AI Security Auditor Integration**: The data populated by this script is continuously monitored by the AIOps LLM prompt. The system cross-references the `vendor` and `product` fields of new KEV entries against the `tech_stack` defined in `SystemConfig` to automatically alert operators if internal infrastructure is actively targeted.
