# Enterprise Architecture & Functional Specification: `src/cloud_worker.py` *(Updated)*

## 1. Executive Overview

The `src/cloud_worker.py` module functions as the **Global Infrastructure Polling Engine** for the Intelligence Fusion Center. It proactively ingests and normalizes the operational status of mission-critical third-party SaaS and IaaS providers (AWS, Azure, GCP, Cloudflare, etc.).

In its latest architectural iteration, this module has been significantly upgraded with an **Enterprise Noise Reduction Engine**. It now implements advanced Lexical Analysis (Regex) to aggressively filter out non-actionable intelligence—specifically, scheduled maintenance planned for future dates and outages explicitly isolated to foreign, non-US regions. This drastically reduces database bloat and prevents false-positive alerts on the NOC dashboard.

---

## 2. The Enterprise Noise Reduction Engine

To prevent the NOC from being flooded with irrelevant data (e.g., an AWS EC2 outage in Mumbai or a planned Microsoft 365 update occurring next week), the worker introduces three rigorous heuristic filters.

### 2.1 Geographic Isolation: `is_foreign_region(text)`
This function ensures that only outages with the potential to impact North American operations are ingested.
* **The Dictionary:** Utilizes a hardcoded list of `FOREIGN_IDENTIFIERS` encompassing global region tags (e.g., `eu-`, `ap-`, `tokyo`, `frankfurt`).
* **Execution Logic:** It scans the concatenated `title` and `description` of the alert using a bounded Regular Expression (`\b`). 
* **Failsafe Bypass:** If a foreign tag is detected, the function performs a secondary check. If the text *also* mentions a US/Global region (e.g., `"us-"`, `"north america"`, `"global"`), it allows the alert through, assuming a multi-regional or cascading failure. If the text mentions *only* a foreign region, the alert is discarded.

### 2.2 Temporal Context Filtering: `is_future_maintenance(title, description)`
Many cloud providers utilize their RSS feeds to announce scheduled maintenance days or weeks in advance. This function prevents future maintenance from triggering live alarms.
* **Lexical Triggers:** It first checks for maintenance keywords (`"scheduled"`, `"upcoming"`, `"maintenance"`). 
* **Active State Bypass:** If the maintenance notice includes active verbiage (`"in progress"`, `"currently undergoing"`), it allows the alert through.
* **Date Normalization:** It generates an array of today's date formatted in four distinct syntaxes (e.g., `"mar 17"`, `"march 17"`, `"2026-03-17"`, `"03/17/2026"`). If the maintenance notice text does *not* contain today's exact date string, the worker classifies it as "future noise" and discards it.

### 2.3 Regional Enrichment: `extract_us_regions(text)`
Rather than just identifying if an outage is within the US, this function extracts the specific sector to provide NOC operators with precise situational awareness on the dashboard.
* **The Mapping Dictionary:** Iterates through `US_REGIONS` (e.g., mapping `"us-east-1"` to `"US-East (N. Virginia)"`).
* **UI Appending:** If matched, the worker dynamically appends the translated region string to the end of the Service Name in the database (e.g., `"AWS Infrastructure [US-East (N. Virginia)]"`).

---

## 3. Data Source & Ingestion Mechanics

### The `CLOUD_FEEDS` Dictionary
The worker relies on a hardcoded dictionary of 18 RSS/Atom feed endpoints representing the official status pages of major ecosystems (Hyperscalers, Edge Security, Collaboration, Identity).

### Ingestion Resilience
* **Strict Timeouts:** To prevent `feedparser` from hanging indefinitely on an unresponsive vendor server, the worker first uses the `requests` library to fetch the XML payload with a strict `timeout=10` seconds.
* **Isolated Error Handling:** The feed iteration is wrapped in a nested `try...except` block. If a provider throws an HTTP error, the script catches the exception, appends the provider to a `failed_providers` list, and gracefully continues to the next vendor.

---

## 4. Algorithmic Processing & State Management

### `fetch_cloud_outages()`
This is the primary operational loop, designed for idempotency and self-cleaning state management.

1.  **Pagination Limit:** To prevent massive database transaction overhead when connecting to a feed, the script explicitly slices the incoming array to process only the top 15 most recent entries (`feed.entries[:15]`).
2.  **Time Bounds:** It strictly ignores any incident published older than 7 days (`recent_cutoff`).
3.  **Application of Noise Filters:** The extracted text is passed through `is_future_maintenance()` and `is_foreign_region()`. If either evaluates to `True`, the loop executes a `continue`, skipping the database transaction entirely.
4.  **Database Operations (Upsert):**
    * **Check:** Queries the database using a composite key of `provider`, `title`, and `updated_at`. 
    * **Insert:** If the record does not exist, it inserts a new `CloudOutage`.
    * **Update:** If the record *does* exist, it checks if the operational status has changed from down to resolved (via keyword heuristics like `[RESOLVED]`). If so, it flips the `is_resolved` boolean to `True`.
5.  **Data Retention Lifecycle:** The worker executes an automated garbage collection routine (`session.query.delete()`) to permanently remove any incident where `is_resolved == True` AND the timestamp is older than 3 days, ensuring the table remains highly performant.
