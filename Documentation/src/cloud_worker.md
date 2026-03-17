# Enterprise Architecture & Functional Specification: `src/cloud_worker.py`

## 1. Executive Overview

The `src/cloud_worker.py` module functions as the **Global Infrastructure Polling Engine** for the Intelligence Fusion Center. It is an automated backend worker designed to proactively ingest, normalize, and track the operational status of mission-critical third-party SaaS and IaaS providers (e.g., AWS, Azure, GCP, Cloudflare, Okta). 

By monitoring these external dependencies, the system can feed the `AIOpsEngine` with the necessary context to determine if a localized NOC alert is actually a symptom of a massive downstream cloud outage, drastically reducing mean-time-to-innocence (MTTI) for network operators.

---

## 2. Configuration & Data Sources

### The `CLOUD_FEEDS` Dictionary
The worker relies on a hardcoded, highly curated dictionary of RSS/Atom feed endpoints representing the official status pages of major service providers. 

**Tracked Ecosystems Include:**
* **Hyperscalers:** AWS, Microsoft Azure, Google Cloud Platform.
* **Edge & Security:** Cloudflare, Zscaler, CrowdStrike, Cisco Umbrella.
* **Collaboration & DevSecOps:** GitHub, Slack, Zoom, Atlassian, PagerDuty.
* **Identity & Networking:** Okta, Cisco Meraki.

*Architectural Note:* By strictly binding to RSS/Atom feeds, the worker avoids brittle web-scraping techniques, ensuring high reliability and standardized XML parsing.

---

## 3. Algorithmic Processing & Heuristics

### `extract_service_name(provider, title)`
Service provider RSS feeds are notoriously chaotic and unstandardized. This function acts as a heuristic normalizer to extract the specific service impacted (e.g., isolating "EC2 North Virginia" from a verbose alert title).

**Execution Logic:**
1.  **Sanitization:** Strips common status-page brackets (`[Investigating]`, `[Resolved]`, `[Update]`) from the string.
2.  **Delimiter Splitting:** Iterates through common vendor delimiters (` - `, `: `, ` | `). If found, it splits the string and assumes the first segment is the specific service name.
3.  **Vendor Fallbacks:** If no delimiter is present, it applies hardcoded fallbacks based on the hyperscaler (e.g., defaulting to "AWS Infrastructure" or "Microsoft Azure").

---

## 4. The Core Execution Engine: `fetch_cloud_outages()`

This is the primary operational loop of the worker. It is designed for absolute fault tolerance; a failure in one provider's feed will not crash the worker or halt the ingestion of other feeds.

### 4.1 Ingestion & Resilience
* **Strict Timeouts:** To prevent `feedparser` from hanging indefinitely on an unresponsive vendor server, the worker first uses the `requests` library to fetch the XML payload with a strict `timeout=10` seconds.
* **Isolated Error Handling:** The feed iteration is wrapped in a `try...except` block *inside* the main loop. If a provider (e.g., Slack) throws an HTTP 500 or times out, the script catches the exception, appends the provider to a `failed_providers` list for logging, and gracefully `continue`s to the next vendor.

### 4.2 Parsing & Resolution Logic
For each valid entry in a feed, the worker determines the outage status:
1.  **Time Bounds:** It strictly ignores any incident published older than 7 days (`recent_cutoff`), preventing the ingestion of massive historical archives when connecting to a new feed.
2.  **Keyword Heuristics for Resolution:** It concatenates the `title` and `description`, converts them to uppercase, and scans for resolution indicators: `["[RESOLVED]", "RESOLVED", "OPERATIONAL", "COMPLETED", "MITIGATED"]`. If found, `is_resolved` evaluates to `True`.

### 4.3 Database Operations (Upsert Logic)
The worker interacts with the `CloudOutage` database model:
* **Deduplication:** Queries the database using a composite key of `provider`, `title`, and `updated_at`. 
* **Insert:** If the record does not exist, it inserts a new `CloudOutage`.
* **Update:** If the record *does* exist, it checks if the operational status has changed from down to resolved. If so, it flips the `is_resolved` boolean to `True` and updates the timestamp.

### 4.4 Data Retention Lifecycle (Self-Cleaning)
To prevent database bloat, the worker includes an automated garbage collection routine at the end of its run.
* **Purge Logic:** It executes a bulk delete query against the `CloudOutage` table, permanently removing any incident where `is_resolved == True` AND the `updated_at` timestamp is older than 3 days. 
* *Result:* The database acts as an ephemeral state-machine, only holding active outages and recently resolved historical context for the AIOps engine.

---

## 5. System Integration Context

Within the broader architecture, this module is executed by:
* **The Global Scheduler (`src/scheduler.py`)**: Runs this script on a predefined chronological loop (e.g., every 5 minutes) via a background thread.
* **User Manual Override (`app.py`)**: Can be forcefully triggered by NOC Operators clicking the "Sync Cloud Status" button in the Threat Telemetry UI, which bypasses the scheduler for an immediate data pull.
