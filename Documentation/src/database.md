### Core System & IAM (Identity and Access Management) Models
These tables manage system state, global configurations, and Role-Based Access Control (RBAC).

* **`User`** (Table: `users`): Manages authentication and user profiles. It stores the username, bcrypt-hashed passwords, session tokens (for persistent 30-day logins), and contact information.
* **`Role`** (Table: `roles`): The backbone of the granular RBAC system. It stores highly descriptive JSON arrays (`allowed_pages` and `allowed_actions`) that dictate exactly which dashboards, tabs, and buttons a specific user role (e.g., "admin" vs. "analyst") is permitted to access.
* **`SystemConfig`** (Table: `system_config`): A single-row table that holds global application state. This includes LLM API endpoints and keys, internal tech stack definitions (used by the AI Auditor), the cached text for the rolling AI shift briefing, and SMTP credentials for autonomous report broadcasting.
* **`Keyword`** (Table: `keywords`): Stores the weighted dictionary used by the triage engines to heuristically score incoming intelligence articles based on organizational relevance.
* **`FeedSource`** (Table: `feed_sources`): Manages the URLs and descriptive names of the external RSS feeds that the background workers continuously poll for cyber and geopolitical intelligence.
* **`SavedReport`** (Table: `saved_reports`): A shared library archive where analysts can persistently save the bespoke, AI-synthesized intelligence reports generated in the Report Center module.

### Intelligence & Threat Models
These tables store the parsed, scored, and categorized Open-Source Intelligence (OSINT) and cybersecurity threat data.

* **`Article`** (Table: `articles`): The central repository for ingested intelligence. It stores the raw article content, the assigned threat score, the regex-determined category (e.g., "Cyber: Malware"), the AI-generated Bottom Line Up Front (BLUF), and flags indicating if it is "pinned" to the NOC dashboard.
* **`ExtractedIOC`** (Table: `extracted_iocs`): Houses specific Indicators of Compromise (e.g., IPv4 addresses, SHA256 hashes, CVEs) automatically extracted from the text of incoming articles by the Threat Hunting workers.
* **`CveItem`** (Table: `cve_items`): A localized, synchronized mirror of the CISA Known Exploited Vulnerabilities (KEV) catalog. It allows the system to rapidly cross-reference emerging exploits against the organization's tech stack without querying external APIs.
* **`DailyBriefing`** (Table: `daily_briefings`): Archives the "Daily Master Fusion Report," an AI-synthesized situational report generated every morning summarizing the last 24 hours of global cyber and physical telemetry.

### Grid, Weather, & AIOps Models
These tables manage the physical footprint of the organization, external infrastructure dependencies, and raw telemetry clustering for Root Cause Analysis.

* **`MonitoredLocation`** (Table: `monitored_locations`): Defines the organization's physical asset footprint (e.g., Data Centers, HQ, POPs). It stores exact latitude and longitude coordinates, facility type, and criticality priority (P1-P3) required for geospatial risk calculations.
* **`RegionalHazard`** (Table: `regional_hazards`): Tracks active National Weather Service (NWS) and Storm Prediction Center (SPC) weather polygons (e.g., Tornado Warnings, Wildfires). This is used to calculate intersecting blast radii with `MonitoredLocations`.
* **`CrimeIncident`** (Table: `crime_incidents`): Logs hyper-localized kinetic threats (arson, theft, violence) polled from municipal law enforcement APIs. It records the incident type, severity, and exact distance (in miles) from critical facilities.
* **`CloudOutage`** (Table: `cloud_outages`): Tracks active service degradations across 18+ Tier-1 SaaS and IaaS providers (AWS, Azure, Cloudflare) used to determine if an internal IT failure is actually caused by an upstream vendor.
* **`BgpAnomaly`** (Table: `bgp_anomalies`): Logs global internet routing anomalies affecting specific carrier Autonomous System Numbers (ASNs).
* **`RegionalOutage`** (Table: `regional_outages`): Tracks broad, utility-level failures, such as county-wide power grid outages.
* **`SolarWindsAlert`** (Table: `solarwinds_alerts`): The primary ingestion table for raw NMS/ITSM telemetry. It stores the webhook payload, node details, mapped physical location, and the AI-calculated root cause. It is heavily indexed (`is_correlated`, `received_at`) to support rapid querying by the AIOps correlation engine.
* **`TimelineEvent`** (Table: `timeline_events`): A chronological event logger that populates the active ticker tape on the AIOps RCA board, tracking incoming alerts, system resolutions, and operator acknowledgments.
