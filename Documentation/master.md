# Master Architecture & Documentation: Intelligence Fusion Center (IFC)

## 1. System Deployment & Infrastructure
The IFC utilizes a decoupled, microservices-style container topology built to isolate heavy background processing from interactive user interfaces.

* **Immutable Blueprint**: All containers are built from a unified `Dockerfile` based on `python:3.11-slim` to optimize size and provide modern asynchronous support.
* **The Web Service**: Hosts the interactive Streamlit dashboards for operators on port 8501.
* **The Worker Service**: Operates as a headless daemon driving the master scheduler, asynchronous fetching, and LLM reporting.
* **The Webhook Service**: An asynchronous FastAPI gateway hosted on port 8100, dedicated to receiving ITSM and NMS alerts like SolarWinds.
* **State Management**: To ensure unified operation, a local SQLite file is shared across containers via volume mounting, supported by `check_same_thread=False` concurrency settings.

## 2. Database & Data Dictionary
The object-relational mapping (ORM) layer is powered by SQLAlchemy and dynamically configures connection behaviors to support both edge SQLite deployments and enterprise PostgreSQL clusters.

* **Identity & Access**: Manages operator credentials (bcrypt hashed) and Role-Based Access Control (RBAC) permissions.
* **Threat Intelligence**: Stores parsed RSS feeds (`Article`), extracted Indicators of Compromise (`ExtractedIOC`), and localized mirrors of the CISA Known Exploited Vulnerabilities catalog (`CveItem`).
* **Infrastructure**: Tracks physical NOC locations (`MonitoredLocation`), severe weather risks (`RegionalHazard`), and SaaS/IaaS degradation (`CloudOutage`).
* **AIOps**: Ingests raw external webhooks (`SolarWindsAlert`) and maps them to physical sites to correlate incidents.

## 3. Orchestration & Telemetry Ingestion
A robust set of background workers automates the collection of multi-domain intelligence.

* **Master Scheduler (`scheduler.py`)**: Utilizes a hybrid concurrency model (Asyncio + Multiprocessing) to fetch global feeds without blocking operations. It also performs database garbage collection to purge stale data.
* **Webhook Listener (`webhook_listener.py`)**: Normalizes messy inbound ITSM alerts, detects automated incident resolutions, and heuristically classifies failed devices (e.g., switches vs. firewalls).
* **Cloud Worker (`cloud_worker.py`)**: Polls RSS/Atom feeds of major cloud providers (AWS, Azure, Cloudflare) to track downstream outages.
* **Infrastructure Worker (`infra_worker.py`)**: Integrates with NOAA and NWS APIs. It calculates geospatial point-in-polygon intersections to detect severe weather over NOC facilities.
* **Telemetry Worker (`telemetry_worker.py`)**: Polls the ORNL ODIN API for power grid outages, RIPE Stat for BGP routing anomalies, and IODA for ISP degradation.
* **CVE Worker (`cve_worker.py`)**: Idempotently synchronizes the CISA KEV catalog for rapid cross-referencing against internal tech stacks.

## 4. Analytical & Cognitive Engines
Data is processed through a tiered architecture combining determinism with generative AI.

* **Categorizer (`categorizer.py`)**: Uses pre-compiled regex pipelines to instantly route intelligence into Cyber, Physical/Weather, or Geopolitics operational buckets.
* **Threat Hunter (`threat_hunter.py`)**: Refangs sanitized data and extracts structured IOCs (IPv4, Domains, SHA256 hashes, MITRE ATT&CK techniques) while filtering out false positives like internal IP spaces.
* **Hybrid Scoring Logic (`logic.py`)**: Assigns threat scores using a two-pronged approach. It takes the maximum value between deterministic keyword matching and a probabilistic ML model.
* **ML Pipeline (`train_model.py`)**: A Human-in-the-Loop reinforcement engine that builds a Scikit-Learn TF-IDF and Naive Bayes model based on analysts accepting or dismissing specific articles.
* **AIOps Engine (`aiops_engine.py`)**: Clusters alerts by site to calculate root cause. It evaluates blast radius, cascade duration, and physical/environmental contexts to dispatch detailed ITSM tickets. It also uncovers chronic hardware degradation patterns.
* **LLM Cognitive Hub (`llm.py`)**: Manages context windows and agnostic endpoints (OpenAI or Local). It executes complex Map-Reduce pipelines to convert disparate telemetry into Boardroom-ready Markdown reports and tactical shift briefings.

## 5. Reporting & Notification
* **Report Worker (`report_worker.py`)**: A resilient background daemon that safely executes a daily Map-Reduce compilation of the last 24 hours of intelligence. It ensures the Daily Master Fusion Report is generated before operators arrive.
* **Mailer (`mailer.py`)**: An automated outbound SMTP engine. It translates internal Markdown formatting into HTML to dispatch global SitReps and ITSM alerts securely.
