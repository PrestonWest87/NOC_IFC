# 🌐 NOC Intelligence Fusion Center

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, 18+ global cloud infrastructure providers, regional utility grids, global BGP routing tables, and **geofenced local law enforcement open-data APIs**. 

It utilizes a highly optimized hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring, pre-compiled Regex for **Term-Hit Density** triage, strict deterministic algorithms for causal correlation, and edge-optimized LLMs for automated Map-Reduce synthesis—to cut through alert fatigue and deliver actionable intelligence.

## 🏗️ Architecture

* **Frontend (`web`):** Streamlit (Python) running interactive, zero-scroll dashboards with context-aware real-time asynchronous polling, dynamic cookie-persistent UI theming, and an integrated UI Debouncing/Cooldown Engine to protect backend resources.
* **Service-Oriented Architecture (SOA):** A strict Data Access Layer (`services.py`) that completely decouples the Streamlit UI from SQLAlchemy ORM models, utilizing detached `DotDict` patterns and aggressive RAM caching to prevent detached instance crashes and database locking.
* **Background Orchestration (`worker`):** A headless daemon driving a Master Scheduler that bypasses Python's GIL using a Hybrid Concurrency Model (Asynchronous I/O combined with Multiprocessing via `ProcessPoolExecutor`).
* **Ingestion Gateway (`webhook`):** A dedicated FastAPI asynchronous listener hosting REST APIs to receive, parse, and normalize live ITSM telemetry (e.g., SolarWinds).
* **Database:** Defaults to a lightweight, file-based SQLite database (`noc_fusion.db`) pushed to the limit via low-level C-library pragmas (Write-Ahead Logging, in-memory temp stores, and memory-mapped files) for extreme edge-compute concurrency, with seamless fallback to enterprise PostgreSQL.
* **Correlation Engines:**
    * *Topological AIOps:* Evaluates infrastructure dependencies (Power > Transport > Access > Compute) to map cascading failure blast radii.
    * *Term-Hit Density Triage:* A pre-compiled Regex engine that calculates keyword density across 8 specialized NOC/SOC domains to prevent single-word miscategorization.
* **Synthesis & Broadcast:** A universal LLM abstraction layer heavily tuned for Local Edge Compute (Ollama, LM Studio) utilizing adaptive chunking and Map-Reduce pipelines to prevent VRAM context-window overflows.
* **Deployment:** A decoupled, 3-container microservices topology built from a unified `python:3.11-slim` Dockerfile.

## ✨ Key Features

### 1. ⚡ AIOps Root Cause Analysis & Predictive Analytics
A near real-time self-healing correlation engine that ingests raw network alerts and maps them against global and regional telemetry.
* **The Supreme Patient Zero Algorithm:** Bypasses traditional "polling cycle traps" by scoring alerting nodes based on a weighted matrix of Topological Hierarchy, Severity States, and Time Offsets. A core router alerting 3 minutes late will correctly outrank an IP camera that alerted immediately.
* **Predictive Analytics Module:** Executes deep Pandas aggregations on historical database records to identify chronically flapping cellular circuits, environmental VSAT vulnerabilities, and uncommanded hardware reboots *before* catastrophic failure.
* **NOC/TOC Maintenance Controls:** Operators can geofence specific IT facilities with active maintenance windows/ETRs, silencing correlation alarms while work is underway.

### 2. 📊 Executive Grid Threat Matrix
A synthesized command dashboard designed for executive leadership detailing risk to Bulk Electric System (BES) infrastructure.
* **Unified Posture Scoring:** Aggregates real-time localized perimeter crime, 48-hour cyber OSINT, and active CISA ICS-CERT advisories into a single high-level threat score (GREEN to RED), mapped against a dynamic 14-Day Baseline Deviation Trend.
* **FBI UCR Taxonomy:** Native categorization of local kinetic incidents into "Crimes Against Persons," "Property," or "Society" to dynamically weigh perimeter risks.
* **Automated HTML SitReps:** Single-click dispatch of Outlook-native HTML intelligence reports covering perimeter kinetic risks and cyber threat landscapes.

### 3. 🤖 Edge-Optimized LLM & AI Shift Logbook (New)
* **Map-Reduce LLM Synthesis:** Processes massive datasets of raw intelligence by securely chunking context windows, extracting technical facts via low-temperature mapping, and reducing them into highly polished narratives.
* **Automated Shift Logbook:** A tactical replacement for external notepads. Operators log active incidents, and the LLM Map-Reduce engine synthesizes the raw chronological data into concise, professional 2-3 paragraph end-of-shift handoff reports or weekly Executive Rollups.
* **Dynamic Ticket Generation:** Translates complex AIOps Incident Objects directly into formatted, ITSM-ready text for instant dispatch to RemedyForce or ServiceNow.

### 4. 🚨 Multi-Domain Threat Telemetry & Crime Intelligence
The backend worker concurrently scrapes and normalizes physical, digital, and kinetic infrastructure data.
* **Lightning-Fast Spatial Math:** Uses Bounding-Box Pre-Check float math to instantly evaluate thousands of IT facilities against active NWS polygons, falling back to heavy Shapely CPU math *only* when a site is directly inside a storm's bounding square.
* **Perimeter Kinetic Threats:** Automatically polls local law enforcement endpoints (e.g., LRPD Open Data API). Uses ArcGIS Geocoding with a mathematical "Donut of Uncertainty" fallback if coordinates are missing, plotting physical threats within a 3D PyDeck geofenced map.
* **CISA KEV Integration:** Maintains an offline, heavily indexed mirror of the Known Exploited Vulnerabilities catalog. The AI Security Auditor routinely cross-references incoming CVEs against the organization's customized `sys_config.tech_stack`.

### 5. Enterprise-Grade Security & Maintenance
* **Role-Based Access Control (RBAC):** Built-in user authentication with bcrypt password hashing, session cookies, and dynamic JSON-based permissions mapping down to specific UI tabs and actions.
* **Silent Database Migrations:** Self-healing bootstrap sequence (`init_db`) that natively uses SQLite pragmas and `ALTER TABLE` statements to inject new columns and roles, ensuring legacy instances are automatically upgraded without wiping data.
* **Master Garbage Collector:** A self-cleaning routine that runs hourly to purge 0-score junk, unpinned intelligence older than 30 days, and expired kinetic incident telemetry. 

---

## ⚙️ System Requirements & Deployment

This application scales exceptionally well. It is optimized to run on low-power edge-compute hardware via SQLite, while fully capable of saturating enterprise-grade servers connected to PostgreSQL during massive asynchronous data ingestion and parallel ML scoring tasks. 

### **Real-World Resource Utilization (Docker)**
* **Base Memory Footprint:** Highly optimized via slim base images and localized memory dictionaries; ~650 MB total across all 3 microservices.
* **Database Storage:** The local SQLite file utilizes WAL (Write-Ahead Logging) and requires minimal disk space compared to an independent PostgreSQL container.
* **Compute Profiling:** Web and Webhook gateways remain idle (< 1% CPU) until concurrent alert floods occur. The worker container may briefly spike compute resources during heavy geospatial polygon rendering or multiprocessing NLP vectorization.

### **Minimum Hardware**
* **CPU:** 2 Cores
* **RAM:** 2 GB 
* **Storage:** 5 GB 

### **Recommended Hardware**
* **CPU:** 4+ Cores (Allows the Python `ProcessPoolExecutor` to offload Scikit-Learn vectorization without bottlenecking the main scheduler loop).
* **RAM:** 4 GB 
* **Storage:** 15 GB SSD (Improves SQLite I/O speeds for high-velocity webhook bursts).
* *Note: If connecting the system to a locally hosted LLM (e.g., Ollama), ensure the host machine has sufficient dedicated VRAM (8GB+).*

### **Software Requirements**
* **Docker:** Engine v20.10.0 or higher
* **Docker Compose:** v2.0.0 or higher
* **OS:** Any Linux distribution (Ubuntu/Debian recommended), Windows (via WSL2), or macOS.

## 🚀 Installation & Deployment

1. **Clone the repository** and navigate to the project folder.
2. **Set up environment variables:** Edit the `.env` file to set your LLM API endpoints and optionally define a `DATABASE_URL` if bypassing the default SQLite setup.
3. **Ensure Local Volume Persistence:** The `docker-compose.yml` automatically mounts the `./data` directory to share the SQLite database file across the `web`, `worker`, and `webhook` containers.
4. **Build and start the containers:**
```bash
docker compose up --build -d
```

5. **Access the Dashboard:** Open a web browser and navigate to `http://localhost:8501`.
* *Default zero-config bootstrap login is `admin` / `admin123` (promptly reset this in Settings)*.

6. **Route Webhooks:** Point your external monitoring tools (SolarWinds, Datadog, PRTG) to `POST http://<your-server-ip>:8100/webhook/solarwinds`.

## 🛠️ Troubleshooting & Commands

**View Live Worker Logs (To monitor async scraping, telemetry fetching, and reporting cron-jobs):**
```bash
docker compose logs -f worker
```

**View Webhook Gateway Logs (Useful for tuning NLP matching logic and device classification):**
```bash
docker compose logs -f webhook
```

**Manual Database Cleanup:**
If the dashboard feels sluggish after importing massive data feeds, navigate to **Settings & Admin > ⚠️ Danger Zone** and click **🧹 Run Garbage Collector** to force a cleanup of orphaned IOCs and stale telemetry.

---

## 🤖 Addendum: AI-Generated Codebase

Please note that the entirety of this application's codebase was generated by Artificial Intelligence.

The Python backend, Streamlit frontend, Scikit-Learn machine learning logic, unified SQLite/PostgreSQL database schema, complex LLM Prompt Engineering pipelines, Regex algorithms, and Docker microservices configurations were written by an AI assistant (Google's Gemini) based on continuous, iterative prompting.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, optimization targeting, and rigorous hallucination-debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.
