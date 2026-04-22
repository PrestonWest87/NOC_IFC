# 🌐 NOC Intelligence Fusion Center

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, 18+ global cloud infrastructure providers, regional utility grids, global BGP routing tables, **geofenced local law enforcement CAD APIs**, and **internal hardware/software asset inventories**. 

It utilizes a highly optimized hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring, pre-compiled Regex for **Term-Hit Density** triage, strict deterministic algorithms for causal correlation, and edge-optimized LLMs for automated Map-Reduce synthesis—to cut through alert fatigue and deliver actionable intelligence.

---

## 🏗️ Core Architecture

* **Frontend (`web`):** Streamlit (Python) running interactive, zero-scroll dashboards with context-aware real-time asynchronous polling, dynamic cookie-persistent UI theming, and an integrated UI Debouncing/Cooldown Engine to protect backend resources.
* **Service-Oriented Architecture (SOA):** A strict Data Access Layer (`services.py`) that completely decouples the Streamlit UI from SQLAlchemy ORM models, utilizing detached `DotDict` patterns and aggressive RAM caching to prevent detached instance crashes and database locking.
* **Background Orchestration (`worker`):** A headless daemon driving a Master Scheduler that bypasses Python's GIL using a Hybrid Concurrency Model (Asynchronous I/O combined with Multiprocessing via `ProcessPoolExecutor`).
* **Ingestion Gateway (`webhook`):** A dedicated FastAPI asynchronous listener hosting REST APIs to receive, parse, and normalize live ITSM telemetry (e.g., SolarWinds) without blocking the UI.
* **Database (`database.py`):** Defaults to a lightweight SQLite database pushed to the limit via low-level C-library pragmas (Write-Ahead Logging, in-memory temp stores, and memory-mapped files) for extreme edge-compute concurrency.
* **Synthesis & Broadcast (`llm.py`):** A universal LLM abstraction layer heavily tuned for Local Edge Compute (Ollama, LM Studio) utilizing adaptive chunking, strict temperature controls, and Map-Reduce pipelines to prevent VRAM context-window overflows.

---

## 🖥️ Modules & Functional Capabilities (UI Deep Dive)

The application routes operators between 8 distinct operational modules based on their assigned Role-Based Access Control (RBAC) permissions.

### 1. 👁️ Global Dashboards
High-level strategic views aggregating telemetry across all domains.
* **Operational Dashboard:** Displays 24-hour KPIs. Houses auto-rotating panels for "Threat Triage" (Pinned/Live intel), "Infrastructure Status" (Active Cloud Outages, CVEs, Hazards), and an "AI Analysis" panel featuring an LLM-powered rolling summary and AI Security Auditor.
* **Global Risk (Executive Matrix):** Evaluates live unified threat posture (Cyber + Physical) against a 14-Day Baseline Deviation Trend utilizing the MS-ISAC/CIS Alert Framework (GREEN to RED). 
* **Internal Risk (Asset Posture):** Tracks the organization's hardware and software footprint against active OSINT threats, producing a localized risk score and highlighting critical asset exposures via historical trend lines.
* **Unified Brief:** Displays an autonomous Map-Reduce narrative that merges the Global OSINT Threat with the Internal Asset Risk Matrix into a single macroscopic brief (auto-updates every 2 hours).

### 2. 📡 Threat Telemetry
The primary ingestion view for global and perimeter open-source intelligence.
* **RSS Triage:** Implements advanced pagination logic to gracefully render thousands of threat articles across "Pinned", "Live", "Low", and "Search" sub-tabs. Operators can manually pin, boost, or send articles to the ML training queue.
* **Exploits (KEV):** An offline, heavily indexed mirror of the CISA Known Exploited Vulnerabilities catalog.
* **Cloud Services:** Monitors 18+ active IaaS/SaaS status pages (AWS, Azure, GCP, Datadog, etc.) to detect upstream dependencies affecting the NOC.
* **Perimeter Crime:** Renders a 3D PyDeck map of localized law enforcement dispatch data geofenced around HQ. Features dynamic radius filtering (1, 3, 5, or 10 miles) and interactive row-selection that auto-zooms to specific kinetic threats.

### 3. 🗺️ Regional Grid
Advanced geospatial intelligence engine tracking environmental and kinetic threats to physical infrastructure.
* **Geospatial Map:** Deep PyDeck integration overlaying authorized NOC facilities with active SPC Convective outlooks, NWS Warnings/Watches, NIFC Active Wildfires, and NWS Red Flag warnings. Includes an embedded live precipitation radar.
* **Executive Dash:** Uses Plotly pie and bar charts to present critical infrastructure exposure by District, Priority, and Threat Type, alongside an AI Meteorological Briefing generator.
* **Deep Hazard Analytics:** Provides an intersectional dataset displaying exactly which facilities sit inside specific storm geometries.
* **Location Matrix & Alerts Log:** Raw data tables providing deep-dive inspection windows into explicit NWS action instructions and coordinates.

### 4. 🎯 Threat Hunting & IOCs
Proactive detection engineering and indicator extraction tools.
* **Live Global IOC Matrix:** Displays autonomously extracted IOCs (IPv4, SHA256, CVE) with hyperlinked "OSINT Pivots" to external tools like VirusTotal and Shodan, fully exportable to CSV.
* **Deep Hunt Builder:** Takes a target entity (e.g., "Volt Typhoon"), queries historical telemetry, and instructs the LLM to generate custom Splunk/SIEM queries, MITRE mappings, and YARA rules.

### 5. ⚡ AIOps RCA (Root Cause Analysis)
A near real-time self-healing correlation engine mapping raw network alerts against physical realities.
* **Active Board:** Renders an auto-focusing map of alerting locations. Evaluates topology using the **Supreme Patient Zero Algorithm** (Topological Tier + Severity + Time Offset) to find the root cause. Integrates **Global Fleet Event Detection** (warning of massive carrier outages) and features a dynamic ticket dispatch system that drafts LLM correlation narratives direct to ITSM platforms.
* **Predictive Analytics:** Executes heavy Pandas aggregations to highlight specific nodes experiencing state-flapping and sites suffering from chronic instability over 60-day historical periods.
* **Global Correlation:** Deterministically graphs causal links between external global intelligence and internal network telemetry drops.

### 6. 📝 Shift Logbook
A tactical operations tool replacing external notepads, driven by AI Map-Reduce.
* **Active Shift Entry:** Analysts log manual updates or utilize the "Auto-Draft Active Outages" engine, which polls the AIOps Engine to calculate and format active outage downtimes.
* **Persistent Daily Summaries:** Autonomously generates "End of Morning" and "End of Day" handoff reports using the LLM. 
* **Aggregated Executive Summaries:** Allows operators to target specific organizational roles (e.g., TOC vs. NOC) and run deep LLM analyses summarizing historical logs across an entire "Current Week" or "Current Month."
* **Log Explorer:** A dynamic day/week calendar interface featuring soft-delete auditing, modal expansions, and an Admin CSV export utility.

### 7. 📑 Reporting & Briefings
Automated and manual intelligence synthesis pipelines.
* **Daily Fusion Briefing:** An archive of automated AI-synthesized situational reports covering Cyber, Physical, and Cloud telemetry, natively converting Markdown into inline-CSS HTML for enterprise Outlook delivery.
* **Custom Report Builder:** A multi-select interface allowing analysts to manually aggregate database articles into a targeted LLM pipeline.
* **Shared Library:** An organizational repository for saving and reviewing generated custom reports.

### 8. ⚙️ Settings & Admin
The control plane for system maintenance and access management.
* **Facilities & Internal Assets:** Bulk JSON/CSV importers to manage Monitored Locations, Hardware tracking, and Software footprints.
* **RSS Sources & ML Training:** General database mutation, keyword weighting, and Scikit-Learn neural weight re-calibration interfaces.
* **AI & SMTP:** Manages LLM endpoints, tech stack inputs, mail servers, and custom baseline overrides for the Executive Threat Matrix.
* **Users & Roles (Geographic RBAC):** Granular controls allowing admins to craft custom roles mapped to specific pages, UI actions, and explicitly `allowed_site_types` (geographically or operationally restricting the map layers for specific users).
* **Backup & Restore:** Generates and imports master JSON backups containing keywords, feeds, and locations.
* **Danger Zone:** Houses destructive tools to run the Garbage Collector, clear crime/weather telemetry arrays, apply taxonomy migrations, or trigger full factory database resets. 
* **Black Ops:** Undocumented operational tools (*Operation: Nick* and *Operation: Dean*) used for targeted UI locking or cascading failure mock drills.

---

## 🧠 Background Engines & Workflows

### The Hybrid Concurrency Scheduler (`scheduler.py`)
Bypasses the Python Global Interpreter Lock (GIL) to maintain high throughput.
* **Async I/O (`aiohttp`):** Handles high-latency, low-CPU network requests (polling hundreds of RSS feeds, NWS API, LRPD dispatch API) concurrently every 5 to 15 minutes.
* **Multiprocessing (`ProcessPoolExecutor`):** Offloads heavy CPU-bound analytical tasks—such as calculating Haversine distances or running TF-IDF matrix predictions—to separate CPU cores, ensuring the primary scheduler loop never stalls.

### Geospatial Bounding-Box Math (`services.py`)
Before executing CPU-intensive point-in-polygon math (`site_pt.within(shape)`), the algorithm extracts the strict min/max boundaries of every weather polygon. It runs a pure float-math evaluation (`minx <= lon <= maxx`). If the facility is not inside the rough square of the storm, it skips the expensive Shapely math. This allows the system to evaluate thousands of IT locations against national weather systems instantly without UI latency.

### The "Donut of Uncertainty" Geocoding (`crime_worker.py`)
Automatically polls local CAD APIs. Uses ArcGIS Geocoding to translate addresses to Lat/Lon. If the third-party API fails or times out, the engine executes a mathematical fallback, generating a random radial offset (between 0.009 and 0.018 degrees) from HQ, ensuring the incident is still plotted on the UI map with an `(Approx Loc)` flag to preserve situational awareness.

---

## ⚙️ System Requirements & Deployment

This application scales exceptionally well. It is optimized to run on low-power edge-compute hardware via SQLite, while fully capable of saturating enterprise-grade servers connected to PostgreSQL during massive asynchronous data ingestion and parallel ML scoring tasks. 

### **Real-World Resource Utilization (Docker)**
* **Base Memory Footprint:** Highly optimized via slim base images and localized memory dictionaries; ~650 MB total across all 3 microservices.
* **Database Storage:** The local SQLite file utilizes WAL (Write-Ahead Logging) and requires minimal disk space compared to an independent PostgreSQL container.
* **Compute Profiling:** Web and Webhook gateways remain idle (< 1% CPU) until concurrent alert floods occur. The worker container may briefly spike compute resources during heavy geospatial polygon rendering or multiprocessing NLP vectorization.

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

**Manual Database Cleanup & Admin Tools:**
If the dashboard feels sluggish after importing massive data feeds, navigate to **Settings & Admin > ⚠️ Danger Zone** and click **🧹 Run Garbage Collector** to force a cleanup of orphaned IOCs and stale telemetry. Administrators can also leverage undocumented internal tests (*Operation: Dean*) to simulate cascading failure loads on the map engine.

---

## 🤖 Addendum: AI-Generated Codebase

Please note that the entirety of this application's codebase was generated by Artificial Intelligence.

The Python backend, Streamlit frontend, Scikit-Learn machine learning logic, unified SQLite/PostgreSQL database schema, complex LLM Prompt Engineering pipelines, Regex algorithms, and Docker microservices configurations were written by an AI assistant (Google's Gemini) based on continuous, iterative prompting.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, optimization targeting, and rigorous hallucination-debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.

### OpenCode Usage Guide

This codebase supports development and maintenance via [OpenCode](https://opencode.ai), an interactive CLI tool for software engineering tasks.

#### Getting Started

1. **Install OpenCode:**
   ```bash
   npm install -g opencode
   ```

2. **Interactive Development:**
   ```bash
   opencode
   ```

3. **Natural Language Commands:**
   OpenCode accepts natural language queries about the codebase. Examples:
   - "How does the AIOps root cause analysis work?"
   - "Find all functions that query the database"
   - "Explain the IOC extraction regex patterns"

#### Available Agents

| Agent | Purpose |
|-------|---------|
| `explore` | Fast codebase exploration by patterns and keywords |
| `general` | Multi-step research and task execution |

#### Example Sessions

```bash
# Explore RSS feed fetching logic
opencode "How are RSS feeds fetched and parsed?"

# Find database query functions
opencode "Find all functions in services.py that query the database"

# Explain ML scoring
opencode "Explain the HybridScorer in logic.py"
```

---

## 📚 External API References & Citations

### Core Dependencies

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| Streamlit | UI Framework | https://docs.streamlit.io |
| SQLAlchemy | ORM / Database | https://docs.sqlalchemy.org |
| FastAPI | Webhook Gateway | https://fastapi.tiangolo.com |
| Scikit-Learn | ML Classification | https://scikit-learn.org |
| Pandas | Data Processing | https://pandas.pydata.org |
| PyDeck | Geospatial Maps | https://pydeck.js.org |
| Feedparser | RSS Ingestion | https://feedparser.readthedocs.io |

### External Intelligence Feeds

| Source | Purpose | API URL |
|--------|---------|---------|
| CISA KEV | Known Exploited Vulnerabilities | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| NWS Alerts | National Weather Service | https://www.weather.gov/api/ |
| SPC Outlooks | Storm Prediction Center | https://www.spc.noaa.gov/ |
| ArcGIS Geocoding | Address → Lat/Lon | https://developers.arcgis.com/ |
| RIPE RIS | BGP Routing | https://ris.ripe.net/ |
| ORNL ODIN | Power Outages | https://odn.disasterspacing.org/ |
| LRPD CAD | Local Dispatch (Little Rock) | https://www.littlerock.gov/CAD/ |
| IODA | Internet Outage Detection | https://ioda.caida.org/ |

### LLM Integration

| Provider | Purpose | SDK |
|----------|---------|-----|
| Ollama | Local LLM | https://github.com/ollama/ollama |
| LM Studio | Local LLM | https://lmstudio.ai/ |
| OpenAI | Cloud LLM | https://platform.openai.com/ |
| Anthropic | Cloud LLM | https://docs.anthropic.com/ |

### SIEM Integration

| System | Purpose | API |
|--------|---------|-----|
| Elasticsearch | SIEM Telemetry | https://www.elastic.co/ |
| Cisco FTD | Network Alerts | https://www.cisco.com/c/en/us/index.html |

### Email / Notifications

| Service | Purpose | Protocol |
|---------|---------|----------|
| SMTP | Risk Alerts | RFC 5321 |
| SendGrid | Email Relay | https://sendgrid.com/ |
| Mailgun | Email Relay | https://www.mailgun.com/ |

---

*Documentation generated for NOC Intelligence Fusion Center v1.0*
