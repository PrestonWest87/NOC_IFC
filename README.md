# 🌐 NOC Intelligence Fusion Center

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, 18+ global cloud infrastructure providers, regional utility grids, global BGP routing tables, and **geofenced local law enforcement open-data APIs**. 

It utilizes a highly optimized hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring, pre-compiled Regex for high-speed triage and IOC extraction, strict deterministic algorithms for causal correlation, and model-agnostic LLMs for automated Map-Reduce synthesis—to cut through alert fatigue and deliver actionable intelligence.

## 🏗️ Architecture

* **Frontend (`web`):** Streamlit (Python) running interactive, zero-scroll dashboards with context-aware real-time asynchronous polling, PyDeck 3D spatial rendering, and dynamic database pagination.
* **Background Orchestration (`worker`):** A headless daemon driving a Master Scheduler that bypasses Python's GIL using a Hybrid Concurrency Model (Asynchronous I/O via `aiohttp` combined with Multiprocessing via `ProcessPoolExecutor`).
* **Ingestion Gateway (`webhook`):** A dedicated FastAPI asynchronous listener hosting REST APIs to receive, parse, and normalize live telemetry from NMS/ITSM platforms like SolarWinds.
* **Database:** Defaults to a lightweight, file-based SQLite database (`noc_fusion.db`) optimized with `check_same_thread=False` for concurrent container access, with seamless ORM fallback to enterprise PostgreSQL clusters.
* **Correlation Engines:**
    * *Deterministic RCA:* Programmatic math engine that calculates geospatial blast radii, cascade durations, and clusters alerts by physical sites.
    * *Hybrid Threat Scoring:* Fuses deterministic Keyword Heuristics with probabilistic Scikit-Learn predictions (TF-IDF + Multinomial Naive Bayes).
    * *Asset Mapping:* A 5-stage pipeline utilizing exact matching, known aliases, regex heuristics, and ML prediction to map messy alerts to physical NOC sites.
* **Synthesis & Broadcast:** A universal LLM abstraction layer supporting OpenAI, Groq, or local models, combined with a native Python SMTP client that translates Markdown to HTML for automated Situation Report (SitRep) delivery.
* **Deployment:** A decoupled, 3-container microservices topology built from a unified `python:3.11-slim` Dockerfile.

## ✨ Key Features

### 1. ⚡ AIOps Root Cause Analysis (Live Engine)
A near real-time self-healing correlation engine that ingests raw network alerts and maps them against global and regional telemetry.
* **Deep Device Fingerprinting:** The webhook gateway standardizes arbitrary JSON payloads and uses heuristic fingerprinting to identify specific hardware.
* **Ontological Incident Clustering:** Alerts are clustered into unified "Site Blocks" to instantly reveal cascading failures.
* **100% Local Deterministic RCA:** Calculates geospatial point-in-polygon intersections for severe weather and scans payloads for upstream cloud/ISP matches before utilizing LLMs.

### 2. 📊 Executive Grid Threat Matrix (New)
A synthesized command dashboard designed for executive leadership detailing risk to Bulk Electric System (BES) infrastructure.
* **Unified Posture Scoring:** Aggregates real-time localized perimeter crime, 48-hour cyber OSINT, and active CISA ICS-CERT advisories into a single high-level threat score.
* **Automated HTML SitReps:** Single-click dispatch of Outlook-native HTML intelligence reports covering perimeter kinetic risks and cyber threat landscapes.

### 3. 🌍 Global SitRep & Autonomous Reporting
* **Map-Reduce LLM Synthesis:** Processes massive datasets of raw intelligence by chunking context windows, extracting facts, and synthesizing narratives.
* **Automated SMTP Delivery:** Instantly broadcasts AI-synthesized tickets and Global Situation Reports directly to ITSM platforms or distribution lists.

### 4. 🚨 Multi-Domain Threat Telemetry & Crime Intelligence
The backend worker concurrently scrapes and normalizes physical, digital, and kinetic infrastructure data.
* **Cyber Intel:** Custom RSS feed aggregation evaluated by a Human-in-the-Loop reinforcement ML model.
* **Physical & Environmental Grids:** Ingests NOAA/SPC severe weather polygons, county-level power grid outages via ORNL ODIN, global BGP route leaks via RIPE Stat, NIFC active wildfires, and NWS Fire Weather / Red Flag warnings.
* **Perimeter Kinetic Threats:** Automatically polls local law enforcement endpoints (e.g., LRPD Open Data API), calculates Haversine distances, and alerts on kinetic threats (arson, theft, violence) occurring within a strict 1-mile radius of the NOC/HQ.

### 5. Enterprise-Grade Security & Maintenance
* **Role-Based Access Control (RBAC):** Built-in user authentication with bcrypt password hashing, session tokens, and dynamic JSON-based permissions mapping down to specific UI buttons.
* **Automated Master Garbage Collector:** A self-cleaning routine that runs hourly to purge 0-score junk, unpinned intelligence older than 30 days, and expired kinetic incident telemetry. 

---

## ⚙️ System Requirements & Deployment

This application scales exceptionally well. It is optimized to run on low-power edge-compute hardware via SQLite, while fully capable of saturating enterprise-grade servers connected to PostgreSQL during massive asynchronous data ingestion and parallel ML scoring tasks. 

### **Real-World Resource Utilization (Docker)**
* **Base Memory Footprint:** Highly optimized via slim base images and localized memory dictionaries; ~650 MB total across all 3 microservices.
* **Database Storage:** The local SQLite file requires minimal disk space compared to an independent PostgreSQL container.
* **Compute Profiling:** Web and Webhook gateways remain idle (< 1% CPU) until concurrent alert floods occur. The worker container may briefly spike compute resources during heavy geospatial polygon rendering or multiprocessing NLP vectorization.

### **Minimum Hardware**
* **CPU:** 2 Cores
* **RAM:** 2 GB 
* **Storage:** 5 GB 

### **Recommended Hardware**
* **CPU:** 4+ Cores (Allows the Python `ProcessPoolExecutor` to offload Scikit-Learn vectorization without bottlenecking the main scheduler loop).
* **RAM:** 4 GB 
* **Storage:** 15 GB SSD (Improves SQLite I/O speeds for high-velocity webhook bursts).

### **Software Requirements**
* **Docker:** Engine v20.10.0 or higher
* **Docker Compose:** v2.0.0 or higher
* **OS:** Any Linux distribution (Ubuntu/Debian recommended), Windows (via WSL2), or macOS.

## 🚀 Installation & Deployment

1. **Clone the repository** and navigate to the project folder.
2. **Set up environment variables:** Edit the `.env` file to set your local LLM API endpoints and optionally define a `DATABASE_URL` if bypassing the default SQLite setup.
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
