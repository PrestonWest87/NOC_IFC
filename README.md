# 🌐 NOC Intelligence Fusion Center

*(Formerly RSS_Filter)*

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, 18+ global cloud infrastructure providers, and regional utility grids. 

It utilizes a highly optimized hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring, RapidFuzz for heuristic asset mapping, strict deterministic algorithms for causal correlation, and local Large Language Models (LLMs) for automated synthesis—to cut through alert fatigue and deliver actionable intelligence.



## 🏗️ Architecture

* **Frontend:** Streamlit (Python) with context-aware real-time asynchronous polling (5-second loops for AIOps, throttled elsewhere), in-RAM metric caching, and dynamic database pagination.
* **Ingestion Gateways:** * *Scraping:* `schedule` running an Asynchronous I/O Network Engine (`aiohttp`/`asyncio`) combined with a CPU Multiprocessing cluster (`ProcessPoolExecutor`).
    * *Webhooks:* FastAPI asynchronous listener with NLP-based JSON flattening and multi-tiered device fingerprinting.
* **Database:** PostgreSQL 15 (Configured for high-concurrency pooling, Transactional Bulk Inserts, B-Tree Indexing, and Automated Vacuuming).
* **Correlation Engines:** * *Deterministic RCA:* Programmatic math and string-matching engine that calculates geospatial blast radii and clusters alerts by physical sites.
    * *Threat Scoring:* Scikit-Learn (TF-IDF Vectorizer + Naive Bayes Classifier).
    * *Asset Mapping:* `rapidfuzz` (Fuzzy string matching and heuristic learning).
* **Synthesis & Broadcast:** Local LLM API Integration combined with a native Python SMTP client for automated Situation Report (SitRep) delivery.
* **Deployment:** Docker Compose.

## ✨ Key Features

### 1. ⚡ AIOps Root Cause Analysis (Live Engine)
A near real-time (5-second polling) self-healing correlation engine that ingests raw network alerts and maps them against global and regional telemetry.

* **Deep Device Fingerprinting:** The webhook gateway accepts *any* arbitrary JSON payload. It recursively flattens the data, extracts IPs, and uses NLP to identify the specific hardware (Router, VM, SCADA/OT, Camera, Fire Alarm) and categorize the fault (Hardware Failure, Resource Exhaustion, Routing).
* **Site-Based Incident Clustering:** Alerts are not treated as isolated events. The matrix dynamically clusters disparate device alerts into unified "Site Blocks" to instantly reveal cascading local failures (e.g., a firewall and three VMs dropping simultaneously in the same building).
* **100% Local Deterministic RCA:** The correlation engine uses hard programmatic math *before* touching an LLM. It calculates geospatial distances from power/ISP outages and scans payloads for upstream cloud provider matches. The correlation engine will never go down, even if your AI provider does.
* **Auto-Resolution & Timeline:** A scrolling timeline tracks all system events. If a recovery payload is detected, the system auto-resolves the alert and clears the board without human intervention.

### 2. 🌍 Global SitRep & SMTP Broadcasting
* **Multi-Domain Correlation:** A dedicated engine that zooms out from individual alerts to ingest the *entire active state of the network* (all down nodes, cloud outages, and regional weather hazards), mapping out unified Situation Reports.
* **Automated SMTP Delivery:** Instantly broadcast AI-synthesized Global Situation Reports directly to your team's inbox or ticketing system via any external SMTP server.

### 3. The Main Dashboard (Zero-Scroll HUD)
A high-density, card-based interface designed to be left on a NOC wall monitor. It features a strict 24-hour operational focus.

* **AI Shift Briefing:** An auto-updating, rolling narrative summarizing the last **6 hours** of cyber threats, regional hazards, and cloud outages.
* **AI Security Auditor:** Cross-references your configured internal "Tech Stack" against the last 30 days of the CISA Known Exploited Vulnerabilities (KEV) catalog via prompt chunking.

### 4. Multi-Domain Threat Telemetry
The backend worker concurrently scrapes and normalizes data using a single-thread asynchronous engine.

* **Cyber Intel:** Custom RSS feed aggregation with ML keyword-weight scoring.
* **Massive Cloud Tracking:** Monitors live status pages for 18+ tier-1 providers (AWS, Azure, GCP, Cisco, Cloudflare, CrowdStrike, GitHub, etc.) and dynamically generates UI tabs only for systems currently degraded.
* **Regional Hazards:** Tracks severe weather and physical grid threats via the National Weather Service.

### 5. Enterprise-Grade Security & Maintenance
* **Role-Based Access Control (RBAC):** Built-in user authentication with bcrypt password hashing, session tokens, and dynamic, on-the-fly customizable roles.
* **JSON Backup & Restore:** Export your entire custom configuration (RSS Feeds, Keywords, Monitored Locations, and ML Aliases) into a single portable JSON file, and restore the database with a single click.
* **Automated Master Garbage Collector:** A self-cleaning routine that runs hourly to purge 0-score junk, unpinned intelligence older than 30 days, and resolved telemetry older than 72 hours. 

## ⚙️ System Requirements

This application scales exceptionally well. It is optimized to run on low-power edge-compute hardware, while fully capable of saturating enterprise-grade servers (e.g., 32-core Intel Xeon environments) during massive asynchronous data ingestion and parallel ML scoring tasks. 

### **Real-World Resource Utilization (Docker)**
* **Base Memory Footprint:** ~650 MB total across all 4 microservices.
* **Database Storage:** Highly optimized. PostgreSQL consumes < 100 MB for tens of thousands of active intel rows.
* **Compute Profiling:** Web and Webhook gateways remain idle (< 1% CPU) until concurrent alert floods occur. The UI container may briefly spike compute resources during heavy geospatial PyDeck map rendering or Map-Reduce LLM prompt generation.

### **Minimum Hardware**
* **CPU:** 2 Cores
* **RAM:** 2 GB 
* **Storage:** 5 GB 

### **Recommended Hardware**
* **CPU:** 4+ Cores (Allows the Python `ProcessPoolExecutor` to offload Scikit-Learn vectorization without bottlenecking the async web server).
* **RAM:** 4 GB 
* **Storage:** 15 GB SSD (Improves database read/write speeds for bulk inserts and vacuuming).

### **Software Requirements**
* **Docker:** Engine v20.10.0 or higher
* **Docker Compose:** v2.0.0 or higher
* **OS:** Any Linux distribution (Ubuntu/Debian recommended), Windows (via WSL2), or macOS.

## 🚀 Installation & Deployment

1. **Clone the repository** and navigate to the project folder.
2. **Set up environment variables:** Edit the `.env` file to set your database passwords and point the application to your Local LLM API endpoint.
3. **Build and start the containers:**
```bash
docker compose up --build -d

```

4. **Access the Dashboard:** Open a web browser and navigate to `http://localhost:8501`.
* *Default login is `admin` / `admin123` (promptly reset this in Settings).*


5. **Route Webhooks:** Point your external monitoring tools (SolarWinds, Datadog, PRTG) to `POST http://<your-server-ip>:8100/webhook/solarwinds`. *(Note: Verify your `docker-compose.yml` port mappings, this may be configured to 8100 depending on your environment).*

## 🛠️ Troubleshooting & Commands

**View Live Worker Logs (To monitor async scraping and maintenance tasks):**

```bash
docker compose logs -f worker

```

**View Webhook Gateway Logs (Useful for tuning NLP matching logic):**

```bash
docker compose logs -f webhook

```

**Manual Database Vacuum & Cleanup:**
If the dashboard feels sluggish after importing massive data feeds, navigate to **Settings & Admin > ⚠️ Danger Zone** and click **🧹 Run Garbage Collector** to force a PostgreSQL dead-tuple sweep.

---

## 🤖 Addendum: AI-Generated Codebase

Please note that the entirety of this application's codebase was generated by Artificial Intelligence.

The Python backend, Streamlit frontend, Scikit-Learn machine learning logic, PostgreSQL database schema, complex LLM Prompt Engineering pipelines, RapidFuzz Heuristic algorithms, and Docker deployment configurations were written by an AI assistant (Google's Gemini) based on continuous, iterative prompting.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, optimization targeting, and rigorous hallucination-debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.

```
```
