# 🌐 NOC Intelligence Fusion Center

*(Formerly RSS_Filter)*

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, 18+ global cloud infrastructure providers, and regional utility grids. 

It utilizes a hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring, RapidFuzz for heuristic asset mapping, and local Large Language Models (LLMs) for automated synthesis and Root Cause Analysis (RCA)—to cut through alert fatigue and deliver actionable intelligence.



## 🏗️ Architecture

* **Frontend:** Streamlit (Python) with context-aware real-time asynchronous polling, in-RAM metric caching, and dynamic database pagination.
* **Ingestion Gateways:** * *Scraping:* `schedule` running an Asynchronous I/O Network Engine (`aiohttp`/`asyncio`) combined with a CPU Multiprocessing cluster (`ProcessPoolExecutor`).
    * *Webhooks:* FastAPI asynchronous listener with NLP-based JSON flattening.
* **Database:** PostgreSQL 15 (Configured for high-concurrency pooling, Transactional Bulk Inserts, B-Tree Indexing, and Automated Vacuuming).
* **Correlation & ML Engines:** * *Threat Scoring:* Scikit-Learn (TF-IDF Vectorizer + Naive Bayes Classifier).
    * *Asset Mapping:* `rapidfuzz` (Fuzzy string matching and heuristic learning).
    * *Geospatial:* `shapely` and `pydeck` (Dynamic blast radius and coordinate intersection).
* **Synthesis Engine (AI):** Local LLM API Integration (Optimized for small-parameter models via Prefix Forcing and Map-Reduce Chunking).
* **Deployment:** Docker Compose.

## ✨ Key Features

### 1. ⚡ AIOps Root Cause Analysis (Live Engine)
A near real-time (5-second polling) self-healing correlation engine that ingests raw network alerts and maps them against global and regional telemetry.

* **Heuristic Ingestion:** The webhook gateway accepts *any* arbitrary JSON payload. It recursively flattens the data, uses RegEx to extract IP addresses, and uses NLP conceptual mapping to figure out what the alert means without requiring strict schemas.
* **ML Alias Learning:** Automatically learns to map cryptic network node names (e.g., `BENTON-DC-FW-01`) to your physical site list. Unsure guesses are routed to a human-in-the-loop training matrix for verification.
* **Dynamic Blast Radius:** The 3D map dynamically calculates the scope of an outage. Base blast radii expand mathematically based on node-failure density at a single site, and apply massive multipliers if failures cascade to geographically nearby sites.
* **Multi-Domain Correlation:** The LLM actively cross-references your internal network failure against local Power Grid outages, ISP drops, and NWS severe weather alerts to determine if a router broke, or if the building lost power.
* **Auto-Resolution & Timeline:** A scrolling chronological timeline tracks all system events. If a recovery payload is detected, the system auto-resolves the alert and clears the board without human intervention.

### 2. The Main Dashboard (Zero-Scroll HUD)
A high-density, card-based interface designed to be left on a NOC wall monitor. It features a strict 24-hour operational focus.

* **AI Shift Briefing:** An auto-updating, rolling narrative summarizing the last **6 hours** of cyber threats, regional hazards, and cloud outages.
* **AI Security Auditor:** Cross-references your configured internal "Tech Stack" against the last 30 days of the CISA Known Exploited Vulnerabilities (KEV) catalog via prompt chunking.

### 3. Multi-Domain Threat Telemetry
The backend worker concurrently scrapes and normalizes data using a single-thread asynchronous engine.

* **Cyber Intel:** Custom RSS feed aggregation with ML keyword-weight scoring.
* **Vulnerabilities:** Direct integration with the CISA KEV catalog.
* **Massive Cloud Tracking:** Monitors live status pages for 18+ tier-1 providers (AWS, Azure, GCP, Cisco, Cloudflare, Zscaler, CrowdStrike, GitHub, etc.) and dynamically generates UI tabs only for systems currently degraded.
* **Regional Hazards:** Tracks severe weather and physical grid threats via the National Weather Service.

### 4. Automated Intel Report Builder
Tools for analysts to synthesize massive amounts of data into actionable briefings.

* **Report Builder:** Search the database, multi-select specific articles, and instruct the local LLM to generate an exhaustive, highly technical intelligence report. It programmatically appends clickable Markdown source links to the final output.
* **Daily Fusion Report:** A standalone page that chunks yesterday's entire daily intake by category and generates a cohesive, executive-level master briefing.

### 5. Enterprise-Grade Security & Maintenance
* **Role-Based Access Control (RBAC):** Built-in user authentication with bcrypt password hashing, session tokens, and dynamic, on-the-fly customizable roles.
* **Automated Master Garbage Collector:** A self-cleaning database routine that runs hourly to purge 0-score junk, unpinned intelligence older than 30 days, and resolved telemetry older than 72 hours. 

## ⚙️ System Requirements

This application is highly optimized for edge-compute hardware, but heavily relies on CPU math for continuous NLP extraction, fuzzy-string alias matching, and geospatial intersection calculations.

### **Minimum Hardware**
* **CPU:** 2 Cores
* **RAM:** 2 GB 
* **Storage:** 5 GB 

### **Recommended Hardware (For Real-Time AIOps)**
* **CPU:** 4+ Cores (Expect periodic utilization spikes up to **15-20%** during concurrent, chaotic webhook ingestion and Map-Reduce LLM formatting).
* **RAM:** 4 GB (Application comfortably consumes **~700 MB** under active, real-time load).
* **Storage:** 15 GB SSD (Improves database read/write speeds for bulk inserts and vacuuming).

### **Software Requirements**
* **Docker:** Engine v20.10.0 or higher
* **Docker Compose:** v2.0.0 or higher
* **OS:** Any Linux distribution (Ubuntu/Debian recommended), Windows (via WSL2), or macOS.

## 🚀 Installation & Deployment

1. **Clone the repository** and navigate to the project folder.
2. **Set up environment variables:** Edit the `.env` file to set your database passwords and point the application to your Local LLM API endpoint.
3. **Build and start the containers:**
```
docker compose up --build -d
```
    Access the Dashboard: Open a web browser and navigate to http://localhost:8501.
    
        Default login is admin / admin123 (promptly reset this in Settings).

    Route Webhooks: Point your external monitoring tools (SolarWinds, Datadog, PRTG) to POST http://<your-server-ip>:8000/webhook/solarwinds.

🛠️ Troubleshooting & Commands

View Live Worker Logs:
Bash

docker compose logs -f worker

View Webhook Gateway Logs (Useful for tuning NLP matching):
Bash

docker compose logs -f webhook

Manual Database Vacuum & Cleanup:
If the dashboard feels sluggish after importing massive data feeds, navigate to Settings & Admin > ⚠️ Danger Zone and click 🧹 Run Garbage Collector to force a PostgreSQL dead-tuple sweep.
🤖 Addendum: AI-Generated Codebase

Please note that the entirety of this application's codebase was generated by Artificial Intelligence.

The Python backend, Streamlit frontend, Scikit-Learn machine learning logic, PostgreSQL database schema, complex LLM Prompt Engineering pipelines, RapidFuzz Heuristic algorithms, and Docker deployment configurations were written by an AI assistant (Google's Gemini) based on continuous, iterative prompting.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, optimization targeting, and rigorous hallucination-debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.
