# 🌐 NOC Intelligence Fusion Center

*(Formerly RSS_Filter)*

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, cloud infrastructure statuses, and regional physical hazards. It utilizes a hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring and local Large Language Models (LLMs) for automated synthesis—to cut through alert fatigue and deliver actionable intelligence.

## 🏗️ Architecture

* **Frontend:** Streamlit (Python) with in-RAM metric caching and dynamic database pagination.
* **Backend Worker:** `schedule` running an Asynchronous I/O Network Engine (`aiohttp`/`asyncio`) combined with a CPU Multiprocessing cluster (`ProcessPoolExecutor`) to bypass the Python GIL.
* **Database:** PostgreSQL 15 (Configured for high-concurrency pooling, Transactional Bulk Inserts, B-Tree Indexing, and Automated Vacuuming).
* **Scoring Engine (ML):** Scikit-Learn (TF-IDF Vectorizer + Naive Bayes Classifier).
* **Synthesis Engine (AI):** Local LLM API Integration (Optimized for small-parameter models via Prefix Forcing and Map-Reduce Chunking).
* **Deployment:** Docker Compose.

## ✨ Key Features

### 1. The Main Dashboard (Zero-Scroll HUD)

A high-density, card-based interface designed to be left on a NOC wall monitor. It features a strict 24-hour operational focus, surfacing only the most critical, immediate threats.

* **AI Shift Briefing:** An auto-updating, rolling narrative summarizing the last **6 hours** of cyber threats, regional hazards, and cloud outages.
* **Pinned Intelligence:** Manually pin critical articles to the top of the HUD so they never leave the glass.
* **AI Security Auditor:** Cross-references your configured internal "Tech Stack" against the last 30 days of the CISA Known Exploited Vulnerabilities (KEV) catalog via prompt chunking.
* **RAM-Cached Metrics:** Top-level threat metrics are cached in memory and updated every 60 seconds to prevent database hammering during multi-user sessions.

### 2. Multi-Domain Ingestion (High-Speed Async)

The backend worker concurrently scrapes and normalizes data using a single-thread asynchronous engine, passing payloads to isolated CPU cores for ML processing.

* **Cyber Intel:** Custom RSS feed aggregation with automated keyword-weight scoring.
* **Vulnerabilities:** Direct integration with the CISA KEV catalog.
* **Cloud Infrastructure:** Monitors live status pages for tier-1 providers (AWS, Azure, GCP, Cisco).
* **Regional Hazards:** Tracks severe weather and physical grid threats via the National Weather Service.

### 3. Automated Intel Report Builder & Daily Fusion

Tools for analysts to synthesize massive amounts of data into actionable briefings.

* **Report Builder:** Search the database, multi-select specific articles, and instruct the local LLM to generate an exhaustive, highly technical intelligence report. It programmatically appends clickable Markdown source links to the final output.
* **Daily Fusion Report:** A standalone page that chunks yesterday's entirely daily intake by category and generates a cohesive, executive-level master briefing.

### 4. Advanced RSS Triage & Pagination

Replaces the standard "Inbox" with a continuous, tabbed intelligence stream.

* Splits feeds into **Live Feed (>50 Score)** and **Below Threshold (<50 Score)**.
* **Dynamic Pagination:** Effortlessly browse thousands of historical database entries using integrated UI pagination without bogging down browser memory.
* Includes 1-click **Batch BLUF (Bottom Line Up Front)** generation for high-threat items.

### 5. Enterprise-Grade Security & Maintenance

* **Role-Based Access Control (RBAC):** Built-in user authentication with bcrypt password hashing, session tokens, and customizable roles (Admin vs Analyst) to restrict access to sensitive configurations or destructive actions.
* **Automated Master Garbage Collector:** A self-cleaning database routine that runs hourly to purge 0-score junk, unpinned intelligence older than 30 days, and resolved cloud/weather alerts older than 24-48 hours. It concludes with a PostgreSQL `VACUUM ANALYZE` command to reclaim physical disk space and optimize B-Tree indexes.

## ⚙️ System Requirements

This application is highly optimized for edge-compute hardware. The requirements below are based on real-world telemetry with 100+ active RSS feeds, background API polling, and the Multiprocessing Machine Learning engine active. *(Note: The local LLM server is assumed to be hosted externally/separately from this core stack).*

### **Minimum Hardware**

* **CPU:** 2 Cores
* **RAM:** 2 GB (Application consumes ~550 MB under active load)
* **Storage:** 5 GB (Accommodates Docker images and PostgreSQL text storage)

### **Recommended Hardware**

* **CPU:** 4+ Cores (Required to fully leverage the Python `ProcessPoolExecutor` for parallel ML scoring without interrupting network I/O)
* **RAM:** 4 GB
* **Storage:** 15 GB SSD (Improves database read/write speeds for bulk inserts and vacuuming)

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



## 🧠 Hybrid Intelligence: ML & LLM

This platform utilizes two completely different forms of Artificial Intelligence to manage the data pipeline.

### Part 1: The ML Scoring Engine (Noise Reduction)

The system uses a Scikit-Learn Naive Bayes model to score incoming RSS articles.

* **Rule-Based Start:** Initially, it scores based on your configured keywords and weights.
* **Training the Brain:** As you click **🧠 Learn: Keep** or **🧠 Learn: Dismiss** on articles in the live feed, you train the model on your operational preferences.
* **ML Takeover:** Once enough data is gathered, click **🚀 Retrain Model Now** in the settings. The system will generate `ml_model.pkl` and switch to contextual probability scoring.

### Part 2: The LLM Synthesis Engine (Context Generation)

The system connects to a local LLM to generate BLUFs, Shift Briefings, and Intel Reports. To ensure stability with smaller, local models (like 3B-8B parameter models), the system employs enterprise-grade prompt engineering:

* **Map-Reduce Chunking:** Complex queries are sliced into isolated API batches (e.g., 15 CVEs at a time) to prevent Context Window overflow. The responses are then stitched back together.
* **Prefix Forcing:** Strict prompts dictate the exact starting words for local LLMs, breaking their conversational habits and mathematically forcing them to output direct, factual summaries.
* **Short-Circuit Logic:** If the database contains no high-threat alerts for a given period, the Python backend bypasses the LLM entirely, saving compute cycles and preventing the AI from hallucinating data to fill a quota.

## 🛠️ Troubleshooting & Commands

**View Live Worker Logs (To monitor async scraping and multiprocessing tasks):**

```bash
docker compose logs -f worker

```

**Restart the Worker (Required after manual Python code changes):**

```bash
docker compose restart worker

```

**Manual Database Vacuum & Cleanup:**
If the dashboard feels sluggish after importing massive data feeds, navigate to **Settings & Admin > ⚠️ Danger Zone** and click **🧹 Run Garbage Collector** to force a PostgreSQL dead-tuple sweep.

**Database Migrations & Manual Overrides:**
To manually inject columns or run SQL commands against the database container:

```bash
docker exec -it <container_name_db_1> psql -U admin -d rss_db -c "YOUR SQL COMMAND;"

```

---

## 🤖 Addendum: AI-Generated Codebase

Please note that the entirety of this application's codebase was generated by Artificial Intelligence.

The Python backend, Streamlit frontend, Scikit-Learn machine learning logic, PostgreSQL database schema, complex LLM Prompt Engineering pipelines, Asynchronous mapping, and Docker deployment configurations were written by an AI assistant (Google's Gemini) based on continuous, iterative prompting.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, optimization targeting, and rigorous hallucination-debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.
