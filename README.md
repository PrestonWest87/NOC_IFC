# 🌐 NOC Intelligence Fusion Center

*(Formerly RSS_Filter)*

An enterprise-grade, AI-powered intelligence aggregator and Heads-Up Display (HUD) built for Network Operations Centers. This platform ingests real-time telemetry from hundreds of RSS feeds, CISA vulnerabilities, cloud infrastructure statuses, and regional physical hazards. It utilizes a hybrid intelligence engine—combining Scikit-Learn Machine Learning for threat scoring and local Large Language Models (LLMs) for automated synthesis—to cut through alert fatigue and deliver actionable intelligence.

## 🏗️ Architecture

* **Frontend:** Streamlit (Python)
* **Backend Worker:** Python `schedule` with multithreaded `requests`
* **Database:** PostgreSQL 15
* **Scoring Engine (ML):** Scikit-Learn (TF-IDF Vectorizer + Naive Bayes Classifier)
* **Synthesis Engine (AI):** Local LLM Integration (Optimized for small-parameter models like Dolphin-Phi)
* **Deployment:** Docker Compose

## ✨ Key Features

### 1. The Main Dashboard (Zero-Scroll HUD)

A high-density, card-based interface designed to be left on a NOC wall monitor. It features a strict 24-hour operational focus, surfacing only the most critical, immediate threats.

* **AI Shift Briefing:** An auto-updating, rolling narrative summarizing the last 24 hours of cyber threats, regional hazards, and cloud outages.
* **Pinned Intelligence:** Manually pin critical articles to the top of the HUD so they never leave the glass.
* **AI Security Auditor:** Cross-references your configured internal "Tech Stack" against the last 30 days of the CISA Known Exploited Vulnerabilities (KEV) catalog.

### 2. Multi-Domain Ingestion

The backend worker concurrently scrapes and normalizes data from multiple critical infrastructure domains:

* **Cyber Intel:** Custom RSS feed aggregation with automated keyword-weight scoring.
* **Vulnerabilities:** Direct integration with the CISA KEV catalog.
* **Cloud Infrastructure:** Monitors live status pages for tier-1 providers (AWS, Azure, GCP, Cisco).
* **Regional Hazards:** Tracks severe weather and physical grid threats via the National Weather Service.

### 3. Automated Intel Report Builder

A dedicated tool for analysts to search the database, multi-select specific articles, and instruct the local LLM to generate an exhaustive, highly technical intelligence report.

* Outputs directly to properly formatted Markdown (`.md`).
* Enforces strict "Context-Bounding" and Zero-Temperature prompting to completely eliminate AI hallucinations and ensure only factual, source-backed data is included.

### 4. Advanced RSS Triage

Replaces the standard "Inbox" with a continuous, tabbed intelligence stream.

* Splits feeds into **Live Feed (>50 Score)** and **Below Threshold (<50 Score)**.
* Includes 1-click **Batch BLUF (Bottom Line Up Front)** generation for high-threat items.
* Features AI Macro Overviews that can read 50+ headlines and synthesize the broader global threat landscape.

## ⚙️ System Requirements

This application is highly optimized. The requirements below are based on real-world telemetry with 100+ active RSS feeds, background API polling, and the Machine Learning engine active. *(Note: The local LLM server is assumed to be hosted externally/separately from this core stack).*

### **Minimum Hardware**

* **CPU:** 2 Cores
* **RAM:** 2 GB (Application consumes ~550 MB under active load)
* **Storage:** 5 GB (Accommodates Docker images and PostgreSQL text storage)

### **Recommended Hardware**

* **CPU:** 4+ Cores (For smooth UI rendering during batch BLUF generation and ML retraining)
* **RAM:** 4 GB
* **Storage:** 15 GB SSD (Improves database read/write speeds for massive historical archives)

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

## 🧠 Hybrid Intelligence: ML & LLM

This platform utilizes two completely different forms of Artificial Intelligence to manage the data pipeline.

### Part 1: The ML Scoring Engine (Noise Reduction)

The system uses a Scikit-Learn Naive Bayes model to score incoming RSS articles.

* **Rule-Based Start:** Initially, it scores based on your configured keywords and weights.
* **Training the Brain:** As you click **🧠 Learn: Keep** or **🧠 Learn: Dismiss** on articles in the live feed, you train the model on your operational preferences.
* **ML Takeover:** Once enough data is gathered, click **🚀 Retrain Model Now** in the settings. The system will generate `ml_model.pkl` and switch to contextual probability scoring.

### Part 2: The LLM Synthesis Engine (Context Generation)

The system connects to a local LLM to generate BLUFs, Shift Briefings, and Intel Reports. To ensure stability with smaller, local models (like 3B-8B parameter models), the system employs enterprise-grade prompt engineering:

* **Prompt Chunking:** Complex queries (like the Shift Briefing) are broken down into isolated API calls per domain (Cyber, Weather, Cloud) to prevent "Recency Bias" and prompt confusion.
* **Zero-Temperature Execution:** Analytical tasks run at `0.0` or `0.1` temperature with strict XML bounding to mathematically prevent hallucinations and creative roleplay.
* **Short-Circuit Logic:** If the database contains no high-threat alerts for a given period, the Python backend bypasses the LLM entirely, saving compute cycles and preventing the AI from inventing data to fill a quota.

## 🛠️ Troubleshooting & Commands

**View Live Worker Logs (To monitor scraping and background tasks):**

```bash
docker compose logs -f worker

```

**Restart the Worker (Required after manual code changes):**

```bash
docker compose restart worker

```

**Database Migrations & Manual Overrides:**
To manually inject columns or run SQL commands against the database container:

```bash
docker exec -it <container_name_db_1> psql -U admin -d rss_db -c "YOUR SQL COMMAND;"

```

---

## 🤖 Addendum: AI-Generated Codebase

Please note that the entirety of this application's codebase was generated by Artificial Intelligence.

The Python backend, Streamlit frontend, Scikit-Learn machine learning logic, PostgreSQL database schema, complex LLM Prompt Engineering pipelines, and Docker deployment configurations were written by an AI assistant (Google's Gemini) based on continuous, iterative prompting.

While the code was AI-generated, the system architecture, feature requirements, NOC operational workflow methodologies, and rigorous hallucination-debugging were orchestrated and directed entirely by a human engineer. This project serves as a practical demonstration of AI-assisted software engineering to rapidly build customized, enterprise-grade critical infrastructure monitoring tools.
