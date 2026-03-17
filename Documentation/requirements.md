# Enterprise Architecture & Dependency Specification: `requirements.txt`

## 1. Executive Overview

The `requirements.txt` file serves as the **Master Dependency Manifest** for the Intelligence Fusion Center (IFC). Rather than a monolithic framework, the IFC employs a micro-framework, composable architecture. This file defines the specific third-party Python libraries required to build the application's distinct operational layers: the asynchronous ingestion engine, the Machine Learning pipeline, the geospatial math module, and the interactive Streamlit presentation layer.

---

## 2. User Interface & Presentation Layer
These libraries power the visual dashboards, interactive maps, and session management for NOC operators.

* **`streamlit`**: The core frontend framework. Used to rapidly build the React-based dashboards (`app.py`) purely in Python.
* **`streamlit-autorefresh`**: A utility component that forcefully re-renders specific Streamlit containers at timed intervals, enabling the "Live NOC View" rotating dashboard without requiring human interaction.
* **`streamlit-cookies-controller==0.0.3`**: Manages browser-side cookies to persist user session tokens (UUIDs) across hard refreshes, preventing operators from being logged out when the page reloads.
* **`pydeck`**: A high-scale spatial rendering library (deck.gl binding for Python). Used to render the 3D interactive maps in the AIOps and Regional Threat dashboards.

---

## 3. Machine Learning & Artificial Intelligence
The cognitive core of the application, split between local statistical ML and remote Generative AI.

* **`scikit-learn`**: The enterprise standard for traditional machine learning. Used to build the `MultinomialNB` classifier and `TfidfVectorizer` NLP pipeline for threat triage (`train_model.py`).
* **`joblib`**: A highly optimized serialization library used to save and load the trained Scikit-Learn models (`ml_model.pkl`) into memory without massive overhead.
* **`pandas`**: The premier data manipulation library. Used to convert database queries into vectorized DataFrames for ML training and AIOps predictive analytics (e.g., chronic flap detection).
* **`openai` & `google-generativeai`**: Official SDKs for communicating with LLM endpoints (used abstractly in `llm.py` to support OpenAI, local LM Studio, or Gemini models for deep forensic analysis).

---

## 4. Telemetry Ingestion & Concurrency
The engine utilizes a hybrid concurrency model to ingest thousands of data points without blocking the main application thread.

* **`aiohttp` & `aiofiles`**: Asynchronous HTTP client and file I/O libraries. Critical for `scheduler.py` to concurrently fetch dozens of external RSS feeds without waiting for sequential blocking operations.
* **`requests`**: The standard synchronous HTTP library. Used heavily in the background workers (`cloud_worker.py`, `infra_worker.py`) where strict timeouts and sequential processing are preferred.
* **`feedparser`**: A robust parser for handling messy, non-standardized RSS and Atom XML feeds from global intelligence sources.
* **`beautifulsoup4`**: An HTML/XML parsing library, typically used to strip raw HTML tags out of poorly formatted RSS summaries before passing them to the AI.

---

## 5. Geospatial Analytics
* **`shapely`**: A high-performance planar geometry library. Used exclusively by `infra_worker.py` to create complex Polygon objects from NOAA/SPC weather alerts and calculate deterministic "Point-in-Polygon" intersections against the exact latitude/longitude of NOC facilities.

---

## 6. Webhook Gateway & API Layer
Libraries powering the inbound ITSM/NMS integration pipeline.

* **`fastapi`**: A modern, high-performance web framework used in `webhook_listener.py` to create the REST API endpoints that receive live SolarWinds alerts.
* **`uvicorn`**: A lightning-fast ASGI server implementation used to host the FastAPI application asynchronously.

---

## 7. Database Persistence & ORM
* **`sqlalchemy`**: The master Object-Relational Mapper (ORM). Abstracts raw SQL queries into Python objects, enabling the application to swap seamlessly between SQLite (for edge deployments) and PostgreSQL.
* **`psycopg2-binary`**: The PostgreSQL database adapter. Required by SQLAlchemy to communicate with remote enterprise Postgres clusters.

---

## 8. Security, Scheduling & Utilities
* **`bcrypt==4.1.2`**: A cryptographic hashing library used to securely salt and hash user passwords in the `users` table, preventing plaintext credential storage.
* **`rapidfuzz`**: A hyper-fast string matching library (using Levenshtein distance). Used by the webhook listener to fuzzy-match messy incoming node names (e.g., "AR-LIT-FW01") to formal database locations (e.g., "Little Rock").
* **`schedule`**: A lightweight, human-readable cron-style scheduling library used in `scheduler.py` to orchestrate the timed execution of the various data workers (e.g., `schedule.every(15).minutes.do(fetch_feeds)`).
* **`python-dotenv`**: Loads environment variables from a `.env` file into `os.environ`, keeping sensitive credentials (like the `DATABASE_URL` or LLM API keys) out of the source code.
