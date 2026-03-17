# Enterprise Architecture & Deployment Specification: `docker-compose.yml`

## 1. Executive Overview

The `docker-compose.yml` file defines the **Production Containerization Topology** for the Intelligence Fusion Center (IFC). Rather than running a monolithic server, the application is deployed as a decoupled, microservices-style cluster. This architecture ensures that heavy background Machine Learning tasks do not consume the resources required to render the interactive operator dashboards, while maintaining a single unified codebase.

---

## 2. Container Topology & Service Specifications

The deployment spins up three distinct containers, all built from the same unified `Dockerfile` (`build: .`) but executing fundamentally different entrypoints and operational responsibilities.

### 2.1 The `web` Service (Presentation Layer)
* **Role:** Hosts the interactive Streamlit dashboards for the NOC operators (`app.py`).
* **Execution:** `command: streamlit run src/app.py --server.port=8501 --server.address=0.0.0.0`
* **Networking:** Maps container port `8501` to host port `8501`. This is the primary URI operators will navigate to in their web browsers to access the IFC UI.
* **Resource Profile:** High memory usage (for UI rendering and session management) but relatively low CPU utilization.

### 2.2 The `worker` Service (Background Orchestration)
* **Role:** The headless daemon running the Master Scheduler (`scheduler.py`). It is responsible for all async feed fetching, ML multiprocessing, database garbage collection, and chronological LLM reporting.
* **Execution:** `command: python -u src/scheduler.py`
  * *Note on `-u`:* The `-u` flag forces the Python standard output and standard error streams to be unbuffered. This is a critical Docker best practice, ensuring that the worker's deep logging prints directly to the Docker daemon (`docker logs`) in real-time without getting trapped in a memory buffer.
* **Networking:** Fully isolated. Exposes no external ports, communicating only with the shared database and external APIs.
* **Resource Profile:** Extremely high CPU utilization (due to the `concurrent.futures` ProcessPool and NLP vectorization tasks).

### 2.3 The `webhook` Service (API Gateway)
* **Role:** Hosts the asynchronous FastAPI server (`webhook_listener.py`) dedicated to receiving ITSM and NMS alerts (e.g., SolarWinds).
* **Execution:** `command: python -u src/webhook_listener.py`
* **Networking:** Maps container port `8100` to host port `8100`. This is the dedicated ingress port that external alerting systems must be configured to point toward.
* **Resource Profile:** I/O bound. Requires rapid network concurrency rather than heavy compute.

---

## 3. Data Persistence & State Management

Because the three services run in isolated containers, they must share state to operate as a single unified application. This is handled via localized volume mounting.

### 3.1 The Shared SQLite Volume
* **Mapping:** `- ./data:/app/data`
* **Architecture Impact:** Since the application utilizes a local SQLite file (`noc_fusion.db`) rather than a remote PostgreSQL cluster, this volume mount is the linchpin of the entire system. 
* By mounting the host's `./data` directory into `/app/data` for *all three containers*, they are effectively interacting with the exact same physical database file. 
  * The `webhook` container writes new SolarWinds alerts to the file.
  * The `worker` container writes new RSS intelligence to the file.
  * The `web` container reads from the file to render the live UI.
* *Note:* The `check_same_thread=False` engine configuration defined in `database.py` is what mathematically permits this shared-file concurrency without locking crashes.

### 3.2 Code Hot-Reloading
* **Mapping:** `- ./src:/app/src`
* **Architecture Impact:** Mounts the local source code directly into the containers. This allows developers to edit Python files on the host machine and see the changes reflected immediately in the running containers without requiring a time-consuming `docker compose build` cycle.

---

## 4. Environment Configuration
* **Implementation:** `env_file: .env`
* All three containers securely load their environment variables from a single `.env` file at the root level. This ensures that sensitive artifacts—such as the `DATABASE_URL`, OpenAI API keys, and custom SMTP configurations—are injected securely at runtime and remain entirely excluded from version control.
