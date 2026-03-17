# Enterprise Architecture & Deployment Specification: `Dockerfile`

## 1. Executive Overview

The `Dockerfile` serves as the **Immutable Environment Blueprint** for the Intelligence Fusion Center (IFC). It defines the exact operating system, runtime dependencies, and configuration required to execute the application reliably across any infrastructure. 

By utilizing a single, unified Dockerfile to build the images for all three microservices (Web, Worker, Webhook), the architecture guarantees environment parity—eliminating the classic "it works on my machine" deployment failure.

---

## 2. Base Image Selection

### `FROM python:3.11-slim`
* **Runtime:** Establishes Python 3.11 as the execution runtime, providing access to modern asynchronous features (critical for `scheduler.py` and `webhook_listener.py`) and robust type hinting.
* **Optimization (`-slim`):** Rather than using the massive standard Debian image or the notoriously difficult Alpine variant, the `-slim` tag provides a perfectly balanced middle ground. It strips out unnecessary OS-level packages (like heavy graphical libraries), drastically reducing the attack surface area and the final image size, which accelerates CI/CD pipeline deployments.

---

## 3. System-Level Dependencies & Compilation

### `RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*`
While the application defaults to SQLite for local storage, enterprise deployments require PostgreSQL. Python's primary PostgreSQL adapter, `psycopg2`, often requires C-level compilation during installation.
* **`gcc` & `libpq-dev`:** Injects the GNU C Compiler and the PostgreSQL C client libraries into the Linux environment, ensuring `psycopg2` builds successfully.
* **Layer Optimization (`rm -rf...`):** Docker images are built in layers. By clearing the `apt` package cache in the exact same `RUN` command that installs the packages, it permanently deletes the cache from the final image layer, preventing unnecessary bloat.

---

## 4. Application Dependency Management

### `COPY requirements.txt .`
### `RUN pip install --no-cache-dir -r requirements.txt`
* **Caching Strategy:** By copying *only* the `requirements.txt` file first, Docker caches this specific build layer. If a developer changes a Python script but does not alter the dependencies, Docker skips the time-consuming `pip install` step on subsequent builds, slashing rebuild times from minutes to seconds.
* **Space Optimization:** The `--no-cache-dir` flag prevents `pip` from saving downloaded `.whl` and `.tar.gz` files to the container's hidden cache directory, further compressing the final container footprint.

---

## 5. Source Code & Path Configuration

### `COPY . .`
Injects the entirety of the local IFC repository (the `src` directory, `README`, etc.) into the `/app` working directory of the container.

### `ENV PYTHONPATH=/app`
**Architectural Criticality:** This is one of the most vital lines in the file. Because the application uses an organized `src/` directory structure, Python scripts frequently use absolute imports (e.g., `from src.database import SessionLocal`). 
* If the `PYTHONPATH` is not explicitly set to the root `/app` directory, the Python interpreter will fail to resolve the `src` module and crash immediately upon startup with a `ModuleNotFoundError`. This environment variable ensures Python natively understands the project's namespace hierarchy.
