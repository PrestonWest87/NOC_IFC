# Enterprise Architecture & Functional Specification: `src/report_worker.py`

## 1. Executive Overview

The `src/report_worker.py` module serves as the **Autonomous Reporting Cron-Engine** for the Intelligence Fusion Center (IFC). It is a persistent, long-running background daemon responsible for orchestrating the generation of the "Daily Master Fusion Report." 

By abstracting this heavy, time-consuming LLM Map-Reduce workload into a dedicated background worker, the system ensures that the comprehensive daily situational briefing is fully generated, formatted, and cached in the database *before* NOC operators arrive for their morning shift, guaranteeing zero UI latency when they open the dashboard.

---

## 2. Core Execution Logic: `run_daily_report()`

This function manages the data state, prevents duplication, and acts as the bridge between the LLM cognitive engine and the PostgreSQL/SQLite database.

### 2.1 Timezone & Temporal Scoping
* **Strict Localization:** The module enforces `ZoneInfo("America/Chicago")` (CST/CDT). This ensures that "yesterday" is calculated accurately based on the physical location of the NOC, rather than defaulting to UTC, which would cause reports to shift into the wrong calendar day.
* **Date Normalization:** It calculates `yesterday_local` by subtracting 1 day from the current local time and aggressively stripping the hours, minutes, seconds, and microseconds (e.g., `2026-03-16 00:00:00`). This normalized timestamp acts as the unique identifier for that day's report.

### 2.2 Idempotency & State Validation
To prevent the costly LLM engine from re-running if the server crashes or the Docker container is restarted during the 6:00 AM hour:
* The script queries the `DailyBriefing` table for a record matching `yesterday_local`.
* If a record exists, the function gracefully aborts (`return`), ensuring **absolute idempotency**.

### 2.3 LLM Handoff & Persistence
1.  **Generation:** Calls `generate_daily_fusion_report(session)` from `src.llm`, passing the open database session so the LLM engine can query the last 24 hours of Cyber, KEV, Infrastructure, and Cloud telemetry.
2.  **Validation:** Checks if the LLM returned a valid `report_markdown` string (preventing the storage of null/empty records if the OpenAI API is down).
3.  **Database Commit:** Wraps the markdown in a `DailyBriefing` ORM object, stages it (`session.add`), and writes it to disk (`session.commit()`).

---

## 3. The Scheduling Mechanism: `start_report_scheduler()`

Because standard cron jobs can be brittle inside containerized environments, this module implements its own resilient, pure-Python scheduling loop.

### 3.1 The Execution Window
* **Infinite Polling:** Operates on a `while True:` loop.
* **Target Trigger:** Checks if `now_cst.hour == 6 and now_cst.minute < 10`. This creates a safe 10-minute execution window (06:00 AM to 06:09 AM CST). 
* *Failsafe:* If the server is under heavy load and the thread wakes up at 06:01 AM instead of exactly 06:00:00, the window ensures the report still fires.

### 3.2 Debounce & Sleep Logic
* **Window Clearing (Debounce):** Once `run_daily_report()` successfully executes, the worker is forced into a deep sleep for exactly 1 hour (`time.sleep(3600)`). This ensures the script completely overshoots the 6:00 AM - 6:09 AM window, guaranteeing the report is never generated twice in the same morning.
* **Idle Polling:** If it is *not* the 6:00 AM hour, the script sleeps for 60 seconds (`time.sleep(60)`) before checking the time again. This creates virtually zero CPU overhead while maintaining minute-level accuracy.

---

## 4. Execution & Fault Tolerance

* **Database Session Lifecycle:** The database connection is explicitly established inside the `run_daily_report()` function, rather than globally. This ensures the connection is fresh. 
* **Rollback Protection:** A `try...except` block wraps the generation sequence. If the API fails or a database lock occurs, `session.rollback()` is fired to prevent corrupted states. 
* **Graceful Closure:** The `finally: session.close()` block ensures the connection is returned to the SQLAlchemy pool, averting "Too many connections" errors over months of continuous uptime.

---

## 5. System Integration Context

Within the broader architecture:
* **The Master Scheduler (`src/scheduler.py`):** Typically, this `start_report_scheduler()` function is invoked as a parallel `threading.Thread` by the main application orchestrator upon startup.
* **The User Interface (`app.py`):** When operators navigate to the **"📰 Daily Fusion Report"** tab in the Streamlit UI, the application simply queries the `DailyBriefing` table and renders this pre-compiled Markdown, resulting in instantaneous load times. (The UI also contains a manual override button to force-trigger this generation if needed).

---

## 6. Complete Function Reference

| Function | Signature | Purpose |
|----------|----------|---------|
| `run_daily_report` | `() -> None` | Generate daily report at 06:00 |
| `start_report_scheduler` | `() -> None` | Report scheduler loop |

---

## 7. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|-------------|
| datetime | Time handling | https://docs.python.org/3/library/datetime.html |
| time | Sleep | https://docs.python.org/3/library/time.html |
