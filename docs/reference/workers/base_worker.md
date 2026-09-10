# BaseWorker Module

**File:** `src/workers/base_worker.py`

## Overview

Provides the `BaseWorker` abstract base class that defines a standardized lifecycle for all background worker processes in the NOC Intelligence Fusion Center. Concrete subclasses implement the `execute()` method and inherit timing, logging, and run-loop semantics.

---

## Classes

### `BaseWorker(ABC)`

Abstract base class for all background workers. Manages worker identity, execution interval, timezone-aware logging, and a blocking run loop.

#### `__init__(self, name: str = None, interval: int = 300, timezone: str = "America/Chicago")`

- **Purpose:** Initialises a new worker instance with a human-readable name, execution interval in seconds, and a timezone for log timestamps.
- **Parameters:**
  - `name` (`str`, optional): Worker display name. Defaults to the subclass class name.
  - `interval` (`int`, optional): Sleep interval in seconds between `execute()` calls. Default `300` (5 minutes).
  - `timezone` (`str`, optional): IANA timezone string for log timestamps. Default `"America/Chicago"`.
- **Returns:** `None`
- **Raises:** `ZoneInfo` may raise `KeyError` if the timezone string is invalid.
- **Flow:**
  1. Resolve worker name (explicit or class name).
  2. Store interval and timezone.
  3. Initialise `_running` flag to `False`.
- **Dependencies:** `zoneinfo.ZoneInfo`

#### `execute(self) -> None` *(abstract)*

- **Purpose:** Concrete worker logic. Must be overridden by subclasses.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** `NotImplementedError` if not overridden.
- **Flow:** Called by `run_once()` and `run_loop()`.
- **Dependencies:** None (contract for subclasses).

#### `log(self, message: str, level: str = "INFO") -> None`

- **Purpose:** Emit a timezone-aware, prefixed log message through the standard `logging` module.
- **Parameters:**
  - `message` (`str`): The log message text.
  - `level` (`str`, optional): Log level name (e.g. `"INFO"`, `"ERROR"`, `"WARNING"`). Defaults to `"INFO"`.
- **Returns:** `None`
- **Raises:** `AttributeError` if the log level string is not a valid `logging` module attribute.
- **Flow:**
  1. Format local time as `HH:MM:SS`.
  2. Resolve the logging function by level name (falls back to `logger.info` on invalid level).
  3. Emit: `[HH:MM:SS] [WORKER_NAME] message`.
- **Dependencies:** `logging.getLogger(__name__)`, `datetime`, `zoneinfo.ZoneInfo`

#### `run_once(self) -> None`

- **Purpose:** Execute a single work cycle with exception safety.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (all exceptions are caught and logged).
- **Flow:**
  1. Log `"Starting execution..."`.
  2. Call `self.execute()`.
  3. Log `"Execution complete."`.
  4. If `execute()` raises, catch and log as `ERROR`.
- **Dependencies:** `self.execute()` (subclass implementation).

#### `run_loop(self) -> None`

- **Purpose:** Start the worker's blocking run loop. Intended for dedicated thread or process use.
- **Parameters:** None
- **Returns:** `None` (blocks indefinitely until `stop()` is called from another thread).
- **Raises:** None.
- **Flow:**
  1. Set `_running = True`.
  2. Log `"Worker online. Interval: {interval}s"`.
  3. While `_running` is `True`:
     a. Call `run_once()`.
     b. `time.sleep(self.interval)`.
- **Dependencies:** `time.sleep`, `self.run_once()`

#### `stop(self) -> None`

- **Purpose:** Signal the worker loop to terminate gracefully on the next iteration.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None.
- **Flow:**
  1. Set `_running = False`.
  2. Log `"Worker stopped."`.
- **Dependencies:** None (side-effect flag used by `run_loop()`).
