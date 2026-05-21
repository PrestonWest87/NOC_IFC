"""
BaseWorker class for standardized worker lifecycle management.
"""

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)


class BaseWorker(ABC):
    """Abstract base class for all background workers."""

    def __init__(self, name: str = None, interval: int = 300, timezone: str = "America/Chicago"):
        self.name = name or self.__class__.__name__
        self.interval = interval
        self.tz = ZoneInfo(timezone)
        self._running = False

    @abstractmethod
    def execute(self) -> None:
        """Main work logic - subclasses must implement."""
        raise NotImplementedError

    def log(self, message: str, level: str = "INFO") -> None:
        local_time = datetime.now(self.tz).strftime("%H:%M:%S")
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{local_time}] [{self.name.upper()}] {message}")

    def run_once(self) -> None:
        try:
            self.log("Starting execution...", "INFO")
            self.execute()
            self.log("Execution complete.", "INFO")
        except Exception as e:
            self.log(f"Execution failed: {e}", "ERROR")

    def run_loop(self) -> None:
        self._running = True
        self.log(f"Worker online. Interval: {self.interval}s", "INFO")
        while self._running:
            self.run_once()
            time.sleep(self.interval)

    def stop(self) -> None:
        self._running = False
        self.log("Worker stopped.", "INFO")
