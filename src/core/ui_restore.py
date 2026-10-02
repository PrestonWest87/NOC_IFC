"""Cooperative cross-container coordinator for administrator-initiated restore."""

from __future__ import annotations

import logging
from pathlib import Path
import threading
import time

from src.core import backup_manager, restore_control

logger = logging.getLogger(__name__)
_restore_thread_lock = threading.Lock()
_restore_threads: dict[str, threading.Thread] = {}
QUIESCE_TIMEOUT_SECONDS = 600


def prepare_staged_restore(stage_id: str, requested_by: str) -> str:
    """Validate the staged filename and enter the shared maintenance gate."""
    backup_manager.get_staged_backup_path(stage_id)
    return restore_control.begin_restore(stage_id, requested_by)


def launch_staged_restore(restore_id: str) -> None:
    """Launch the restore after WebSocket clients have been disconnected."""
    try:
        _launch(restore_id)
    except Exception:
        restore_control.finish_restore(restore_id, "error", "The restore worker could not be started.")
        raise


def resume_pending_restore() -> str | None:
    """Resume a durable restore request after an API-container restart."""
    request = restore_control.active_restore()
    if not request:
        return None
    restore_id = str(request.get("restore_id", ""))
    if not restore_id:
        return None
    try:
        backup_manager.get_staged_backup_path(str(request.get("stage_id", "")))
    except backup_manager.BackupError as exc:
        restore_control.finish_restore(restore_id, "error", "The staged restore file is missing; use offline recovery.")
        logger.error("Pending UI restore could not resume because its staged package is missing: %s", exc)
        return None
    launch_staged_restore(restore_id)
    return restore_id


def _launch(restore_id: str) -> None:
    with _restore_thread_lock:
        current = _restore_threads.get(restore_id)
        if current and current.is_alive():
            return
        thread = threading.Thread(
            target=_run_restore,
            args=(restore_id,),
            name=f"ui-restore-{restore_id[:8]}",
            daemon=True,
        )
        _restore_threads[restore_id] = thread
        thread.start()


def _wait_for_writers(restore_id: str) -> None:
    deadline = time.monotonic() + QUIESCE_TIMEOUT_SECONDS
    last_message = ""
    while time.monotonic() < deadline:
        request = restore_control.active_restore()
        if not request or request.get("restore_id") != restore_id:
            raise RuntimeError("Restore maintenance mode was cleared before writers quiesced.")

        activity = restore_control.api_activity()
        worker = restore_control.process_status("worker", restore_id)
        webhook = restore_control.process_status("webhook", restore_id)
        pending = []
        if activity["active_requests"] or activity["active_background_writers"]:
            pending.append("API requests/background tasks")
        if not worker or worker.get("state") != "paused" or worker.get("active", 0):
            pending.append("scheduler worker")
        if not webhook or webhook.get("state") != "paused" or webhook.get("active", 0):
            pending.append("webhook listener")
        if not pending:
            return

        message = "Waiting for " + ", ".join(pending) + " to finish active writes."
        if message != last_message:
            restore_control.update_restore(restore_id, "quiescing", message, percent=5)
            last_message = message
        time.sleep(0.5)
    raise TimeoutError(
        "The API, worker, and webhook did not all become idle within the maintenance window. "
        "No restore was installed; retry after active work completes."
    )


def _refresh_restored_runtime() -> None:
    from src import services as svc

    for value in vars(svc).values():
        clear = getattr(value, "clear", None)
        if callable(value) and callable(clear):
            try:
                clear()
            except Exception:
                logger.debug("Unable to clear a restored-data cache", exc_info=True)
    try:
        from src.services.logic import force_reload_scorer

        force_reload_scorer()
    except Exception:
        # The restored database/model files remain valid even if the optional
        # scorer artifact cannot be loaded; keyword scoring remains available.
        logger.exception("Could not reload the optional ML scorer after restore")


def _run_restore(restore_id: str) -> None:
    request = restore_control.active_restore()
    if not request or request.get("restore_id") != restore_id:
        return
    package_path: Path | None = None
    try:
        package_path = backup_manager.get_staged_backup_path(str(request.get("stage_id", "")))
        restore_control.update_restore(
            restore_id, "quiescing", "Pausing API, worker, and webhook writers.", percent=5,
        )
        _wait_for_writers(restore_id)
        restore_control.update_restore(
            restore_id, "restoring", "Validating, migrating, and installing the full database snapshot.", percent=20,
        )
        result = backup_manager.restore_backup(package_path, maintenance_confirmed=True)

        restore_control.update_restore(
            restore_id, "reloading", "Reloading application data and scorer from the restored snapshot.", percent=90,
        )
        from src.core.db import init_db

        init_db()
        _refresh_restored_runtime()
        restore_control.finish_restore(
            restore_id,
            "complete",
            "Restore completed. Restored sessions and account links were invalidated; sign in again.",
            result={
                "backup_created_at": result.get("backup_created_at"),
                "table_count": result.get("table_count"),
                "model_restored": result.get("model_restored"),
                "credentials_invalidated": result.get("credentials_invalidated", {}),
                "pre_restore_backup": result.get("pre_restore_backup"),
            },
        )
    except Exception as exc:
        logger.exception("UI-initiated offline restore failed restore_id=%s", restore_id)
        message = str(exc).strip() or "Restore failed. The existing database was not replaced."
        restore_control.finish_restore(restore_id, "error", message[:500])
    finally:
        with _restore_thread_lock:
            _restore_threads.pop(restore_id, None)
