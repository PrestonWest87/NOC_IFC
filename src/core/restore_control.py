"""Cross-process maintenance coordination for UI-initiated full restores."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import uuid

from src.core.paths import application_data_dir


class RestoreInProgressError(RuntimeError):
    """A restore is already holding the shared application in maintenance mode."""


_activity = threading.Condition()
_active_requests = 0
_active_background_writers = 0
RESTORE_STATUS_TTL_SECONDS = 24 * 60 * 60


def _control_dir() -> Path:
    path = application_data_dir() / ".restore-control"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def _requests_dir() -> Path:
    path = _control_dir() / "requests"
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _status_dir() -> Path:
    path = _control_dir() / "process-status"
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _marker_path() -> Path:
    return application_data_dir() / ".restore-control" / "active-restore.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def active_restore() -> dict | None:
    return _read_json(_marker_path())


def maintenance_requested() -> bool:
    return _marker_path().exists()


def begin_api_request() -> bool:
    """Reserve an API request slot unless the restore gate is already active."""
    global _active_requests
    with _activity:
        if maintenance_requested():
            return False
        _active_requests += 1
        return True


def end_api_request() -> None:
    global _active_requests
    with _activity:
        _active_requests = max(0, _active_requests - 1)
        _activity.notify_all()


def begin_api_background_writer() -> bool:
    """Register a detached API thread that can write to the database."""
    global _active_background_writers
    with _activity:
        if maintenance_requested():
            return False
        _active_background_writers += 1
        return True


def end_api_background_writer() -> None:
    global _active_background_writers
    with _activity:
        _active_background_writers = max(0, _active_background_writers - 1)
        _activity.notify_all()


@contextmanager
def api_background_writer():
    if not begin_api_background_writer():
        raise RestoreInProgressError("A database restore is in progress.")
    try:
        yield
    finally:
        end_api_background_writer()


def api_activity() -> dict:
    with _activity:
        return {
            "active_requests": _active_requests,
            "active_background_writers": _active_background_writers,
        }


def begin_restore(stage_id: str, requested_by: str) -> str:
    """Persist the maintenance gate before notifying the other services."""
    _control_dir()
    with _activity:
        if _marker_path().exists():
            raise RestoreInProgressError("A full database restore is already in progress.")
        restore_id = uuid.uuid4().hex
        now = _utc_now()
        request = {
            "restore_id": restore_id,
            "stage_id": stage_id,
            "requested_by": str(requested_by or "")[:128],
            "state": "quiescing",
            "started_at": now,
            "updated_at": now,
        }
        _atomic_json(_marker_path(), request)
        _atomic_json(_requests_dir() / f"{restore_id}.json", {
            "restore_id": restore_id,
            "state": "quiescing",
            "message": "Pausing database writers before restore.",
            "percent": 5,
            "started_at": now,
            "updated_at": now,
        })
        _activity.notify_all()
        return restore_id


def update_restore(restore_id: str, state: str, message: str, *, percent: int | None = None, result: dict | None = None) -> dict:
    request = active_restore()
    if not request or request.get("restore_id") != restore_id:
        raise RestoreInProgressError("The active restore request changed unexpectedly.")
    request.update({"state": state, "updated_at": _utc_now()})
    _atomic_json(_marker_path(), request)
    status_path = _requests_dir() / f"{restore_id}.json"
    status = _read_json(status_path) or {"restore_id": restore_id, "started_at": request["started_at"]}
    status.update({"state": state, "message": str(message)[:500], "updated_at": _utc_now()})
    if percent is not None:
        status["percent"] = max(0, min(100, int(percent)))
    if result is not None:
        status["result"] = result
    _atomic_json(status_path, status)
    return status


def finish_restore(restore_id: str, state: str, message: str, *, result: dict | None = None) -> None:
    update_restore(restore_id, state, message, percent=100 if state == "complete" else None, result=result)
    with _activity:
        request = active_restore()
        if request and request.get("restore_id") == restore_id:
            _marker_path().unlink(missing_ok=True)
        _activity.notify_all()


def restore_status(restore_id: str) -> dict | None:
    try:
        normalized = uuid.UUID(hex=restore_id).hex
    except (ValueError, AttributeError, TypeError):
        return None
    status = _read_json(_requests_dir() / f"{normalized}.json")
    if status is None:
        return None
    try:
        updated = datetime.fromisoformat(str(status["updated_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return None
    if (datetime.now(timezone.utc) - updated).total_seconds() > RESTORE_STATUS_TTL_SECONDS:
        return None
    return status


def publish_process_status(process_name: str, state: str, *, active: int = 0, jobs: list[str] | None = None) -> None:
    if process_name not in {"worker", "webhook"}:
        raise ValueError("Unknown restore-coordination process.")
    request = active_restore()
    _atomic_json(_status_dir() / f"{process_name}.json", {
        "process": process_name,
        "restore_id": request.get("restore_id") if request else None,
        "state": state,
        "active": max(0, int(active)),
        "jobs": list(jobs or [])[:32],
        "updated_at": _utc_now(),
    })


def process_status(process_name: str, restore_id: str) -> dict | None:
    value = _read_json(_status_dir() / f"{process_name}.json")
    if not value or value.get("restore_id") != restore_id:
        return None
    try:
        updated = datetime.fromisoformat(str(value["updated_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return None
    if (datetime.now(timezone.utc) - updated).total_seconds() > 10:
        return None
    return value
