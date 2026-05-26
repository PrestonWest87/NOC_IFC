import logging
from datetime import datetime
from fastapi import APIRouter, Query, Body
from typing import Any

from src import services as svc
from src.core.db import SessionLocal
from src.models.schema import ShiftLogEntry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/logbook", tags=["logbook"])


@router.get("/entries")
def entries(role_filter: str = Query("All"), start_date: str = None, end_date: str = None, session_token: str = Query(None)):
    sd = datetime.fromisoformat(start_date) if start_date else None
    ed = datetime.fromisoformat(end_date) if end_date else None
    if session_token:
        user = svc.get_user_by_token(session_token)
        if user and user.role != "admin":
            role_filter = user.role
    return svc.get_shift_logs(role_filter, sd, ed)


@router.post("/entries")
def create_entry(
    analyst: str = "",
    role: str = "analyst",
    shift_period: str = "Morning",
    content: str = "",
    custom_date: str = None,
    session_token: str = Query(None),
):
    if session_token:
        user = svc.get_user_by_token(session_token)
        if user and user.role != "admin":
            role = user.role
    cd = datetime.fromisoformat(custom_date) if custom_date else None
    svc.save_shift_log(analyst, role, shift_period, content, cd)
    return {"status": "ok"}


@router.patch("/entries/{entry_id}")
def update_entry(entry_id: int, is_deleted: bool = None):
    with SessionLocal() as session:
        entry = session.query(ShiftLogEntry).get(entry_id)
        if not entry:
            return {"status": "error", "message": "Entry not found"}
        if is_deleted is not None:
            entry.is_deleted = is_deleted
        session.commit()
        return {"status": "ok", "id": entry_id, "is_deleted": entry.is_deleted}


@router.post("/generate-summary")
def generate_shift_summary(data: dict[str, Any] = Body({})):
    role_filter = data.get("role_filter", "All")
    shift_period = data.get("shift_period", "Morning")
    timeframe_label = data.get("timeframe_label", shift_period + " Shift")
    auto_append = data.get("auto_append", False)
    logger.info("POST /generate-summary role=%s shift=%s auto_append=%s", role_filter, shift_period, auto_append)
    result = svc.trigger_shift_summary(
        role_filter=role_filter,
        shift_period=shift_period,
        timeframe_label=timeframe_label,
        auto_append=auto_append,
    )
    return result
