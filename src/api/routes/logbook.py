import logging
from datetime import datetime
from fastapi import APIRouter, Query, Body, Depends, HTTPException
from typing import Any

from src import services as svc
from src.core.db import SessionLocal
from src.models.schema import ShiftLogEntry
from src.api.auth_guard import require_page, require_action, get_current_user, is_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/logbook", tags=["logbook"], dependencies=[Depends(require_page("Shift Logbook"))])


@router.get("/entries")
def entries(role_filter: str = Query("All"), start_date: str = None, end_date: str = None, session_token: str = Query(None)):
    logger.debug("GET /logbook/entries role=%s start=%s end=%s", role_filter, start_date, end_date)
    sd = datetime.fromisoformat(start_date) if start_date else None
    ed = datetime.fromisoformat(end_date) if end_date else None
    if session_token:
        user = svc.get_user_by_token(session_token)
        if user and user.role != "admin":
            role_filter = user.role
    return svc.get_shift_logs(role_filter, sd, ed)


@router.post("/entries", dependencies=[Depends(require_action("Action: Submit Shift Log"))])
def create_entry(
    role: str = "analyst",
    shift_period: str = "Morning",
    content: str = "",
    custom_date: str = None,
    session_token: str = Query(None),
    user=Depends(get_current_user),
):
    analyst = user.full_name or user.username
    if not is_admin(user):
        role = user.role or "analyst"
    if shift_period not in {"Morning", "Afternoon", "Evening", "No Shift"}:
        raise HTTPException(status_code=400, detail="Invalid shift period.")
    if not content.strip() or len(content) > 20000:
        raise HTTPException(status_code=400, detail="Shift log content is required and must be 20,000 characters or fewer.")
    logger.info("POST /logbook/entries user=%s role=%s shift=%s content_length=%d",
                 user.username, role, shift_period, len(content) if content else 0)
    cd = datetime.fromisoformat(custom_date) if custom_date else None
    svc.save_shift_log(analyst, role, shift_period, content, cd)
    return {"status": "ok"}


@router.patch("/entries/{entry_id}", dependencies=[Depends(require_action("Action: Submit Shift Log"))])
def update_entry(entry_id: int, data: dict[str, Any] = Body({})):
    is_deleted = data.get("is_deleted")
    logger.info("PATCH /logbook/entries/%d is_deleted=%s", entry_id, is_deleted)
    with SessionLocal() as session:
        entry = session.query(ShiftLogEntry).get(entry_id)
        if not entry:
            return {"status": "error", "message": "Entry not found"}
        if is_deleted is not None:
            entry.is_deleted = is_deleted
        session.commit()
        return {"status": "ok", "id": entry_id, "is_deleted": entry.is_deleted}


@router.post("/generate-summary", dependencies=[Depends(require_action("Action: Trigger AI Functions"))])
def generate_shift_summary(data: dict[str, Any] = Body({}), user=Depends(get_current_user)):
    role_filter = str(data.get("role_filter", "All") or "All")
    shift_period = data.get("shift_period", "Morning")
    timeframe_label = data.get("timeframe_label", shift_period + " Shift")
    auto_append = data.get("auto_append", False)
    timeframe = data.get("timeframe", "shift")
    if not is_admin(user):
        role_filter = user.role or "analyst"
    report_role = user.role or "analyst" if role_filter == "All" else role_filter
    logger.info("POST /logbook/generate-summary role=%s triggered_by=%s triggered_by_role=%s shift=%s auto_append=%s timeframe=%s", role_filter, user.username, user.role, shift_period, auto_append, timeframe)
    result = svc.trigger_shift_summary(
        role_filter=role_filter,
        shift_period=shift_period,
        timeframe_label=timeframe_label,
        auto_append=auto_append,
        timeframe=timeframe,
        generated_by=user.full_name or user.username,
        generated_by_role=report_role,
    )
    return result
