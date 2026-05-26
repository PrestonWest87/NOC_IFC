from datetime import datetime
from fastapi import APIRouter, Query

from src import services as svc
from src.core.db import SessionLocal
from src.models.schema import ShiftLogEntry

router = APIRouter(prefix="/api/v1/logbook", tags=["logbook"])


@router.get("/entries")
def entries(role_filter: str = Query("All"), start_date: str = None, end_date: str = None):
    sd = datetime.fromisoformat(start_date) if start_date else None
    ed = datetime.fromisoformat(end_date) if end_date else None
    return svc.get_shift_logs(role_filter, sd, ed)


@router.post("/entries")
def create_entry(
    analyst: str = "",
    role: str = "analyst",
    shift_period: str = "Morning",
    content: str = "",
    custom_date: str = None,
):
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
