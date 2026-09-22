import logging
import json
from fastapi import APIRouter, Query, Depends
from fastapi import Body, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src import services as svc
from src.api.auth_guard import require_action, require_page

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/hunting", tags=["hunting"], dependencies=[Depends(require_page("Threat Hunting & IOCs"))])


class SIEMEventInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str | int | None = None
    timestamp: str | None = Field(default=None, max_length=64)
    index_name: str | None = Field(default=None, max_length=256)
    severity: str | int | float | None = None
    message: str | None = Field(default=None, max_length=2000)
    source_ip: str | None = Field(default=None, max_length=128)
    event_category: str | None = Field(default=None, max_length=256)


class SIEMTriageRequest(BaseModel):
    events: list[SIEMEventInput] = Field(min_length=1, max_length=50)


@router.get("/iocs")
def iocs(days_back: int = Query(3, ge=1, le=30), limit: int = Query(1000, ge=1, le=1000)):
    logger.debug("GET /iocs days_back=%d", days_back)
    return svc.get_iocs(days_back=days_back, limit=limit)


@router.get("/osint-pivot")
def osint_pivot(ioc_type: str = "", ioc_value: str = ""):
    logger.debug("GET /osint-pivot type=%s value=%s", ioc_type, ioc_value)
    return {"link": svc.get_osint_pivot_link(ioc_type, ioc_value)}


@router.get("/search-articles")
def search_articles(target: str = "", days_back: int = Query(3, ge=1, le=30)):
    logger.info("GET /search-articles target=%s days_back=%d", target, days_back)
    return svc.search_articles_for_hunting(target, days_back=days_back)


@router.get("/elastic-events", dependencies=[Depends(require_action("Tab: Reporting -> Elastic SIEM Report"))])
def elastic_events(
    hours_back: int = Query(24, ge=1, le=168),
    page: int = Query(1, ge=1, le=1000),
    page_size: int = Query(100, ge=1, le=500),
):
    logger.debug("GET /elastic-events hours_back=%d page=%d page_size=%d", hours_back, page, page_size)
    return svc.get_elastic_events(hours_back=hours_back, page=page, page_size=page_size)


@router.post("/sync-elastic-cache", dependencies=[Depends(require_action("Action: Manually Sync Data"))])
def sync_elastic_cache(hours_back: int = Query(24, ge=1, le=168)):
    logger.info("POST /hunting/sync-elastic-cache hours_back=%d", hours_back)
    from src.workers.elastic_worker import run_elastic_sync
    result = run_elastic_sync(hours_back=hours_back)
    if isinstance(result, dict) and result.get("status") == "error":
        raise HTTPException(status_code=502, detail=result.get("message", "Elastic cache sync failed."))
    return {"status": "ok", "message": "Elastic cache synced.", "result": result}


@router.post("/generate-siem-triage", dependencies=[Depends(require_action("Action: Trigger AI Functions"))])
def generate_siem_triage(data: SIEMTriageRequest = Body(...)):
    events = [event.model_dump(exclude_none=True) for event in data.events]
    if len(json.dumps(events, separators=(",", ":"))) > 100_000:
        raise HTTPException(status_code=413, detail="SIEM triage payload is too large")
    from src.utils.llm import generate_siem_triage_summary
    from src.core.db import SessionLocal
    with SessionLocal() as session:
        summary = generate_siem_triage_summary(session, events)
    return {"summary": summary or "Unable to generate triage summary."}
