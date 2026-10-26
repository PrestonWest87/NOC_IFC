"""Threat telemetry reads and manual RSS, KEV, cloud, crime, and Elastic syncs."""

import json
from fastapi import APIRouter, Query, Body, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
import logging

from src import services as svc
from src.api.auth_guard import require_page, require_action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/threat", tags=["threat"], dependencies=[Depends(require_page("Threat Telemetry"))])


class SIEMEventInput(BaseModel):
    """Allowlist bounded fields from an external SIEM event for LLM triage."""
    model_config = ConfigDict(extra="ignore")

    id: str | int | None = None
    timestamp: str | None = Field(default=None, max_length=64)
    index_name: str | None = Field(default=None, max_length=256)
    severity: str | int | float | None = None
    message: str | None = Field(default=None, max_length=2000)
    source_ip: str | None = Field(default=None, max_length=128)
    event_category: str | None = Field(default=None, max_length=256)


class SIEMTriageRequest(BaseModel):
    """Constrain a threat-workspace triage request to one through fifty events."""
    events: list[SIEMEventInput] = Field(min_length=1, max_length=50)


@router.get("/cves", dependencies=[Depends(require_action("Tab: Threat Telemetry -> CISA KEV"))])
def list_cves(limit: int = Query(50, ge=1, le=200), days_back: int = Query(30, ge=1, le=365)):
    """Return CISA KEV rows within the bounded count and date window."""
    logger.debug("GET /threat/cves limit=%d days_back=%d", limit, days_back)
    return svc.get_cves(limit=limit, days_back=days_back)


@router.get("/cloud-outages", dependencies=[Depends(require_action("Tab: Threat Telemetry -> Cloud Services"))])
def list_cloud_outages(active_only: bool = True, days_back: int = Query(7, ge=1, le=90)):
    """Return cloud outage records filtered by active state and lookback."""
    logger.debug("GET /threat/cloud-outages active_only=%s days_back=%d", active_only, days_back)
    return svc.get_cloud_outages(active_only=active_only, days_back=days_back)


@router.get("/crime-incidents", dependencies=[Depends(require_action("Tab: Threat Telemetry -> Perimeter Crime"))])
def list_crime_incidents(hours_back: int = Query(24, ge=1, le=168), max_distance: float = Query(1.0, ge=0.1)):
    """Return recent crime records within the requested headquarters distance."""
    logger.debug("GET /threat/crime-incidents hours_back=%d max_distance=%.1f", hours_back, max_distance)
    return svc.get_recent_crimes(max_distance=max_distance, hours_back=hours_back)


@router.get("/articles", dependencies=[Depends(require_action("Tab: Threat Telemetry -> RSS Triage"))])
def list_articles(
    category: str = Query("live", pattern="^(live|pinned|low|search)$"),
    cat_filter: str = Query("All"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=5, le=100),
    search_term: str = Query(None),
    min_score: int = Query(0, ge=0),
):
    """Return paginated article records using the selected triage category/search filters."""
    logger.debug("GET /threat/articles category=%s cat_filter=%s page=%d page_size=%d", category, cat_filter, page, page_size)
    items, total, total_pages, current = svc.get_paginated_articles(
        category, cat_filter, page, page_size, search_term, min_score
    )
    return {"items": items, "total": total, "total_pages": total_pages, "page": current}


@router.get("/articles/{article_id}", dependencies=[Depends(require_action("Tab: Threat Telemetry -> RSS Triage"))])
def get_article(article_id: int):
    """Return one article's detail or a not-found error object."""
    logger.debug("GET /threat/articles/%d", article_id)
    article = svc.get_article_detail(article_id)
    if not article:
        return {"error": "Article not found"}
    return article


@router.post("/fetch-feeds", dependencies=[Depends(require_action("Tab: Threat Telemetry -> RSS Triage")), Depends(require_action("Action: Manually Sync Data"))])
def fetch_feeds():
    """Run the RSS fetch cycle synchronously as an authorized manual sync."""
    logger.info("POST /threat/fetch-feeds: manual trigger")
    from src.scheduler import fetch_feeds as _do_fetch
    try:
        _do_fetch(source="API Trigger")
        return {"status": "ok", "message": "Feeds fetched successfully."}
    except Exception as e:
        logger.error("fetch-feeds error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/sync-cisa-kev", dependencies=[Depends(require_action("Tab: Threat Telemetry -> CISA KEV")), Depends(require_action("Action: Manually Sync Data"))])
def sync_cisa_kev():
    """Invoke the CISA KEV worker for an authorized manual refresh."""
    logger.info("POST /threat/sync-cisa-kev: manual trigger")
    from src.workers.cve_worker import fetch_cisa_kev
    try:
        fetch_cisa_kev()
        return {"status": "ok", "message": "CISA KEV synced."}
    except Exception as e:
        logger.error("sync-cisa-kev error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/sync-cloud-status", dependencies=[Depends(require_action("Tab: Threat Telemetry -> Cloud Services")), Depends(require_action("Action: Manually Sync Data"))])
def sync_cloud_status():
    """Invoke cloud-provider status ingestion for an authorized manual refresh."""
    logger.info("POST /threat/sync-cloud-status: manual trigger")
    from src.workers.cloud_worker import fetch_cloud_outages
    try:
        fetch_cloud_outages()
        return {"status": "ok", "message": "Cloud status synced."}
    except Exception as e:
        logger.error("sync-cloud-status error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/fetch-crime-data", dependencies=[Depends(require_action("Tab: Threat Telemetry -> Perimeter Crime")), Depends(require_action("Action: Manually Sync Data"))])
def fetch_crime_data():
    """Trigger a manual Little Rock CAD crime-data fetch and report its result."""
    logger.info("POST /threat/fetch-crime-data: manual trigger")
    if svc.force_fetch_crime_data():
        return {"status": "ok", "message": "Crime data fetched."}
    return {"status": "error", "message": "Crime fetch failed."}


@router.post("/sync-elastic-cache", dependencies=[
    Depends(require_page("Threat Hunting & IOCs")),
    Depends(require_action("Tab: Reporting -> Elastic SIEM Report")),
    Depends(require_action("Action: Manually Sync Data")),
])
def sync_elastic_cache(hours_back: int = Query(24, ge=1, le=168)):
    """Refresh bounded Elastic cache data and map skipped/errors to 503/502 responses."""
    logger.info("POST /threat/sync-elastic-cache hours_back=%d", hours_back)
    from src.workers.elastic_worker import run_elastic_sync
    try:
        result = run_elastic_sync(hours_back=hours_back)
        if isinstance(result, dict) and result.get("status") in {"error", "skipped"}:
            status_code = 503 if result.get("status") == "skipped" else 502
            raise HTTPException(status_code=status_code, detail=result.get("message", "Elastic cache sync failed."))
        return {"status": "ok", "message": "Elastic cache synced.", "result": result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("sync-elastic-cache error: %s", e)
        raise HTTPException(status_code=502, detail="Elastic cache sync failed.") from e


@router.post("/generate-siem-triage", dependencies=[
    Depends(require_page("Threat Hunting & IOCs")),
    Depends(require_action("Tab: Reporting -> Elastic SIEM Report")),
    Depends(require_action("Action: Trigger AI Functions")),
])
def generate_siem_triage(data: SIEMTriageRequest = Body(...)):
    """Generate a triage summary after enforcing the serialized 100 KB prompt bound."""
    events = [event.model_dump(exclude_none=True) for event in data.events]
    if len(json.dumps(events, separators=(",", ":"))) > 100_000:
        raise HTTPException(status_code=413, detail="SIEM triage payload is too large")
    logger.info("POST /threat/generate-siem-triage events_count=%d", len(events))
    from src.utils.llm import generate_siem_triage_summary
    from src.core.db import SessionLocal
    with SessionLocal() as session:
        summary = generate_siem_triage_summary(session, events)
    return {"summary": summary or "Unable to generate triage summary."}
