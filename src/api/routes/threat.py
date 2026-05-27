from fastapi import APIRouter, Query, Body
import logging

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/threat", tags=["threat"])


@router.get("/cves")
def list_cves(limit: int = Query(50, ge=1, le=200), days_back: int = Query(30, ge=1, le=365)):
    return svc.get_cves(limit=limit, days_back=days_back)


@router.get("/cloud-outages")
def list_cloud_outages(active_only: bool = True, days_back: int = Query(7, ge=1, le=90)):
    return svc.get_cloud_outages(active_only=active_only, days_back=days_back)


@router.get("/crime-incidents")
def list_crime_incidents(hours_back: int = Query(24, ge=1, le=168), max_distance: float = Query(1.0, ge=0.1)):
    return svc.get_recent_crimes(max_distance=max_distance, hours_back=hours_back)


@router.get("/articles")
def list_articles(
    category: str = Query("live", pattern="^(live|pinned|low|search)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=5, le=100),
    search_term: str = Query(None),
    min_score: int = Query(0, ge=0),
):
    items, total, total_pages, current = svc.get_paginated_articles(
        category, "All", page, page_size, search_term, min_score
    )
    return {"items": items, "total": total, "total_pages": total_pages, "page": current}


@router.post("/fetch-feeds")
def fetch_feeds():
    from src.scheduler import fetch_feeds as _do_fetch
    try:
        _do_fetch(source="API Trigger")
        return {"status": "ok", "message": "Feeds fetched successfully."}
    except Exception as e:
        logger.error("fetch-feeds error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/sync-cisa-kev")
def sync_cisa_kev():
    from src.workers.cve_worker import fetch_cisa_kev
    try:
        fetch_cisa_kev()
        return {"status": "ok", "message": "CISA KEV synced."}
    except Exception as e:
        logger.error("sync-cisa-kev error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/sync-cloud-status")
def sync_cloud_status():
    from src.workers.cloud_worker import fetch_cloud_outages
    try:
        fetch_cloud_outages()
        return {"status": "ok", "message": "Cloud status synced."}
    except Exception as e:
        logger.error("sync-cloud-status error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/fetch-crime-data")
def fetch_crime_data():
    if svc.force_fetch_crime_data():
        return {"status": "ok", "message": "Crime data fetched."}
    return {"status": "error", "message": "Crime fetch failed."}


@router.post("/sync-elastic-cache")
def sync_elastic_cache(hours_back: int = Query(24, ge=1)):
    from src.workers.elastic_worker import run_elastic_sync
    try:
        run_elastic_sync(hours_back=hours_back)
        return {"status": "ok", "message": "Elastic cache synced."}
    except Exception as e:
        logger.error("sync-elastic-cache error: %s", e)
        return {"status": "error", "message": str(e)}


@router.post("/generate-siem-triage")
def generate_siem_triage(data: dict = Body({})):
    from src.utils.llm import generate_siem_triage_summary
    from src.core.db import SessionLocal
    with SessionLocal() as session:
        summary = generate_siem_triage_summary(session, data.get("events", []))
    return {"summary": summary or "Unable to generate triage summary."}
