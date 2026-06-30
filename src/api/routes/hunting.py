import logging
from fastapi import APIRouter, Query

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/hunting", tags=["hunting"])


@router.get("/iocs")
def iocs(days_back: int = Query(3, ge=1, le=30)):
    logger.debug("GET /iocs days_back=%d", days_back)
    return svc.get_iocs(days_back=days_back)


@router.get("/osint-pivot")
def osint_pivot(ioc_type: str = "", ioc_value: str = ""):
    logger.debug("GET /osint-pivot type=%s value=%s", ioc_type, ioc_value)
    return {"link": svc.get_osint_pivot_link(ioc_type, ioc_value)}


@router.get("/search-articles")
def search_articles(target: str = "", days_back: int = Query(3, ge=1, le=30)):
    logger.info("GET /search-articles target=%s days_back=%d", target, days_back)
    return svc.search_articles_for_hunting(target, days_back=days_back)
