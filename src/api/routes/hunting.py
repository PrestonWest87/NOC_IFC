from fastapi import APIRouter, Query

from src import services as svc

router = APIRouter(prefix="/api/v1/hunting", tags=["hunting"])


@router.get("/iocs")
def iocs(days_back: int = Query(3, ge=1, le=30)):
    return svc.get_iocs(days_back=days_back)


@router.get("/osint-pivot")
def osint_pivot(ioc_type: str = "", ioc_value: str = ""):
    return {"link": svc.get_osint_pivot_link(ioc_type, ioc_value)}


@router.get("/search-articles")
def search_articles(target: str = "", days_back: int = Query(3, ge=1, le=30)):
    return svc.search_articles_for_hunting(target, days_back=days_back)
