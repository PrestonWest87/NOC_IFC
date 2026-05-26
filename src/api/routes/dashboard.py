import logging
from fastapi import APIRouter, Query, Body
from typing import Any

from src import services as svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/metrics")
def dashboard_metrics():
    return svc.get_dashboard_metrics()


@router.get("/pinned-articles")
def pinned_articles():
    return svc.get_pinned_articles()


@router.get("/live-articles")
def live_articles(limit: int = Query(15, ge=1, le=100)):
    return svc.get_live_articles(limit=limit)


@router.get("/hazards")
def hazards(limit: int = Query(15, ge=1, le=100)):
    return svc.get_hazards(limit=limit)


@router.get("/threat-trends")
def threat_trends(days: int = Query(14, ge=1, le=90)):
    return svc.get_historical_threat_scores(days=days)


@router.get("/internal-risk")
def internal_risk():
    data = svc.get_latest_internal_risk()
    if not data:
        return {"status": "empty", "message": "No internal risk snapshot available yet."}
    return data


@router.get("/internal-risk/history")
def internal_risk_history(days: int = Query(28, ge=1, le=365)):
    return svc.get_internal_risk_history(days=days)


@router.get("/executive-intel")
def executive_intel():
    crimes = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
    from src.models.schema import RegionalHazard
    from src.core.db import SessionLocal
    with SessionLocal() as db:
        active_warn = db.query(RegionalHazard).count()
    return svc.get_executive_grid_intel(active_warn, crimes)


@router.post("/generate-internal-risk")
def generate_internal_risk():
    return svc.generate_and_save_internal_risk_snapshot()


@router.post("/generate-unified-brief")
def generate_unified_brief():
    logger.info("POST /generate-unified-brief: manual trigger")
    result = svc.trigger_unified_brief()
    return result


@router.post("/generate-rolling-summary")
def generate_rolling_summary():
    logger.info("POST /generate-rolling-summary: manual trigger")
    result = svc.trigger_rolling_summary()
    return result


@router.post("/generate-scoring-rationale")
def generate_scoring_rationale(data: dict[str, Any] = Body({})):
    logger.info("POST /generate-scoring-rationale: manual trigger")
    intel = data.get("intel", {})
    result = svc.trigger_scoring_rationale(intel)
    return result


@router.post("/articles/toggle-pin")
def toggle_pin(article_id: int):
    svc.toggle_pin(article_id)
    return {"status": "ok"}


@router.post("/articles/boost-score")
def boost_score(article_id: int, amount: int = Query(15, ge=1, le=100)):
    svc.boost_score(article_id, amount)
    return {"status": "ok"}


@router.post("/articles/feedback")
def article_feedback(article_id: int, feedback: int = Query(0, ge=0, le=2)):
    svc.change_status(article_id, feedback)
    return {"status": "ok"}


@router.post("/articles/generate-bluf")
def generate_article_bluf(article_id: int = Query(0, ge=0)):
    from src.utils.llm import generate_bluf
    from src.models.schema import Article
    from src.core.db import SessionLocal
    with SessionLocal() as session:
        art = session.query(Article).filter(Article.id == article_id).first()
        if not art:
            return {"status": "error", "message": "Article not found."}
        b = generate_bluf(art, session)
        if b:
            svc.save_ai_bluf(art.id, b)
            return {"status": "ok", "bluf": b}
        return {"status": "error", "message": "AI generation failed."}
