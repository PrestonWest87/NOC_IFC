import logging
import uuid
import threading
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/reporting", tags=["reporting"])

_report_progress_store: dict[str, dict] = {}
_report_result_store: dict[str, dict] = {}
_report_lock = threading.Lock()


class BroadcastRequest(BaseModel):
    report_date: str = ""
    content: str = ""
    recipients: str = ""


class BroadcastCustomRequest(BaseModel):
    title: str = "NOC Custom Intel Report"
    content: str = ""
    recipients: str = ""


class SaveReportRequest(BaseModel):
    title: str = "Untitled Report"
    author: str = "Unknown"
    content: str = ""


class GenerateCustomRequest(BaseModel):
    target: str = ""
    days_back: int = 7
    article_ids: Optional[list[int]] = None
    objective: str = ""
    analyst: str = "Unknown"


@router.get("/executive-intel")
def get_executive_intel():
    logger.debug("GET /reporting/executive-intel")
    intel = svc.get_executive_grid_intel(0, [])
    return intel


@router.get("/saved-reports")
def list_saved_reports():
    logger.debug("GET /reporting/saved-reports")
    return svc.get_saved_reports()


@router.get("/daily-briefings")
def list_daily_briefings():
    logger.debug("GET /reporting/daily-briefings")
    return svc.get_all_daily_briefings()


@router.post("/generate-daily")
def generate_daily_report():
    logger.info("POST /reporting/generate-daily")
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from src.core.db import SessionLocal
    from src.utils.llm import generate_daily_fusion_report
    with SessionLocal() as session:
        date_obj, report_markdown = generate_daily_fusion_report(session)
    if report_markdown:
        svc.save_daily_briefing(date_obj, report_markdown)
        date_str = date_obj.strftime('%Y-%m-%d') if hasattr(date_obj, 'strftime') else str(date_obj)
        logger.info("POST /reporting/generate-daily success date=%s", date_str)
        return {"status": "ok", "date": date_str, "content": report_markdown}
    logger.warning("POST /reporting/generate-daily failed")
    return {"status": "error", "message": "Report generation failed or AI is disabled."}


@router.post("/broadcast")
def broadcast_report(data: BroadcastRequest):
    logger.info("POST /reporting/broadcast recipients=%s", data.recipients)
    if not data.recipients:
        logger.warning("POST /reporting/broadcast: no recipients")
        return {"status": "error", "message": "No recipients specified."}
    formatted_html = svc.generate_daily_report_email_html(data.report_date, data.content)
    from src.utils.mailer import send_alert_email
    success, msg = send_alert_email(
        f"Daily Fusion Report - {data.report_date}",
        formatted_html,
        recipient_override=data.recipients,
        is_html=True,
    )
    logger.info("POST /reporting/broadcast success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.post("/broadcast-custom")
def broadcast_custom_report(data: BroadcastCustomRequest):
    logger.info("POST /reporting/broadcast-custom title=%s recipients=%s", data.title, data.recipients)
    if not data.recipients.strip():
        return {"status": "error", "message": "No recipients specified."}
    if not data.content.strip():
        return {"status": "error", "message": "No report content available."}

    from datetime import datetime
    from zoneinfo import ZoneInfo
    from src.utils.mailer import send_alert_email

    report_time = datetime.now(ZoneInfo("America/Chicago")).strftime("%A, %B %d, %Y at %I:%M %p %Z")
    formatted_html = svc.generate_custom_report_email_html(data.title, report_time, data.content)
    success, msg = send_alert_email(
        data.title.strip() or "NOC Custom Intel Report",
        formatted_html,
        recipient_override=data.recipients,
        is_html=True,
    )
    logger.info("POST /reporting/broadcast-custom success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.post("/save-report")
def save_custom_report(data: SaveReportRequest):
    logger.info("POST /reporting/save-report title=%s author=%s", data.title, data.author)
    svc.save_custom_report(data.title, data.author, data.content)
    return {"status": "ok"}


@router.delete("/saved-reports/{report_id}")
def delete_saved_report(report_id: int):
    logger.info("DELETE /reporting/saved-reports/%d", report_id)
    svc.delete_record("SavedReport", report_id)
    return {"status": "ok"}


class SearchArticlesRequest(BaseModel):
    target: str = ""
    days_back: int = 7


@router.post("/search-articles")
def search_articles_for_report(data: SearchArticlesRequest):
    logger.info("POST /reporting/search-articles target=%s days_back=%d", data.target, data.days_back)
    if not data.target or not data.target.strip():
        return {"status": "error", "message": "Please enter a search target.", "articles": []}
    articles = svc.search_articles_for_hunting(data.target.strip(), data.days_back)
    results = []
    for a in articles:
        results.append({
            "id": a.get("id"),
            "title": a.get("title", ""),
            "source": a.get("source", ""),
            "score": a.get("score", 0),
            "published_date": a.get("published_date", ""),
            "summary": (a.get("summary") or "")[:300],
            "category": a.get("category", ""),
        })
    return {"status": "ok", "articles": results}


def _run_custom_report_generation(generation_id, target, days_back, article_ids, objective, analyst):
    """Background thread for custom report generation."""
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from src.core.db import SessionLocal
    from src.utils.llm import build_custom_intel_report

    def _progress(stage, message, percent=0):
        with _report_lock:
            _report_progress_store[generation_id] = {
                "stage": stage, "message": message, "percent": percent
            }

    try:
        _progress("searching", "Searching for matching articles...", 5)

        if article_ids:
            articles = svc.get_articles_by_ids(article_ids)
        else:
            articles = svc.search_articles_for_hunting(target, days_back)

        if not articles:
            _progress("error", f"No articles found.", 0)
            with _report_lock:
                _report_result_store[generation_id] = {
                    "status": "error", "message": "No articles found for the given target."
                }
            return

        _progress("generating", f"Processing {len(articles)} articles through AI...", 20)

        with SessionLocal() as session:
            def _llm_progress(done, total_chunks, total_items, processed):
                pct = int((done / total_chunks) * 75) + 20
                _progress("generating", f"AI map-reduce: chunk {done}/{total_chunks}", pct)

            report_md = build_custom_intel_report(articles, objective, session,
                                                   progress_callback=_llm_progress)

        if not report_md or "[WARN]" in (report_md or ""):
            _progress("error", "AI report generation failed.", 0)
            with _report_lock:
                _report_result_store[generation_id] = {
                    "status": "error", "message": "Report generation failed or AI is disabled."
                }
            return

        _progress("assembling", "Assembling final report...", 95)

        now = datetime.now(ZoneInfo("America/Chicago")).strftime("%A, %B %d, %Y at %I:%M %p %Z")
        full_report = (
            f"# \U0001f4cb NOC Custom Intel Report\n"
            f"**Target:** {target or ', '.join(str(i) for i in article_ids)}\n"
            f"**Date:** {now}\n"
            f"**Analyst:** {analyst}\n\n"
            f"---\n\n{report_md}"
        )

        _progress("complete", "Report generation complete.", 100)
        with _report_lock:
            _report_result_store[generation_id] = {
                "status": "ok", "content": full_report
            }

    except Exception as e:
        logger.error("_run_custom_report_generation: error: %s", str(e), exc_info=True)
        _progress("error", f"Report generation failed: {str(e)}", 0)
        with _report_lock:
            _report_result_store[generation_id] = {
                "status": "error", "message": f"Report generation failed: {str(e)}"
            }


@router.post("/generate-custom")
def generate_custom_report(data: GenerateCustomRequest):
    logger.info("POST /reporting/generate-custom target=%s days_back=%d article_ids=%s", data.target, data.days_back, data.article_ids)

    has_target = data.target and data.target.strip()
    has_ids = data.article_ids and len(data.article_ids) > 0
    if not has_target and not has_ids:
        return {"status": "error", "message": "Please enter a target entity or select articles."}

    generation_id = str(uuid.uuid4())

    with _report_lock:
        _report_progress_store[generation_id] = {
            "stage": "starting", "message": "Initializing report generation...", "percent": 0
        }
        _report_result_store.pop(generation_id, None)

    thread = threading.Thread(
        target=_run_custom_report_generation,
        args=(generation_id, data.target.strip() if has_target else "", data.days_back, data.article_ids if has_ids else None, data.objective, data.analyst),
        daemon=True
    )
    thread.start()

    return {"status": "started", "generation_id": generation_id}


@router.get("/generate-custom-status")
def get_custom_report_status(generation_id: str):
    with _report_lock:
        progress = _report_progress_store.get(generation_id, {})
        result = _report_result_store.get(generation_id)

    if result:
        with _report_lock:
            _report_progress_store.pop(generation_id, None)
            _report_result_store.pop(generation_id, None)
        return result

    return {"status": "in_progress", "progress": progress}
