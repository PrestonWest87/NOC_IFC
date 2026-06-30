import logging
from fastapi import APIRouter
from pydantic import BaseModel

from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/reporting", tags=["reporting"])


class BroadcastRequest(BaseModel):
    report_date: str = ""
    content: str = ""
    recipients: str = ""


class SaveReportRequest(BaseModel):
    title: str = "Untitled Report"
    author: str = "Unknown"
    content: str = ""


class GenerateCustomRequest(BaseModel):
    target: str = ""
    days_back: int = 7
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


@router.post("/generate-custom")
def generate_custom_report(data: GenerateCustomRequest):
    logger.info("POST /reporting/generate-custom target=%s days_back=%d", data.target, data.days_back)
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    from src.core.db import SessionLocal
    from src.utils.llm import build_custom_intel_report

    articles = svc.search_articles_for_hunting(data.target, data.days_back)
    if not articles:
        logger.warning("POST /reporting/generate-custom: no articles found for target=%s", data.target)
        return {"status": "error", "message": "No articles found for the given target."}

    with SessionLocal() as session:
        report_md = build_custom_intel_report(articles, data.objective, session)

    if not report_md:
        logger.warning("POST /reporting/generate-custom: AI report generation failed")
        return {"status": "error", "message": "Report generation failed or AI is disabled."}

    now = datetime.now(ZoneInfo("America/Chicago")).strftime("%A, %B %d, %Y at %I:%M %p %Z")
    full_report = f"# \U0001f4cb NOC Custom Intel Report\n**Target:** {data.target}\n**Date:** {now}\n**Analyst:** {data.analyst}\n\n---\n\n{report_md}"

    logger.info("POST /reporting/generate-custom success")
    return {"status": "ok", "content": full_report}
