import time
import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from src.core.db import SessionLocal
from src.models.schema import DailyBriefing
from src.utils.llm import generate_daily_fusion_report

LOCAL_TZ = ZoneInfo("America/Chicago")
logger = logging.getLogger(__name__)


def run_daily_report():
    logger.info("06:00 AM trigger hit! Initiating Daily Fusion Report synthesis...")
    session = SessionLocal()
    try:
        now_local = datetime.now(LOCAL_TZ)
        yesterday_local = (now_local - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

        existing = session.query(DailyBriefing).filter(DailyBriefing.report_date == yesterday_local).first()
        if existing:
            logger.info("Report for yesterday already exists. Skipping.")
            return

        date_obj, report_markdown = generate_daily_fusion_report(session)

        if report_markdown:
            new_rep = DailyBriefing(report_date=date_obj, content=report_markdown)
            session.add(new_rep)
            session.commit()
            logger.info("Daily Fusion Report completed and saved to database!")
        else:
            logger.warning("AI returned an empty report. Check API connection.")

    except Exception as e:
        logger.error(f"Crash during report generation: {e}")
        session.rollback()
    finally:
        session.close()


def start_report_scheduler():
    logger.info("Online. Standing by for 06:00 AM CST...")
    while True:
        now_cst = datetime.now(LOCAL_TZ)
        if now_cst.hour == 6 and now_cst.minute < 10:
            run_daily_report()
            time.sleep(3600)
        else:
            time.sleep(60)
