import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from src.database import SessionLocal, DailyBriefing
from src.llm import generate_daily_fusion_report

LOCAL_TZ = ZoneInfo("America/Chicago")

def run_daily_report():
    print("🤖 [REPORT WORKER] 06:00 AM trigger hit! Initiating Daily Fusion Report synthesis...")
    session = SessionLocal()
    try:
        now_local = datetime.now(LOCAL_TZ)
        yesterday_local = (now_local - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        
        # 1. Prevent duplicate runs if the server restarts
        existing = session.query(DailyBriefing).filter(DailyBriefing.report_date == yesterday_local).first()
        if existing:
            print("✅ [REPORT WORKER] Report for yesterday already exists. Skipping.")
            return

        # 2. Fire the Map-Reduce AI engine
        date_obj, report_markdown = generate_daily_fusion_report(session)
        
        # 3. Save to database
        if report_markdown:
            new_rep = DailyBriefing(report_date=date_obj, content=report_markdown)
            session.add(new_rep)
            session.commit()
            print("✅ [REPORT WORKER] Daily Fusion Report completed and saved to database!")
        else:
            print("⚠️ [REPORT WORKER] AI returned an empty report. Check API connection.")
            
    except Exception as e:
        print(f"❌ [REPORT WORKER] Crash during report generation: {e}")
        session.rollback()
    finally:
        session.close()

def start_report_scheduler():
    print("⏳ [REPORT WORKER] Online. Standing by for 06:00 AM CST...")
    while True:
        now_cst = datetime.now(LOCAL_TZ)
        
        # Trigger between 06:00 AM and 06:10 AM CST
        if now_cst.hour == 6 and now_cst.minute < 10:
            run_daily_report()
            # Sleep for 1 hour to completely clear the 6 AM window
            time.sleep(3600)
        else:
            # Check the time every 60 seconds
            time.sleep(60)