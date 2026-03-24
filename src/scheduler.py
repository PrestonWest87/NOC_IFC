import time
import schedule
import feedparser
import sys
import asyncio
import aiohttp
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# Expanded imports to grab all the new models for the Garbage Collector
from src.database import (
    SessionLocal, Article, FeedSource, RegionalHazard, CloudOutage, 
    ExtractedIOC, engine, init_db, SolarWindsAlert, BgpAnomaly, 
    CveItem, RegionalOutage
)

from src.cve_worker import fetch_cisa_kev
from src.infra_worker import fetch_regional_hazards
from src.cloud_worker import fetch_cloud_outages
from src.telemetry_worker import run_telemetry_sync
from src.train_model import train  # <-- IMPORT ML TRAINING FUNCTION
from src.crime_worker import fetch_live_crimes

init_db()

def log(message, source="SYSTEM"):
    local_time = datetime.now(ZoneInfo("America/Chicago")).strftime('%H:%M:%S')
    print(f"[{local_time}] [{source.upper()}] {message}")
    sys.stdout.flush()

# --- PRE-LOAD SCORER FOR SINGLE-CORE EFFICIENCY ---
from src.logic import get_scorer
log("Pre-loading NLP Scorer into memory...", "SYSTEM")
_global_scorer = get_scorer()

async def fetch_single_feed(session, f_name, f_url):
    try:
        headers = headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        async with session.get(f_url, headers=headers, timeout=15) as response:
            response.raise_for_status()
            content = await response.text()
            return f_name, content
    except Exception as e:
        log(f"⚠️ Async Fetch Error on {f_name}: {e}", "WORKER")
        return f_name, None

async def fetch_all_feeds(feed_data):
    """Network I/O is cheap, so we keep the async fetcher to download everything concurrently."""
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_single_feed(session, f_name, f_url) for _, f_name, f_url in feed_data]
        return await asyncio.gather(*tasks)

def parse_and_score_feed(f_name, content, known_links):
    from src.ioc_extractor import ioc_engine 
    from src.categorizer import categorize_text
    
    ALERT_THRESHOLD = 45
        
    if not content: return f_name, []
    
    feed = feedparser.parse(content)
    new_articles_data = []
    seen_in_batch = set()

    for entry in feed.entries:
        link = entry.get('link', '')
        if not link or link in known_links or link in seen_in_batch: 
            continue
            
        seen_in_batch.add(link)
        title = entry.get('title', '')
        summary = entry.get('summary', '')
        full_text = f"{title} {summary}"
        
        score, reasons = _global_scorer.score(full_text)
        category = categorize_text(full_text)
        
        extracted_iocs = []
        if score >= 50.0 and category == "Cyber":
            extracted_iocs = ioc_engine.extract(full_text) 
            
        new_articles_data.append({
            "title": title, "link": link, "summary": summary, "source": f_name,
            "score": float(score), "category": category, "keywords_found": reasons,
            "is_bubbled": (score >= ALERT_THRESHOLD),
            "iocs": extracted_iocs
        })
    return f_name, new_articles_data

def bulk_save_to_db(db_session, arts_data):
    if not arts_data: return 0
    added = 0
    for d in arts_data:
        art = Article(
            title=d["title"], link=d["link"], summary=d["summary"], source=d["source"],
            published_date=datetime.utcnow(), score=d["score"], category=d["category"],
            keywords_found=d["keywords_found"], is_bubbled=d["is_bubbled"]
        )
        db_session.add(art)
        try:
            db_session.flush() # Locks in the ID for the IOC foreign key
            if d.get("iocs"):
                ioc_objs = [
                    ExtractedIOC(
                        article_id=art.id, 
                        indicator_type=ioc["Type"], 
                        indicator_value=ioc["Indicator"], 
                        context=ioc["Context"]
                    ) for ioc in d["iocs"]
                ]
                db_session.add_all(ioc_objs)
            db_session.commit()
            added += 1
        except IntegrityError:
            db_session.rollback()
    return added

def fetch_feeds(source="Scheduled"):
    log("🚀 Starting LOW-CPU feed fetch cycle...", source)
    
    main_session = SessionLocal()
    sources = main_session.query(FeedSource).filter(FeedSource.is_active == True).all()
    feed_data = [(s.id, s.name, s.url) for s in sources]
    
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    known_links_query = main_session.query(Article.link).filter(Article.published_date >= seven_days_ago).all()
    known_links = {link[0] for link in known_links_query}
    
    if not feed_data:
        main_session.close(); return

    # Phase 1: Download everything concurrently (Cheap on CPU)
    results = asyncio.run(fetch_all_feeds(feed_data))
    total_added = 0
    
    # Phase 2: Sequential Processing with Yielding (Hyper-efficient)
    for f_name, content in results:
        try:
            _, extracted_arts = parse_and_score_feed(f_name, content, known_links)
            if extracted_arts:
                added = bulk_save_to_db(main_session, extracted_arts)
                if added > 0: log(f"✅ {f_name}: Saved {added} new articles.", "WORKER")
                total_added += added
                
            # THE MAGIC SAUCE: Yield CPU for 100 milliseconds
            time.sleep(0.1)
            
        except Exception as e:
            log(f"💥 Processing error on {f_name}: {e}", "WORKER")

    log(f"🏁 Cycle complete. Added {total_added} items.", source)
    main_session.close()
        
def run_database_maintenance():
    log("🧹 Running Master Database Maintenance...", "SYSTEM")
    session = SessionLocal()
    try:
        now = datetime.utcnow()
        
        hours_12_ago = now - timedelta(hours=12)
        hours_24_ago = now - timedelta(hours=24) 
        hours_48_ago = now - timedelta(hours=48)
        days_7_ago   = now - timedelta(days=7)
        days_14_ago  = now - timedelta(days=14)
        
        # --- CLEANUP LOGIC ---
        session.query(Article).filter(Article.score <= 0.0).delete()
        session.query(Article).filter(Article.published_date < days_14_ago, Article.is_pinned == False).delete()
        session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at < days_7_ago).delete()
        session.query(RegionalHazard).filter(RegionalHazard.updated_at < hours_48_ago).delete()
        session.query(RegionalOutage).filter(RegionalOutage.detected_at < hours_12_ago).delete()
        session.query(BgpAnomaly).filter(BgpAnomaly.detected_at < hours_12_ago).delete()
        session.query(CveItem).filter(CveItem.date_added < days_7_ago).delete()
        session.query(CloudOutage).filter(CloudOutage.updated_at < hours_24_ago).delete()
        
        # --- NEW: CRIME INCIDENT PURGE (48H Window) ---
        session.query(CrimeIncident).filter(CrimeIncident.timestamp < days_7_ago).delete()
        
        # Cleanup orphaned IOCs
        session.execute(text("DELETE FROM extracted_iocs WHERE article_id NOT IN (SELECT id FROM articles);"))
        
        session.commit()
        log("✅ Database tables pruned and committed.", "SYSTEM")
    except Exception as e:
        session.rollback()
        log(f"⚠️ Maintenance Error: {e}", "SYSTEM")
    finally:
        session.close()
        
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            # SQLite safe vacuuming
            if engine.dialect.name == "sqlite":
                conn.execute(text("PRAGMA optimize;"))
            else:
                # Postgres maintenance for high-churn tables
                conn.execute(text("VACUUM ANALYZE articles;"))
                conn.execute(text("VACUUM ANALYZE extracted_iocs;"))
                conn.execute(text("VACUUM ANALYZE crime_incidents;")) # Added for Postgres performance
    except Exception: 
        pass

# --- WRAPPER JOBS ---
def job_cisa(): fetch_cisa_kev()
def job_regional(): fetch_regional_hazards()
def job_cloud(): fetch_cloud_outages()

# --- NEW WRAPPER JOB FOR CRIME WORKER ---
def job_crimes(): fetch_live_crimes()

def job_retrain_ml():
    """Automated Weekly ML Retraining Pipeline"""
    global _global_scorer
    log("🧠 Initiating weekly ML Model Retraining...", "SYSTEM")
    try:
        train()
        log("✅ ML Model retrained successfully and saved to disk.", "SYSTEM")
        
        # Hot-Reload the scorer in memory so the new neural weights take effect immediately
        _global_scorer = get_scorer()
        log("🔄 Global NLP Scorer hot-reloaded with fresh model weights.", "SYSTEM")
        
    except Exception as e:
        log(f"❌ ML Training Pipeline failed: {e}", "SYSTEM")


if __name__ == "__main__":
    import threading
    from src.report_worker import start_report_scheduler
    
    threading.Thread(target=start_report_scheduler, daemon=True).start()
    
    # Run the automated retraining every Sunday at 2:00 AM (server time)
    schedule.every().sunday.at("02:00").do(job_retrain_ml)
    
    schedule.every(60).minutes.do(run_database_maintenance)
    
    schedule.every(15).minutes.do(fetch_feeds)
    schedule.every(5).minutes.do(job_regional)
    schedule.every(5).minutes.do(job_cloud)
    schedule.every(5).minutes.do(run_telemetry_sync)
    schedule.every(6).hours.do(job_cisa)
    
    # --- ADD THE CRIME WORKER TO RUN EVERY 30 MINUTES ---
    schedule.every(30).minutes.do(job_crimes)
    
    fetch_feeds(source="Worker Boot")
    job_cisa()
    job_regional()
    job_cloud()
    
    # --- RUN THE CRIME WORKER IMMEDIATELY ON BOOT ---
    job_crimes()
    
    log("🚀 Master Scheduler Service Started.", "SYSTEM")
    while True:
        schedule.run_pending()
        time.sleep(1)
