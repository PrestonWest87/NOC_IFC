import time
import schedule
import feedparser
import sys
import asyncio
import aiohttp
import threading
import gc
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from src.services import generate_and_save_internal_risk_snapshot

# Expanded imports
from src.database import (
    SessionLocal, Article, FeedSource, RegionalHazard, CloudOutage, 
    ExtractedIOC, engine, init_db, SolarWindsAlert, BgpAnomaly, 
    CveItem, RegionalOutage, CrimeIncident
)

from src.cve_worker import fetch_cisa_kev
from src.infra_worker import fetch_regional_hazards
from src.cloud_worker import fetch_cloud_outages
from src.telemetry_worker import run_telemetry_sync
from src.train_model import train  
from src.crime_worker import fetch_live_crimes
init_db()

def log(message, source="SYSTEM"):
    local_time = datetime.now(ZoneInfo("America/Chicago")).strftime('%H:%M:%S')
    print(f"[{local_time}] [{source.upper()}] {message}")
    sys.stdout.flush()

# --- PRE-LOAD SCORER FOR EFFICIENCY ---
from src.logic import get_scorer
log("Pre-loading NLP Scorer into memory...", "SYSTEM")
_global_scorer = get_scorer()


# =====================================================================
# 1. THE RSS INGESTION ENGINE
# =====================================================================

async def fetch_single_feed(session, f_name, f_url):
    try:
        headers = {
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

async def fetch_all_feeds_chunked(feed_data, chunk_size=5):
    """Fetches feeds in smaller batches to prevent RAM spikes."""
    results = []
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(feed_data), chunk_size):
            chunk = feed_data[i:i + chunk_size]
            tasks = [fetch_single_feed(session, f_name, f_url) for _, f_name, f_url in chunk]
            chunk_results = await asyncio.gather(*tasks)
            results.extend(chunk_results)
            # Brief pause to let the async loop breathe and garbage collect
            await asyncio.sleep(0.1) 
    return results

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
        if score >= 50.0 and category.startswith("Cyber"):
            extracted_iocs = ioc_engine.extract(full_text) 
            
        new_articles_data.append({
            "title": title, "link": link, "summary": summary, "source": f_name,
            "score": float(score), "category": category, "keywords_found": reasons,
            "is_bubbled": (score >= ALERT_THRESHOLD), "iocs": extracted_iocs
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
                        article_id=art.id, indicator_type=ioc["Type"], 
                        indicator_value=ioc["Indicator"], context=ioc["Context"]
                    ) for ioc in d["iocs"]
                ]
                db_session.add_all(ioc_objs)
            db_session.commit()
            db_session.expunge_all()
            added += 1
        except IntegrityError:
            db_session.rollback()
    return added

def fetch_feeds(source="Scheduled"):
    import gc
    log("🚀 Starting LOW-CPU feed fetch cycle...", source)
    
    with SessionLocal() as main_session:
        sources = main_session.query(FeedSource).filter(FeedSource.is_active == True).all()
        if not sources: return
            
        feed_data = [(s.id, s.name, s.url) for s in sources]
        
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        known_links_query = main_session.query(Article.link).filter(Article.published_date >= seven_days_ago).all()
        known_links = {link[0] for link in known_links_query}

        # Phase 1: Download everything concurrently (Cheap on CPU)
        results = asyncio.run(fetch_all_feeds_chunked(feed_data, chunk_size=5))
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
    
    gc.collect()

def job_unified_brief():
    """Auto-generates the Unified Risk Brief every 2 hours."""
    log("🤖 Generating Executive Unified Risk Brief...", "SYSTEM")
    try:
        from src.llm import generate_unified_risk_brief
        from src.services import get_executive_grid_intel, get_recent_crimes, save_global_config
        from src.database import InternalRiskSnapshot, RegionalHazard
        
        # Gather local telemetry
        with SessionLocal() as session:
            latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
            active_nws = session.query(RegionalHazard).count()
        
        # Gather global telemetry
        crime_data = get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
        global_intel = get_executive_grid_intel(active_nws, crime_data)
        
        # Fire AI and Save
        with SessionLocal() as session:
            brief_text = generate_unified_risk_brief(session, global_intel, latest_internal)
            
        if brief_text and "AI is currently disabled" not in brief_text:
            save_global_config({
                "unified_brief": brief_text,
                "unified_brief_time": datetime.utcnow()
            })
            log("✅ Unified Risk Brief generated and saved.", "SYSTEM")
    except Exception as e:
        log(f"❌ Unified Brief Error: {e}", "SYSTEM")

def job_internal_risk():
    """Wrapper to safely execute and log the internal risk calculation."""
    log("🏢 Generating Internal Risk Snapshot...", "SYSTEM")
    try:
        generate_and_save_internal_risk_snapshot()
        log("✅ Internal Risk Snapshot generated successfully.", "SYSTEM")
    except Exception as e:
        log(f"❌ Internal Risk Error: {e}", "SYSTEM")


# =====================================================================
# 2. GARBAGE COLLECTION & MAINTENANCE
# =====================================================================

def run_database_maintenance():
    log("🧹 Running Master Database Maintenance...", "SYSTEM")
    with SessionLocal() as session:
        try:
            now = datetime.utcnow()
            
            hours_12_ago = now - timedelta(hours=12)
            hours_24_ago = now - timedelta(hours=24) 
            hours_48_ago = now - timedelta(hours=48)
            days_7_ago   = now - timedelta(days=7)
            days_14_ago  = now - timedelta(days=14)
            days_60_ago  = now - timedelta(days=60)
            
            # --- CLEANUP LOGIC ---
            session.query(Article).filter(Article.score <= 0.0).delete()
            session.query(Article).filter(Article.published_date < days_14_ago, Article.is_pinned == False).delete()
            session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at < days_60_ago).delete()
            session.query(RegionalHazard).filter(RegionalHazard.updated_at < hours_48_ago).delete()
            session.query(RegionalOutage).filter(RegionalOutage.detected_at < hours_12_ago).delete()
            session.query(BgpAnomaly).filter(BgpAnomaly.detected_at < hours_12_ago).delete()
            session.query(CveItem).filter(CveItem.date_added < days_7_ago).delete()
            session.query(CloudOutage).filter(CloudOutage.updated_at < hours_24_ago).delete()
            session.query(CrimeIncident).filter(CrimeIncident.timestamp < days_7_ago).delete()
            
            # Cleanup orphaned IOCs
            session.execute(text("DELETE FROM extracted_iocs WHERE article_id NOT IN (SELECT id FROM articles);"))
            session.commit()
            
            log("✅ Database tables pruned and committed.", "SYSTEM")
        except Exception as e:
            session.rollback()
            log(f"⚠️ Maintenance Error: {e}", "SYSTEM")
        
    try:
        # SQLite Specific Advanced Maintenance
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("PRAGMA optimize;"))
            conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE);"))
    except Exception: 
        pass


# =====================================================================
# 3. AUTOMATED ML RETRAINING
# =====================================================================

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


# =====================================================================
# 4. THE THREADED MASTER ORCHESTRATOR
# =====================================================================

def run_threaded(job_func, *args, **kwargs):
    """
    Runs scheduled jobs in a separate background thread. 
    This prevents slow APIs from blocking the master schedule loop.
    """
    job_thread = threading.Thread(target=job_func, args=args, kwargs=kwargs)
    job_thread.daemon = True
    job_thread.start()

if __name__ == "__main__":
    from src.report_worker import start_report_scheduler
    
    # 1. Start the Automated Email Reporter
    threading.Thread(target=start_report_scheduler, daemon=True).start()
    
    # 2. Map the Schedules to Threaded Wrappers
    schedule.every().sunday.at("02:00").do(run_threaded, job_retrain_ml)
    schedule.every(60).minutes.do(run_threaded, run_database_maintenance)
    schedule.every(2).hours.do(run_threaded, job_unified_brief)
    schedule.every(15).minutes.do(run_threaded, fetch_feeds)
    schedule.every(3).minutes.do(run_threaded, fetch_live_crimes)
    schedule.every(6).hours.do(run_threaded, fetch_cisa_kev)
    schedule.every(6).hours.do(run_threaded, job_internal_risk)
    
    # High-Priority / High-Churn Telemetry
    schedule.every(2).minutes.do(run_threaded, fetch_regional_hazards)
    schedule.every(5).minutes.do(run_threaded, fetch_cloud_outages)
    schedule.every(5).minutes.do(run_threaded, run_telemetry_sync)
    
    log("🚀 Master Orchestrator Online. Firing Boot Sequence...", "SYSTEM")
    
    # 3. Asynchronous Boot Sequence (Does not block the container from finishing startup)
    boot_jobs = [
    fetch_cisa_kev, 
    fetch_regional_hazards, 
    fetch_cloud_outages, 
    run_telemetry_sync, 
    fetch_live_crimes, 
    fetch_feeds, 
    job_internal_risk,   # Ensure this runs first
    job_unified_brief    # Add this so the brief generates immediately after internal risk
    ]
    for job in boot_jobs:
        run_threaded(job)
    
    # 4. Master Event Loop
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        log("🛑 Orchestrator shutting down gracefully...", "SYSTEM")
        sys.exit(0)
