import time
import schedule
import feedparser
import sys
import asyncio
import aiohttp
import concurrent.futures
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from src.database import SessionLocal, Article, FeedSource, RegionalHazard, CloudOutage, engine, init_db
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from src.cve_worker import fetch_cisa_kev
from src.infra_worker import fetch_regional_hazards
from src.cloud_worker import fetch_cloud_outages

init_db()

def log(message, source="SYSTEM"):
    local_time = datetime.now(ZoneInfo("America/Chicago")).strftime('%H:%M:%S')
    print(f"[{local_time}] [{source.upper()}] {message}")
    sys.stdout.flush()

# --- ASYNC I/O ENGINE (NETWORK FETCHING) ---
async def fetch_single_feed(session, f_name, f_url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        async with session.get(f_url, headers=headers, timeout=15) as response:
            response.raise_for_status()
            content = await response.text()
            return f_name, content
    except Exception as e:
        log(f"⚠️ Async Fetch Error on {f_name}: {e}", "WORKER")
        return f_name, None

async def fetch_all_feeds(feed_data):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_single_feed(session, f_name, f_url) for _, f_name, f_url in feed_data]
        return await asyncio.gather(*tasks)

# --- CPU MULTIPROCESSING ENGINE (ML SCORING) ---
_process_scorer = None
def init_process():
    """Initializes the ML Scorer once per CPU core to prevent overhead."""
    global _process_scorer
    from src.logic import get_scorer
    _process_scorer = get_scorer()

def parse_and_score_feed(f_name, content, known_links):
    """Runs on a separate CPU core, completely bypassing the Python GIL."""
    from src.config import ALERT_THRESHOLD
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
        
        # ML scoring processed on the dedicated CPU core
        score, reasons = _process_scorer.score(f"{title} {summary}")
        
        new_articles_data.append({
            "title": title, "link": link, "summary": summary, "source": f_name,
            "score": float(score), "keywords_found": reasons,
            "is_bubbled": (score >= ALERT_THRESHOLD)
        })
    return f_name, new_articles_data

def bulk_save_to_db(db_session, arts_data):
    """Transactional Bulk Inserts to minimize disk thrashing."""
    if not arts_data: return 0
    new_arts = [
        Article(
            title=d["title"], link=d["link"], summary=d["summary"], source=d["source"],
            published_date=datetime.utcnow(), score=d["score"],
            keywords_found=d["keywords_found"], is_bubbled=d["is_bubbled"]
        ) for d in arts_data
    ]
    try:
        db_session.add_all(new_arts)
        db_session.commit()
        return len(new_arts)
    except IntegrityError:
        db_session.rollback()
        added = 0
        for art in new_arts:
            try:
                db_session.add(art)
                db_session.commit()
                added += 1
            except IntegrityError:
                db_session.rollback()
        return added

def fetch_feeds(source="Scheduled"):
    log("🚀 Starting ASYNC & MULTIPROCESS feed fetch cycle...", source)
    
    main_session = SessionLocal()
    sources = main_session.query(FeedSource).filter(FeedSource.is_active == True).all()
    feed_data = [(s.id, s.name, s.url) for s in sources]
    
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    known_links_query = main_session.query(Article.link).filter(Article.published_date >= seven_days_ago).all()
    known_links = {link[0] for link in known_links_query}
    
    if not feed_data:
        log("⚠️ No active feeds found.", source)
        main_session.close()
        return

    # 1. Fire the Async Network Engine
    results = asyncio.run(fetch_all_feeds(feed_data))
    total_added = 0
    
    # 2. Fire the Multiprocessing CPU Engine
    log("🧠 Offloading XML parsing and ML scoring to CPU cluster...", source)
    with concurrent.futures.ProcessPoolExecutor(initializer=init_process) as executor:
        futures = [executor.submit(parse_and_score_feed, f_name, content, known_links) for f_name, content in results]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                f_name, extracted_arts = future.result()
                if extracted_arts:
                    # 3. Fire the Bulk DB Insert
                    added = bulk_save_to_db(main_session, extracted_arts)
                    if added > 0: log(f"✅ {f_name}: Processed & Saved {added} new articles.", "WORKER")
                    total_added += added
            except Exception as e:
                log(f"💥 Process cluster crash: {e}", "WORKER")

    log(f"🏁 Cycle complete. Added {total_added} total items.", source)
    main_session.close()
        
def run_database_maintenance():
    log("🧹 Running Master Database Maintenance...", "SYSTEM")
    session = SessionLocal()
    try:
        now = datetime.utcnow()
        one_day_ago = now - timedelta(days=1)
        two_days_ago = now - timedelta(days=2)
        thirty_days_ago = now - timedelta(days=30)
        
        p_zero = session.query(Article).filter(Article.score <= 0.0).delete()
        p_old = session.query(Article).filter(Article.published_date < thirty_days_ago, Article.is_pinned == False).delete()
        p_haz = session.query(RegionalHazard).filter(RegionalHazard.updated_at < two_days_ago).delete()
        p_cld = session.query(CloudOutage).filter(CloudOutage.updated_at < one_day_ago).delete()
        session.commit()
        log(f"🧹 Removed {p_zero} junk items, {p_old} old articles, {p_haz} old hazards, and {p_cld} old cloud alerts.", "SYSTEM")
    except Exception as e:
        session.rollback()
    finally:
        session.close()
        
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("VACUUM ANALYZE articles;"))
            conn.execute(text("VACUUM ANALYZE regional_hazards;"))
            conn.execute(text("VACUUM ANALYZE cloud_outages;"))
        log("💽 VACUUM ANALYZE complete. Indexes optimized.", "SYSTEM")
    except Exception: pass

def job_cisa(): fetch_cisa_kev()
def job_regional(): fetch_regional_hazards()
def job_cloud(): fetch_cloud_outages()

if __name__ == "__main__":
    import threading
    from src.report_worker import start_report_scheduler
    
    threading.Thread(target=start_report_scheduler, daemon=True).start()
    schedule.every(60).minutes.do(run_database_maintenance)
    schedule.every(15).minutes.do(fetch_feeds)
    schedule.every(5).minutes.do(job_regional)
    schedule.every(15).minutes.do(job_cloud)
    schedule.every(6).hours.do(job_cisa)
    
    fetch_feeds(source="Worker Boot")
    job_cisa()
    job_regional()
    job_cloud()
    
    log("🚀 Master Scheduler Service Started. All systems armed and ticking.", "SYSTEM")
    while True:
        schedule.run_pending()
        time.sleep(1)