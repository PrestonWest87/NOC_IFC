import time
import schedule
import feedparser
import requests
import sys
import concurrent.futures
from sqlalchemy.exc import IntegrityError
from src.database import SessionLocal, Article, FeedSource, init_db
from src.config import ALERT_THRESHOLD
from src.logic import get_scorer
from datetime import datetime
from zoneinfo import ZoneInfo

# Initialize DB on startup
init_db()

def log(message, source="SYSTEM"):
    """Helper to force print logs instantly in Docker"""
    # Force the log timestamp into Central Time
    local_time = datetime.now(ZoneInfo("America/Chicago")).strftime('%H:%M:%S')
    print(f"[{local_time}] [{source.upper()}] {message}")
    sys.stdout.flush()

def process_single_feed(source_id, source_name, source_url, scorer):
    """Worker function to process a single feed in its own thread."""
    # Every thread MUST have its own database session
    session = SessionLocal()
    total_added = 0
    
    try:
        # 1. Fetch with a strict timeout and a real browser User-Agent
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # Timeout: 5 seconds to connect, 10 seconds to read the data
        response = requests.get(source_url, headers=headers, timeout=(5, 10))
        response.raise_for_status() # Throw error if we get a 404 or 403 Forbidden
        
        # 2. Parse the raw XML content
        feed = feedparser.parse(response.content)
        seen_links_in_batch = set()

        for entry in feed.entries:
            link = entry.get('link', '')
            if not link:
                continue
                
            # DB Deduplication (Fast check)
            if session.query(Article).filter_by(link=link).first():
                continue

            # Batch Deduplication (Per-feed check)
            if link in seen_links_in_batch:
                continue
            seen_links_in_batch.add(link)

            # Process Article
            title = entry.get('title', '')
            summary = entry.get('summary', '')
            full_text = f"{title} {summary}"
            
            score, reasons = scorer.score(full_text)
            
            article = Article(
                title=title,
                link=link,
                summary=summary,
                source=source_name,
                published_date=datetime.utcnow(),
                score=float(score),
                keywords_found=reasons,
                is_bubbled=(score >= ALERT_THRESHOLD)
            )
            
            # --- THE FIX: Safe Individual Commits ---
            try:
                session.add(article)
                session.commit()
                total_added += 1
            except IntegrityError:
                # Another thread beat us to it. Rollback this single article and move on.
                session.rollback()
        
        if total_added > 0:
            log(f"✅ {source_name}: Found {total_added} new articles.", "WORKER")
            
    except requests.exceptions.Timeout:
        log(f"⏳ Timeout skipping {source_name}", "WORKER")
    except requests.exceptions.HTTPError as e:
        log(f"🔒 Blocked/Error on {source_name}: {e.response.status_code}", "WORKER")
    except Exception as e:
        session.rollback()
        log(f"❌ Error on {source_name}: {e}", "WORKER")
    finally:
        # ALWAYS close the session to prevent database lockups
        session.close()
        
    return total_added

def fetch_feeds(source="Scheduled"):
    log("🚀 Starting concurrent feed fetch cycle...", source)
    
    # Use a temporary session just to get the list of active feeds
    main_session = SessionLocal()
    sources = main_session.query(FeedSource).filter(FeedSource.is_active == True).all()
    
    # Store data in memory so we can close the main session before threading
    feed_data = [(s.id, s.name, s.url) for s in sources]
    main_session.close()
    
    if not feed_data:
        log("⚠️ No active feeds found.", source)
        return

    scorer = get_scorer()
    total_added_all = 0
    
    # --- The Multithreading Engine ---
    # Max workers = 15. This means 15 feeds are processed at the exact same time.
    # Do not set this higher than 20 or Postgres might run out of connections.
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            executor.submit(process_single_feed, f_id, f_name, f_url, scorer): f_name 
            for f_id, f_name, f_url in feed_data
        }
        
        for future in concurrent.futures.as_completed(futures):
            feed_name = futures[future]
            try:
                added = future.result()
                total_added_all += added
            except Exception as exc:
                log(f"💥 Thread crashed for {feed_name}: {exc}", source)

    log(f"🏁 Cycle complete. Added {total_added_all} total new items.", source)

    # --- NEW: Purge & AI Grouping ---
    main_session = SessionLocal()
    try:
        from src.database import Article
        from src.llm import group_recent_articles
        
        # 1. Purge zero-score articles
        purged_count = main_session.query(Article).filter(Article.score <= 0.0).delete()
        if purged_count > 0:
            log(f"🗑️ Purged {purged_count} zero-score articles from the database.", source)
            
        # 2. Group related stories and auto-BLUF
        group_recent_articles(main_session)
        main_session.commit()
        
    except Exception as e:
        log(f"⚠️ Post-fetch processing failed: {e}", source)
        main_session.rollback()
    finally:
        main_session.close()

if __name__ == "__main__":
    # --- NEW: Boot up the Daily Report Scheduler on a background thread ---
    import threading
    from src.report_worker import start_report_scheduler
    
    threading.Thread(target=start_report_scheduler, daemon=True).start()
    # Standard 15-minute schedule
    schedule.every(15).minutes.do(fetch_feeds)
    
    # Run once on worker startup
    fetch_feeds(source="Worker Boot")
    
    log("🚀 Scheduler Service Started...", "SYSTEM")
    while True:
        schedule.run_pending()
        time.sleep(1)
        
    print("Starting background worker...")
    while True:
        fetch_feeds("Background Worker")
        time.sleep(900)