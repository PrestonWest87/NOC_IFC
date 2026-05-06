"""
NOC Intelligence Fusion Center - Background Scheduler

This module orchestrates all background tasks for the NOC Intelligence system,
including RSS feed fetching, weather/telemetry ingestion, ML model training,
and automated reporting.

Tasks are scheduled using the 'schedule' library and run in background threads
to prevent blocking the main scheduler loop.
"""

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
    """Print timestamped log messages to stdout for Docker log capture."""
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
    """Fetch a single RSS feed with async HTTP request."""
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
        log(f"[WARN] Async Fetch Error on {f_name}: {e}", "WORKER")
        return f_name, None

async def fetch_all_feeds_chunked(feed_data, chunk_size=5):
    """Fetch multiple RSS feeds in chunks to prevent memory spikes."""
    results = []
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(feed_data), chunk_size):
            chunk = feed_data[i:i + chunk_size]
            tasks = [fetch_single_feed(session, f_name, f_url) for _, f_name, f_url in chunk]
            chunk_results = await asyncio.gather(*tasks)
            results.extend(chunk_results)
            await asyncio.sleep(0.1)
    return results

def parse_and_score_feed(f_name, content, known_links):
    """Parse RSS feed content and score articles for relevance."""
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
    """Saves articles in batches for better memory efficiency."""
    if not arts_data: return 0
    added = 0
    batch_size = 100
    batch = []

    for d in arts_data:
        art = Article(
            title=d["title"], link=d["link"], summary=d["summary"], source=d["source"],
            published_date=datetime.utcnow(), score=d["score"], category=d["category"],
            keywords_found=d["keywords_found"], is_bubbled=d["is_bubbled"]
        )
        batch.append(art)

        if len(batch) >= batch_size:
            db_session.add_all(batch)
            try:
                db_session.flush()
                for item in batch:
                    if d.get("iocs"):
                        ioc_objs = [
                            ExtractedIOC(
                                article_id=item.id, indicator_type=ioc["Type"],
                                indicator_value=ioc["Indicator"], context=ioc["Context"]
                            ) for ioc in d["iocs"]
                        ]
                        db_session.add_all(ioc_objs)
                db_session.commit()
                added += len(batch)
            except IntegrityError:
                db_session.rollback()
            batch = []

    if batch:
        db_session.add_all(batch)
        try:
            db_session.flush()
            for item in batch:
                if d.get("iocs"):
                    ioc_objs = [
                        ExtractedIOC(
                            article_id=item.id, indicator_type=ioc["Type"],
                            indicator_value=ioc["Indicator"], context=ioc["Context"]
                        ) for ioc in d["iocs"]
                    ]
                    db_session.add_all(ioc_objs)
            db_session.commit()
            added += len(batch)
        except IntegrityError:
            db_session.rollback()

    db_session.expunge_all()
    return added

def fetch_feeds(source="Scheduled"):
    """Main entry point for scheduled RSS feed fetching and scoring."""
    import gc
    log("[WORKER] Starting feed fetch cycle...", source)

    with SessionLocal() as main_session:
        sources = main_session.query(FeedSource).filter(FeedSource.is_active == True).all()
        if not sources: return

        feed_data = [(s.id, s.name, s.url) for s in sources]

        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        known_links_query = main_session.query(Article.link).filter(Article.published_date >= seven_days_ago).all()
        known_links = {link[0] for link in known_links_query}

        # Phase 1: Download everything concurrently
        results = asyncio.run(fetch_all_feeds_chunked(feed_data, chunk_size=5))
        total_added = 0

        # Phase 2: Sequential Processing
        for f_name, content in results:
            try:
                _, extracted_arts = parse_and_score_feed(f_name, content, known_links)
                if extracted_arts:
                    added = bulk_save_to_db(main_session, extracted_arts)
                    if added > 0: log(f"[OK] {f_name}: Saved {added} new articles.", "WORKER")
                    total_added += added

                time.sleep(0.1)

            except Exception as e:
                log(f"[ERROR] Processing error on {f_name}: {e}", "WORKER")

    log(f"[COMPLETE] Cycle complete. Added {total_added} items.", source)
    main_session.close()

    gc.collect()

def job_unified_brief():
    """Auto-generates the Unified Risk Brief every 2 hours."""
    log("[AI] Generating Executive Unified Risk Brief...", "SYSTEM")
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
            log("[OK] Unified Risk Brief generated and saved.", "SYSTEM")

            # Check for global risk increase and send alert if needed
            from src.risk_alert import check_and_alert
            check_and_alert(global_risk=global_intel.get('unified_risk'), internal_risk=None)
    except Exception as e:
        log(f"[ERROR] Unified Brief Error: {e}", "SYSTEM")

def job_internal_risk():
    """Wrapper to safely execute and log the internal risk calculation."""
    log("[SYSTEM] Generating Internal Risk Snapshot...", "SYSTEM")
    try:
        from src.services import generate_and_save_internal_risk_snapshot
        cis_data = generate_and_save_internal_risk_snapshot()
        log("[OK] Internal Risk Snapshot generated successfully.", "SYSTEM")

        # Check for internal risk increase and send alert if needed
        if cis_data:
            from src.risk_alert import check_and_alert
            check_and_alert(global_risk=None, internal_risk=cis_data.get('risk_level'))
    except Exception as e:
        log(f"[ERROR] Internal Risk Error: {e}", "SYSTEM")

def job_site_escalation_monitor():
    """
    Monitors active AIOps clusters for Low -> High escalations.
    Waits 5 minutes after the escalation occurs, then sends a notification.
    Enforces a strict 1-hour cooldown per site.
    """
    from src.database import SessionLocal, MonitoredLocation, SolarWindsAlert
    from src.mailer import send_alert_email
    from src.aiops_engine import EnterpriseAIOpsEngine
    from datetime import datetime, timedelta

    log("[SYSTEM] Running Site Escalation Monitor...", "SYSTEM")
    
    now_utc = datetime.utcnow()
    ESCALATION_WAIT_MINUTES = 5  # "Specified amount of time" to wait
    ESCALATION_COOLDOWN_HOURS = 1 # Do not send again for 1 hour
    TARGET_EMAIL = "specific_escalation@aecc.com" # TODO: Update this email

    with SessionLocal() as db:
        # Grab all currently active alerts
        active_alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.status != 'Resolved'
        ).all()

        if not active_alerts:
            return

        ai_engine = EnterpriseAIOpsEngine(db)
        incidents = ai_engine.analyze_and_cluster(active_alerts)

        for site, data in incidents.items():
            alerts = data.get('alerts', [])
            if not alerts:
                continue

            # Separate alerts into low and high priority buckets
            low_alerts = [a for a in alerts if str(a.severity).lower() in ['warning', 'low', 'moderate', '3', '4', '6']]
            high_alerts = [a for a in alerts if str(a.severity).lower() in ['critical', 'high', '1', '2', '5']]

            # Calculate how long the site has been in a high-priority state
            oldest_high_alert = min([a.received_at for a in high_alerts if a.received_at])
            
            # CONDITION 2: Wait the specified amount of time (5 minutes)
            if (now_utc - oldest_high_alert) >= timedelta(minutes=ESCALATION_WAIT_MINUTES):
                
                loc = db.query(MonitoredLocation).filter_by(name=site).first()
                if not loc:
                    continue
                
                # CONDITION 3: The 1-Hour Cooldown Rule
                if loc.last_escalation_dispatch and (now_utc - loc.last_escalation_dispatch) < timedelta(hours=ESCALATION_COOLDOWN_HOURS):
                    continue # Site is muted for escalations

                # ALL CONDITIONS MET - Fire the email
                subject = f"SITE ESCALATION: {site} Has Escalated to High Priority"
                body = f"Site **{site}** initially logged low priority events and has now escalated to HIGH/CRITICAL priority.\n\n"
                body += f"**Active Alerts for this site:**\n"
                for a in alerts:
                    body += f"- **{a.node_name}** ({a.device_type}): {a.severity} - {a.event_type}\n"

                success, msg = send_alert_email(subject, body, recipient_override=TARGET_EMAIL, is_html=True)
                
                if success:
                    log(f"[ESCALATION SENT] Sent site escalation email for {site}.", "SYSTEM")
                    # Update DB Timestamp specifically for escalations
                    loc.last_escalation_dispatch = now_utc
                    db.commit()
                else:
                    log(f"[ESCALATION FAILED] SMTP Error for {site}: {msg}", "SYSTEM")

def job_auto_dispatch_tickets():
    """Evaluates active AIOps clusters and auto-dispatches tickets during off-hours (8 PM - 6 AM)."""
    from src.database import SessionLocal, MonitoredLocation, SolarWindsAlert, RegionalHazard, CloudOutage, BgpAnomaly
    from src.aiops_engine import EnterpriseAIOpsEngine
    from src.mailer import send_alert_email
    from src.services import generate_rca_ticket_text
    from zoneinfo import ZoneInfo
    from datetime import datetime, timedelta
    
    now_local = datetime.now(ZoneInfo("America/Chicago"))
    now_utc = datetime.utcnow()
    hour = now_local.hour
    
    # Restrict execution to Off-hours: 8 PM (20:00) to 6 AM (06:00)
    if 6 <= hour < 20:
        return 
        
    with SessionLocal() as db:
        # --- THE FIX: 24-HOUR HARD CUTOFF ---
        # Ignore the historical backlog. Only look at recent undispatched events.
        cutoff_time = now_utc - timedelta(hours=24)
        
        raw_alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.is_dispatched == False,
            SolarWindsAlert.status != 'Resolved',
            SolarWindsAlert.received_at >= cutoff_time  # <-- Prevents old alerts from firing
        ).all()
        
        if not raw_alerts:
            return
            
        ai_engine = EnterpriseAIOpsEngine(db)
        incidents = ai_engine.analyze_and_cluster(raw_alerts)
        
        for site, data in incidents.items():
            alerts = data.get('alerts', [])
            if not alerts:
                continue
                
            # Find the exact time the very first device in this cluster went down
            valid_times = [a.received_at for a in alerts if a.received_at]
            if not valid_times:
                continue
                
            earliest_alert_time_utc = min(valid_times)
            
            # Convert the outage start time to Central Time to check the hour
            earliest_alert_time_local = earliest_alert_time_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("America/Chicago"))
            incident_start_hour = earliest_alert_time_local.hour
            
            # If the incident STARTED between 6:00 AM and 7:59 PM, ignore it.
            if 6 <= incident_start_hour < 20:
                continue 
                
            # 1. Enforce 5-Hour Ticket Cooldown
            loc = db.query(MonitoredLocation).filter_by(name=site).first()
            if loc and loc.last_auto_dispatch:
                time_since_dispatch = now_utc - loc.last_auto_dispatch
                if time_since_dispatch < timedelta(hours=5):
                    continue # Skip this site, already ticketed recently
                    
            # 2. Dynamic Timer Logic (Resets on newest device failure)
            newest_alert_time = max(valid_times)
            duration_since_newest = now_utc - newest_alert_time
            
            trigger_dispatch = False
            if len(alerts) == 1:
                # Condition: 1 device down for > 30 minutes
                if duration_since_newest > timedelta(minutes=30):
                    trigger_dispatch = True
            else:
                # Condition: Multiple devices down for > 10 minutes
                if duration_since_newest > timedelta(minutes=10):
                    trigger_dispatch = True
                    
            # 3. Dispatch the Ticket
            if trigger_dispatch:
                print(f"[{now_local.strftime('%H:%M:%S')}] [AUTO-TICKET] Conditions met for {site} ({len(alerts)} nodes). Dispatching...")
                
                active_weather = db.query(RegionalHazard).all()
                active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
                active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()
                
                cause, score, priority, _, _, p0_name, _ = ai_engine.calculate_root_cause(
                    site, data, active_weather, active_clouds, active_bgp
                )
                
                ticket_body = generate_rca_ticket_text(site, data, priority, p0_name or "Unknown", cause)
                fixed_recipients = "remedyforceworkflow@aecc.com, noc@aecc.com"
                clean_p = priority.replace("?", "").strip()
                
                success, msg = send_alert_email(
                    f"URGENT: {clean_p} Incident at {site}", 
                    ticket_body, 
                    recipient_override=fixed_recipients, 
                    is_html=False
                )
                
                if success:
                    # Update alerts as dispatched to prevent infinite loop
                    for a in alerts:
                        db_alert = db.query(SolarWindsAlert).filter_by(id=a.id).first()
                        if db_alert:
                            db_alert.is_dispatched = True
                            
                    # Start the 5-hour cooldown timer
                    if loc:
                        loc.last_auto_dispatch = now_utc
                    db.commit()
                    print(f"[AUTO-TICKET] Successfully dispatched ticket for {site}.")
                else:
                    print(f"[AUTO-TICKET] Failed to send ticket for {site}: {msg}")
# =====================================================================
# 2. GARBAGE COLLECTION & MAINTENANCE
# =====================================================================

def run_database_maintenance():
    log("[CLEANUP] Running Master Database Maintenance...", "SYSTEM")
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
            
            log("[OK] Database tables pruned and committed.", "SYSTEM")
        except Exception as e:
            session.rollback()
            log(f"[WARN] Maintenance Error: {e}", "SYSTEM")
        
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
    log("[AI] Initiating weekly ML Model Retraining...", "SYSTEM")
    try:
        train()
        log("[OK] ML Model retrained successfully and saved to disk.", "SYSTEM")
        
        # Hot-Reload the scorer in memory so the new neural weights take effect immediately
        _global_scorer = get_scorer()
        log(" Global NLP Scorer hot-reloaded with fresh model weights.", "SYSTEM")
        
    except Exception as e:
        log(f"[ERROR] ML Training Pipeline failed: {e}", "SYSTEM")


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
    schedule.every(30).minutes.do(run_threaded, job_unified_brief)
    schedule.every(15).minutes.do(run_threaded, fetch_feeds)
    schedule.every(3).minutes.do(run_threaded, fetch_live_crimes)
    schedule.every(6).hours.do(run_threaded, fetch_cisa_kev)
    schedule.every(1).hours.do(run_threaded, job_internal_risk)
    
    # High-Priority / High-Churn Telemetry
    schedule.every(2).minutes.do(run_threaded, fetch_regional_hazards)
    schedule.every(5).minutes.do(run_threaded, fetch_cloud_outages)
    schedule.every(5).minutes.do(run_threaded, run_telemetry_sync)
    schedule.every(1).minutes.do(run_threaded, job_auto_dispatch_tickets)
    
    log("[START] Master Orchestrator Online. Firing Boot Sequence...", "SYSTEM")
    
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
        log("[STOP] Orchestrator shutting down gracefully...", "SYSTEM")
        sys.exit(0)
