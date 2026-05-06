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

def job_tiered_alert_escalation():
    """
    Comprehensive Tiered Alert & RCA Ticketing Manager.
    - Active ONLY during After-Hours (Nights & Weekends).
    - Guarantees a standard ticket is created for ALL valid alerts.
    - Appends ONPAGE routing exclusively for P1 and escalated P1 clusters.
    - Enforces Anti-Flap Cooldowns (1hr High Priority, 5hr Low Priority).
    """
    from src.database import SessionLocal, SolarWindsAlert, MonitoredLocation, RegionalHazard, CloudOutage, BgpAnomaly
    from src.mailer import send_alert_email
    from src.aiops_engine import EnterpriseAIOpsEngine
    from src.services import generate_rca_ticket_text
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo

    now_utc = datetime.utcnow()
    now_local = datetime.now(ZoneInfo("America/Chicago"))
    
    # Define Business Hours (Mon-Fri, 06:00 - 20:00 Central Time)
    is_business_hours = (0 <= now_local.weekday() <= 4) and (6 <= now_local.hour < 20)
    
    # --- STRICT AFTER-HOURS ENFORCEMENT ---
    if is_business_hours:
        return

    log("[SYSTEM] After-Hours RCA Ticketing & Escalation Manager Active...", "SYSTEM")
    
    # Restrict to current issues (12-hour boundary prevents ghost tickets)
    cutoff_time = now_utc - timedelta(hours=12)
    
    # --- ROUTING CONSTANTS ---
    BASE_TICKET_EMAILS = "remedyforceworkflow@aecc.com, noc@aecc.com" 
    ONPAGE_EMAIL = "noc@aecc.com" # TODO: Update to actual paging system email

    # Rules Map: wait (mins), sla (str), weight (int), requires_onpage (bool), cooldown (hours)
    PRIORITY_RULES = {
        "p1-high": {"wait": 15,  "sla": "1 Hour",   "weight": 70, "requires_onpage": True,  "cooldown": 1},
        "p1-low":  {"wait": 45,  "sla": "4 Hours",  "weight": 60, "requires_onpage": True,  "cooldown": 1},
        "p2-high": {"wait": 30,  "sla": "2.5 Hours","weight": 50, "requires_onpage": False, "cooldown": 5},
        "p2-low":  {"wait": 45,  "sla": "4 Hours",  "weight": 40, "requires_onpage": False, "cooldown": 5},
        "p3":      {"wait": 45,  "sla": "8 Hours",  "weight": 30, "requires_onpage": False, "cooldown": 5},
        "p4":      {"wait": 60,  "sla": "24 Hours", "weight": 20, "requires_onpage": False, "cooldown": 5},
        "p5":      {"wait": 120, "sla": "72 Hours", "weight": 10, "requires_onpage": False, "cooldown": 5}
    }

    with SessionLocal() as db:
        # Fetch active alerts within the last 12 hours
        active_alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.status != 'Resolved',
            SolarWindsAlert.received_at >= cutoff_time
        ).all()

        if not active_alerts:
            return

        active_weather = db.query(RegionalHazard).all()
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()

        ai_engine = EnterpriseAIOpsEngine(db)
        incidents = ai_engine.analyze_and_cluster(active_alerts)

        # --- HELPER: Anti-Flap Node Checker ---
        def is_node_on_cooldown(node_name, cooldown_hours):
            """Checks if we already dispatched a ticket for this exact node within its cooldown window."""
            cooldown_cutoff = now_utc - timedelta(hours=cooldown_hours)
            recent_dispatch = db.query(SolarWindsAlert).filter(
                SolarWindsAlert.node_name == node_name,
                SolarWindsAlert.is_dispatched == True,
                SolarWindsAlert.received_at >= cooldown_cutoff
            ).first()
            return recent_dispatch is not None

        for site, data in incidents.items():
            alerts = data.get('alerts', [])
            if not alerts: 
                continue

            def get_tier(alert):
                p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
                cp = p.get('Custom_Properties_Universal') or {}
                raw_level = str(cp.get('Alert_Level', 'Unknown')).strip().lower()
                for key in PRIORITY_RULES.keys():
                    if key in raw_level: return key
                return "unknown"

            alerts.sort(key=lambda a: a.received_at)
            
            cause, score, rca_priority, _, _, p0_name, _ = ai_engine.calculate_root_cause(
                site, data, active_weather, active_clouds, active_bgp
            )
            
            # =========================================================
            # 1. COMBINATION / CASCADE LOGIC (Low -> High)
            # =========================================================
            earliest_alert = alerts[0]
            base_tier = get_tier(earliest_alert)
            base_weight = PRIORITY_RULES[base_tier]["weight"] if base_tier in PRIORITY_RULES else 0
            
            escalating_alert = None
            for a in alerts[1:]:
                a_tier = get_tier(a)
                a_weight = PRIORITY_RULES[a_tier]["weight"] if a_tier in PRIORITY_RULES else 0
                if a_weight > base_weight:
                    escalating_alert = a
                    break

            if escalating_alert:
                loc = db.query(MonitoredLocation).filter_by(name=site).first()
                time_since_escalation = now_utc - escalating_alert.received_at
                
                # Wait 5 minutes after the escalation occurs to send combination ticket
                if time_since_escalation >= timedelta(minutes=5):
                    # Enforce the 1-Hour Site-Level Cascade Mute
                    if not loc or not loc.last_escalation_dispatch or (now_utc - loc.last_escalation_dispatch) >= timedelta(hours=1):
                        
                        esc_tier = get_tier(escalating_alert)
                        rules = PRIORITY_RULES.get(esc_tier, {})
                        
                        target_recipients = BASE_TICKET_EMAILS
                        if rules.get("requires_onpage"):
                            target_recipients += f", {ONPAGE_EMAIL}"
                        
                        ticket_body = f"*** AFTER-HOURS SITE ESCALATION / CASCADE ***\n"
                        ticket_body += f"Site {site} cascaded to {esc_tier.upper()}.\n"
                        ticket_body += f"Resolution SLA: {rules.get('sla', 'Unknown')}\n\n"
                        ticket_body += generate_rca_ticket_text(site, data, esc_tier.upper(), p0_name or "Unknown", cause)

                        success, msg = send_alert_email(
                            f"URGENT ESCALATION: Cascade Incident at {site}", 
                            ticket_body, 
                            recipient_override=target_recipients, 
                            is_html=False
                        )
                        
                        if success:
                            log(f"[CASCADE DISPATCHED] Sent ticket & notifications for {site}", "SYSTEM")
                            if loc: loc.last_escalation_dispatch = now_utc
                            
                            for a in alerts:
                                a.is_dispatched = True
                            db.commit()
                        else:
                            log(f"[CASCADE FAILED] SMTP Error for {site}: {msg}", "SYSTEM")
                        
                        continue

            # =========================================================
            # 2. STANDARD TIERED SLA LOGIC (Individual Tickets)
            # =========================================================
            undispatched_alerts = [a for a in alerts if not a.is_dispatched]
            
            for a in undispatched_alerts:
                tier = get_tier(a)
                duration_active = now_utc - a.received_at
                
                if tier == "unknown":
                    if duration_active >= timedelta(minutes=30):
                        if not is_node_on_cooldown(a.node_name, cooldown_hours=5): # Default 5hr cooldown for unknowns
                            ticket_body = f"*** REQUIRES MANAGEMENT DIRECTION ***\nUndocumented Priority Level: {a.event_type}\n\n"
                            ticket_body += generate_rca_ticket_text(site, data, "UNKNOWN", p0_name or "Unknown", cause)
                            
                            success, msg = send_alert_email(f"UNDOCUMENTED ALERT: {a.node_name}", ticket_body, recipient_override=BASE_TICKET_EMAILS, is_html=False)
                            if success:
                                a.is_dispatched = True
                                db.commit()
                    continue
                    
                rules = PRIORITY_RULES[tier]
                
                if duration_active >= timedelta(minutes=rules["wait"]):
                    
                    # --- NEW: ANTI-FLAP NODE COOLDOWN CHECK ---
                    if is_node_on_cooldown(a.node_name, rules["cooldown"]):
                        # Silently mark as dispatched so it stops checking this specific bouncing alert
                        a.is_dispatched = True
                        db.commit()
                        log(f"[MUTED] Suppressed alert for {a.node_name} (Node is on a {rules['cooldown']}hr cooldown).", "SYSTEM")
                        continue
                        
                    is_onpage = rules["requires_onpage"]
                    target_recipients = BASE_TICKET_EMAILS
                    if is_onpage:
                        target_recipients += f", {ONPAGE_EMAIL}"
                        
                    subject_prefix = "URGENT ESCALATION" if is_onpage else "AFTER-HOURS TICKET"
                    
                    ticket_body = f"*** {subject_prefix} ***\nPriority: {tier.upper()}\nTarget SLA: {rules['sla']}\n"
                    if tier == "p2-high":
                        ticket_body += "Requirement: Positive Handoff (No ONPAGE)\n"
                    ticket_body += "\n" + generate_rca_ticket_text(site, data, tier.upper(), p0_name or "Unknown", cause)

                    success, msg = send_alert_email(
                        f"{subject_prefix}: {tier.upper()} Incident at {site}", 
                        ticket_body, 
                        recipient_override=target_recipients, 
                        is_html=False
                    )
                    
                    if success:
                        log_type = "ONPAGE+TICKET" if is_onpage else "STANDARD TICKET"
                        log(f"[DISPATCHED {log_type}] Sent {tier.upper()} for {a.node_name} to {target_recipients}", "SYSTEM")
                        a.is_dispatched = True
                        db.commit()
                    else:
                        log(f"[DISPATCH FAILED] SMTP Error for {a.node_name}: {msg}", "SYSTEM")


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
    schedule.every(1).minutes.do(run_threaded, job_tiered_alert_escalation)
    
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
