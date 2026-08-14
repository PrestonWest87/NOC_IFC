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
import logging
import asyncio
import aiohttp
import requests
import threading
import gc
import concurrent.futures
import calendar
from typing import List, Dict, Tuple, Optional

import urllib3
_orig_create_pool = urllib3.PoolManager.__init__
def _patched_pool_init(self, *a, **kw):
    _orig_create_pool(self, *a, **kw)
    self.connection_pool_kw.setdefault("maxsize", 3)
urllib3.PoolManager.__init__ = _patched_pool_init
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from datetime import datetime, timedelta

from src.database import (
    SessionLocal, Article, FeedSource, RegionalHazard, CloudOutage,
    ExtractedIOC, engine, init_db, SolarWindsAlert, BgpAnomaly,
    CveItem, RegionalOutage, CrimeIncident, MonitoredLocation,
    InternalRiskSnapshot, TimelineEvent, ElasticEvent
)

from src.workers.cve_worker import fetch_cisa_kev
from src.workers.infra_worker import fetch_regional_hazards
from src.workers.cloud_worker import fetch_cloud_outages
from src.workers.telemetry_worker import run_telemetry_sync
from src.workers.crime_worker import fetch_live_crimes
init_db()

logger = logging.getLogger(__name__)

def log(message, source="SYSTEM", level=None):
    """Log timestamped messages formatted for Docker log capture."""
    if level is None:
        level = logging.INFO
    logger.log(level, "[%s] %s", source.upper(), message)

def log_memory_usage(tag=""):
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = line.strip().split()[1]
                    log(f"[{tag}] RSS: {rss} kB", "MEMORY", logging.INFO)
                    break
    except Exception as e:
        log(f"memory check failed: {e}", "MEMORY", logging.WARNING)

# --- Lazy-load scorer on first use ---
_global_scorer = None

def _ensure_scorer():
    global _global_scorer
    if _global_scorer is None:
        from src.services.logic import get_scorer
        log("Loading NLP Scorer into memory...", "SYSTEM")
        _global_scorer = get_scorer()
    return _global_scorer


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

def _fetch_full_content(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch and extract full article content from URL using trafilatura."""
    try:
        import trafilatura
    except ImportError:
        return None
    try:
        response = requests.get(url, timeout=(3, timeout), headers={"User-Agent": "NOC-Fusion/2.0"})
        response.raise_for_status()
        if response.text:
            return trafilatura.extract(response.text, include_comments=False, include_tables=True,
                                        no_fallback=False, favor_recall=True)
    except Exception:
        pass
    return None

def _entry_published_at(entry):
    """Use the source timestamp so feed freshness and retention remain accurate."""
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed:
        try:
            return datetime.utcfromtimestamp(calendar.timegm(parsed))
        except (TypeError, ValueError, OverflowError):
            pass
    return datetime.utcnow()

def parse_and_score_feed(f_name, content, known_links):
    """Parse RSS feed content and score articles for relevance."""
    from src.services.ioc_extractor import ioc_engine
    from src.services.categorizer import categorize_text
    
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
        
        score, reasons = _ensure_scorer().score(full_text)
        category = categorize_text(full_text)
        
        extracted_iocs = []
        if score >= 50.0 and category.startswith("Cyber"):
            extracted_iocs = ioc_engine.extract(full_text) 
            
        new_articles_data.append({
            "title": title, "link": link, "summary": summary, "source": f_name,
            "published_date": _entry_published_at(entry),
            "score": float(score), "category": category, "keywords_found": reasons,
            "is_bubbled": (score >= ALERT_THRESHOLD), "iocs": extracted_iocs,
            "full_content": None
        })

    return f_name, new_articles_data

def bulk_save_to_db(db_session, arts_data):
    """Persist every valid article independently so one duplicate cannot lose a batch."""
    if not arts_data: return 0
    added = 0
    for d in arts_data:
        art = Article(
            title=d["title"], link=d["link"], summary=d["summary"], source=d["source"],
            published_date=d.get("published_date", datetime.utcnow()), ingested_at=datetime.utcnow(),
            score=d["score"], category=d["category"],
            enrichment_status="pending" if d["score"] >= 40.0 else "enriched",
            keywords_found=d["keywords_found"], is_bubbled=d["is_bubbled"],
            full_content=d.get("full_content")
        )
        try:
            with db_session.begin_nested():
                db_session.add(art)
                db_session.flush()
                for ioc in d.get("iocs", []):
                    db_session.add(ExtractedIOC(
                        article_id=art.id, indicator_type=ioc["Type"],
                        indicator_value=ioc["Indicator"], context=ioc["Context"]
                    ))
            added += 1
        except IntegrityError:
            continue
        except Exception as e:
            log(f"[WARN] Article persistence failed for {d.get('link', '')}: {e}", "WORKER", logging.WARNING)
            continue

    db_session.commit()
    db_session.expunge_all()
    return added

def enrich_pending_articles(limit=25):
    """Enrich captured articles without blocking the RSS persistence path."""
    with SessionLocal() as db:
        pending = db.query(Article.id, Article.link).filter(
            Article.enrichment_status.in_(["pending", "failed"]),
            Article.enrichment_attempts < 3,
            Article.score >= 40.0,
        ).order_by(Article.score.desc(), Article.ingested_at.asc()).limit(limit).all()
        ids = [row.id for row in pending]
        for article_id in ids:
            db.query(Article).filter(Article.id == article_id).update({
                "enrichment_status": "content_pending",
                "enrichment_attempts": Article.enrichment_attempts + 1,
            }, synchronize_session=False)
        db.commit()

    if not pending:
        return 0

    def fetch(row):
        return row.id, _fetch_full_content(row.link)

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = executor.map(fetch, pending)
        for article_id, content in results:
            with SessionLocal() as db:
                article = db.query(Article).filter(Article.id == article_id).first()
                if not article:
                    continue
                if content:
                    article.full_content = content[:200000]
                    article.enrichment_status = "enriched"
                    article.last_enriched_at = datetime.utcnow()
                    article.last_enrichment_error = None
                    completed += 1
                else:
                    article.enrichment_status = "failed"
                    article.last_enrichment_error = "Full-content extraction returned no content."
                db.commit()
    return completed

def fetch_feeds(source="Scheduled"):
    """Main entry point for scheduled RSS feed fetching and scoring."""
    import gc
    log("[WORKER] Starting feed fetch cycle...", source, logging.DEBUG)

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
                    if added > 0: log(f"[OK] {f_name}: Saved {added} new articles.", "WORKER", logging.DEBUG)
                    total_added += added

                time.sleep(0.1)

            except Exception as e:
                log(f"[ERROR] Processing error on {f_name}: {e}", "WORKER")

    log(f"[COMPLETE] Cycle complete. Added {total_added} items.", source)
    with SessionLocal() as dedup_session:
        from src.services import deduplicate_articles
        deduped = deduplicate_articles(dedup_session)
        if deduped:
            log(f"[CLEANUP] De-duplicated {deduped} articles after feed fetch.", "WORKER", logging.DEBUG)

def job_unified_brief():
    """Auto-generates the Unified Risk Brief every 30 minutes."""
    log("[AI] Generating Executive Unified Risk Brief...", "SYSTEM")
    try:
        from src.utils.llm import generate_unified_risk_brief
        from src.services import get_executive_grid_intel, get_recent_crimes, save_global_config
        from src.database import InternalRiskSnapshot, RegionalHazard

        with SessionLocal() as session:
            latest_internal = session.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
            active_nws = session.query(RegionalHazard).count()

        crime_data = get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
        global_intel = get_executive_grid_intel(active_nws, crime_data)

        with SessionLocal() as session:
            brief_text = generate_unified_risk_brief(session, global_intel, latest_internal)

        if brief_text and "AI is currently disabled" not in brief_text:
            save_global_config({
                "unified_brief": brief_text,
                "unified_brief_time": datetime.utcnow()
            })
            log("[OK] Unified Risk Brief generated and saved.", "SYSTEM")

            from src.utils.risk_alert import check_and_alert
            check_and_alert(global_risk=global_intel.get('unified_risk'), internal_risk=None)
    except Exception as e:
        log(f"[ERROR] Unified Brief Error: {e}", "SYSTEM")

def job_global_brief():
    """Auto-generates the Global Threat Brief every 1 hour."""
    log("[AI] Generating Global Threat Brief (US Critical Infrastructure Focus)...", "SYSTEM")
    try:
        from src.services import trigger_global_brief
        trigger_global_brief()
        log("[OK] Global Threat Brief generated and saved.", "SYSTEM")
    except Exception as e:
        log(f"[ERROR] Global Brief Error: {e}", "SYSTEM")

def job_internal_brief():
    """Auto-generates the Internal Asset Risk Brief every 2 hours."""
    log("[AI] Generating Internal Asset Risk Brief...", "SYSTEM")
    try:
        from src.services import trigger_internal_brief
        trigger_internal_brief()
        log("[OK] Internal Asset Risk Brief generated and saved.", "SYSTEM")
    except Exception as e:
        log(f"[ERROR] Internal Brief Error: {e}", "SYSTEM")

def job_internal_risk():
    """Wrapper to safely execute and log the internal risk calculation."""
    log("[SYSTEM] Generating Internal Risk Snapshot...", "SYSTEM")
    try:
        from src.services import generate_and_save_internal_risk_snapshot
        cis_data = generate_and_save_internal_risk_snapshot()
        log("[OK] Internal Risk Snapshot generated successfully.", "SYSTEM")

        # Check for internal risk increase and send alert if needed
        if cis_data:
            from src.utils.risk_alert import check_and_alert
            check_and_alert(global_risk=None, internal_risk=cis_data.get('risk_level'))
    except Exception as e:
        log(f"[ERROR] Internal Risk Error: {e}", "SYSTEM")

def job_daily_email_unified_brief():
    """Sends the latest Executive Unified Risk Brief via email at 07:00 daily."""
    log("[EMAIL] Dispatching Daily Executive Unified Risk Brief...", "SYSTEM")
    try:
        import os
        from datetime import datetime
        from zoneinfo import ZoneInfo
        from src.utils.mailer import send_alert_email
        from src.services import generate_unified_brief_email_html
        from src.database import InternalRiskSnapshot, SystemConfig, SessionLocal
        from src.services import get_executive_grid_intel, get_recent_crimes

        ub_recipients = os.environ.get("RISK_ALERT_RECIPIENTS")
        if not ub_recipients:
            log("[WARN] RISK_ALERT_RECIPIENTS not set. Skipping daily email.", "SYSTEM")
            return

        now_local = datetime.now(ZoneInfo("America/Chicago"))
        brief_time = now_local.strftime("%A, %B %d, %Y at %I:%M %p %Z")

        with SessionLocal() as db:
            sys_config = db.query(SystemConfig).first()
            if not sys_config or not sys_config.unified_brief:
                log("[WARN] No unified brief available. Skipping daily email.", "SYSTEM")
                return

            current_internal = None
            latest_internal = db.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
            if latest_internal:
                current_internal = latest_internal.risk_level

        from src.services import get_cached_geojson
        cached_geo = get_cached_geojson()
        ar_warn = cached_geo[3] or {}
        oos_warn = cached_geo[4] or {}
        active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))
        crime_data = get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
        global_intel = get_executive_grid_intel(active_nws, crime_data)
        current_global = global_intel.get('unified_risk')

        formatted_html = generate_unified_brief_email_html(
            brief_time, sys_config.unified_brief,
            global_risk=current_global,
            internal_risk=current_internal
        )

        success, msg = send_alert_email(
            "Executive Unified Risk Brief", formatted_html,
            recipient_override=ub_recipients, is_html=True
        )
        if success:
            log("[OK] Daily Unified Risk Brief emailed successfully.", "SYSTEM")
        else:
            log(f"[ERROR] Failed to send daily brief email: {msg}", "SYSTEM")

    except Exception as e:
        log(f"[ERROR] Daily Email Brief Error: {e}", "SYSTEM")


# =====================================================================
# 2. GARBAGE COLLECTION & MAINTENANCE
# =====================================================================

def run_database_maintenance():
    log("[CLEANUP] Running Master Database Maintenance...", "SYSTEM", logging.DEBUG)
    with SessionLocal() as session:
        try:
            now = datetime.utcnow()
            
            hours_12_ago = now - timedelta(hours=12)
            hours_24_ago = now - timedelta(hours=24) 
            hours_48_ago = now - timedelta(hours=48)
            days_7_ago   = now - timedelta(days=7)
            days_3_ago   = now - timedelta(days=3)
            days_14_ago  = now - timedelta(days=14)
            days_30_ago  = now - timedelta(days=30)
            days_60_ago  = now - timedelta(days=60)
            days_90_ago  = now - timedelta(days=90)
            hours_72_ago = now - timedelta(hours=72)
            
            # --- CLEANUP LOGIC ---
            # Low-value articles get a shorter retention window; recent captures remain available
            # for triage while high-value and pinned intelligence receives the full retention period.
            session.query(Article).filter(
                Article.score < 50.0,
                Article.published_date < days_3_ago,
                Article.is_pinned == False,
            ).delete()
            session.query(Article).filter(Article.published_date < days_30_ago, Article.is_pinned == False).delete()
            session.query(SolarWindsAlert).filter(SolarWindsAlert.received_at < days_60_ago).delete()
            session.query(RegionalHazard).filter(RegionalHazard.updated_at < hours_48_ago).delete()
            session.query(RegionalOutage).filter(RegionalOutage.detected_at < hours_12_ago).delete()
            session.query(BgpAnomaly).filter(BgpAnomaly.detected_at < hours_12_ago).delete()
            session.query(CveItem).filter(CveItem.date_added < days_7_ago).delete()
            session.query(CloudOutage).filter(CloudOutage.updated_at < hours_24_ago).delete()
            session.query(CloudOutage).filter(
                CloudOutage.is_resolved == False,
                CloudOutage.updated_at < days_14_ago
            ).delete()
            session.query(CrimeIncident).filter(CrimeIncident.timestamp < days_7_ago).delete()
            session.query(InternalRiskSnapshot).filter(InternalRiskSnapshot.timestamp < days_90_ago).delete()
            session.query(TimelineEvent).filter(TimelineEvent.timestamp < days_90_ago).delete()
            session.query(ElasticEvent).filter(ElasticEvent.timestamp < hours_72_ago).delete()
            
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
            conn.execute(text("PRAGMA wal_checkpoint(PASSIVE);"))
    except Exception: 
        pass


# =====================================================================
# 2b. AUTO-CLEAR EXPIRED MAINTENANCE
# =====================================================================

def job_clear_expired_maintenance():
    """Clear maintenance status on sites whose ETR has passed, broadcast update to AIOps page."""
    from src.services import auto_clear_expired_maintenance
    cleared = auto_clear_expired_maintenance()
    if cleared:
        log(f"[MAINT] Auto-cleared expired maintenance for: {', '.join(cleared)}", "SYSTEM")
        try:
            from src.api.main import manager
            import asyncio
            asyncio.run(manager.broadcast_json({"type": "RCA_UPDATE"}))
        except Exception:
            pass


# =====================================================================
# 3. TIERED ALERT ESCALATION (24/7 RCA Ticketing)
# =====================================================================

def job_tiered_alert_escalation():
    """
    Comprehensive 24/7 Tiered Alert & RCA Ticketing Manager.
    - DAY SHIFT (0600-2000 M-F): Sends ONLY Remedyforce tickets. P1s are immediate, P2-P5 delay 10 mins.
    - AFTER HOURS (Nights/Weekends): Full escalation path. Tickets, NOC Notifications, and Smart Onpage.
    - Determines the highest priority alert for a site (handling Cascades inherently).
    - Injects District info into tickets/notifications.
    """
    from src.utils.mailer import send_alert_email
    from src.services.aiops_engine import EnterpriseAIOpsEngine
    from src.services import generate_rca_ticket_text
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    import re
    import os

    now_utc = datetime.utcnow()
    local_tz = ZoneInfo("America/Chicago")

    def is_business_hours(dt_utc):
        if not dt_utc: return False
        dt_local = dt_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(local_tz)
        return (0 <= dt_local.weekday() <= 4) and (6 <= dt_local.hour < 20)

    log("[SYSTEM] 24/7 RCA Ticketing & Escalation Manager Active...", "SYSTEM", logging.DEBUG)
    cutoff_time = now_utc - timedelta(hours=12)

    # --- 1. EMAIL DISPATCH DESTINATIONS (Strict .env Pull) ---
    TICKET_EMAIL = os.environ.get("REMEDYFORCE_TICKET_EMAIL")
    NOTIFY_EMAIL = os.environ.get("NOC_NOTIFY_EMAIL")
    NOC_ONPAGE_EMAIL = os.environ.get("NOC_ONPAGE_EMAIL")
    ITNETWORK_ONPAGE_EMAIL = os.environ.get("ITNETWORK_ONPAGE_EMAIL")

    log(f"[ENV] REMEDYFORCE_TICKET_EMAIL={'SET' if TICKET_EMAIL else 'MISSING'}", "SYSTEM", logging.DEBUG)
    log(f"[ENV] NOC_NOTIFY_EMAIL={'SET' if NOTIFY_EMAIL else 'MISSING'}", "SYSTEM", logging.DEBUG)
    log(f"[ENV] NOC_ONPAGE_EMAIL={'SET' if NOC_ONPAGE_EMAIL else 'MISSING'}", "SYSTEM", logging.DEBUG)
    log(f"[ENV] ITNETWORK_ONPAGE_EMAIL={'SET' if ITNETWORK_ONPAGE_EMAIL else 'MISSING'}", "SYSTEM", logging.DEBUG)

    if not TICKET_EMAIL:
        log("[ERROR] REMEDYFORCE_TICKET_EMAIL missing from environment. Aborting run.", "SYSTEM")
        return

    # --- 2. DUAL SLA DICTIONARIES ---
    AFTER_HOURS_RULES = {
        "p1-high": {"wait": 0,   "sla": "1 Hour",   "weight": 70, "requires_onpage": True,  "cooldown": 1},
        "p1-low":  {"wait": 45,  "sla": "4 Hours",  "weight": 60, "requires_onpage": True,  "cooldown": 1},
        "p2-high": {"wait": 30,  "sla": "2.5 Hours","weight": 50, "requires_onpage": False, "cooldown": 5},
        "p2-low":  {"wait": 45,  "sla": "4 Hours",  "weight": 40, "requires_onpage": False, "cooldown": 5},
        "p3":      {"wait": 45,  "sla": "8 Hours",  "weight": 30, "requires_onpage": False, "cooldown": 5},
        "p4":      {"wait": 60,  "sla": "24 Hours", "weight": 20, "requires_onpage": False, "cooldown": 5},
        "p5":      {"wait": 120, "sla": "72 Hours", "weight": 10, "requires_onpage": False, "cooldown": 5}
    }

    DAY_SHIFT_RULES = {
        "p1-high": {"wait": 0,  "sla": "1 Hour",   "weight": 70, "requires_onpage": False, "cooldown": 1},
        "p1-low":  {"wait": 0,  "sla": "4 Hours",  "weight": 60, "requires_onpage": False, "cooldown": 1},
        "p2-high": {"wait": 10, "sla": "2.5 Hours","weight": 50, "requires_onpage": False, "cooldown": 5},
        "p2-low":  {"wait": 10, "sla": "4 Hours",  "weight": 40, "requires_onpage": False, "cooldown": 5},
        "p3":      {"wait": 10, "sla": "8 Hours",  "weight": 30, "requires_onpage": False, "cooldown": 5},
        "p4":      {"wait": 10, "sla": "24 Hours", "weight": 20, "requires_onpage": False, "cooldown": 5},
        "p5":      {"wait": 10, "sla": "72 Hours", "weight": 10, "requires_onpage": False, "cooldown": 5}
    }

    # --- 3. DATA ACQUISITION & CLUSTERING ---
    with SessionLocal() as db:
        raw_alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.status != 'Resolved',
            SolarWindsAlert.received_at >= cutoff_time
        ).all()

        active_alerts = raw_alerts
        if not active_alerts:
            return

        active_weather = db.query(RegionalHazard).all()
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()

        ai_engine = EnterpriseAIOpsEngine(db)
        incidents = ai_engine.analyze_and_cluster(active_alerts)

        def is_node_on_cooldown(node_name, cooldown_hours):
            cooldown_cutoff = now_utc - timedelta(hours=cooldown_hours)
            return db.query(SolarWindsAlert).filter(
                SolarWindsAlert.node_name == node_name,
                SolarWindsAlert.is_ticketed == True,
                SolarWindsAlert.received_at >= cooldown_cutoff
            ).first() is not None

        def get_tier(alert):
            p = alert.raw_payload if isinstance(alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}
            raw_level = str(p.get('Normalized_Alert_Level') or cp.get('Alert_Level') or '').strip().lower()

            if "p1-high" in raw_level: return "p1-high"
            if "p1-low" in raw_level: return "p1-low"
            if "p2-high" in raw_level: return "p2-high"
            if "p2-low" in raw_level: return "p2-low"

            match = re.search(r'\d+', raw_level)
            if match:
                level_num = int(match.group())
                if level_num == 1: return "p1-low" if "low" in raw_level else "p1-high"
                elif level_num == 2: return "p2-low" if "low" in raw_level else "p2-high"
                elif level_num == 3: return "p3"
                elif level_num == 4: return "p4"
                elif level_num == 5: return "p5"
            return "unknown"

        # --- 4. SITE EVALUATION LOOP ---
        for site, data in incidents.items():
            alerts = data.get('alerts', [])
            undispatched_alerts = [a for a in alerts if not a.is_ticketed]

            if not undispatched_alerts:
                continue

            loc = db.query(MonitoredLocation).filter_by(name=site).first()

            # Site-level onpage mute
            alert_is_day = is_business_hours(undispatched_alerts[0].received_at)
            if not alert_is_day and loc and getattr(loc, 'last_escalation_ticket', None):
                time_since_onpage = now_utc - loc.last_escalation_ticket
                if time_since_onpage < timedelta(hours=1):
                    log(f"[SITE MUTED] Suppressed alerts for {site}. Site recently ONPAGED.", "SYSTEM")
                    for a in undispatched_alerts: a.is_ticketed = True
                    db.commit()
                    continue

            undispatched_alerts.sort(key=lambda a: a.received_at)

            cause, score, rca_priority, _, _, p0_name, _ = ai_engine.calculate_root_cause(
                site, data, active_weather, active_clouds, active_bgp
            )

            target_alert = undispatched_alerts[0]
            alert_is_day = is_business_hours(target_alert.received_at)
            ACTIVE_RULES = DAY_SHIFT_RULES if alert_is_day else AFTER_HOURS_RULES

            target_tier = get_tier(target_alert)
            is_cascade = False
            base_weight = ACTIVE_RULES.get(target_tier, {"weight": -1})["weight"]

            for a in undispatched_alerts[1:]:
                a_tier = get_tier(a)
                a_weight = ACTIVE_RULES.get(a_tier, {"weight": -1})["weight"]
                if a_weight > base_weight:
                    target_alert = a
                    target_tier = a_tier
                    is_cascade = True
                    log(f"[CASCADE DETECTED] {site} escalated to {target_tier.upper()}", "SYSTEM")
                    break

            duration_active = now_utc - target_alert.received_at
            if target_tier == "unknown":
                unknown_wait = 10 if alert_is_day else 30
                if duration_active >= timedelta(minutes=unknown_wait):
                    if not is_node_on_cooldown(target_alert.node_name, cooldown_hours=5):
                        log(f"[DISPATCHING] Unknown priority alert for {site}", "SYSTEM")
                        t_body = "Automated Comms Outage\n*** REQUIRES MANAGEMENT DIRECTION ***\n"
                        t_body += f"Unmapped Priority: {target_alert.event_type}\n\n"
                        t_body += generate_rca_ticket_text(site, data, "UNKNOWN", p0_name or "Unknown", cause)

                        t_ok, _ = send_alert_email(f"UNDOCUMENTED ALERT: {target_alert.node_name}", t_body, TICKET_EMAIL, is_html=False)

                        n_ok = False
                        if not alert_is_day and NOTIFY_EMAIL:
                            n_ok, _ = send_alert_email(f"UNDOCUMENTED ALERT (NOTIFY): {target_alert.node_name}", t_body, NOTIFY_EMAIL, is_html=False)

                        if t_ok or n_ok:
                            for a in undispatched_alerts: a.is_ticketed = True
                            db.commit()
                continue

            rules = ACTIVE_RULES[target_tier]
            p = target_alert.raw_payload if isinstance(target_alert.raw_payload, dict) else {}
            cp = p.get('Custom_Properties_Universal') or {}

            db_loc_type = getattr(loc, 'loc_type', '').lower() if loc else ''
            cp_loc_type = str(cp.get('Location_Type') or cp.get('LocationType') or '').lower()
            district = str(cp.get('District') or data.get('site_metadata', {}).get('district') or 'Unknown')

            is_swf_device = "swf" in target_alert.node_name.lower() or any(x in db_loc_type or x in cp_loc_type for x in ["fiber hut", "fiber cabinet"])

            wait_minutes = rules["wait"]
            is_onpage = rules.get("requires_onpage", False)

            if is_cascade:
                wait_minutes = 0

            # --- 7. DISPATCH EVALUATION ---
            if duration_active >= timedelta(minutes=wait_minutes):

                if is_node_on_cooldown(target_alert.node_name, rules["cooldown"]):
                    log(f"[NODE FLAPPING] Muted cluster for {site} (Node {target_alert.node_name} on cooldown).", "SYSTEM")
                    for a in undispatched_alerts: a.is_ticketed = True
                    db.commit()
                    continue

                shift_prefix = "DAY-SHIFT" if alert_is_day else "AFTER-HOURS"
                prefix = f"{shift_prefix} SITE ESCALATION / CASCADE" if is_cascade else f"{shift_prefix} TICKET"

                base_body = f"Priority: {target_tier.upper()}\n"
                base_body += f"District: {district.title()}\n"
                base_body += f"Target SLA: {rules['sla']}\n"
                if target_tier == "p2-high" and not alert_is_day:
                    base_body += "Requirement: Positive Handoff (No ONPAGE)\n"
                base_body += "\n" + generate_rca_ticket_text(site, data, target_tier.upper(), p0_name or "Unknown", cause)

                dispatch_success = False

                ticket_body = f"Automated Comms Outage\n*** {prefix} ***\n" + base_body
                log(f"[DISPATCH] Sending ticket email for {site} to {TICKET_EMAIL}", "SYSTEM", logging.DEBUG)
                t_success, t_msg = send_alert_email(
                    f"{'CASCADE ' if is_cascade else ''}TICKET: {target_tier.upper()} Incident at {site}",
                    ticket_body, recipient_override=TICKET_EMAIL, is_html=False
                )
                if t_success:
                    log(f"[TICKET OK] Ticket sent for {site}", "SYSTEM", logging.DEBUG)
                    dispatch_success = True
                else:
                    log(f"[TICKET FAILED] SMTP Error for {site}: {t_msg}", "SYSTEM")

                if not alert_is_day:

                    if NOTIFY_EMAIL:
                        log(f"[DISPATCH] Sending NOC notification for {site} to {NOTIFY_EMAIL}", "SYSTEM", logging.DEBUG)
                        n_success, n_msg = send_alert_email(
                            f"NOC NOTIFICATION {'(CASCADE) ' if is_cascade else ''}: {target_tier.upper()} Incident at {site}",
                            f"*** NOC NOTIFICATION {'ESCALATION ' if is_cascade else ''}***\n" + base_body,
                            recipient_override=NOTIFY_EMAIL, is_html=False
                        )
                        if n_success:
                            log(f"[NOTIFY OK] Notification sent for {site}", "SYSTEM", logging.DEBUG)
                            dispatch_success = True
                        else:
                            log(f"[NOTIFY FAILED] SMTP Error for {site}: {n_msg}", "SYSTEM")

                    if is_onpage:
                        if is_swf_device:
                            target_onpage_email = NOC_ONPAGE_EMAIL
                            onpage_title = "NOC"
                        else:
                            target_onpage_email = ITNETWORK_ONPAGE_EMAIL
                            onpage_title = "ITNETWORK"

                        if target_onpage_email:
                            log(f"[DISPATCH] Sending {onpage_title} ONPAGE for {site} to {target_onpage_email}", "SYSTEM", logging.DEBUG)
                            o_success, o_msg = send_alert_email(
                                f"URGENT {onpage_title} ONPAGE {'CASCADE ' if is_cascade else ''}: {target_tier.upper()} Incident at {site}",
                                f"*** URGENT {onpage_title} ONPAGE {'ESCALATION ' if is_cascade else ''}***\n" + base_body,
                                recipient_override=target_onpage_email, is_html=False
                            )
                            if o_success:
                                log(f"[ONPAGE OK] {onpage_title} onpage sent for {site}", "SYSTEM", logging.DEBUG)
                                dispatch_success = True
                                if loc: loc.last_escalation_ticket = now_utc
                            else:
                                log(f"[{onpage_title} ONPAGE FAILED] SMTP Error for {site}: {o_msg}", "SYSTEM")
                        else:
                            log(f"[SKIP] {onpage_title} ONPAGE email not configured for {site}", "SYSTEM")

                if dispatch_success:
                    log(f"[SUCCESS] Fully Ticketed {target_tier.upper()} cluster for {site}", "SYSTEM", logging.DEBUG)
                    for a in undispatched_alerts: a.is_ticketed = True
                    db.commit()

    gc.collect()

# =====================================================================
# 4. AUTOMATED ML RETRAINING
# =====================================================================

def job_retrain_ml():
    """Automated Weekly ML Retraining Pipeline"""
    global _global_scorer
    from src.train_model import train
    log("[AI] Initiating weekly ML Model Retraining...", "SYSTEM")
    try:
        train()
        log("[OK] ML Model retrained successfully and saved to disk.", "SYSTEM")
        
        # Hot-Reload the scorer in memory so the new neural weights take effect immediately
        _global_scorer = None
        _ensure_scorer()
        log(" Global NLP Scorer hot-reloaded with fresh model weights.", "SYSTEM")
        
    except Exception as e:
        log(f"[ERROR] ML Training Pipeline failed: {e}", "SYSTEM")


# =====================================================================
# 4. THE THREADED MASTER ORCHESTRATOR
# =====================================================================

_job_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="scheduled-job")
_running_jobs = set()
_running_jobs_lock = threading.Lock()

def run_threaded(job_func, *args, **kwargs):
    """
    Submit a job to the bounded executor unless the same job is already queued or running.
    """
    job_name = getattr(job_func, "__name__", str(job_func))
    with _running_jobs_lock:
        if job_name in _running_jobs:
            log(f"[SKIP] {job_name} is already running.", "WORKER", logging.DEBUG)
            return False
        _running_jobs.add(job_name)

    def _run():
        log_memory_usage(f"pre-{job_name}")
        try:
            job_func(*args, **kwargs)
        except Exception as e:
            log(f"[CRASH] Job {job_name} failed: {e}", "WORKER", logging.ERROR)
            import traceback
            log(f"[CRASH] Traceback: {traceback.format_exc()}", "WORKER", logging.ERROR)
        finally:
            log_memory_usage(f"post-{job_name}")
            with _running_jobs_lock:
                _running_jobs.discard(job_name)
    _job_executor.submit(_run)
    return True

if __name__ == "__main__":
    from src.core.config import setup_logging
    setup_logging()

    from src.workers.report_worker import start_report_scheduler
    
    # 1. Start the Automated Email Reporter
    threading.Thread(target=start_report_scheduler, daemon=True).start()
    
    # 2. Map the Schedules to Threaded Wrappers — STAGGERED to prevent CPU spikes
    
    # Tier 1: Must be responsive (1 min)
    schedule.every(1).minutes.do(run_threaded, job_tiered_alert_escalation)
    schedule.every(5).minutes.do(log_memory_usage, "periodic")
    
    # Tier 2: High-frequency data collection — staggered to avoid pile-ups
    schedule.every(5).minutes.do(run_threaded, fetch_feeds)
    schedule.every(3).minutes.do(run_threaded, enrich_pending_articles)
    schedule.every(5).minutes.do(run_threaded, job_clear_expired_maintenance)
    schedule.every(6).minutes.do(run_threaded, run_telemetry_sync)
    schedule.every(7).minutes.do(run_threaded, fetch_regional_hazards)
    schedule.every(8).minutes.do(run_threaded, fetch_cloud_outages)
    schedule.every(10).minutes.do(run_threaded, fetch_live_crimes)
    
    # Tier 3: Hourly — offset from each other
    schedule.every(60).minutes.do(run_threaded, run_database_maintenance)
    schedule.every(2).hours.do(run_threaded, job_internal_risk)
    
    # Tier 4: LLM briefs — staggered across the day
    schedule.every(3).hours.do(run_threaded, job_internal_brief)
    schedule.every(6).hours.do(run_threaded, job_unified_brief)
    schedule.every(7).hours.do(run_threaded, fetch_cisa_kev)
    
    # Tier 5: Daily
    schedule.every().day.at("02:00").do(run_threaded, job_global_brief)
    
    # Tier 6: Weekly
    schedule.every().sunday.at("02:00").do(run_threaded, job_retrain_ml)
    
    # Daily Email Unified Brief at 07:00 CST
    try:
        schedule.every().day.at("07:00", "America/Chicago").do(run_threaded, job_daily_email_unified_brief)
    except Exception:
        schedule.every().day.at("07:00").do(run_threaded, job_daily_email_unified_brief)
    
    log("[START] Master Orchestrator Online. Firing Boot Sequence...", "SYSTEM")

    # 3. Staggered Boot Sequence — groups of 3 with 30s delays to avoid CPU storm
    boot_groups = [
        [job_tiered_alert_escalation, job_clear_expired_maintenance, fetch_feeds],
        [fetch_cisa_kev, fetch_regional_hazards, fetch_cloud_outages],
        [run_telemetry_sync, fetch_live_crimes, job_internal_risk],
        [job_unified_brief, job_global_brief, job_internal_brief],
    ]
    for i, group in enumerate(boot_groups):
        for job in group:
            run_threaded(job)
        if i < len(boot_groups) - 1:
            time.sleep(30)
    
    # 4. Master Event Loop
    try:
        while True:
            try:
                schedule.run_pending()
            except Exception as e:
                log(f"[CRASH] Main loop error: {e}", "WORKER", logging.ERROR)
                import traceback
                log(f"[CRASH] Traceback: {traceback.format_exc()}", "WORKER", logging.ERROR)
            time.sleep(1)
    except KeyboardInterrupt:
        log("[STOP] Orchestrator shutting down gracefully...", "SYSTEM")
        sys.exit(0)
