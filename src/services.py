import pandas as pd
import requests
import bcrypt
import uuid
import re
import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from shapely.geometry import Point, shape
import streamlit as st
# Import your DB setup and models
from src.database import (
    SessionLocal, Article, FeedSource, Keyword, SystemConfig, CveItem,
    RegionalHazard, CloudOutage, User, Role, SavedReport, DailyBriefing,
    ExtractedIOC, MonitoredLocation, SolarWindsAlert, TimelineEvent,
    RegionalOutage, BgpAnomaly, GeoJsonCache, DailyThreatScore, ShiftLogEntry
)

LOCAL_TZ = ZoneInfo("America/Chicago")

# ==========================================
# 0. CORE UTILITIES & CACHED MAPPERS
# ==========================================

class DotDict(dict):
    """Utility class to allow dot.notation access to dicts for seamless UI integration."""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

def to_dotdict(obj):
    if not obj: return None
    return DotDict({c.name: getattr(obj, c.name) for c in obj.__table__.columns})

def to_dotdict_list(objs):
    return [to_dotdict(obj) for obj in objs]

@st.cache_data(ttl=300)
def get_cached_config():
    with SessionLocal() as db:
        config = db.query(SystemConfig).filter_by(is_active=True).first()
        if not config:
            config = SystemConfig(); db.add(config); db.commit(); db.refresh(config)
        return to_dotdict(config)

@st.cache_data(ttl=600, max_entries=1)
def get_cached_locations():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(MonitoredLocation).all())

@st.cache_data(ttl=120, max_entries=1)
def get_cached_geojson():
    """Reads the pre-fetched JSON geometry directly from the database."""
    spc, ar, oos = None, None, None
    with SessionLocal() as db:
        spc_rec = db.query(GeoJsonCache).filter_by(feed_name="spc").first()
        ar_rec = db.query(GeoJsonCache).filter_by(feed_name="nws_ar").first()
        oos_rec = db.query(GeoJsonCache).filter_by(feed_name="nws_oos").first()
        
        if spc_rec: spc = spc_rec.data
        if ar_rec: ar = ar_rec.data
        if oos_rec: oos = oos_rec.data
        
    return spc, ar, oos

@st.cache_data(ttl=86400, max_entries=1)
def get_ar_counties_mapping():
    """Fetches and caches the official US County boundaries, filtering for Arkansas (FIPS 05)."""
    try:
        url = "https://raw.githubusercontent.com/plotly/datasets/master/geojson-counties-fips.json"
        data = requests.get(url, timeout=10).json()
        ar_counties = {}
        for f in data.get("features", []):
            if f.get("properties", {}).get("STATE") == "05":
                name = f["properties"].get("NAME", "").lower()
                ar_counties[name] = f["geometry"]
        return ar_counties
    except Exception as e:
        print(f"Error fetching county GeoJSON: {e}")
        return {}

@st.cache_data(ttl=86400, max_entries=1)
def get_regional_counties_mapping():
    """Fetches official US County boundaries for the operational region using FIPS codes."""
    try:
        url = "https://raw.githubusercontent.com/plotly/datasets/master/geojson-counties-fips.json"
        data = requests.get(url, timeout=10).json()
        regional_counties = {}
        # FIPS: AR(05), LA(22), MO(29), MS(28), OK(40), TN(47), TX(48)
        target_states = ["05", "22", "29", "28", "40", "47", "48"]
        for f in data.get("features", []):
            state_fips = f.get("properties", {}).get("STATE")
            if state_fips in target_states:
                fips = f.get("id")
                name = f["properties"].get("NAME", "")
                regional_counties[fips] = {
                    "name": name, 
                    "state_fips": state_fips, 
                    "geometry": f["geometry"]
                }
        return regional_counties
    except Exception as e:
        print(f"Error fetching county GeoJSON: {e}")
        return {}

def get_all_site_types():
    from src.database import MonitoredLocation
    with SessionLocal() as db:
        types = db.query(MonitoredLocation.loc_type).distinct().all()
        return [t[0] for t in types if t[0]]

def set_cluster_dispatch(alert_ids, is_dispatched):
    from src.database import SolarWindsAlert
    with SessionLocal() as db:
        alerts = db.query(SolarWindsAlert).filter(SolarWindsAlert.id.in_(alert_ids)).all()
        for a in alerts:
            a.is_dispatched = is_dispatched
        db.commit()
        return True
      
def get_shift_logs(role_filter="All", start_date=None, end_date=None):
    with SessionLocal() as db:
        query = db.query(ShiftLogEntry)
        
        # If the filter is explicitly a role (e.g., 'analyst'), apply it. Otherwise, fetch all.
        if role_filter and role_filter != "All":
            query = query.filter(ShiftLogEntry.author_role == role_filter)
            
        if start_date:
            query = query.filter(ShiftLogEntry.created_at >= start_date)
        if end_date:
            query = query.filter(ShiftLogEntry.created_at < end_date + timedelta(days=1))
            
        logs = query.order_by(ShiftLogEntry.created_at.asc()).all()
        return to_dotdict_list(logs)

def save_shift_log(analyst, role, shift_period, content, custom_date=None):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    with SessionLocal() as db:
        new_log = ShiftLogEntry(
            analyst=analyst, 
            author_role=role, 
            shift_period=shift_period, 
            content=content
        )
        
        # If a custom date was selected (No Shift), override the timestamp
        if custom_date:
            # Combine the selected date with the current time so it orders nicely
            local_dt = datetime.combine(custom_date, datetime.now(ZoneInfo("America/Chicago")).time()).replace(tzinfo=ZoneInfo("America/Chicago"))
            utc_dt = local_dt.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            new_log.created_at = utc_dt
            new_log.shift_date = utc_dt
            
        db.add(new_log)
        db.commit()
        return True

def set_site_maintenance(site_name, is_maint, etr_date, reason):
    from src.database import SessionLocal, MonitoredLocation
    from datetime import datetime
    with SessionLocal() as db:
        loc = db.query(MonitoredLocation).filter_by(name=site_name).first()
        if loc:
            loc.under_maintenance = is_maint
            loc.maintenance_etr = datetime.combine(etr_date, datetime.min.time()) if etr_date else None
            loc.maintenance_reason = reason
            db.commit()
    get_cached_locations.clear()


# ==========================================
# 1. AUTHENTICATION & USER PROFILE
# ==========================================

def authenticate_user(username, password):
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            new_token = str(uuid.uuid4())
            user.session_token = new_token
            db.commit()
            return to_dotdict(user), new_token
        return None, None

def get_user_by_token(token):
    with SessionLocal() as db:
        return to_dotdict(db.query(User).filter(User.session_token == token).first())

def get_user_by_username(username):
    with SessionLocal() as db:
        return to_dotdict(db.query(User).filter(User.username == username).first())

def update_user_profile(username, full_name, job_title, contact_info, old_pwd, new_pwd):
    with SessionLocal() as db:
        u = db.query(User).filter(User.username == username).first()
        if not u: return False, "User not found."
        u.full_name = full_name
        u.job_title = job_title
        u.contact_info = contact_info
        if new_pwd:
            if bcrypt.checkpw(old_pwd.encode('utf-8'), u.password_hash.encode('utf-8')):
                u.password_hash = bcrypt.hashpw(new_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            else:
                return False, "Incorrect current password."
        db.commit()
        return True, "Updated!"

def logout_user(username):
    with SessionLocal() as db:
        u = db.query(User).filter(User.username == username).first()
        if u: u.session_token = None; db.commit()


# ==========================================
# 2. OPERATIONAL DASHBOARD & ARTICLE ACTIONS
# ==========================================

@st.cache_data(ttl=60)
def get_dashboard_metrics():
    with SessionLocal() as db:
        t = datetime.utcnow() - timedelta(days=1)
        return {
            "rss_count": db.query(Article).filter(Article.published_date >= t, Article.score >= 50).count(),
            "cve_count": db.query(CveItem).filter(CveItem.date_added >= t).count(),
            "hazard_count": db.query(RegionalHazard).filter(RegionalHazard.updated_at >= t).count(),
            "cloud_count": db.query(CloudOutage).filter(CloudOutage.updated_at >= t, CloudOutage.is_resolved == False).count()
        }

def get_pinned_articles():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Article).filter_by(is_pinned=True).order_by(Article.published_date.desc()).all())

def get_live_articles(limit=15):
    with SessionLocal() as db:
        t = datetime.utcnow() - timedelta(days=1)
        return to_dotdict_list(db.query(Article).filter(Article.published_date >= t, Article.score >= 50.0, Article.is_pinned == False).order_by(Article.score.desc()).limit(limit).all())

def toggle_pin(art_id):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a: a.is_pinned = not a.is_pinned; db.commit()

def boost_score(art_id, amount=15):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a: a.score = min(100.0, a.score + amount); db.commit()

def change_status(art_id, new_feedback):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a:
            if a.human_feedback == 0 and new_feedback in [1, 2] and a.keywords_found:
                for kw in a.keywords_found:
                    kdb = db.query(Keyword).filter_by(word=kw).first()
                    if kdb:
                        if new_feedback == 2: kdb.weight += 1
                        elif new_feedback == 1: kdb.weight = max(1, kdb.weight - 1)
            a.human_feedback = new_feedback
            db.commit()

def save_ai_bluf(art_id, bluf_text):
    with SessionLocal() as db:
        a = db.query(Article).filter_by(id=art_id).first()
        if a: a.ai_bluf = bluf_text; db.commit()


# ==========================================
# 3. EXECUTIVE DASHBOARD & CRIME INTELLIGENCE
# ==========================================

def get_recent_crimes(max_distance=None, grid_only=False, hours_back=168):
    """Queries the database for active perimeter incidents, with dynamic filtering for different dashboards."""
    from src.database import SessionLocal, CrimeIncident
    from datetime import datetime, timedelta
    
    with SessionLocal() as db:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours_back)
        query = db.query(CrimeIncident).filter(CrimeIncident.timestamp >= cutoff_time)
        
        if grid_only:
            # EXPANDED: Included Society crimes (Trespassing/Disturbances) to support FBI UCR taxonomy
            grid_threat_categories = [
                'Perimeter Breach/Vandalism', 
                'Violent Proximity Threat', 
                'Asset/Copper Theft Risk',
                'Trespassing/Suspicious Activity',
                'Public Disturbance/Narcotics'
            ]
            query = query.filter(CrimeIncident.category.in_(grid_threat_categories))
        
        if max_distance is not None:
            query = query.filter(CrimeIncident.distance_miles <= max_distance)
            
        crimes = query.order_by(CrimeIncident.timestamp.desc()).all()
        return [{
            "id": c.id, "category": c.category, "raw_title": c.raw_title,
            "timestamp": c.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "distance_miles": c.distance_miles, "severity": c.severity,
            "lat": c.lat, "lon": c.lon
        } for c in crimes]
        
def force_fetch_crime_data():
    """Triggers the crime worker logic manually from the UI."""
    try:
        from src.crime_worker import fetch_live_crimes
        fetch_live_crimes()
        dispatch_perimeter_crime_alerts() # <-- ADD THIS LINE
        return True
    except Exception as e:
        print(f"Manual fetch failed: {e}")
        return False

def get_historical_threat_scores(days=14):
    """Fetches historical daily scores to calculate the operational baseline."""
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(days=days)
        scores = db.query(DailyThreatScore).filter(DailyThreatScore.record_date >= cutoff).order_by(DailyThreatScore.record_date.asc()).all()
        return to_dotdict_list(scores)

def save_threat_score(c_pts, p_pts, c_base, p_base):
    """Saves the highest daily score to maintain an accurate deviation baseline."""
    with SessionLocal() as db:
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        record = db.query(DailyThreatScore).filter(DailyThreatScore.record_date == today).first()
        if record:
            record.cyber_points = max(record.cyber_points, c_pts)
            record.physical_points = max(record.physical_points, p_pts)
            record.cyber_baseline = c_base
            record.physical_baseline = p_base
        else:
            db.add(DailyThreatScore(record_date=today, cyber_points=c_pts, physical_points=p_pts, cyber_baseline=c_base, physical_baseline=p_base))
        db.commit()



def get_executive_grid_intel(active_warn_count, recent_crimes):
    """Synthesizes LIVE OSINT and telemetry using the CIS Alert Level Framework and FBI UCR Taxonomy."""
    from src.database import SessionLocal, Article, CveItem
    from datetime import datetime, timedelta
    
    sys_config = get_cached_config()
    history = get_historical_threat_scores(14)
    
    baseline_cyber = float(sys_config.baseline_override_cyber) if sys_config and sys_config.get('baseline_override_cyber', 0.0) > 0 else max(sum(h.cyber_points for h in history) / len(history), 20.0) if history else 20.0
    baseline_phys = float(sys_config.baseline_override_phys) if sys_config and sys_config.get('baseline_override_phys', 0.0) > 0 else max(sum(h.physical_points for h in history) / len(history), 25.0) if history else 25.0

    with SessionLocal() as db:
        t48 = datetime.utcnow() - timedelta(hours=48)
        
        # PULLING CYBER TELEMETRY (Articles, ICS, and CVEs)
        raw_cyber_articles = db.query(Article).filter(Article.published_date >= t48, Article.category.in_(['Cyber: Exploits & Vulns', 'Cyber: Malware & Threats', 'ICS/OT & SCADA', 'Cloud & IT Infra']), Article.score >= 50).order_by(Article.score.desc()).all()
        raw_ics_articles = db.query(Article).filter(Article.published_date >= t48).order_by(Article.published_date.desc()).all()
        raw_phys_articles = db.query(Article).filter(Article.published_date >= t48, Article.category.in_(['Physical Security', 'Severe Weather', 'Geopolitics & Policy']), Article.score >= 50).order_by(Article.score.desc()).all()
        
        recent_cves = db.query(CveItem).filter(CveItem.date_added >= t48).all()

        geopolitical_noise_words = ["troop", "missile", "election", "ballot", "warfare", "kinetic", "embassy"]
        threat_actors = ["volt typhoon", "sandworm", "dragos", "chernovite", "apt", "lazarus"]
        ransomware_kws = ["ransomware", "encryption", "extortion", "breach"]

        # --- 1. PROCESS CYBER ---
        pure_cyber_articles = []
        utility_keywords = ["grid", "power", "utility", "energy", "bes", "electric", "scada", "ics", "miso", "spp", "cooperative"]
        seen_cyber_titles = set() 
        
        for art in raw_cyber_articles:
            text_check = f"{art.title} {art.summary}".lower()
            if any(noise in text_check for noise in geopolitical_noise_words) and not any(k in text_check for k in ["infrastructure", "grid", "scada"]): 
                continue
            
            title_stub = art.title[:50].lower()
            if title_stub in seen_cyber_titles: continue
            seen_cyber_titles.add(title_stub)
            
            art.is_utility_related = any(ukw in text_check for ukw in utility_keywords)
            art.is_apt_related = any(apt in text_check for apt in threat_actors)
            art.is_ransomware = any(rw in text_check for rw in ransomware_kws)
            pure_cyber_articles.append(art)

        # --- 2. PROCESS PHYSICAL ---
        pure_phys_articles = []
        ar_keywords = ["arkansas", "little rock", "pulaski", "benton", "entergy", "aecc", "cooperative"]
        threat_keywords = ["terror", "attack", "grid", "substation", "sabotage", "vandalism", "infrastructure", "transformer", "sniper", "shoot", "explosive"]
        seen_phys_titles = set()
        
        for art in raw_phys_articles:
            text_check = f"{art.title} {art.summary}".lower()
            source_lower = art.source.lower() if art.source else ""
            if "cisa" in source_lower or "cyber" in text_check or "cve-" in text_check or "ics-cert" in source_lower: continue
                
            title_stub = art.title[:50].lower()
            if title_stub in seen_phys_titles: continue
            
            if any(kw in text_check for kw in ar_keywords) and any(kw in text_check for kw in threat_keywords): 
                seen_phys_titles.add(title_stub)
                pure_phys_articles.append(art)

        # --- 3. PROCESS ICS & KEV ---
        ics_advisories = []
        critical_vendors = ["SEL", "SCHWEITZER", "SIEMENS", "SCHNEIDER", "GE ", "ABB", "ROCKWELL", "EMERSON", "HONEYWELL", "OMRON"]
        for art in raw_ics_articles:
            source_upper = art.source.upper() if art.source else ""
            if "ICS" in source_upper or "CISA" in source_upper:
                is_critical = any(v in art.title.upper() for v in critical_vendors)
                is_kev = "KEV" in art.title.upper() or "EXPLOITED IN THE WILD" in art.title.upper() 
                ics_advisories.append({"title": art.title, "link": art.link, "published": art.published_date.strftime("%Y-%m-%d"), "is_critical": is_critical, "is_kev": is_kev})

    # ==========================================
    # CIS-ALIGNED & FBI UCR SCORING ALGORITHM
    # ==========================================
    
    # --- CYBER SCORING (MACROSCOPIC ENVIRONMENTAL ASSESSMENT) ---
    cyber_points = 0
    c, l, s, n = 2, 2, 3, 4 # Baseline Posture: Routine monitoring
    evidence_log = ["**Base Posture:** Routine monitoring. No active exploits targeting the perimeter. (C:2, L:2, S:3, N:4)"]

    # 1. Evaluate Exploits (KEVs and CVEs)
    kev_count = len([a for a in ics_advisories if a['is_kev']])
    if kev_count > 0:
        l = 5; s = 1
        cyber_points += 50
        evidence_log.append(f"🔴 **Lethality ↑(5), SysDef ↓(1):** {kev_count} Active KEVs (Known Exploited Vulnerabilities) detected bypassing patches.")
    elif len(recent_cves) > 10:
        l = max(l, 3); s = min(s, 2)
        cyber_points += 15
        evidence_log.append(f"🟠 **Lethality ↑(3), SysDef ↓(2):** Elevated vulnerability volume ({len(recent_cves)} recent CVEs) increasing exploit probability.")

    # 2. Evaluate ICS / SCADA targeting
    critical_ics = [a for a in ics_advisories if a['is_critical']]
    if critical_ics:
        c = 5
        cyber_points += 20
        evidence_log.append(f"🔴 **Criticality ↑(5):** {len(critical_ics)} ICS advisories explicitly targeting core OT/SCADA vendors (e.g., SEL, Siemens).")
    elif ics_advisories:
        c = max(c, 4)
        cyber_points += 10
        evidence_log.append(f"🟠 **Criticality ↑(4):** {len(ics_advisories)} general ICS advisories detected.")

    # 3. Evaluate General Threat Actor OSINT
    apt_count = sum(1 for a in pure_cyber_articles if getattr(a, 'is_apt_related', False))
    ran_count = sum(1 for a in pure_cyber_articles if getattr(a, 'is_ransomware', False))
    util_count = sum(1 for a in pure_cyber_articles if getattr(a, 'is_utility_related', False))

    if apt_count > 0 or ran_count > 0:
        l = max(l, 4)
        c = max(c, 4)
        cyber_points += (apt_count * 15) + (ran_count * 10)
        evidence_log.append(f"🟠 **Lethality ↑(4), Criticality ↑(4):** Active tracking of {apt_count} APT and {ran_count} Ransomware campaigns in industry OSINT.")

    if util_count > 0:
        c = 5
        cyber_points += (util_count * 10)
        evidence_log.append(f"🔴 **Criticality ↑(5):** {util_count} threats explicitly mention targeting Utility/Grid infrastructure.")

    # Final Calculation
    cis_cyber_score = (c + l) - (s + n)

    if cis_cyber_score >= 6: cyber_score = "RED"
    elif cis_cyber_score >= 3: cyber_score = "ORANGE"
    elif cis_cyber_score >= -1: cyber_score = "YELLOW"
    elif cis_cyber_score >= -4: cyber_score = "BLUE"
    else: cyber_score = "GREEN"
        
    cyber_brief = f"**CIS Aggregate Score: {cis_cyber_score}** | Synthesizing {len(pure_cyber_articles)} OSINT threats, {len(ics_advisories)} ICS alerts, and {len(recent_cves)} CVEs."
    
    # --- PHYSICAL SCORING (HIGH-CRIME URBAN ADJUSTMENT) ---
    physical_points = 0
    crimes_persons = []
    crimes_property = []
    crimes_society = []
    
    for c_item in recent_crimes:
        title_cat = (str(c_item.get('raw_title', '')) + " " + str(c_item.get('category', ''))).lower()
        if any(x in title_cat for x in ['assault', 'shoot', 'homicide', 'murder', 'violent', 'robbery', 'kidnap', 'battery', 'weapon', 'gun', 'stab']):
            c_item['fbi_category'] = "Crimes Against Persons"
            crimes_persons.append(c_item)
        elif any(x in title_cat for x in ['suspicious', 'disturbance', 'narcotic', 'drug', 'loiter', 'trespass']):
            c_item['fbi_category'] = "Crimes Against Society"
            crimes_society.append(c_item)
        elif any(x in title_cat for x in ['vandalism', 'theft', 'burglary', 'arson', 'property', 'copper', 'breach', 'damage', 'stolen']):
            c_item['fbi_category'] = "Crimes Against Property"
            crimes_property.append(c_item)
        else:
            c_item['fbi_category'] = "Crimes Against Society"
            crimes_society.append(c_item)
            
    physical_points += len(crimes_persons) * 10
    physical_points += len(crimes_property) * 5
    physical_points += len(crimes_society) * 1
    
    osint_phys_pts = min(sum([10 if art.score >= 80 else 2 for art in pure_phys_articles]), 20)
    physical_points += osint_phys_pts 
    physical_points += min((active_warn_count * 1.5), 15) 
    
    if physical_points >= (baseline_phys * 4.0) or len(crimes_persons) >= 5 or len(crimes_property) >= 10: physical_score = "RED"
    elif physical_points >= (baseline_phys * 3.0) or len(crimes_persons) >= 3 or len(crimes_property) >= 6: physical_score = "ORANGE"
    elif physical_points >= (baseline_phys * 1.8): physical_score = "YELLOW"
    elif physical_points >= (baseline_phys * 1.2): physical_score = "BLUE"
    else: physical_score = "GREEN"
        
    physical_brief = f"**HQ Perimeter (24h):** {len(recent_crimes)} total incidents. "
    physical_brief += f"({len(crimes_persons)} Persons, {len(crimes_property)} Property, {len(crimes_society)} Society). "
    if len(pure_phys_articles) > 0: physical_brief += f"🚨 OSINT: {len(pure_phys_articles)} local physical threats. "
    physical_brief += f"Weather footprint: {min(int(active_warn_count * 1.5), 20)} pts."

    # --- UNIFIED TIERING ---
    tier_weights = {"RED": 5, "ORANGE": 4, "YELLOW": 3, "BLUE": 2, "GREEN": 1}
    reverse_tiers = {5: "RED", 4: "ORANGE", 3: "YELLOW", 2: "BLUE", 1: "GREEN"}
    unified_risk = reverse_tiers[max(tier_weights[cyber_score], tier_weights[physical_score])]
    
    save_threat_score(cyber_points, physical_points, baseline_cyber, baseline_phys)
    
    return {
            "timestamp": datetime.now(LOCAL_TZ).strftime("%H:%M:%S %Z"),
            "unified_risk": unified_risk, "physical_score": physical_score, "physical_brief": physical_brief,
            "cyber_score": cyber_score, "cyber_brief": cyber_brief, "cis_cyber_score": cis_cyber_score,
            "recent_crimes": recent_crimes, "raw_cyber_articles": pure_cyber_articles, "raw_phys_articles": pure_phys_articles,
            "evidence_log": evidence_log,
            "current_cyber_pts": cyber_points, "current_phys_pts": physical_points,
            "baseline_cyber": baseline_cyber, "baseline_phys": baseline_phys
        }

def calculate_internal_cis_score(db_session):
    """
    Calculates an Internal CIS Threat Score based PURELY on OSINT correlations.
    Features a Tokenized Index, Double-Gatekeeper Context Filter for news noise, 
    and Bi-Directional Proximity Regex for ambiguous software names.
    """
    from src.database import HardwareAsset, SoftwareAsset, Article, CveItem
    from datetime import datetime, timedelta
    import re

    # Fetch raw assets from the database
    hw_assets_raw = db_session.query(HardwareAsset).all()
    sw_assets_raw = db_session.query(SoftwareAsset).all()
    
    # --- PRE-PROCESSING DEDUPLICATION ---
    # Eliminates redundant regex scanning and prevents duplicate rows in the UI
    hw_assets = list({hw.ip_address: hw for hw in hw_assets_raw if hw.ip_address}.values())
    sw_assets = list({sw.name.strip().lower(): sw for sw in sw_assets_raw if sw.name}.values())
    
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_articles = db_session.query(Article).filter(Article.published_date >= thirty_days_ago).all()
    recent_cves = db_session.query(CveItem).order_by(CveItem.date_added.desc()).limit(300).all()

    # ==========================================
    # PHASE 1: ENGINE RULES & SIGNATURE COMPILATION
    # ==========================================
    STOP_WORDS = {"and", "the", "for", "with", "system", "server", "software", "application", "platform", "tool", "device"}
    
    IGNORE_LIST = {
        "apps", "app store", "books", "calculator", "calendar", "canvas", "chess", "clock", 
        "computer", "connect", "console", "contacts", "customer support", "dashboard", 
        "docs", "facetime", "family", "file", "games", "home", "installer", "keynote", 
        "launchpad", "login", "mail", "maps", "messages", "music", "network", "news", 
        "notes", "numbers", "pages", "paint", "passwords", "phone", "photos", "podcasts", 
        "preferences", "preview", "print", "protector", "reader", "reminders", "screenshot", 
        "script editor", "settings", "siri", "slides", "software update", "stress", 
        "system settings", "terminal", "terminals", "time", "tips", "utilities", 
        "voice memos", "weather", "wish", "xbox"
    }

    # Nouns that are common English words but legitimately need tracking
    COMMON_NOUNS = {
        "apt", "npm", "yum", "pip", "brew", "mac", "windows", "linux", "android", 
        "zoom", "cups", "ssh", "ftp", "telnet", "sudo", "mount", "ufw", "make", 
        "tracker", "patch", "bash", "cron", "less", "office", "info", "youtube", "surface", "google"
    }

    # Double-Gatekeeper Classification
    STRONG_CYBER_KWS = {"vulnerability", "cve", "malware", "ransomware", "phishing", "zero-day", "0-day", "exploit", "rce", "ddos", "cyber", "hacked", "botnet"}
    WEAK_CYBER_KWS = {"breach", "patch", "flaw", "leak", "bug", "actor", "bypass"}
    
    # Regex string for the 100-character proximity checking
    PROXIMITY_KWS = "|".join(list(STRONG_CYBER_KWS) + ["flaw", "bug", "bypass", "patch"])

    ACRONYM_COLLISIONS = {
        "apt": re.compile(r'\b(?:advanced persistent threat|apt\s*(?:group|actor|campaign|hacker|attack|malware|botnet|linked))\b', re.IGNORECASE),
        "mac": re.compile(r'\b(?:mac\s*(?:address|spoofing|layer|protocol))\b', re.IGNORECASE),
        "surface": re.compile(r'\b(?:attack\s*surface|surface\s*area)\b', re.IGNORECASE),
        "office": re.compile(r'\b(?:office\s*of)\b', re.IGNORECASE)
    }

    def get_trigger_token(name):
        """Extracts the longest valid word to act as an O(1) dictionary gatekeeper."""
        words = re.findall(r'\b[a-z]{3,}\b', str(name).lower())
        valid = [w for w in words if w not in STOP_WORDS]
        return max(valid, key=len) if valid else None

    # Pre-compile Advanced Regex Signatures
    hw_search_maps = []
    for hw in hw_assets:
        vendor = str(hw.os_vendor or "").strip().lower()
        name = str(hw.operating_system or hw.os_product or "").strip().lower()
        version = str(hw.os_version or "").strip().lower()
        
        if not name or len(name) < 2 or name in IGNORE_LIST: continue
            
        trigger = get_trigger_token(name) or get_trigger_token(vendor)
        if not trigger: continue
            
        exact_patterns = []
        if name in COMMON_NOUNS:
            # PROXIMITY CHECK: Product must be within ~100 chars of a security keyword
            pat = rf'(?:\b(?:{PROXIMITY_KWS})\b.{{0,100}}\b{re.escape(name)}\b)|(?:\b{re.escape(name)}\b.{{0,100}}\b(?:{PROXIMITY_KWS})\b)'
            if version:
                pat = rf'(?:\b(?:{PROXIMITY_KWS})\b.{{0,100}}\b{re.escape(name)}\b.{{0,50}}\b{re.escape(version)}\b)'
            exact_patterns.append(re.compile(pat, re.IGNORECASE | re.DOTALL))
        else:
            if version:
                exact_patterns.append(re.compile(rf'\b{re.escape(name)}\b.{{0,50}}\b{re.escape(version)}\b', re.IGNORECASE | re.DOTALL))
                if vendor and vendor not in name:
                     exact_patterns.append(re.compile(rf'\b{re.escape(vendor)}\b.{{0,50}}\b{re.escape(version)}\b', re.IGNORECASE | re.DOTALL))
            else:
                exact_patterns.append(re.compile(rf'\b{re.escape(name)}\b', re.IGNORECASE | re.DOTALL))
            
        hw_search_maps.append({'obj': hw, 'is_hw': True, 'trigger': trigger, 'exact': exact_patterns, 'raw_name': name, 'matches': []})

    sw_search_maps = []
    for sw in sw_assets:
        name = str(sw.name or "").strip().lower()
        if not name or len(name) < 2 or name in IGNORE_LIST: continue
        
        trigger = get_trigger_token(name)
        if not trigger: continue
            
        exact_patterns = []
        if name in COMMON_NOUNS:
            # PROXIMITY CHECK
            pat = rf'(?:\b(?:{PROXIMITY_KWS})\b.{{0,100}}\b{re.escape(name)}\b)|(?:\b{re.escape(name)}\b.{{0,100}}\b(?:{PROXIMITY_KWS})\b)'
            exact_patterns.append(re.compile(pat, re.IGNORECASE | re.DOTALL))
        else:
            exact_patterns.append(re.compile(rf'\b{re.escape(name)}\b', re.IGNORECASE | re.DOTALL))
            
        sw_search_maps.append({'obj': sw, 'is_hw': False, 'trigger': trigger, 'exact': exact_patterns, 'raw_name': name, 'matches': []})

    all_assets = hw_search_maps + sw_search_maps

    # ==========================================
    # PHASE 2: INVERTED INDEXING (DOUBLE-GATEKEEPER)
    # ==========================================
    article_index = []
    for art in recent_articles:
        if art.score >= 40:
            text_blob = f"{art.title} {art.summary or ''}".lower()
            
            # Tokenize into a set for O(1) matching
            word_set = set(re.findall(r'\b[a-z0-9]{2,}\b', text_blob))
            
            strong_hits = len(word_set.intersection(STRONG_CYBER_KWS))
            weak_hits = len(word_set.intersection(WEAK_CYBER_KWS))
            
            # GATEKEEPER: An article must have 1 Strong OR 2 Weak keywords to proceed.
            # This instantly drops stories about "whales breaching" or "leaking pipes".
            if strong_hits > 0 or weak_hits >= 2:
                article_index.append({
                    'obj': art, 'text': text_blob, 'word_set': word_set,
                    'is_critical': art.score >= 80
                })

    cve_index = []
    for cve in recent_cves:
        text_blob = f"{cve.product} {cve.description}".lower()
        cve_index.append({
            'obj': cve, 'text': text_blob,
            'word_set': set(re.findall(r'\b[a-z0-9]{2,}\b', text_blob)),
            'vendor': str(cve.vendor).lower(), 'product': str(cve.product).lower()
        })

    # ==========================================
    # PHASE 3: O(1) BATCH CORRELATION SCAN
    # ==========================================
    
    # 1. SCAN ARTICLES
    for art in article_index:
        for asset_map in all_assets:
            if asset_map['trigger'] not in art['word_set']: continue
                
            collision_regex = ACRONYM_COLLISIONS.get(asset_map['raw_name'])
            if collision_regex and collision_regex.search(art['text']): continue

            for pat in asset_map['exact']:
                if pat.search(art['text']):
                    asset_map['matches'].append({"title": art['obj'].title, "is_critical": art['is_critical']})
                    break 

    # 2. SCAN CVE DATABASE
    for cve in cve_index:
        for asset_map in all_assets:
            if asset_map['trigger'] not in cve['word_set'] and asset_map['trigger'] not in cve['vendor']:
                continue

            matched = False
            
            if asset_map['is_hw']:
                hw = asset_map['obj']
                hw_vendor = str(hw.os_vendor or "").lower()
                hw_name = str(hw.operating_system or hw.os_product or "").lower()
                
                if (hw_vendor and hw_vendor in cve['vendor']) and (hw_name and hw_name in cve['product']):
                    asset_map['matches'].append({"title": f"CISA KEV: {cve['obj'].cve_id}", "is_critical": True})
                    continue

            collision_regex = ACRONYM_COLLISIONS.get(asset_map['raw_name'])
            if collision_regex and collision_regex.search(cve['text']): continue

            for pat in asset_map['exact']:
                if pat.search(cve['text']):
                    asset_map['matches'].append({"title": f"CISA KEV: {cve['obj'].cve_id}", "is_critical": True})
                    matched = True
                    break

    # ==========================================
    # PHASE 4: POSTURE RECONSTRUCTION
    # ==========================================
    annotated_sw = []
    annotated_hw = []
    
    global_osint_titles = set()
    global_critical_titles = set()

    for asset_map in all_assets:
        if not asset_map['matches']: continue
            
        unique_intel = {}
        for m in asset_map['matches']:
            unique_intel[m['title']] = m
            global_osint_titles.add(m['title'])
            if m['is_critical']: global_critical_titles.add(m['title'])
            
        if asset_map['is_hw']:
            hw = asset_map['obj']
            display_name = hw.asset_name if hw.asset_name else f"Device ({hw.ip_address})"
            os_display = f"{hw.operating_system or 'Unknown'} {hw.os_version or ''}".strip()
            
            annotated_hw.append({
                "Identifier": display_name,
                "IP Address": hw.ip_address,
                "OS": os_display,
                "OSINT Risk Score": min(len(unique_intel) * 25, 100),
                "OSINT Threat Matches": len(unique_intel),
                "Top Threat Reference": list(unique_intel.keys())[0]
            })
        else:
            sw = asset_map['obj']
            annotated_sw.append({
                "Software Name": sw.name,
                "OSINT Risk Score": min(len(unique_intel) * 25, 100),
                "Active OSINT Matches": len(unique_intel),
                "Top Threat Reference": list(unique_intel.keys())[0]
            })

    # ==========================================
    # PHASE 5: CIS RISK CALCULATION
    # ==========================================
    total_osint_hits = len(global_osint_titles)
    critical_osint_hits = len(global_critical_titles)

    lethality = 0
    if critical_osint_hits > 20: lethality += 5
    elif critical_osint_hits > 5: lethality += 3
    elif critical_osint_hits > 0: lethality += 2
    elif total_osint_hits > 10: lethality += 1

    total_assets = len(hw_assets) + len(sw_assets)
    assets_at_risk = len(annotated_hw) + len(annotated_sw)
    percent_at_risk = (assets_at_risk / total_assets) * 100 if total_assets > 0 else 0

    criticality = 0
    if percent_at_risk > 30: criticality += 4
    elif percent_at_risk > 15: criticality += 2
    elif percent_at_risk > 5: criticality += 1

    countermeasures = 4 
    
    raw_score = (criticality + lethality) - countermeasures
    final_score = max(-8, min(8, raw_score))

    if final_score >= 6: risk_level = "RED"
    elif final_score >= 3: risk_level = "ORANGE"
    elif final_score >= -1: risk_level = "YELLOW"
    elif final_score >= -4: risk_level = "BLUE"
    else: risk_level = "GREEN"

    return {
        "score": final_score,
        "risk_level": risk_level,
        "total_assets": total_assets,
        "total_hw_loaded": len(hw_assets),
        "total_sw_loaded": len(sw_assets),
        "total_osint_hits": total_osint_hits,
        "critical_osint_hits": critical_osint_hits,
        "hw_data": sorted(annotated_hw, key=lambda x: x["OSINT Risk Score"], reverse=True),
        "sw_data": sorted(annotated_sw, key=lambda x: x["OSINT Risk Score"], reverse=True)
    }
    
def generate_and_save_internal_risk_snapshot():
    """Runs the optimized CIS calculation and saves the snapshot to the DB for the dashboard."""
    from src.database import SessionLocal, InternalRiskSnapshot
    import json
    
    with SessionLocal() as db_session:
        # 1. Run the heavy calculation
        cis_data = calculate_internal_cis_score(db_session)
        
        # 2. Package it into a database snapshot
        snapshot = InternalRiskSnapshot(
            score=cis_data['score'],
            risk_level=cis_data['risk_level'],
            total_assets=cis_data['total_assets'],
            total_osint_hits=cis_data['total_osint_hits'],
            critical_osint_hits=cis_data['critical_osint_hits'],
            hw_data_json=json.dumps(cis_data['hw_data']),
            sw_data_json=json.dumps(cis_data['sw_data'])
        )
        
        # 3. Save to database
        db_session.add(snapshot)
        db_session.commit()

import re

def generate_unified_brief_email_html(report_time, markdown_content):
    # 1. Safely extract risk levels from the AI's generated text
    def extract_risk(keyword, text):
        match = re.search(rf'(?i){keyword}.{{0,50}}?\b(RED|ORANGE|YELLOW|BLUE|GREEN)\b', text)
        return match.group(1).upper() if match else "UNKNOWN"
        
    global_risk = extract_risk("Global", markdown_content)
    internal_risk = extract_risk("Internal", markdown_content)
    overall_risk = extract_risk("Overall", markdown_content)
    
    # Fallbacks just in case the LLM worded it slightly differently
    if overall_risk == "UNKNOWN": overall_risk = global_risk if global_risk != "UNKNOWN" else "YELLOW"
    if global_risk == "UNKNOWN": global_risk = overall_risk
    if internal_risk == "UNKNOWN": internal_risk = overall_risk
    
    color_map = {
        "GREEN": "#28a745", "BLUE": "#007bff", 
        "YELLOW": "#ffc107", "ORANGE": "#fd7e14", 
        "RED": "#dc3545", "UNKNOWN": "#6c757d"
    }
    
    overall_color = color_map.get(overall_risk, "#6c757d")
    global_color = color_map.get(global_risk, "#6c757d")
    internal_color = color_map.get(internal_risk, "#6c757d")

    def native_md_to_html(text):
        # Base formatting
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#2c3e50; margin-bottom:5px; margin-top:15px;">\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#2980b9; margin-bottom:5px; border-bottom:1px solid #eee; margin-top:20px;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#2c3e50;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#3498db; text-decoration:none;">\1</a>', text)
        text = re.sub(r'^\* (.*?)$', r'&#8226; \1<br>', text, flags=re.MULTILINE)
        text = re.sub(r'^- (.*?)$', r'&#8226; \1<br>', text, flags=re.MULTILINE)
        text = text.replace('\n', '<br>').replace('<br><br><h', '<br><h')
        
        # EMOJI STRIPPING REMOVED: Emojis will now pass through natively
        return text

    raw_html = native_md_to_html(markdown_content)
    
    # 2. Build the visual table banners (Outlook Safe)
    banners_html = f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 15px;">
        <tr>
            <td style="text-align: center; padding: 20px; background-color: #f8f9fa; border: 1px solid #eeeeee; border-radius: 4px;">
                <h3 style="margin: 0; color: #333333; text-transform: uppercase; font-size: 15px; letter-spacing: 1px;">Unified Threat Posture</h3>
                <div style="margin-top: 15px; padding: 10px 25px; background-color: {overall_color}; color: #ffffff; display: inline-block; font-size: 22px; font-weight: bold; border-radius: 4px;">
                    {overall_risk}
                </div>
            </td>
        </tr>
    </table>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 25px;">
        <tr>
            <td width="48%" style="text-align: center; padding: 15px; background-color: #f8f9fa; border: 1px solid #eeeeee; border-radius: 4px;">
                <h3 style="margin: 0; color: #333333; text-transform: uppercase; font-size: 13px; letter-spacing: 1px;">Global Risk</h3>
                <div style="margin-top: 10px; padding: 8px 20px; background-color: {global_color}; color: #ffffff; display: inline-block; font-size: 16px; font-weight: bold; border-radius: 4px;">
                    {global_risk}
                </div>
            </td>
            <td width="4%"></td> <td width="48%" style="text-align: center; padding: 15px; background-color: #f8f9fa; border: 1px solid #eeeeee; border-radius: 4px;">
                <h3 style="margin: 0; color: #333333; text-transform: uppercase; font-size: 13px; letter-spacing: 1px;">Internal Risk</h3>
                <div style="margin-top: 10px; padding: 8px 20px; background-color: {internal_color}; color: #ffffff; display: inline-block; font-size: 16px; font-weight: bold; border-radius: 4px;">
                    {internal_risk}
                </div>
            </td>
        </tr>
    </table>
    """

    # 3. Assemble Final HTML
    formatted_html = f"""
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 900px; margin: 0 auto; color: #333; line-height: 1.5;">
        <div style="background-color: #fcfcfc; padding: 20px; border-radius: 6px; border-left: 4px solid {overall_color}; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h2 style="color: #2c3e50; margin-top: 0; text-transform: uppercase;">Executive Unified Risk Brief</h2>
            <p style="color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px;"><strong>Generated:</strong> {report_time}</p>
            
            {banners_html}
            
            <div style="font-size: 14px; background-color: #ffffff; padding: 20px; border-radius: 4px; border: 1px solid #eee;">
                {raw_html}
            </div>
            
            <div style="margin-top: 25px; text-align: center; font-size: 11px; color: #999999;">
                This is an automated intelligence briefing generated by the internal NOC AIOps system.<br>Please do not reply directly to this email.
            </div>
        </div>
    </div>
    """
    return formatted_html
    
def generate_outlook_html_report(intel):
    """Generates the static fallback report if the LLM generation fails or is bypassed."""
    color_map = {
        "GREEN": "#28a745", 
        "BLUE": "#007bff", 
        "YELLOW": "#ffc107", 
        "ORANGE": "#fd7e14", 
        "RED": "#dc3545"
    }
    badge_color = color_map.get(intel["unified_risk"].upper(), "#28a745")
    
    name_map = {
        "GREEN": "GREEN (LOW)", "BLUE": "BLUE (GUARDED)", 
        "YELLOW": "YELLOW (ELEVATED)", "ORANGE": "ORANGE (HIGH)", "RED": "RED (SEVERE)"
    }
    display_risk = name_map.get(intel["unified_risk"].upper(), "UNKNOWN")
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; max-width: 600px; margin: 0 auto; border: 1px solid #dddddd; border-radius: 8px;">
            <tr>
                <td style="padding: 20px; background-color: #0f172a; border-radius: 8px 8px 0 0; text-align: center;">
                    <h2 style="color: #ffffff; margin: 0;">BES Threat Intelligence Summary</h2>
                    <p style="color: #94a3b8; margin: 5px 0 0 0; font-size: 12px;">Generated: {intel['timestamp']}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 30px 20px; text-align: center;">
                    <h3 style="margin: 0; color: #333333; text-transform: uppercase;">Unified Threat Posture</h3>
                    <div style="margin-top: 15px; padding: 10px 20px; background-color: {badge_color}; color: #ffffff; display: inline-block; font-size: 24px; font-weight: bold; border-radius: 4px;">
                        {display_risk}
                    </div>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px;">
                    <h4 style="color: #0056b3; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">⚡ Physical & Crime Intelligence</h4>
                    <p style="color: #444444; line-height: 1.6; font-size: 14px;"><strong>Status: {name_map.get(intel['physical_score'], 'UNKNOWN')}</strong><br/>{intel['physical_brief']}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px; padding-top: 0;">
                    <h4 style="color: #0056b3; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">🛡️ Cyber & SCADA Intelligence</h4>
                    <p style="color: #444444; line-height: 1.6; font-size: 14px;"><strong>Status: {name_map.get(intel['cyber_score'], 'UNKNOWN')}</strong><br/>{intel['cyber_brief']}</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    return html

def send_executive_report(recipient_email, intel, sys_config):
    try:
        html_body = generate_outlook_html_report(intel)
        from src.mailer import send_alert_email
        success, msg = send_alert_email(
            subject=f"Grid Threat Intelligence Update - Posture: {intel['unified_risk']}", 
            body=html_body, recipient_override=recipient_email, is_html=True
        )
        return success, msg
    except Exception as e: return False, f"Email Dispatch Failed: {e}"


# ==========================================
# 4. DAILY FUSION REPORT
# ==========================================

def get_all_daily_briefings():
    with SessionLocal() as db:
        reports = db.query(DailyBriefing).order_by(DailyBriefing.report_date.desc()).all()
        return to_dotdict_list(reports)

def get_daily_briefing(target_date):
    with SessionLocal() as db:
        return to_dotdict(db.query(DailyBriefing).filter(DailyBriefing.report_date == target_date).first())

def save_daily_briefing(target_date, content):
    with SessionLocal() as db:
        b = db.query(DailyBriefing).filter(DailyBriefing.report_date == target_date).first()
        if b:
            b.content = content
            b.created_at = datetime.utcnow()
        else:
            db.add(DailyBriefing(report_date=target_date, content=content))
        db.commit()

def generate_daily_report_email_html(report_date, markdown_content):
    def native_md_to_html(text):
        text = re.sub(r'^### (.*?)$', r'<h3 style="color:#2c3e50; margin-bottom:5px;">\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.*?)$', r'<h2 style="color:#2980b9; margin-bottom:5px; border-bottom:1px solid #eee;">\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^# (.*?)$', r'<h1 style="color:#2c3e50;">\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color:#3498db; text-decoration:none;">\1</a>', text)
        text = re.sub(r'^\* (.*?)$', r'&#8226; \1<br>', text, flags=re.MULTILINE)
        text = re.sub(r'^- (.*?)$', r'&#8226; \1<br>', text, flags=re.MULTILINE)
        text = text.replace('\n', '<br>').replace('<br><br><h', '<br><h')
        return text

    raw_html = native_md_to_html(markdown_content)
    
    formatted_html = f"""
    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 900px; margin: 0 auto; color: #333; line-height: 1.5;">
        <div style="background-color: #fcfcfc; padding: 20px; border-radius: 6px; border-left: 4px solid #d9534f; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <h2 style="color: #2c3e50; margin-top: 0;">📰 NOC Daily Fusion Report</h2>
            <p style="color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px;"><strong>Date:</strong> {report_date}</p>
            <div style="font-size: 14px; background-color: #ffffff; padding: 15px; border-radius: 4px; border: 1px solid #eee;">
                {raw_html}
            </div>
        </div>
    </div>
    """
    return formatted_html


# ==========================================
# 5. THREAT TELEMETRY (CISA, Cloud, NWS, Regional Grid)
# ==========================================

def get_paginated_articles(feed_type, cat_filter, page, page_size, search_term=None, min_score=0):
    with SessionLocal() as db:
        q = db.query(Article)
        if feed_type == "pinned": q = q.filter_by(is_pinned=True)
        elif feed_type == "live": q = q.filter(Article.score >= 50.0, Article.is_pinned == False)
        elif feed_type == "low": q = q.filter(Article.score < 50.0, Article.is_pinned == False)

        if cat_filter != "All": q = q.filter_by(category=cat_filter)
        if search_term: q = q.filter(Article.title.ilike(f"%{search_term}%") | Article.summary.ilike(f"%{search_term}%"))
        q = q.filter(Article.score >= min_score)

        total_items = q.count()
        total_pages = max(1, (total_items + page_size - 1) // page_size)
        page = min(max(1, page), total_pages)

        if feed_type in ["pinned", "live", "low"]: q = q.order_by(Article.published_date.desc())
        else: q = q.order_by(Article.score.desc(), Article.published_date.desc())

        items = q.offset((page - 1) * page_size).limit(page_size).all()
        return to_dotdict_list(items), total_items, total_pages, page

def get_cves(limit=15, days_back=None):
    with SessionLocal() as db:
        q = db.query(CveItem)
        if days_back: q = q.filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=days_back))
        return to_dotdict_list(q.order_by(CveItem.date_added.desc()).limit(limit).all())

def get_cloud_outages(active_only=True, limit=None):
    with SessionLocal() as db:
        q = db.query(CloudOutage)
        if active_only: q = q.filter_by(is_resolved=False)
        q = q.order_by(CloudOutage.updated_at.desc())
        if limit: q = q.limit(limit)
        return to_dotdict_list(q.all())

@st.cache_data(ttl=900, max_entries=1)
def get_active_wildfires():
    try:
        url = "https://services3.arcgis.com/T4QMspbfLg3qTGWY/arcgis/rest/services/WFIGS_Incident_Locations/FeatureServer/0/query"
        cutoff_date = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
        states = "('US-AR', 'US-MO', 'US-TN', 'US-MS', 'US-LA', 'US-TX', 'US-OK')"
        params = {
            "where": f"POOState IN {states} AND IncidentTypeCategory = 'WF' AND (PercentContained < 100 OR PercentContained IS NULL) AND FireDiscoveryDateTime >= '{cutoff_date}'", 
            "outFields": "IncidentName,IncidentSize,PercentContained,POOState,IncidentTypeCategory", "f": "geojson", "returnGeometry": "true"
        }
        resp = requests.get(url, params=params, timeout=10)
        
        if resp.status_code == 200:
            active_fires = []
            for f in resp.json().get("features", []):
                props, geom = f.get("properties", {}), f.get("geometry", {})
                if not geom or "coordinates" not in geom: continue
                
                inc_name = str(props.get("IncidentName", "Unnamed")).upper()
                contained_val = 0 if props.get("PercentContained") is None else props.get("PercentContained")
                size = props.get("IncidentSize", 0)
                
                if props.get("IncidentTypeCategory", "") != "WF": continue
                if " RX" in inc_name or inc_name.startswith("RX ") or "PRESCRIBED" in inc_name: continue
                if contained_val >= 100 or not size or size <= 0.1: continue
                if re.search(r'(201\d|202[0-4]|/\d{2}$)', inc_name): continue
                
                active_fires.append({
                    "name": props.get("IncidentName", "Unnamed"), "state": props.get("POOState", "Unknown").replace("US-", ""),
                    "acres": round(size, 2), "contained": contained_val, "lon": geom["coordinates"][0], "lat": geom["coordinates"][1],
                    "color": [220, 20, 60, 230]
                })
            return active_fires
        return []
    except: return []

def dispatch_perimeter_crime_alerts():
    """Checks for un-dispatched high severity crimes within 0.4 miles and sends an SMS-friendly alert."""
    from src.database import SessionLocal, CrimeIncident
    import os
    from zoneinfo import ZoneInfo
    
    # Reads the recipient(s) from your .env file. Supports comma-separated lists!
    alert_sms = os.getenv("CRIME_ALERT_SMS")
    if not alert_sms:
        # Fallback to the old env var
        alert_sms = os.getenv("CRIME_ALERT_EMAIL")
        if not alert_sms:
            return False, "CRIME_ALERT_SMS not set in environment variables."
            
    # Clean up the string just in case there are weird spaces in the .env file
    alert_sms = ", ".join([email.strip() for email in alert_sms.split(",")])
        
    with SessionLocal() as db:
        # Find all un-dispatched crimes within 0.4 miles that are categorized as High severity
        new_crimes = db.query(CrimeIncident).filter(
            CrimeIncident.distance_miles <= 0.4,
            CrimeIncident.severity.ilike('%High%'),
            CrimeIncident.is_alert_dispatched == False
        ).all()
        
        if not new_crimes:
            return True, "No new alerts to dispatch."
            
        for crime in new_crimes:
            # Standard Google Maps query link (mobile SMS click-through)
            gmaps_link = f"https://www.google.com/maps?q={crime.lat},{crime.lon}"
            
            # Formatted to be slightly shorter for SMS reading
            local_time = crime.timestamp.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("America/Chicago")).strftime('%m/%d %I:%M %p')
            
            # Concise Plain Text format for SMS
            sms_body = (
                f"🚨 PERIMETER ALERT 🚨\n"
                f"{crime.raw_title}\n"
                f"Dist: {crime.distance_miles} mi\n"
                f"Time: {local_time}\n"
                f"Map: {gmaps_link}"
            )
            
            from src.mailer import send_alert_email
            success, msg = send_alert_email(
                subject=f"Crime Alert: {crime.distance_miles}mi",
                body=sms_body,
                recipient_override=alert_sms,  # Passes the cleaned, comma-separated list
                is_html=False 
            )
            
            # If the SMS sent successfully, mark it as dispatched so we never send it again
            if success:
                crime.is_alert_dispatched = True
                
        db.commit()
    return True, "Perimeter SMS alerts processed."

def get_hazards(limit=15, hours_back=None):
    with SessionLocal() as db:
        q = db.query(RegionalHazard)
        if hours_back: q = q.filter(RegionalHazard.updated_at >= datetime.utcnow() - timedelta(hours=hours_back))
        return to_dotdict_list(q.order_by(RegionalHazard.updated_at.desc()).limit(limit).all())

def process_nws_alerts(data, selected_events, is_oos=False):
    map_diagnostics = []
    warn_geo = {"type": "FeatureCollection", "features": []}
    watch_geo = {"type": "FeatureCollection", "features": []}
    zonewide_alerts = []

    if not data or "features" not in data:
        map_diagnostics.append(f"⚠️ {'OOS' if is_oos else 'AR'} data empty or missing 'features'.")
        return warn_geo, watch_geo, zonewide_alerts, map_diagnostics

    regional_counties_geom = get_regional_counties_mapping()

    for idx, f_raw in enumerate(data.get("features", [])):
        geom, props = f_raw.get("geometry"), f_raw.get("properties", {})
        event_type, headline = props.get("event", "Unknown"), props.get("headline", "")

        if event_type not in selected_events: continue
        prefix = "[OOS]" if is_oos else "[AR]"
        geometries_to_process = []

        if geom: 
            geometries_to_process.append(geom)
        else:
            # THE ENTERPRISE FIX: Strict FIPS Code Matching
            geocode_dict = props.get("geocode", {})
            same_codes = geocode_dict.get("SAME", [])
            
            for same_code in same_codes:
                # NWS SAME codes are 6 chars (e.g., 005001). Extract last 5 for standard FIPS.
                fips = same_code[-5:]
                if fips in regional_counties_geom:
                    state_fips = regional_counties_geom[fips]["state_fips"]
                    
                    # Strict Border Enforcement: 
                    # AR feed gets only AR counties. OOS feed gets only non-AR counties.
                    if (not is_oos and state_fips == "05") or (is_oos and state_fips != "05"):
                        geometries_to_process.append(regional_counties_geom[fips]["geometry"])
                    
            if not geometries_to_process:
                zonewide_alerts.append({"Event": f"{prefix} {event_type}", "Affected Area": props.get("areaDesc", "Unknown"), "Details": headline})
                continue

        for g in geometries_to_process:
            try:
                poly_shape = shape(g)
                is_severe = "Warning" in event_type or "Emergency" in event_type
                severity = "Warning" if is_severe else "Watch/Advisory"

                micro_feature = {"type": "Feature", "geometry": g, "properties": {"info": f"{prefix} {event_type}", "severity": severity, "shapely_obj": poly_shape}}

                if is_severe:
                    micro_feature['properties']['fill_color'] = [139, 0, 0, 60] if is_oos else [255, 0, 0, 60]
                    micro_feature['properties']['line_color'] = [139, 0, 0, 255] if is_oos else [255, 0, 0, 255]
                    warn_geo["features"].append(micro_feature)
                else:
                    micro_feature['properties']['fill_color'] = [204, 119, 34, 60] if is_oos else [255, 165, 0, 60]
                    micro_feature['properties']['line_color'] = [204, 119, 34, 255] if is_oos else [255, 165, 0, 255]
                    watch_geo["features"].append(micro_feature)
            except Exception as e: continue
            
    return warn_geo, watch_geo, zonewide_alerts, map_diagnostics

def get_weather_alerts_log(ar_data, oos_data, selected_events):
    all_alert_details = []
    for geo_ds, is_oos in [(ar_data, False), (oos_data, True)]:
        if geo_ds and "features" in geo_ds:
            for f in geo_ds["features"]:
                props = f.get("properties", {})
                event = props.get("event", "Unknown")
                if event not in selected_events: continue
                
                prefix = "[OOS]" if is_oos else "[AR]"
                all_alert_details.append({
                    "Event": f"{prefix} {event}", "Severity": props.get("severity", "Unknown"), "Certainty": props.get("certainty", "Unknown"),
                    "Headline": props.get("headline", "No headline available."), "Affected Area": props.get("areaDesc", "Unknown Area"),
                    "Effective": props.get("effective", "N/A"), "Expires": props.get("expires", "N/A"),
                    "Description": props.get("description", "No detailed description provided by NWS."),
                    "Instructions": props.get("instruction", "No explicit instructions provided.")
                })
    return all_alert_details

def calculate_site_intersections(map_df, master_polygons):
    toggled_affected_sites, master_affected_sites = [], []
    if map_df.empty or not master_polygons: return toggled_affected_sites, master_affected_sites

    # 1. Pre-calculate bounding boxes once to avoid recalculating in the loop
    for p in master_polygons:
        p['bounds'] = p['shape'].bounds # Returns (minx, miny, maxx, maxy)

    for _, row in map_df.iterrows():
        if pd.notna(row['Lat']) and pd.notna(row['Lon']):
            lat, lon = row['Lat'], row['Lon']
            site_pt = Point(lon, lat)
            act_toggled = []
            
            for p in master_polygons:
                minx, miny, maxx, maxy = p['bounds']
                
                # 2. LIGHTNING FAST Bounding Box Pre-Check (Pure float math)
                if minx <= lon <= maxx and miny <= lat <= maxy:
                    
                    # 3. Only execute heavy Shapely CPU math if the point is inside the rough square!
                    if site_pt.within(p["shape"]):
                        
                        # Always add to the Master List for Executive Analytics
                        master_affected_sites.append({
                            "Monitored Site": row['Name'], 
                            "Type": row['Type'], 
                            "District": row.get('District', 'Central'),
                            "Priority": row['Priority'], 
                            "Hazard": p["event"], 
                            "Severity": p["severity"]
                        })
                        
                        # Only add to the Map/Toggled list if the UI switch is turned on
                        if p.get("is_toggled", False):
                            act_toggled.append(p["event"])
                            
            if act_toggled: 
                toggled_affected_sites.append({
                    "Monitored Site": row['Name'], 
                    "District": row.get('District', 'Central'),
                    "Facility Type": row['Type'], 
                    "Priority": row['Priority'], 
                    "Intersecting Hazards": ", ".join(list(set(act_toggled)))
                })
                
    return toggled_affected_sites, master_affected_sites

def get_infrastructure_analytics(map_df, master_affected_sites):
    """Generates real-time analytics by reading the live geospatial intersection array."""
    payload = {
        "total_sites": len(map_df),
        "at_risk_sites": 0, "highest_risk": "None", 
        "spc_distribution": pd.DataFrame(), "nws_distribution": pd.DataFrame(),
        "type_distribution": pd.DataFrame(), "district_distribution": pd.DataFrame(), 
        "priority_risk_matrix": pd.DataFrame(), "type_risk_matrix": pd.DataFrame(), "district_risk_matrix": pd.DataFrame()
    }
    
    spc_risks = {}
    nws_alerts = {}
    
    severity_rank = {
        "HIGH": 100, "MDT": 90, "ENH": 80, "SLGT": 70, "MRGL": 60, "TSTM": 50,
        "Extreme": 95, "Severe": 85, "Moderate": 75, "Minor": 65,
        "WARNING": 85, "WATCH": 75, "ADVISORY": 65, "STATEMENT": 55, "NONE": 0
    }
    
    if master_affected_sites:
        sites_df = pd.DataFrame(master_affected_sites)
        
        def rank_hazard(hazard_str):
            score = 0
            for key, val in severity_rank.items():
                if key.upper() in str(hazard_str).upper() and val > score: score = val
            return score if score > 0 else 10 

        sites_df['Risk_Score'] = sites_df['Hazard'].apply(rank_hazard)
        worst_risks_df = sites_df.sort_values('Risk_Score', ascending=False).drop_duplicates(subset=['Monitored Site']).copy()
        
        for _, r in sites_df.iterrows():
            site = r['Monitored Site']
            haz = r['Hazard'].upper()
            if "SPC:" in haz:
                risk_lvl = "TSTM"
                for lvl in ["HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM"]:
                    if lvl in haz: risk_lvl = lvl; break
                if site not in spc_risks or severity_rank.get(risk_lvl, 0) > severity_rank.get(spc_risks.get(site, "NONE"), 0):
                    spc_risks[site] = risk_lvl
            else:
                alert_type = "STATEMENT"
                if "WARNING" in haz: alert_type = "WARNING"
                elif "WATCH" in haz: alert_type = "WATCH"
                elif "ADVISORY" in haz: alert_type = "ADVISORY"
                if site not in nws_alerts or severity_rank.get(alert_type, 0) > severity_rank.get(nws_alerts.get(site, "NONE"), 0):
                    nws_alerts[site] = alert_type

        payload["at_risk_sites"] = len(worst_risks_df)
        
        def get_primary_label(hazard_str):
            s = str(hazard_str).upper()
            if "HIGH" in s: return "HIGH"
            if "MDT" in s: return "MDT"
            if "ENH" in s: return "ENH"
            if "SLGT" in s: return "SLGT"
            if "MRGL" in s: return "MRGL"
            if "TSTM" in s: return "TSTM"
            if "WARNING" in s: return "WARNING"
            if "WATCH" in s: return "WATCH"
            if "ADVISORY" in s: return "ADVISORY"
            return "OTHER"
            
        payload["highest_risk"] = get_primary_label(worst_risks_df.iloc[0]['Hazard']) if not worst_risks_df.empty else "None"
        
        payload["type_distribution"] = worst_risks_df['Type'].value_counts().reset_index().rename(columns={'Type': 'Facility Type', 'count': 'Count'}).set_index('Facility Type')
        payload["district_distribution"] = worst_risks_df['District'].value_counts().reset_index().rename(columns={'District': 'District', 'count': 'Count'}).set_index('District')
        
        worst_risks_df['Risk_Label'] = worst_risks_df['Hazard'].apply(get_primary_label)
        payload["priority_risk_matrix"] = pd.crosstab(worst_risks_df['Priority'], worst_risks_df['Risk_Label'])
        payload["type_risk_matrix"] = pd.crosstab(worst_risks_df['Type'], worst_risks_df['Risk_Label'])
        payload["district_risk_matrix"] = pd.crosstab(worst_risks_df['District'], worst_risks_df['Risk_Label'])
    
    # Map SPC and NWS back to ALL sites to get complete totals
    spc_list = []
    nws_list = []
    for _, row in map_df.iterrows():
        site = row['Name']
        spc_list.append(spc_risks.get(site, "None"))
        nws_list.append(nws_alerts.get(site, "None"))
        
    map_df_copy = map_df.copy()
    map_df_copy['Live_SPC'] = spc_list
    map_df_copy['Live_NWS'] = nws_list
    
    risk_order = ["HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "None"]
    map_df_copy['Live_SPC'] = pd.Categorical(map_df_copy['Live_SPC'], categories=risk_order, ordered=True)
    payload["spc_distribution"] = map_df_copy['Live_SPC'].value_counts().reset_index().rename(columns={'Live_SPC': 'SPC Risk'})
    
    nws_order = ["WARNING", "WATCH", "ADVISORY", "STATEMENT", "None"]
    map_df_copy['Live_NWS'] = pd.Categorical(map_df_copy['Live_NWS'], categories=nws_order, ordered=True)
    payload["nws_distribution"] = map_df_copy['Live_NWS'].value_counts().reset_index().rename(columns={'Live_NWS': 'NWS Alert'})

    return payload


def generate_hazard_sitrep_html(analytics_df):
    p1_count = len(analytics_df[analytics_df['Priority'] == 1]['Monitored Site'].unique())
    rows_html = ""
    for _, r in analytics_df.sort_values(by=['Priority', 'Monitored Site']).iterrows():
        p_style = "background-color: #d9534f; color: white;" if r['Priority'] == 1 else "background-color: #f0ad4e; color: white;" if r['Priority'] == 2 else "background-color: #6c757d; color: white;"
        rows_html += f"<tr><td style='padding: 12px; border-bottom: 1px solid #e0e0e0;'>{r['Monitored Site']}</td><td style='padding: 12px; border-bottom: 1px solid #e0e0e0;'>{r['Facility Type']}</td><td style='padding: 12px; border-bottom: 1px solid #e0e0e0; text-align: center;'><span style='{p_style} padding: 4px 8px; border-radius: 4px; font-weight: bold;'>P{r['Priority']}</span></td><td style='padding: 12px; border-bottom: 1px solid #e0e0e0; color: #d9534f; font-weight: bold;'>{r['Hazard']}</td></tr>"

    return f"""
    <!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
    <body style="margin: 0; padding: 0; background-color: #f4f7f6;">
    <div style="font-family: Arial, sans-serif; max-width: 850px; margin: 0 auto; background-color: #f4f7f6; padding: 10px;">
        <div style="background-color: #ffffff; border-radius: 8px; border-top: 6px solid #d9534f; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="padding: 20px; border-bottom: 1px solid #eeeeee; background-color: #fafafa;">
                <h2 style="margin: 0; color: #333333; font-size: 22px;">SEVERE WEATHER INFRASTRUCTURE IMPACT</h2>
                <p style="margin: 5px 0 0 0; color: #777777; font-size: 13px;">Automated NOC Broadcast | {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M %Z')}</p>
            </div>
            <div style="padding: 20px;">
                <h3 style="color: #2c3e50; font-size: 18px; border-bottom: 2px solid #e9ecef; padding-bottom: 8px;">Executive Overview</h3>
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="display: inline-block; width: 45%; min-width: 200px; padding: 15px; background-color: #f8f9fa; border-radius: 6px; border: 1px solid #e9ecef; margin: 5px;">
                        <div style="font-size: 28px; font-weight: bold; color: #333333;">{len(analytics_df['Monitored Site'].unique())}</div>
                        <div style="font-size: 12px; color: #6c757d;">Total Sites Impacted</div>
                    </div>
                    <div style="display: inline-block; width: 45%; min-width: 200px; padding: 15px; background-color: #fff5f5; border-radius: 6px; border: 1px solid #ffe3e3; margin: 5px;">
                        <div style="font-size: 28px; font-weight: bold; color: #d9534f;">{p1_count}</div>
                        <div style="font-size: 12px; color: #d9534f;">Critical (P1) Exposures</div>
                    </div>
                </div>
                <h3 style="color: #2c3e50; font-size: 18px; border-bottom: 2px solid #e9ecef; padding-bottom: 8px;">Detailed Impact Matrix</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px; text-align: left;">
                    <thead><tr style="background-color: #343a40; color: #ffffff;"><th style="padding: 10px;">Monitored Site</th><th style="padding: 10px;">Type</th><th style="padding: 10px; text-align: center;">Priority</th><th style="padding: 10px;">Hazard</th></tr></thead>
                    <tbody>{rows_html}</tbody>
                </table>
            </div>
        </div>
    </div></body></html>""".replace("\n", "")

def import_locations(data):
    with SessionLocal() as db:
        added = 0
        existing_names = {l[0] for l in db.query(MonitoredLocation.name).all()}
        for item in data:
            name, lat, lon = item.get("name"), item.get("lat"), item.get("lon")
            if name and lat is not None and lon is not None and name not in existing_names:
                # ADDED DISTRICT HERE
                db.add(MonitoredLocation(name=name, lat=float(lat), lon=float(lon), loc_type=item.get("type", "General"), district=item.get("district", "Central"), priority=int(item.get("priority", 3))))
                existing_names.add(name); added += 1
        db.commit()
    get_cached_locations.clear()
    return added

def update_locations(edited_df):
    with SessionLocal() as db:
        for _, row in edited_df.iterrows():
            db_loc = db.query(MonitoredLocation).filter_by(id=row['id']).first()
            if db_loc:
                # ADDED DISTRICT HERE
                db_loc.name, db_loc.loc_type, db_loc.district, db_loc.priority, db_loc.lat, db_loc.lon = row['Name'], row['Type'], row['District'], row['Priority'], row['Lat'], row['Lon']
        db.commit()
    get_cached_locations.clear()

def nuke_crime_data():
    """Wipes all records from Little Rock crime table."""
    from src.database import CrimeIncident, JmsCrimeIncident
    with SessionLocal() as db:
        try:
            # Delete rows from both tables and combine the count
            lr_deleted = db.query(CrimeIncident).delete()
            db.commit()
            return True, (lr_deleted + jms_deleted)
        except Exception as e:
            db.rollback()
            return False, str(e)


# ==========================================
# 6. THREAT HUNTING & IOCs
# ==========================================

def get_iocs(days_back=3):
    with SessionLocal() as db:
        t = datetime.utcnow() - timedelta(days=days_back)
        iocs = db.query(ExtractedIOC).filter(ExtractedIOC.detected_at >= t).order_by(ExtractedIOC.detected_at.desc()).all()
        result = []
        for ioc in iocs:
            art = db.query(Article).filter_by(id=ioc.article_id).first()
            result.append({
                "Type": ioc.indicator_type, "Indicator": ioc.indicator_value,
                "Context": ioc.context if hasattr(ioc, 'context') else "Context unavailable.",
                "Detected": ioc.detected_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S'),
                "Source Article": art.link if art else "Unknown"
            })
        return result

def search_articles_for_hunting(target, days_back):
    with SessionLocal() as db:
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        arts = db.query(Article).filter(Article.published_date >= cutoff, (Article.title.ilike(f"%{target}%") | Article.summary.ilike(f"%{target}%"))).limit(30).all()
        return to_dotdict_list(arts)

def get_osint_pivot_link(ioc_type, value):
    if ioc_type in ["SHA256", "MD5", "SHA1"]: return f"https://www.virustotal.com/gui/file/{value}"
    elif ioc_type == "IPv4": return f"https://www.shodan.io/host/{value}"
    elif ioc_type == "Domain": return f"https://www.virustotal.com/gui/domain/{value}"
    elif ioc_type == "CVE": return f"https://nvd.nist.gov/vuln/detail/{value}"
    elif ioc_type == "MITRE ATT&CK": return f"https://attack.mitre.org/techniques/{value.replace('.', '/')}"
    return None


# ==========================================
# 7. AIOps RCA (Root Cause Analysis)
# ==========================================

def get_aiops_dashboard_data():
    with SessionLocal() as db:
        alerts = db.query(SolarWindsAlert).filter(SolarWindsAlert.status != 'Resolved', SolarWindsAlert.is_correlated == False).all()
        events = db.query(TimelineEvent).order_by(TimelineEvent.timestamp.desc()).limit(50).all()
        grid = db.query(RegionalOutage).filter_by(is_resolved=False).all()
        # Removed aliases from the return
        return to_dotdict_list(alerts), to_dotdict_list(events), to_dotdict_list(grid)

def clear_timeline_events():
    with SessionLocal() as db: db.query(TimelineEvent).delete(); db.commit()

def nuke_active_alerts():
    with SessionLocal() as db: db.query(SolarWindsAlert).delete(); db.commit()

def resolve_alert(alert_id, node_name):
    with SessionLocal() as db:
        a = db.query(SolarWindsAlert).filter_by(id=alert_id).first()
        if a:
            a.status = 'Resolved'
            db.add(TimelineEvent(source="User", event_type="Resolution", message=f"🟢 Operator manually resolved {node_name}"))
            db.commit()

def acknowledge_cluster(alert_ids):
    with SessionLocal() as db:
        for aid in alert_ids:
            a = db.query(SolarWindsAlert).filter_by(id=aid).first()
            if a: a.is_correlated = True
        db.commit()

def save_alias(alias_id, new_mapped_name):
    with SessionLocal() as db:
        a = db.query(NodeAlias).filter_by(id=alias_id).first()
        if a:
            a.mapped_location_name, a.is_verified, a.confidence_score = new_mapped_name, True, 100.0
            db.commit()

def generate_global_sitrep(sys_config_dict):
    """Generates the Global Correlation SitRep using the Enterprise AIOps Engine."""
    from src.database import RegionalHazard, CloudOutage, BgpAnomaly, SolarWindsAlert
    from src.aiops_engine import EnterpriseAIOpsEngine
    
    with SessionLocal() as db:
        # FIX 1: Capture ALL active alerts, not just strings matching 'Down'
        raw_alerts = db.query(SolarWindsAlert).filter(
            SolarWindsAlert.is_correlated == False, 
            SolarWindsAlert.status != 'Resolved'
        ).all()
        
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_weather = db.query(RegionalHazard).all()
        active_bgp = db.query(BgpAnomaly).filter_by(is_resolved=False).all()

        report = f"### 🌍 Global Situation Report (SitRep)\n\n"
        report += f"**Active Infrastructure Alerts:** {len(raw_alerts)} | "
        report += f"**Cloud Outages:** {len(active_clouds)} | "
        report += f"**Grid/Weather Anomalies:** {len(active_weather)}\n\n"

        if not raw_alerts:
            report += "✅ **Grid Operational:** No active un-correlated infrastructure alerts detected.\n"
            return report

        # FIX 2: Route the alerts through our Supreme AI Engine!
        ai_engine = EnterpriseAIOpsEngine(db)
        incidents = ai_engine.analyze_and_cluster(raw_alerts)

        report += "#### 🧠 Deterministic Causal Clusters\n"
        
        for site, data in incidents.items():
            cause, score, priority, evidence, blast, p0, cascade = ai_engine.calculate_root_cause(
                site, data, active_weather, active_clouds, active_bgp
            )
            
            icon = "🔴" if score >= 80 else "🟠" if score >= 50 else "🟡"
            
            report += f"**{icon} {site} [{priority}]**\n"
            report += f"- **Impact:** {len(data['alerts'])} nodes offline across {len(data['domains_affected'])} topology layers ({blast}).\n"
            report += f"- **Patient Zero:** `{p0}` (Cascade Delay: {cascade})\n"
            report += f"- **Root Cause:** {cause}\n\n"

        # AI Summary Generator
        if sys_config_dict and sys_config_dict.get('is_active'):
            from src.llm import call_llm
            sys_prompt = "You are an elite NOC AIOps Engine. Summarize the following deterministic IT SitRep into a technical 2-sentence executive summary. Do not use pleasantries."
            ai_summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": report}], sys_config_dict, temperature=0.1)

            if ai_summary and "⚠️" not in ai_summary:
                report = f"### 🤖 AI Executive Summary\n> {ai_summary}\n\n---\n\n" + report

        return report
def generate_rca_ticket_text(site, data, priority, patient_zero, root_cause):
    pz_obj = data.get('patient_zero')
    trigger_time = pz_obj.received_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%m/%d/%Y %I:%M %p %Z') if pz_obj and pz_obj.received_at else "Unknown Time"
    
    ticket_text = f"Automated Comms Outage\n\n{site} - Trouble\n\nA communications failure occurred on {trigger_time} and did not recover. This is affecting SCADA connectivity. IT is requesting a technician onsite to investigate.\n\n"
    ticket_text += "="*50 + f"\nPRIORITY: {priority}\nSITE/LOCATION: {site}\nSUSPECTED ORIGIN (PATIENT ZERO): {patient_zero}\nTOTAL NODES AFFECTED: {len(data.get('alerts', []))}\n" + "="*50 + f"\n\nROOT CAUSE ANALYSIS:\n" + "-"*20 + f"\n{root_cause}\n\nAFFECTED INFRASTRUCTURE DETAILS:\n" + "-"*30 + "\n"
    
    for idx, alert in enumerate(data.get('alerts', []), 1):
        rcv_time = alert.received_at.strftime('%Y-%m-%d %H:%M:%S UTC') if alert.received_at else "Unknown"
        ticket_text += f"[{idx}] Node: {alert.node_name} | IP: {alert.ip_address} | Type: {alert.device_type}\n    Status: {alert.status} | Severity: {alert.severity}\n    Event Category: {alert.event_category}\n    Logged Time: {rcv_time}\n"
        if alert.details: ticket_text += f"    Details: {alert.details.strip()}\n"
        ticket_text += "\n"
    return ticket_text


# ==========================================
# 8. REPORT CENTER
# ==========================================

def search_articles(query, limit):
    with SessionLocal() as db:
        q = db.query(Article)
        if query: q = q.filter(Article.title.ilike(f"%{query}%") | Article.summary.ilike(f"%{query}%"))
        return to_dotdict_list(q.order_by(Article.published_date.desc()).limit(limit).all())

def get_saved_reports():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(SavedReport).order_by(SavedReport.created_at.desc()).all())

def save_custom_report(title, author, content):
    with SessionLocal() as db:
        db.add(SavedReport(title=title, author=author, content=content))
        db.commit()


# ==========================================
# 9. SETTINGS & ADMINISTRATION
# ==========================================

@st.cache_data(ttl=300)
def get_all_roles():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Role).all())

def create_role(name, allowed_pages, allowed_actions, allowed_site_types=None):
    if allowed_site_types is None: allowed_site_types = []
    with SessionLocal() as db:
        if db.query(Role).filter(Role.name == name).first(): return False
        db.add(Role(name=name, allowed_pages=allowed_pages, allowed_actions=allowed_actions, allowed_site_types=allowed_site_types))
        db.commit()
        return True

def update_role(name, allowed_pages, allowed_actions, allowed_site_types=None):
    if allowed_site_types is None: allowed_site_types = []
    with SessionLocal() as db:
        role = db.query(Role).filter(Role.name == name).first()
        if role:
            role.allowed_pages, role.allowed_actions, role.allowed_site_types = allowed_pages, allowed_actions, allowed_site_types
            db.commit()
            return True
        return False

def create_user(username, password, role):
    with SessionLocal() as db:
        if db.query(User).filter(User.username == username).first(): return False
        db.add(User(username=username, password_hash=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), role=role))
        db.commit()
        return True

def force_reset_pwd(username, new_password):
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.password_hash, user.session_token = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), None
            db.commit()
            return True
        return False

def update_user_role(username, new_role):
    with SessionLocal() as db:
        u = db.query(User).filter_by(username=username).first()
        if u:
            u.role, u.session_token = new_role, None
            db.commit()

def save_global_config(data):
    with SessionLocal() as db:
        config = db.query(SystemConfig).first()
        if not config: config = SystemConfig(); db.add(config)
        for key, value in data.items(): setattr(config, key, value)
        db.commit()
    get_cached_config.clear()

def add_bulk_keywords(raw_text):
    with SessionLocal() as db:
        for line in raw_text.split('\n'):
            if line.strip():
                parts = line.split(',')
                word = parts[0].strip().lower()
                weight = int(parts[1].strip()) if len(parts) > 1 and parts[1].strip().isdigit() else 10
                if not db.query(Keyword).filter_by(word=word).first(): db.add(Keyword(word=word, weight=weight))
        db.commit()

def add_bulk_feeds(raw_text):
    with SessionLocal() as db:
        for line in raw_text.split('\n'):
            if line.strip():
                parts = line.split(',')
                url, name = parts[0].strip(), parts[1].strip() if len(parts) > 1 else "New Feed"
                if not db.query(FeedSource).filter_by(url=url).first(): db.add(FeedSource(url=url, name=name))
        db.commit()

def delete_record(model_name, record_id):
    models = {"Keyword": Keyword, "FeedSource": FeedSource, "User": User, "Role": Role, "SavedReport": SavedReport}
    with SessionLocal() as db:
        record = db.query(models[model_name]).filter_by(id=record_id).first()
        if record: db.delete(record); db.commit()

def get_admin_lists():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Keyword).order_by(Keyword.weight.desc()).all()), to_dotdict_list(db.query(FeedSource).all()), to_dotdict_list(db.query(User).all())

def get_ml_counts():
    with SessionLocal() as db:
        pos, neg = db.query(Article).filter(Article.human_feedback == 2).count(), db.query(Article).filter(Article.human_feedback == 1).count()
        return pos, neg, pos + neg

def get_backup_data():
    with SessionLocal() as db:
        return {
            "keywords": [{"word": k.word, "weight": k.weight} for k in db.query(Keyword).all()],
            "feeds": [{"url": f.url, "name": f.name} for f in db.query(FeedSource).all()],
            "locations": [{"name": l.name, "lat": l.lat, "lon": l.lon, "type": l.loc_type, "prio": l.priority} for l in db.query(MonitoredLocation).all()],
            "aliases": [{"pattern": a.node_pattern, "mapped": a.mapped_location_name, "conf": a.confidence_score, "ver": a.is_verified} for a in db.query(NodeAlias).all()]
        }

def restore_backup_data(data):
    added = {"kw": 0, "feeds": 0, "locs": 0, "alias": 0}
    with SessionLocal() as db:
        for kw in data.get("keywords", []):
            if not db.query(Keyword).filter_by(word=kw["word"]).first(): db.add(Keyword(word=kw["word"], weight=kw["weight"])); added["kw"] += 1
        for f in data.get("feeds", []):
            if not db.query(FeedSource).filter_by(url=f["url"]).first(): db.add(FeedSource(url=f["url"], name=f["name"])); added["feeds"] += 1
        for l in data.get("locations", []):
            if not db.query(MonitoredLocation).filter_by(name=l["name"]).first(): db.add(MonitoredLocation(name=l["name"], lat=l["lat"], lon=l["lon"], loc_type=l.get("type", "General"), priority=l.get("prio", 3))); added["locs"] += 1
        for a in data.get("aliases", []):
            if not db.query(NodeAlias).filter_by(node_pattern=a["pattern"]).first(): db.add(NodeAlias(node_pattern=a["pattern"], mapped_location_name=a["mapped"], confidence_score=a["conf"], is_verified=a["ver"])); added["alias"] += 1
        db.commit()
    return added

def recategorize_all_articles():
    from src.categorizer import categorize_text
    with SessionLocal() as db:
        # Fetch ALL articles, not just "General"
        arts = db.query(Article).all()
        count = 0
        
        for a in arts:
            # Run the article through the new scoring matrix
            new_cat = categorize_text(f"{a.title} {a.summary}")
            
            # Only update and count if the category actually changed
            if a.category != new_cat: 
                a.category = new_cat
                count += 1
                
        db.commit()
        return count

def nuke_tables(model_names):
    models_map = {"CloudOutage": CloudOutage, "MonitoredLocation": MonitoredLocation, "Article": Article, "ExtractedIOC": ExtractedIOC, "FeedSource": FeedSource, "Keyword": Keyword}
    with SessionLocal() as db:
        for name in model_names:
            if name in models_map: db.query(models_map[name]).delete(synchronize_session=False)
        db.commit()

def truncate_db_table(table_query):
    if "monitored_locations" in table_query.lower():
        nuke_tables(["MonitoredLocation"])
        get_cached_locations.clear()

def nuke_weather_data():
    """Wipes all records from Regional Hazards and the GeoJSON cache, and resets location risks."""
    from src.database import RegionalHazard, GeoJsonCache, MonitoredLocation
    with SessionLocal() as db:
        try:
            # Delete all active NWS alerts and the massive map JSON payloads
            haz_deleted = db.query(RegionalHazard).delete()
            geo_deleted = db.query(GeoJsonCache).delete()
            
            # Reset all facility SPC risk levels back to "None"
            db.query(MonitoredLocation).update({MonitoredLocation.current_spc_risk: "None"})
            
            db.commit()
            
            # Clear the Streamlit RAM cache so the map instantly goes blank
            get_cached_geojson.clear()
            
            return True, (haz_deleted + geo_deleted)
        except Exception as e:
            db.rollback()
            return False, str(e)


# ==========================================
# 10. UI MAP GENERATION ENGINE (PyDeck)
# ==========================================

def build_crime_map_layers(df_crimes):
    """Builds the PyDeck layers and view state for the Crime Intelligence map."""
    import pydeck as pdk
    import pandas as pd
    
    # Campus Boundary Polygon
    campus_boundary = [
        [-92.325885, 34.678235], [-92.326196, 34.675942], [-92.324565, 34.675888],
        [-92.324636, 34.674884], [-92.32406120583306, 34.67474187702983],
        [-92.3238084241607, 34.67452124894587], [-92.32373734260989, 34.674349128685705],
        [-92.32376809344501, 34.673623615079805], [-92.32351586802497, 34.67332173763069],
        [-92.3220985004393, 34.67324489899573], [-92.32198879648926, 34.673705411555176],
        [-92.32118128553886, 34.673676198116304], [-92.32110794479303, 34.67493955311931],
        [-92.32189171929349, 34.67527638012709], [-92.32180319236035, 34.67672422178229],
        [-92.3216835943636, 34.678465279952555], [-92.32589779219425, 34.67833455896807],
        [-92.325885, 34.678235]
    ]
    polygon_df = pd.DataFrame([{"coordinates": campus_boundary}])
    
    layers = [
        pdk.Layer(
            "PolygonLayer", polygon_df, get_polygon="coordinates", 
            get_fill_color=[0, 255, 100, 45], get_line_color=[0, 255, 100, 255], 
            line_width_min_pixels=2, stroked=True, filled=True
        ),
        pdk.Layer(
            "ScatterplotLayer", data=df_crimes, get_position="[lon, lat]", 
            get_radius=50, get_fill_color=[255, 69, 0, 220], 
            pickable=True, auto_highlight=True
        )
    ]
    view_state = pdk.ViewState(latitude=34.6755, longitude=-92.3235, zoom=15.5, pitch=45)
    return layers, view_state

def build_aiops_map_layers(alerts, locs):
    """Builds the PyDeck layers and view state for the AIOps RCA board."""
    import pydeck as pdk
    import pandas as pd
    
    map_data, alert_pulses = [], []
    alert_mapped = [a.mapped_location for a in alerts]
    
    for l in locs:
        c = alert_mapped.count(l.name)
        map_data.append({
            "name": l.name, "lat": l.lat, "lon": l.lon, 
            "color": [255, 0, 0, 200] if c > 0 else [0, 255, 0, 160]
        })
        if c > 0:
            alert_pulses.append({"lat": l.lat, "lon": l.lon, "radius": 4000 + (c * 2500)})

    layers = [
        pdk.Layer("ScatterplotLayer", pd.DataFrame(map_data), get_position="[lon, lat]", get_fill_color="color", get_radius=1800, pickable=True)
    ]
    if alert_pulses:
        layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(alert_pulses), get_position="[lon, lat]", get_fill_color=[255, 0, 0, 40], get_radius="radius"))
        
    view_state = pdk.ViewState(latitude=34.8, longitude=-92.2, zoom=6.0, pitch=0)
    return layers, view_state

@st.cache_data(ttl=150, max_entries=2)
def _precompute_geo_matrix(spc_data, ar_data, oos_data, selected_events_tuple, map_df):
    """Heavy Math Engine: Parses JSON, builds Shapely objects, and calculates all intersections ONCE."""
    import pandas as pd
    from shapely.geometry import Point, shape
    
    master_polygons = []
    map_diagnostics = []
    
    # 1. Process SPC
    spc_micro = {"type": "FeatureCollection", "features": []}
    if spc_data:
        color_map = {"TSTM": [192, 232, 192, 100], "MRGL": [124, 205, 124, 150], "SLGT": [246, 246, 123, 150], "ENH": [230, 153, 0, 150], "MDT": [255, 0, 0, 150], "HIGH": [255, 0, 255, 150]}
        for f in spc_data.get('features', []):
            label = f.get('properties', {}).get('LABEL', '')
            try:
                poly_shape = shape(f.get("geometry"))
                master_polygons.append({"event": f"SPC: {label}", "shape": poly_shape, "severity": "Watch"})
                spc_micro["features"].append({
                    "type": "Feature", "geometry": f.get("geometry"),
                    "properties": {"fill_color": color_map.get(label, [0, 0, 0, 0]), "line_color": [0, 0, 0, 255], "info": f"SPC Risk: {label}"}
                })
            except Exception: pass

    # 2. Process NWS
    ar_warn, ar_watch, _, ar_logs = process_nws_alerts(ar_data, selected_events_tuple, is_oos=False)
    oos_warn, oos_watch, _, oos_logs = process_nws_alerts(oos_data, selected_events_tuple, is_oos=True)
    map_diagnostics.extend(ar_logs + oos_logs)

    for geo_dict in [ar_warn, ar_watch, oos_warn, oos_watch]:
        for f in geo_dict["features"]:
            master_polygons.append({
                "event": f['properties']['info'], 
                "shape": f['properties']['shapely_obj'], 
                "severity": f['properties']['severity']
            })
            # MUST remove shapely_obj so Streamlit can serialize the dict into RAM cache
            f['properties'].pop('shapely_obj', None)

    # 3. Process Fire Risk
    ar_fire_geo = {"type": "FeatureCollection", "features": []}
    regional_counties = get_regional_counties_mapping()
    fire_fips_to_process = {}
    for geo_ds in [ar_data, oos_data]:
        if geo_ds:
            for f in geo_ds.get('features', []):
                event = f.get('properties', {}).get('event', '')
                if any(k in event for k in ["Fire Weather", "Red Flag", "Fire Warning", "Extreme Fire"]):
                    severity = "Extreme (Burn Ban / Red Flag)" if "Red Flag" in event or "Warning" in event else "High (Fire Weather Watch)"
                    fill_color = [139, 0, 0, 160] if "Red Flag" in event or "Warning" in event else [255, 140, 0, 120]
                    line_color = [255, 0, 0, 255] if "Red Flag" in event or "Warning" in event else [255, 140, 0, 255]
                    
                    same_codes = f.get('properties', {}).get('geocode', {}).get('SAME', [])
                    for same_code in same_codes:
                        fips = same_code[-5:]
                        if fips in regional_counties and regional_counties[fips]["state_fips"] == "05":
                            fire_fips_to_process[fips] = {"severity": severity, "color": fill_color, "line_color": line_color, "event": event, "county_name": regional_counties[fips]["name"]}

    for fips, info in fire_fips_to_process.items():
        geom = regional_counties[fips]["geometry"]
        ar_fire_geo["features"].append({"type": "Feature", "geometry": geom, "properties": {"info": f"{info['county_name'].title()} County\nRisk Level: {info['severity']}\nNWS Alert: {info['event']}", "fill_color": info["color"], "line_color": info["line_color"]}})
        try:
            master_polygons.append({"event": f"Wildfire Risk: {info['event']}", "shape": shape(geom), "severity": "High"})
        except: pass

    # 4. Process Active Wildfires
    nifc_data = get_active_wildfires()
    if nifc_data:
        for row in nifc_data:
            try:
                fire_poly = Point(row['lon'], row['lat']).buffer(0.03)
                master_polygons.append({"event": f"Active Wildfire: {row['name']}", "shape": fire_poly, "severity": "High"})
            except: pass

    # 5. Execute CPU-Heavy Bounding Box Math ONCE
    _, master_affected_sites = calculate_site_intersections(map_df, master_polygons)
    
    return {
        "spc_micro": spc_micro,
        "ar_warn": ar_warn, "ar_watch": ar_watch,
        "oos_warn": oos_warn, "oos_watch": oos_watch,
        "ar_fire_geo": ar_fire_geo,
        "nifc_data": nifc_data,
        "master_affected_sites": master_affected_sites,
        "map_diagnostics": map_diagnostics
    }

def compile_regional_grid_map(map_df, spc_data, ar_data, oos_data, selected_events, toggles):
    """Lightweight UI Compiler: Reads from RAM cache and filters strings natively."""
    import pydeck as pdk
    import pandas as pd
    import uuid
    
    layer_id = str(uuid.uuid4())[:6]
    
    # Extract fully pre-computed dictionaries from RAM (0% CPU impact on UI Toggle)
    cache = _precompute_geo_matrix(spc_data, ar_data, oos_data, tuple(selected_events), map_df)
    
    layers = []
    show_radar = toggles.get("radar", True)
    show_spc = toggles.get("spc", True)
    show_warn = toggles.get("warn", True)
    show_watch = toggles.get("watch", True)
    show_oos = toggles.get("oos", True)
    show_fire_risk = toggles.get("fire_risk", False)
    show_active_wildfires = toggles.get("active_wildfires", False)
    
    # 1. RADAR
    if show_radar:
        layers.append(pdk.Layer("BitmapLayer", image="https://mesonet.agron.iastate.edu/data/gis/images/4326/USCOMP/n0q_0.png", bounds=[-126.0, 21.0, -66.0, 50.0], opacity=0.55, pickable=False))
        
    # 2. Add Pre-computed Layers instantly based on toggles
    if show_spc and cache["spc_micro"]["features"]: 
        layers.append(pdk.Layer("GeoJsonLayer", cache["spc_micro"], id=f"spc_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=1))
        
    if show_warn and cache["ar_warn"]["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=cache["ar_warn"], id=f"ar_warn_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    if show_watch and cache["ar_watch"]["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=cache["ar_watch"], id=f"ar_watch_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    
    if show_oos and cache["oos_warn"]["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=cache["oos_warn"], id=f"oos_warn_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    if show_oos and cache["oos_watch"]["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=cache["oos_watch"], id=f"oos_watch_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    
    if show_fire_risk and cache["ar_fire_geo"]["features"]:
        layers.append(pdk.Layer("GeoJsonLayer", data=cache["ar_fire_geo"], id=f"fire_risk_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
        
    if show_active_wildfires and cache["nifc_data"]:
        df_fires = pd.DataFrame(cache["nifc_data"])
        df_fires['info'] = "🔥 " + df_fires['name'] + " (" + df_fires['state'] + ")\nAcres: " + df_fires['acres'].astype(str) + "\nContainment: " + df_fires['contained'].astype(str) + "%"
        layers.append(pdk.Layer("ScatterplotLayer", data=df_fires, id=f"nifc_{layer_id}", pickable=True, opacity=0.9, stroked=True, filled=True, get_radius="1500 + (acres * 15)", radius_min_pixels=5, radius_max_pixels=35, line_width_min_pixels=1, get_position="[lon, lat]", get_fill_color="color", get_line_color=[0, 0, 0, 255]))

    # Facility Sites
    if not map_df.empty:
        layers.append(pdk.Layer("ScatterplotLayer", map_df, pickable=True, opacity=0.9, stroked=True, filled=True, radius_scale=6, radius_min_pixels=4, radius_max_pixels=12, line_width_min_pixels=1, get_position="[Lon, Lat]", get_fill_color=[255, 255, 255], get_line_color=[0, 0, 0]))

    # 3. Filter the pre-computed intersection matrix for the UI dataframe
    toggled_affected_sites_dict = {}
    for site in cache["master_affected_sites"]:
        hazard = site["Hazard"]
        is_visible = False
        
        if "SPC:" in hazard and show_spc: is_visible = True
        elif "Wildfire Risk:" in hazard and show_fire_risk: is_visible = True
        elif "Active Wildfire:" in hazard and show_active_wildfires: is_visible = True
        elif "[OOS]" in hazard and show_oos: is_visible = True
        elif "[AR]" in hazard:
            if site["Severity"] == "Warning" and show_warn: is_visible = True
            elif site["Severity"] == "Watch/Advisory" and show_watch: is_visible = True
            
        if is_visible:
            name = site["Monitored Site"]
            if name not in toggled_affected_sites_dict:
                toggled_affected_sites_dict[name] = {
                    "Monitored Site": name, 
                    "District": site["District"], 
                    "Facility Type": site["Type"], 
                    "Priority": site["Priority"], 
                    "Hazards": set()
                }
            toggled_affected_sites_dict[name]["Hazards"].add(hazard)
            
    toggled_affected_sites = []
    for v in toggled_affected_sites_dict.values():
        v["Intersecting Hazards"] = ", ".join(list(v["Hazards"]))
        v.pop("Hazards")
        toggled_affected_sites.append(v)
        
    view_state = pdk.ViewState(latitude=34.8, longitude=-92.2, zoom=5.5, pitch=0)

    return layers, view_state, cache["map_diagnostics"], toggled_affected_sites, cache["master_affected_sites"]
