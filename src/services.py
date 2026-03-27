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
    RegionalOutage, BgpAnomaly, GeoJsonCache # <--- ADD THIS
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

def get_recent_crimes(max_distance=None):
    """Queries the database for active 168-hour perimeter incidents, with optional radius filtering."""
    from src.database import SessionLocal, CrimeIncident
    from datetime import datetime, timedelta
    
    with SessionLocal() as db:
        forty_eight_hours_ago = datetime.utcnow() - timedelta(hours=168)
        
        # Base query for the last 7 days
        query = db.query(CrimeIncident).filter(CrimeIncident.timestamp >= forty_eight_hours_ago)
        
        # Apply the radius filter if one is provided
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
        return True
    except Exception as e:
        print(f"Manual fetch failed: {e}")
        return False

def get_executive_grid_intel(active_warn_count, recent_crimes):
    """Synthesizes LIVE OSINT telemetry, Local Perimeter Crime, and DB-native ICS-CERT using a Weighted Point Algorithm."""
    with SessionLocal() as db:
        t48 = datetime.utcnow() - timedelta(hours=48)
        t14 = datetime.utcnow() - timedelta(days=14)
        
        # Raw Data Fetch
        raw_cyber_articles = db.query(Article).filter(Article.published_date >= t48, Article.category.in_(['Cyber: Exploits & Vulns', 'Cyber: Malware & Threats', 'ICS/OT & SCADA', 'Cloud & IT Infra']), Article.score >= 50).order_by(Article.score.desc()).all()
        raw_ics_articles = db.query(Article).filter(Article.published_date >= t14).order_by(Article.published_date.desc()).all()
        raw_phys_articles = db.query(Article).filter(Article.published_date >= t48, Article.category.in_(['Physical Security', 'Severe Weather', 'Geopolitics & Policy']), Article.score >= 50).order_by(Article.score.desc()).all()

        geopolitical_noise_words = ["troop", "missile", "election", "ballot", "warfare", "kinetic", "embassy"]

        # --- 1. PROCESS CYBER (Utility-Focused Deduplication) ---
        pure_cyber_articles = []
        utility_keywords = ["grid", "power", "utility", "energy", "bes", "electric", "scada", "ics"]
        seen_cyber_titles = set() 
        
        for art in raw_cyber_articles:
            text_check = f"{art.title} {art.summary}".lower()
            
            # Strip geopolitics
            if any(noise in text_check for noise in geopolitical_noise_words): continue
            
            # Basic deduplication (prevents RSS spam)
            title_stub = art.title[:50].lower()
            if title_stub in seen_cyber_titles: continue
            seen_cyber_titles.add(title_stub)
            
            # Tag it if it's utility related for the point multiplier
            art.is_utility_related = any(ukw in text_check for ukw in utility_keywords)
            pure_cyber_articles.append(art)

        # --- 2. PROCESS PHYSICAL (Noise Reduction) ---
        pure_phys_articles = []
        ar_keywords = ["arkansas", "little rock", "pulaski", "benton", "entergy", "aecc", "cooperative"]
        threat_keywords = ["terror", "attack", "grid", "substation", "sabotage", "vandalism", "infrastructure", "transformer", "sniper", "shoot", "explosive", "tornado", "hurricane", "flood", "storm", "warning", "wildfire", "fire"]
        seen_phys_titles = set()
        
        for art in raw_phys_articles:
            text_check = f"{art.title} {art.summary}".lower()
            source_lower = art.source.lower() if art.source else ""
            
            if "cisa" in source_lower or "cyber" in text_check or "cve-" in text_check or "ics-cert" in source_lower: continue
                
            title_stub = art.title[:50].lower()
            if title_stub in seen_phys_titles: continue
            
            is_ar_related = any(kw in text_check for kw in ar_keywords)
            has_threat = any(kw in text_check for kw in threat_keywords)
            has_geo_noise = any(kw in text_check for kw in geopolitical_noise_words)
            
            if has_geo_noise and not any(k in text_check for k in ["grid", "substation", "infrastructure"]): continue
            
            if is_ar_related and has_threat: 
                seen_phys_titles.add(title_stub)
                pure_phys_articles.append(art)

        # --- 3. PROCESS ICS ---
        ics_advisories = []
        critical_vendors = ["SEL", "SCHWEITZER", "SIEMENS", "SCHNEIDER", "GE ", "ABB", "ROCKWELL", "EMERSON", "HONEYWELL", "OMRON"]
        for art in raw_ics_articles:
            source_upper = art.source.upper() if art.source else ""
            if "ICS" in source_upper or "CISA" in source_upper:
                is_critical = any(v in art.title.upper() for v in critical_vendors)
                ics_advisories.append({"title": art.title, "link": art.link, "published": art.published_date.strftime("%Y-%m-%d"), "is_critical": is_critical})

    # ==========================================
    # ENTERPRISE SCORING ALGORITHM (WEIGHTED POINTS)
    # ==========================================
    
    # --- CYBER SCORING ---
    cyber_points = 0
    critical_ics = [a for a in ics_advisories if a['is_critical']]
    cyber_points += len(critical_ics) * 15
    cyber_points += (len(ics_advisories) - len(critical_ics)) * 5
    
    for art in pure_cyber_articles:
        pts = 10 if art.score >= 80 else 3
        # 3x Multiplier if the article specifically targets power/utility infrastructure
        if getattr(art, 'is_utility_related', False): pts *= 3 
        cyber_points += pts
        
    if cyber_points >= 60: cyber_score = "HIGH"
    elif cyber_points >= 25: cyber_score = "MEDIUM"
    else: cyber_score = "LOW"
        
    cyber_brief = f"Tracking {len(pure_cyber_articles)} deduplicated OSINT threats (48h). "
    if ics_advisories: cyber_brief += f"CISA ICS-CERT issued {len(ics_advisories)} industrial advisories in 14 days ({len(critical_ics)} affecting critical BES vendors). "
    else: cyber_brief += "No recent CISA ICS-CERT advisories. "
    if pure_cyber_articles: cyber_brief += f"Top OSINT concern: '{pure_cyber_articles[0].title}'."
    
    # --- PHYSICAL SCORING ---
    physical_points = 0
    critical_crimes = [c for c in recent_crimes if c.get("severity") == "Critical"]
    high_crimes = [c for c in recent_crimes if c.get("severity") == "High"]
    med_crimes = [c for c in recent_crimes if c.get("severity") == "Medium"]
    
    # Crime Math
    physical_points += len(critical_crimes) * 30
    physical_points += len(high_crimes) * 5
    physical_points += len(med_crimes) * 1
    
    # OSINT Math
    for art in pure_phys_articles:
        pts = 15 if art.score >= 80 else 5
        physical_points += pts
        
    # Weather Math (Base load, won't spike to high unless > 25 active warnings statewide)
    physical_points += (active_warn_count * 2) 
    
    if physical_points >= 75: physical_score = "HIGH"
    elif physical_points >= 30: physical_score = "MEDIUM"
    else: physical_score = "LOW"
        
    physical_brief = f"Tracking {active_warn_count} active NWS hazards. Perimeter logs show {len(recent_crimes)} total incidents ({len(high_crimes)} High Risk). "
    if len(pure_phys_articles) > 0: physical_brief += f"🚨 OSINT detected {len(pure_phys_articles)} local physical/grid threats. "
    elif len(high_crimes) >= 5: physical_brief += "⚠️ Elevated perimeter crime activity detected. "
    else: physical_brief += "Routine physical perimeter activity. "

    # --- UNIFIED RISK ---
    if "HIGH" in [cyber_score, physical_score]: unified_risk = "HIGH"
    elif cyber_score == "MEDIUM" and physical_score == "MEDIUM": unified_risk = "MEDIUM"
    elif "MEDIUM" in [cyber_score, physical_score]: unified_risk = "MEDIUM"
    else: unified_risk = "LOW"
    
    return {
            "timestamp": datetime.now(LOCAL_TZ).strftime("%H:%M:%S %Z"),
            "unified_risk": unified_risk,
            "physical_score": physical_score,
            "physical_brief": physical_brief,
            "cyber_score": cyber_score,
            "cyber_brief": cyber_brief,
            "recent_crimes": recent_crimes,
            "raw_cyber_articles": pure_cyber_articles,
            "raw_phys_articles": pure_phys_articles
        }


def generate_outlook_html_report(intel):
    color_map = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#dc3545"}
    badge_color = color_map.get(intel["unified_risk"].upper(), "#000000")
    
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
                        {intel['unified_risk']} RISK
                    </div>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px;">
                    <h4 style="color: #0056b3; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">⚡ Physical & Crime Intelligence</h4>
                    <p style="color: #444444; line-height: 1.6; font-size: 14px;"><strong>Status: {intel['physical_score']}</strong><br/>{intel['physical_brief']}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px; padding-top: 0;">
                    <h4 style="color: #0056b3; border-bottom: 2px solid #eeeeee; padding-bottom: 5px;">🛡️ Cyber & SCADA Intelligence</h4>
                    <p style="color: #444444; line-height: 1.6; font-size: 14px;"><strong>Status: {intel['cyber_score']}</strong><br/>{intel['cyber_brief']}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 20px; background-color: #f8f9fa; border-radius: 0 0 8px 8px; font-size: 11px; color: #666666; text-align: center;">
                    <strong>Sources:</strong> CISA ICS-CERT, NIFC, NWS, SpotCrime API.<br/>
                    <em>CONFIDENTIAL: For Executive Leadership Only.</em>
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

def create_role(name, allowed_pages, allowed_actions):
    with SessionLocal() as db:
        if db.query(Role).filter(Role.name == name).first(): return False
        db.add(Role(name=name, allowed_pages=allowed_pages, allowed_actions=allowed_actions))
        db.commit()
        return True

def update_role(name, allowed_pages, allowed_actions):
    with SessionLocal() as db:
        role = db.query(Role).filter(Role.name == name).first()
        if role:
            role.allowed_pages, role.allowed_actions = allowed_pages, allowed_actions
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

def compile_regional_grid_map(map_df, spc_data, ar_data, oos_data, selected_events, toggles):
    """
    The Master Regional Grid Engine.
    Processes SPC Outlooks, NWS Alerts, Fire Weather, and Active Wildfires,
    calculates geospatial intersections, and builds the PyDeck map layers.
    """
    import pydeck as pdk
    import pandas as pd
    import re
    import uuid
    from shapely.geometry import Point, shape

    layers = []
    master_polygons = []
    toggled_polygons = []
    map_diagnostics = []
    layer_id = str(uuid.uuid4())[:6]

    # Unpack UI Toggles
    show_radar = toggles.get("radar", True)
    show_spc = toggles.get("spc", True)
    show_warn = toggles.get("warn", True)
    show_watch = toggles.get("watch", True)
    show_oos = toggles.get("oos", True)
    show_fire_risk = toggles.get("fire_risk", False)
    show_active_wildfires = toggles.get("active_wildfires", False)

    # 1. RADAR OVERLAY
    if show_radar:
        # Replaced TileLayer with BitmapLayer to natively support PNG rendering in PyDeck
        layers.append(pdk.Layer(
            "BitmapLayer", 
            image="https://mesonet.agron.iastate.edu/data/gis/images/4326/USCOMP/n0q_0.png", 
            bounds=[-126.0, 21.0, -66.0, 50.0], # [Left/West, Bottom/South, Right/East, Top/North]
            opacity=0.55, 
            pickable=False
        ))
        
    # 2. SPC CONVECTIVE OUTLOOKS
    spc_micro = {"type": "FeatureCollection", "features": []}
    if spc_data:
        color_map = {"TSTM": [192, 232, 192, 100], "MRGL": [124, 205, 124, 150], "SLGT": [246, 246, 123, 150], "ENH": [230, 153, 0, 150], "MDT": [255, 0, 0, 150], "HIGH": [255, 0, 255, 150]}
        for f in spc_data.get('features', []):
            label = f.get('properties', {}).get('LABEL', '')
            try:
                poly_shape = shape(f.get("geometry"))
                poly_dict = {"event": f"SPC: {label}", "shape": poly_shape, "severity": "Watch"}
                master_polygons.append(poly_dict)
                if show_spc: toggled_polygons.append(poly_dict)
                
                spc_micro["features"].append({
                    "type": "Feature", "geometry": f.get("geometry"),
                    "properties": {"fill_color": color_map.get(label, [0, 0, 0, 0]), "line_color": [0, 0, 0, 255], "info": f"SPC Risk: {label}"}
                })
            except Exception: pass
        if show_spc and spc_micro["features"]:
            layers.append(pdk.Layer("GeoJsonLayer", spc_micro, id=f"spc_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=1))

    # 3. NWS ALERTS (AR & OOS)
    ar_warn, ar_watch, _, ar_logs = process_nws_alerts(ar_data, selected_events, is_oos=False)
    oos_warn, oos_watch, _, oos_logs = process_nws_alerts(oos_data, selected_events, is_oos=True)
    map_diagnostics.extend(ar_logs + oos_logs)

    for f in ar_warn["features"] + ar_watch["features"] + oos_warn["features"] + oos_watch["features"]:
        p_dict = {"event": f['properties']['info'], "shape": f['properties']['shapely_obj'], "severity": f['properties']['severity']}
        master_polygons.append(p_dict)
        
        is_oos_feat = "[OOS]" in p_dict["event"]
        is_severe = p_dict["severity"] == "Warning"
        
        # Check toggles before adding to the active map polygons
        if (is_oos_feat and show_oos) or (not is_oos_feat and is_severe and show_warn) or (not is_oos_feat and not is_severe and show_watch):
            toggled_polygons.append(p_dict)
        f['properties'].pop('shapely_obj', None) # Clean for JSON serialization

    if show_warn and ar_warn["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=ar_warn, id=f"ar_warn_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    if show_watch and ar_watch["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=ar_watch, id=f"ar_watch_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    if show_oos and oos_warn["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=oos_warn, id=f"oos_warn_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
    if show_oos and oos_watch["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=oos_watch, id=f"oos_watch_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))

    # 4. FIRE WEATHER RISK
    if show_fire_risk:
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
                            # Only process AR counties for the AR Fire Risk layer to keep the map clean
                            if fips in regional_counties and regional_counties[fips]["state_fips"] == "05":
                                fire_fips_to_process[fips] = {
                                    "severity": severity, "color": fill_color, 
                                    "line_color": line_color, "event": event,
                                    "county_name": regional_counties[fips]["name"]
                                }

        for fips, info in fire_fips_to_process.items():
            geom = regional_counties[fips]["geometry"]
            ar_fire_geo["features"].append({
                "type": "Feature", "geometry": geom,
                "properties": {
                    "info": f"{info['county_name'].title()} County\nRisk Level: {info['severity']}\nNWS Alert: {info['event']}", 
                    "fill_color": info["color"], "line_color": info["line_color"]
                }
            })
            try:
                poly_dict = {"event": f"Wildfire Risk: {info['event']}", "shape": shape(geom), "severity": "High"}
                master_polygons.append(poly_dict)
                toggled_polygons.append(poly_dict)
            except: pass
                
        if ar_fire_geo["features"]: 
            layers.append(pdk.Layer("GeoJsonLayer", data=ar_fire_geo, id=f"fire_risk_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
            
    # 5. ACTIVE WILDFIRES (NIFC)
    if show_active_wildfires:
        nifc_data = get_active_wildfires()
        if nifc_data:
            df_fires = pd.DataFrame(nifc_data)
            df_fires['info'] = "🔥 " + df_fires['name'] + " (" + df_fires['state'] + ")\nAcres: " + df_fires['acres'].astype(str) + "\nContainment: " + df_fires['contained'].astype(str) + "%"
            layers.append(pdk.Layer(
                "ScatterplotLayer", data=df_fires, id=f"nifc_{layer_id}", pickable=True, opacity=0.9, stroked=True, filled=True,
                get_radius="1500 + (acres * 15)", radius_min_pixels=5, radius_max_pixels=35, line_width_min_pixels=1,
                get_position="[lon, lat]", get_fill_color="color", get_line_color=[0, 0, 0, 255]
            ))
            for _, row in df_fires.iterrows():
                try:
                    fire_poly = Point(row['lon'], row['lat']).buffer(0.03)
                    poly_dict = {"event": f"Active Wildfire: {row['name']}", "shape": fire_poly, "severity": "High"}
                    master_polygons.append(poly_dict)
                    toggled_polygons.append(poly_dict)
                except: pass

    # 6. FACILITY SITE LAYER
    if not map_df.empty:
        layers.append(pdk.Layer("ScatterplotLayer", map_df, pickable=True, opacity=0.9, stroked=True, filled=True, radius_scale=6, radius_min_pixels=4, radius_max_pixels=12, line_width_min_pixels=1, get_position="[Lon, Lat]", get_fill_color=[255, 255, 255], get_line_color=[0, 0, 0]))

    # 7. INTERSECTION MATHEMATICS
    toggled_affected_sites, _ = calculate_site_intersections(map_df, toggled_polygons)
    
    # Calculate master list against ALL hazards for the Analytics Dash, regardless of what is currently hidden on the map
    _, master_affected_sites = calculate_site_intersections(map_df, master_polygons)

    view_state = pdk.ViewState(latitude=34.8, longitude=-92.2, zoom=5.5, pitch=0)

    return layers, view_state, map_diagnostics, toggled_affected_sites, master_affected_sites
