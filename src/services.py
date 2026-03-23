import streamlit as st
import pandas as pd
import requests
import bcrypt
import uuid
import re
import urllib3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from sqlalchemy import text
from shapely.geometry import Point, shape

# Import your DB setup and models
from src.database import (
    SessionLocal, Article, FeedSource, Keyword, SystemConfig, CveItem,
    RegionalHazard, CloudOutage, User, Role, SavedReport, DailyBriefing,
    ExtractedIOC, MonitoredLocation, SolarWindsAlert, TimelineEvent,
    RegionalOutage, NodeAlias, BgpAnomaly
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
    spc, ar, oos = None, None, None
    try: spc = requests.get("https://www.spc.noaa.gov/products/outlook/day1otlk_cat.lyr.geojson", timeout=5).json()
    except: pass
    try: ar = requests.get("https://api.weather.gov/alerts/active?area=AR", headers={"User-Agent": "NOC_Fusion_App"}, timeout=5).json()
    except: pass
    try: oos = requests.get("https://api.weather.gov/alerts/active?area=OK,MS,MO", headers={"User-Agent": "NOC_Fusion_App"}, timeout=5).json()
    except: pass
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@st.cache_data(ttl=3600, max_entries=1)  # Scrapes once per hour
def get_ar_fire_bitmap():
    """
    Chicanery Protocol: Uses regex to hunt down the hidden base64 img-fluid map
    and pins it to Arkansas's precise geospatial bounding box.
    """
    try:
        url = "https://mip.agri.arkansas.gov/agtools/Forestry/Fire_Info"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Pull the raw HTML from the website
        resp = requests.get(url, headers=headers, verify=False, timeout=15)
        html = resp.text

        # STRATEGY 1: Surgical Strike on the `img-fluid` tag
        # This regex looks for an img tag containing 'img-fluid' and captures the data:image base64 string
        match = re.search(r'<img[^>]*class=["\'][^"\']*img-fluid[^"\']*["\'][^>]*src=["\'](data:image/[^"\']+)["\']', html, re.IGNORECASE)
        
        if not match:
            # STRATEGY 2: If the HTML is heavily obfuscated by JS, the tag might be built dynamically. 
            # So, we just hunt for the raw base64 PNG payload floating anywhere in the source code.
            match = re.search(r'(data:image/png;base64,[A-Za-z0-9+/=]+)', html)

        if match:
            image_source = match.group(1)
            
            # EXACT Bounding Box for the State of Arkansas
            # PyDeck format: [West Longitude, South Latitude, East Longitude, North Latitude]
            ar_bounds = [-94.6179, 33.0041, -89.6443, 36.4996]
            
            return {
                "image_data": image_source,
                "bounds": ar_bounds
            }
        else:
            print("🚨 CHICANERY FAILED: Could not find the base64 image string in the HTML source.")
            return None
            
    except Exception as e:
        print(f"🚨 Failed to scrape fire bitmap: {e}")
        return None

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
# 3. DAILY FUSION REPORT
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


# ==========================================
# 4. THREAT TELEMETRY (CISA, Cloud, NWS)
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

def get_hazards(limit=15, hours_back=None):
    with SessionLocal() as db:
        q = db.query(RegionalHazard)
        if hours_back: q = q.filter(RegionalHazard.updated_at >= datetime.utcnow() - timedelta(hours=hours_back))
        return to_dotdict_list(q.order_by(RegionalHazard.updated_at.desc()).limit(limit).all())

def process_nws_alerts(data, selected_events, is_oos=False):
    """Parses raw NWS GeoJSON using RAM-efficient Micro-Features and OOS guardrails."""
    map_diagnostics = []
    warn_geo = {"type": "FeatureCollection", "features": []}
    watch_geo = {"type": "FeatureCollection", "features": []}
    zonewide_alerts = []

    if not data or "features" not in data:
        map_diagnostics.append(f"⚠️ {'OOS' if is_oos else 'AR'} data empty or missing 'features'.")
        return warn_geo, watch_geo, zonewide_alerts, map_diagnostics

    map_diagnostics.append(f"ℹ️ Processing {len(data['features'])} raw NWS features for {'OOS' if is_oos else 'AR'}.")
    ar_counties_geom = get_ar_counties_mapping()

    for idx, f_raw in enumerate(data.get("features", [])):
        geom = f_raw.get("geometry")
        event_type = f_raw.get("properties", {}).get("event", "Unknown")
        headline = f_raw.get("properties", {}).get("headline", "No details provided.")
        area_desc = f_raw.get("properties", {}).get("areaDesc", "Unknown Area")

        if event_type not in selected_events: continue
        prefix = "[OOS]" if is_oos else "[AR]"

        geometries_to_process = []

        if geom:
            geometries_to_process.append(geom)
        else:
            if is_oos:
                map_diagnostics.append(f"  ⚠️ Feature {idx} ({event_type}) [OOS] has no polygon. Safely routed to Area-Wide alerts to prevent cross-state ghosting.")
                zonewide_alerts.append({"Event": f"{prefix} {event_type}", "Affected Area": area_desc, "Details": headline})
                continue

            found_counties = []
            potential_counties = [c.strip().lower() for c in re.split(r'[;,]', area_desc)]

            for c_name in potential_counties:
                c_name = c_name.replace(" county", "").replace(" parish", "").strip()
                if c_name in ar_counties_geom:
                    geometries_to_process.append(ar_counties_geom[c_name])
                    found_counties.append(c_name.title())

            if geometries_to_process:
                map_diagnostics.append(f"  ✅ Recovered missing polygon for Feature {idx} by mapping {len(found_counties)} AR counties.")
            else:
                map_diagnostics.append(f"  ⚠️ Feature {idx} ({event_type}) has no polygon and no AR counties matched. Routed to Area-Wide alerts.")
                zonewide_alerts.append({"Event": f"{prefix} {event_type}", "Affected Area": area_desc, "Details": headline})
                continue

        for g in geometries_to_process:
            try:
                poly_shape = shape(g)
                is_severe = "Warning" in event_type or "Emergency" in event_type
                severity = "Warning" if is_severe else "Watch/Advisory"

                micro_feature = {
                    "type": "Feature",
                    "geometry": g,
                    "properties": {
                        "info": f"{prefix} {event_type}",
                        "severity": severity,
                        "shapely_obj": poly_shape
                    }
                }

                if is_severe:
                    micro_feature['properties']['fill_color'] = [139, 0, 0, 60] if is_oos else [255, 0, 0, 60]
                    micro_feature['properties']['line_color'] = [139, 0, 0, 255] if is_oos else [255, 0, 0, 255]
                    warn_geo["features"].append(micro_feature)
                else:
                    micro_feature['properties']['fill_color'] = [204, 119, 34, 60] if is_oos else [255, 165, 0, 60]
                    micro_feature['properties']['line_color'] = [204, 119, 34, 255] if is_oos else [255, 165, 0, 255]
                    watch_geo["features"].append(micro_feature)

            except Exception as e:
                map_diagnostics.append(f"  ❌ Shapely Error on Feature {idx} ({event_type}): {e}")
                continue

    map_diagnostics.append(f"✅ Generated {len(warn_geo['features'])} Warns, {len(watch_geo['features'])} Watches, {len(zonewide_alerts)} Area-Wide.")
    return warn_geo, watch_geo, zonewide_alerts, map_diagnostics

def calculate_site_intersections(map_df, active_polygons):
    toggled_affected_sites = []
    master_affected_sites = []

    if map_df.empty or not active_polygons:
        return toggled_affected_sites, master_affected_sites

    for index, row in map_df.iterrows():
        if pd.notna(row['Lat']) and pd.notna(row['Lon']):
            site_pt = Point(row['Lon'], row['Lat'])

            act_toggled = []
            for p in active_polygons:
                if site_pt.within(p["shape"]):
                    act_toggled.append(p["event"])
                    master_affected_sites.append({
                        "Monitored Site": row['Name'], "Facility Type": row['Type'],
                        "Priority": row['Priority'], "Hazard": p["event"], "Severity": p["severity"]
                    })

            if act_toggled:
                toggled_affected_sites.append({
                    "Monitored Site": row['Name'], "Facility Type": row['Type'],
                    "Priority": row['Priority'], "Intersecting Hazards": ", ".join(list(set(act_toggled)))
                })

    return toggled_affected_sites, master_affected_sites

def import_locations(data):
    with SessionLocal() as db:
        added = 0
        existing_names = {l[0] for l in db.query(MonitoredLocation.name).all()}
        for item in data:
            name = item.get("name")
            lat, lon = item.get("lat"), item.get("lon")
            if name and lat is not None and lon is not None and name not in existing_names:
                db.add(MonitoredLocation(
                    name=name, lat=float(lat), lon=float(lon),
                    loc_type=item.get("type", "General"), priority=int(item.get("priority", 3))
                ))
                existing_names.add(name)
                added += 1
        db.commit()
    get_cached_locations.clear()
    return added

def update_locations(edited_df):
    with SessionLocal() as db:
        for index, row in edited_df.iterrows():
            db_loc = db.query(MonitoredLocation).filter_by(id=row['id']).first()
            if db_loc:
                db_loc.name = row['Name']
                db_loc.loc_type = row['Type']
                db_loc.priority = row['Priority']
                db_loc.lat = row['Lat']
                db_loc.lon = row['Lon']
        db.commit()
    get_cached_locations.clear()


# ==========================================
# 5. THREAT HUNTING & IOCs
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
        arts = db.query(Article).filter(
            Article.published_date >= cutoff,
            (Article.title.ilike(f"%{target}%") | Article.summary.ilike(f"%{target}%"))
        ).limit(30).all()
        return to_dotdict_list(arts)


# ==========================================
# 6. AIOps RCA (Root Cause Analysis)
# ==========================================

def get_aiops_dashboard_data():
    with SessionLocal() as db:
        alerts = db.query(SolarWindsAlert).filter(SolarWindsAlert.status != 'Resolved', SolarWindsAlert.is_correlated == False).all()
        events = db.query(TimelineEvent).order_by(TimelineEvent.timestamp.desc()).limit(50).all()
        grid = db.query(RegionalOutage).filter_by(is_resolved=False).all()
        aliases = db.query(NodeAlias).order_by(NodeAlias.confidence_score.asc()).all()
        return to_dotdict_list(alerts), to_dotdict_list(events), to_dotdict_list(grid), to_dotdict_list(aliases)

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
            a.mapped_location_name = new_mapped_name
            a.is_verified = True
            a.confidence_score = 100.0
            db.commit()

def generate_global_sitrep(sys_config_dict):
    with SessionLocal() as db:
        down_nodes = db.query(SolarWindsAlert).filter(SolarWindsAlert.is_correlated == False, SolarWindsAlert.status == 'Down').all()
        active_clouds = db.query(CloudOutage).filter_by(is_resolved=False).all()
        active_weather = db.query(RegionalHazard).all()
        active_grid = db.query(RegionalOutage).filter_by(is_resolved=False).all()
        locs_db = db.query(MonitoredLocation).all()

        report = f"###  Global Situation Report (SitRep)\n\n"
        report += f"**Active Node Failures:** {len(down_nodes)} | "
        report += f"**Cloud Outages:** {len(active_clouds)} | "
        report += f"**Grid/Weather Anomalies:** {len(active_weather) + len(active_grid)}\n\n"
        report += "####  Deterministic Causal Links\n"

        isolated_nodes = []

        for alert in down_nodes:
            causation_factors = []
            n_loc = next((l for l in locs_db if l.name == alert.mapped_location), None)

            if active_clouds:
                c_names = [c.provider.lower() for c in active_clouds]
                payload_str = str(alert.raw_payload).lower() if alert.raw_payload else ""
                if any(c in str(alert.details).lower() or c in payload_str for c in c_names):
                    causation_factors.append("☁️ Upstream Cloud Service Outage")

            if n_loc and n_loc.lat and n_loc.lon:
                for issue in active_grid:
                    if issue.lat and issue.lon:
                        dist_km = (((n_loc.lon - issue.lon)**2 + (n_loc.lat - issue.lat)**2)**0.5) * 111
                        if dist_km <= issue.radius_km:
                            causation_factors.append(f"⚡ {issue.outage_type} Outage Geometry ({issue.provider})")

                if n_loc.current_spc_risk not in ["None", "Unknown"]:
                    causation_factors.append(f"🌪️ Severe Weather Hazard ({n_loc.current_spc_risk})")

            if causation_factors:
                report += f"- **{alert.node_name}** ({alert.mapped_location}) is likely impacted by: " + ", ".join(list(set(causation_factors))) + "\n"
            else:
                isolated_nodes.append(f"**{alert.node_name}** ({alert.mapped_location})")

        report += "\n#### 🛠️ Isolated Anomalies (Network Faults)\n"
        if isolated_nodes:
            report += "No external factors detected. Treat as localized hardware/software failures:\n"
            for n in isolated_nodes:
                report += f"- {n}\n"
        else:
            report += "- None detected. All failures are correlated to external events.\n"

        if sys_config_dict and sys_config_dict.get('is_active'):
            from src.llm import call_llm
            sys_prompt = "You are an elite NOC AIOps Engine. Summarize the following deterministic IT SitRep into a technical 2-sentence executive summary."
            ai_summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": report}], sys_config_dict, temperature=0.1)

            if ai_summary and "⚠️" not in ai_summary:
                report = f"### 🤖 AI Executive Summary\n> {ai_summary}\n\n---\n\n" + report

        return report


# ==========================================
# 7. REPORT CENTER
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
# 8. SETTINGS & ADMINISTRATION
# ==========================================

@st.cache_data(ttl=300)
def get_all_roles():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Role).all())

def create_role(name, allowed_pages, allowed_actions):
    """Creates a new custom RBAC role."""
    with SessionLocal() as db:
        if db.query(Role).filter(Role.name == name).first(): return False
        new_role = Role(name=name, allowed_pages=allowed_pages, allowed_actions=allowed_actions)
        db.add(new_role)
        db.commit()
        return True

def update_role(name, allowed_pages, allowed_actions):
    """Updates permissions for an existing role."""
    with SessionLocal() as db:
        role = db.query(Role).filter(Role.name == name).first()
        if role:
            role.allowed_pages = allowed_pages
            role.allowed_actions = allowed_actions
            db.commit()
            return True
        return False

def create_user(username, password, role):
    """Securely hashes a password and creates a new system user."""
    with SessionLocal() as db:
        if db.query(User).filter(User.username == username).first(): return False
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(username=username, password_hash=hashed, role=role)
        db.add(new_user)
        db.commit()
        return True

def force_reset_pwd(username, new_password):
    """Allows admins to overwrite a user's password and force a session logout."""
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.session_token = None
            db.commit()
            return True
        return False

def update_user_role(username, new_role):
    with SessionLocal() as db:
        u = db.query(User).filter_by(username=username).first()
        if u:
            u.role = new_role
            u.session_token = None
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
                url = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else "New Feed"
                if not db.query(FeedSource).filter_by(url=url).first(): db.add(FeedSource(url=url, name=name))
        db.commit()

def delete_record(model_name, record_id):
    models = {"Keyword": Keyword, "FeedSource": FeedSource, "User": User, "Role": Role, "SavedReport": SavedReport}
    with SessionLocal() as db:
        record = db.query(models[model_name]).filter_by(id=record_id).first()
        if record: db.delete(record); db.commit()

def get_admin_lists():
    with SessionLocal() as db:
        return to_dotdict_list(db.query(Keyword).order_by(Keyword.weight.desc()).all()), \
               to_dotdict_list(db.query(FeedSource).all()), \
               to_dotdict_list(db.query(User).all())

def get_ml_counts():
    with SessionLocal() as db:
        pos = db.query(Article).filter(Article.human_feedback == 2).count()
        neg = db.query(Article).filter(Article.human_feedback == 1).count()
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
            if not db.query(Keyword).filter_by(word=kw["word"]).first():
                db.add(Keyword(word=kw["word"], weight=kw["weight"])); added["kw"] += 1
        for f in data.get("feeds", []):
            if not db.query(FeedSource).filter_by(url=f["url"]).first():
                db.add(FeedSource(url=f["url"], name=f["name"])); added["feeds"] += 1
        for l in data.get("locations", []):
            if not db.query(MonitoredLocation).filter_by(name=l["name"]).first():
                db.add(MonitoredLocation(name=l["name"], lat=l["lat"], lon=l["lon"], loc_type=l.get("type", "General"), priority=l.get("prio", 3))); added["locs"] += 1
        for a in data.get("aliases", []):
            if not db.query(NodeAlias).filter_by(node_pattern=a["pattern"]).first():
                db.add(NodeAlias(node_pattern=a["pattern"], mapped_location_name=a["mapped"], confidence_score=a["conf"], is_verified=a["ver"])); added["alias"] += 1
        db.commit()
    return added

def recategorize_all_articles():
    from src.categorizer import categorize_text
    with SessionLocal() as db:
        arts = db.query(Article).filter(Article.category == "General").all()
        count = 0
        for a in arts:
            cat = categorize_text(f"{a.title} {a.summary}")
            if cat != "General":
                a.category = cat
                count += 1
        db.commit()
        return count

def nuke_tables(model_names):
    """Database-agnostic way to wipe tables without causing SQLite syntax errors."""
    models_map = {
        "CloudOutage": CloudOutage,
        "MonitoredLocation": MonitoredLocation,
        "Article": Article,
        "ExtractedIOC": ExtractedIOC,
        "FeedSource": FeedSource,
        "Keyword": Keyword
    }
    with SessionLocal() as db:
        for name in model_names:
            if name in models_map:
                db.query(models_map[name]).delete(synchronize_session=False)
        db.commit()

def truncate_db_table(table_query):
    """
    WARNING INTERCEPTOR: The UI previously sent raw PostgreSQL TRUNCATE commands.
    This function catches that command, extracts the target table, and safely routes
    it to the database-agnostic nuke_tables() function so SQLite doesn't crash.
    """
    if "monitored_locations" in table_query.lower():
        nuke_tables(["MonitoredLocation"])
        get_cached_locations.clear()
