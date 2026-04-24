import streamlit as st
import pandas as pd
import time
import uuid
import re
import json
from streamlit_cookies_controller import CookieController
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from streamlit_autorefresh import st_autorefresh
import pydeck as pdk
import streamlit.components.v1 as components

# --- IMPORT SERVICES ONLY ---
import src.services as svc
from src.database import init_db
from src.scheduler import fetch_feeds
from src.llm import generate_bluf, cross_reference_cves, build_custom_intel_report, generate_rolling_summary, generate_daily_fusion_report, call_llm, generate_executive_weather_brief, generate_unified_risk_brief
@st.cache_resource
def setup_database():
    init_db()
    return True

setup_database()
st.set_page_config(page_title="Intelligence Fusion Center", layout="wide")

@st.cache_resource
def get_black_ops_state():
    return {"nick_enabled": False, "dean_target": None, "dean_start": 0}

black_ops = get_black_ops_state()

LOCAL_TZ = ZoneInfo("America/Chicago")
cookie_controller = CookieController()

def safe_rerun():
    st.rerun()

def check_cooldown(key, cooldown_seconds=60):
    last_click = st.session_state.get(f"cooldown_{key}", 0)
    return (time.time() - last_click) < cooldown_seconds

@st.cache_resource
def force_db_migration():
    from src.database import init_db
    init_db()
    st.cache_data.clear() # Wipes the d41d8cd98f00b204e9800998ecf8427e KeyError

force_db_migration()

def apply_cooldown(key):
    st.session_state[f"cooldown_{key}"] = time.time()

# --- REFACTORED RBAC CONSTANTS ---
ALL_POSSIBLE_PAGES = [
    "Global Dashboards",
    "Threat Telemetry",
    "Regional Grid",
    "Threat Hunting & IOCs",
    "AIOps RCA",
    "Shift Logbook",
    "Reporting & Briefings",
    "Settings & Admin"
]

ALL_POSSIBLE_ACTIONS = [
    "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score", 
    "Action: Trigger AI Functions", "Action: Manually Sync Data", "Action: Dispatch Exec Report",
    "Action: Submit Shift Log", "Action: Dispatch RCA Tickets", "Action: Manage Site Maintenance",
    "Tab: Dashboards -> Operational", "Tab: Dashboards -> Global Risk", "Tab: Dashboards -> Internal Risk",
    "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV", 
    "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Perimeter Crime",
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash", "Tab: Reporting -> Elastic SIEM Report",
    "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather", 
    "Tab: Threat Hunting -> Global IOC Matrix", "Tab: Threat Hunting -> Deep Hunt Builder", 
    "Tab: AIOps RCA -> Active Board", "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
    "Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History", # <-- NEW TABS
    "Tab: Reporting -> Daily Fusion", "Tab: Reporting -> Report Builder", "Tab: Reporting -> Shared Library",
    "Tab: Settings -> Facility Locations", "Tab: Settings -> Internal Assets", "Tab: Settings -> RSS Sources", 
    "Tab: Settings -> AI & SMTP", "Tab: Settings -> Users & Roles", "Tab: Settings -> Backup & Restore", "Tab: Settings -> Danger Zone"
]

if "current_user" not in st.session_state:
    st.session_state.current_user = None
    st.session_state.current_role = None
    st.session_state.allowed_pages = []
    st.session_state.allowed_actions = []

# --- AUTHENTICATION ---
if st.session_state.current_user is None:
    saved_token = cookie_controller.get("noc_session_token")
    if saved_token:
        user = svc.get_user_by_token(saved_token)
        if user:
            st.session_state.current_user = user.username
            st.session_state.current_role = user.role
            if user.role == "admin":
                st.session_state.allowed_pages = ALL_POSSIBLE_PAGES
                st.session_state.allowed_actions = ALL_POSSIBLE_ACTIONS
                st.session_state.allowed_site_types = "ALL"
            else:
                roles = svc.get_all_roles()
                role_obj = next((r for r in roles if r.name == user.role), None)
                if role_obj:
                    st.session_state.allowed_pages = role_obj.allowed_pages
                    st.session_state.allowed_actions = role_obj.allowed_actions or []
                    st.session_state.allowed_site_types = getattr(role_obj, 'allowed_site_types', []) or []
            safe_rerun()

# If the token check failed or they don't have one, render the Login UI
if st.session_state.current_user is None:
    c_space1, c_login, c_space2 = st.columns([1, 2, 1])
    with c_login:
        st.title("NOC Intelligence Fusion Center")
        st.markdown("### Authentication Required")
        with st.form("login_form", clear_on_submit=True):
            username = st.text_input("Username").strip()
            password = st.text_input("Password", type="password")
            
            if st.form_submit_button("Authenticate", width="stretch", type="primary"):
                user, token = svc.authenticate_user(username, password)
                if user:
                    cookie_controller.set("noc_session_token", token, max_age=30*86400)
                    st.session_state.current_user = user.username
                    st.session_state.current_role = user.role
                    
                    if user.role == "admin":
                        st.session_state.allowed_pages = ALL_POSSIBLE_PAGES
                        st.session_state.allowed_actions = ALL_POSSIBLE_ACTIONS
                        st.session_state.allowed_site_types = "ALL"
                    else:
                        roles = svc.get_all_roles()
                        role_obj = next((r for r in roles if r.name == user.role), None)
                        if role_obj:
                            st.session_state.allowed_pages = role_obj.allowed_pages
                            st.session_state.allowed_actions = role_obj.allowed_actions or []
                            st.session_state.allowed_site_types = getattr(role_obj, 'allowed_site_types', []) or []
                    
                    time.sleep(0.5)
                    safe_rerun()
                else: 
                    st.error("Invalid credentials.")
    st.stop() # Prevents the rest of the dashboard from loading behind the login screen

if st.session_state.current_role == "admin":
    st.session_state.allowed_pages = ALL_POSSIBLE_PAGES
    st.session_state.allowed_actions = ALL_POSSIBLE_ACTIONS
    st.session_state.allowed_site_types = "ALL"

can_pin = "Action: Pin Articles" in st.session_state.allowed_actions
can_train = "Action: Train ML Model" in st.session_state.allowed_actions
can_boost = "Action: Boost Threat Score" in st.session_state.allowed_actions
can_trigger_ai = "Action: Trigger AI Functions" in st.session_state.allowed_actions
can_sync = "Action: Manually Sync Data" in st.session_state.allowed_actions

current_user_obj = svc.get_user_by_username(st.session_state.current_user)

sys_config = svc.get_cached_config()
ai_enabled = sys_config.is_active if sys_config else False

if black_ops["nick_enabled"] and st.session_state.current_user == "nwilson":
    import random
    if "nick_troll_end" not in st.session_state:
        # 15% chance to trigger the lock on any UI refresh or click
        if random.random() < 0.15: 
            st.session_state.nick_troll_end = time.time() + 10
    
    if "nick_troll_end" in st.session_state:
        if time.time() < st.session_state.nick_troll_end:
            st.markdown("""
                <div style='position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background-color: black; z-index: 999999; display: flex; justify-content: center; align-items: center;'>
                    <h1 style='color: red; font-size: 15vw; font-family: Impact, sans-serif; text-transform: uppercase;'>YOU SUCK</h1>
                </div>
            """, unsafe_allow_html=True)
            # Force the page to auto-refresh and unlock after 10 seconds
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=10000, limit=2, key="troll_refresh") 
            st.stop()
        else:
            del st.session_state.nick_troll_end


if st.session_state.current_user:
    if "notified_alerts" not in st.session_state:
        st.session_state.notified_alerts = set()
        
    try:
        # Pull required cache
        g_locs = svc.get_cached_locations()
        g_spc_d1, g_spc_d2, g_spc_d3, g_ar_data, g_oos_data = svc.get_cached_geojson()
        
        # Fetch the geographically filtered alerts
        global_alerts = svc.get_filtered_notification_alerts(
            st.session_state.current_user, g_ar_data, g_oos_data, g_locs
        )
        
        new_alerts = []
        for alert in global_alerts:
            # Unique identifier prevents duplicate browser pushes
            alert_key = f"{alert['Event']}_{alert['Affected Area']}_{alert['Expires']}"
            if alert_key not in st.session_state.notified_alerts:
                new_alerts.append(alert)
                st.session_state.notified_alerts.add(alert_key)
                
        # Trigger HTML5 Notification API globally
        if new_alerts:
            js_notifications = ""
            for idx, na in enumerate(new_alerts):
                clean_event = na['Event'].replace('"', '')
                clean_area = na['Affected Area'].replace('"', '')
                title = f"NWS Alert: {clean_event}"
                body = f"Affected: {clean_area}"
                js_notifications += f'setTimeout(() => {{new Notification("{title}", {{body: "{body}"}}); }}, {idx * 500});\n'
                
            js_wrapper = f"""
            <script>
                if ("Notification" in window && Notification.permission === "granted") {{
                    {js_notifications}
                }}
            </script>
            """
            st.components.v1.html(js_wrapper, height=0, width=0)
    except Exception as e:
        pass # Fail silently so global UI doesn't crash on DB locks


# --- DYNAMIC THEMING ENGINE ---
theme_options = [
    "Standard", 
    "NOC Terminal", 
    "High Contrast (Dark)", 
    "Cyberpunk", 
    "Solarized Dark", 
    "Midnight Ocean"
]

# Fetch the user's saved theme from their cookie (if it exists)
theme_cookie_key = f"noc_theme_{st.session_state.current_user}" if st.session_state.current_user else "noc_theme_guest"
saved_theme = cookie_controller.get(theme_cookie_key)

if "ui_theme" not in st.session_state:
    st.session_state.ui_theme = saved_theme if saved_theme in theme_options else "Standard"

# Aggressive CSS overrides to prevent Streamlit's default colors from bleeding through
theme_css = {
    "Standard": "",
    "NOC Terminal": """
        .stApp { background-color: #0e1117 !important; color: #00ff00 !important; }
        h1, h2, h3, p, span, div, label { color: #00ff00 !important; font-family: 'Courier New', Courier, monospace; }
        [data-testid="stSidebar"] { background-color: #000000 !important; border-right: 1px solid #00ff00 !important; }
        .stButton>button { background-color: #002200 !important; color: #00ff00 !important; border: 1px solid #00ff00 !important; }
        .stButton>button:hover { background-color: #00ff00 !important; color: #000000 !important; }
        [data-testid="stContainer"] { background-color: #050505 !important; border: 1px solid #00ff00 !important; }
    """,
    "High Contrast (Dark)": """
        .stApp { background-color: #000000 !important; color: #FFFF00 !important; }
        h1, h2, h3, p, span, div, label { color: #FFFF00 !important; font-weight: 700 !important; }
        [data-testid="stSidebar"] { background-color: #000000 !important; border-right: 3px solid #FFFF00 !important; }
        .stButton>button { background-color: #000000 !important; color: #FFFF00 !important; border: 2px solid #FFFF00 !important; font-weight: 900 !important; }
        .stButton>button:hover { background-color: #FFFF00 !important; color: #000000 !important; }
        [data-testid="stContainer"] { background-color: #000000 !important; border: 3px solid #FFFF00 !important; box-shadow: none !important; }
    """,
    "Cyberpunk": """
        .stApp { background-color: #0b0213 !important; color: #00ffcc !important; }
        h1, h2, h3 { color: #ff007f !important; text-shadow: 0 0 5px #ff007f; }
        p, span, label, div { color: #00ffcc !important; }
        [data-testid="stSidebar"] { background-color: #120422 !important; border-right: 2px solid #ff007f !important; }
        .stButton>button { background-color: #120422 !important; color: #00ffcc !important; border: 1px solid #00ffcc !important; box-shadow: 0 0 5px #00ffcc; }
        .stButton>button:hover { background-color: #00ffcc !important; color: #120422 !important; border: 1px solid #ff007f !important; }
        [data-testid="stContainer"] { background-color: #1a0633 !important; border: 1px solid #ff007f !important; box-shadow: 0 0 10px rgba(255,0,127,0.2) !important; }
    """,
    "Solarized Dark": """
        .stApp { background-color: #002b36 !important; color: #839496 !important; }
        h1, h2, h3 { color: #b58900 !important; }
        p, span, label, div { color: #839496 !important; }
        [data-testid="stSidebar"] { background-color: #073642 !important; border-right: 1px solid #586e75 !important; }
        .stButton>button { background-color: #073642 !important; color: #2aa198 !important; border: 1px solid #2aa198 !important; }
        .stButton>button:hover { background-color: #2aa198 !important; color: #002b36 !important; }
        [data-testid="stContainer"] { background-color: #073642 !important; border: 1px solid #586e75 !important; }
    """,
    "Midnight Ocean": """
        .stApp { background-color: #011627 !important; color: #94a3b8 !important; }
        h1, h2, h3 { color: #38bdf8 !important; }
        p, span, label, div { color: #cbd5e1 !important; }
        [data-testid="stSidebar"] { background-color: #0f172a !important; border-right: 1px solid #1e293b !important; }
        .stButton>button { background-color: #1e293b !important; color: #38bdf8 !important; border: 1px solid #38bdf8 !important; border-radius: 6px !important;}
        .stButton>button:hover { background-color: #38bdf8 !important; color: #0f172a !important; }
        [data-testid="stContainer"] { background-color: #0f172a !important; border: 1px solid #1e293b !important; border-radius: 8px !important; }
    """
}

custom_css = theme_css.get(st.session_state.ui_theme, "")

st.markdown(f"""
    <style>
        .block-container {{ padding-top: 1rem; padding-bottom: 0rem; padding-left: 1rem; padding-right: 1rem; max-width: 100%; }}
        h1 {{ font-size: 1.8rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }}
        h2 {{ font-size: 1.4rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }}
        h3 {{ font-size: 1.1rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }}
        [data-testid="stVerticalBlockBorderWrapper"] p, [data-testid="stVerticalBlockBorderWrapper"] li, [data-testid="stExpanderDetails"] p, [data-testid="stExpanderDetails"] li {{ font-size: 0.9rem !important; margin-bottom: 0.2rem !important; line-height: 1.3 !important; }}
        hr {{ margin-top: 0.5rem; margin-bottom: 0.5rem; }}
        .stButton>button {{ padding: 0rem 0.5rem !important; min-height: 2rem !important; }}
        {custom_css}
    </style>
""", unsafe_allow_html=True)


# --- SIDEBAR ---
st.sidebar.title("NOC Fusion")
display_name = current_user_obj.full_name if current_user_obj and current_user_obj.full_name else st.session_state.current_user.capitalize()
display_title = current_user_obj.job_title if current_user_obj and current_user_obj.job_title else st.session_state.current_role.upper()
st.sidebar.markdown(f" **{display_name}**\n\n<small>{display_title}</small>", unsafe_allow_html=True)

if st.sidebar.button("Log Out", width="stretch"):
    svc.logout_user(st.session_state.current_user)
    cookie_controller.remove("noc_session_token")
    st.session_state.current_user = None; st.session_state.current_role = None
    time.sleep(0.5); safe_rerun()

with st.sidebar.expander("My Profile"):
    # 1. UI Theme Selector (with persistence)
    selected_theme = st.selectbox(
        "UI Theme", 
        theme_options, 
        index=theme_options.index(st.session_state.ui_theme)
    )
    
    if selected_theme != st.session_state.ui_theme:
        st.session_state.ui_theme = selected_theme
        cookie_controller.set(theme_cookie_key, selected_theme, max_age=30*86400) # Save for 30 days
        time.sleep(0.1)
        safe_rerun()
        
    st.divider()
    
    # 2. Profile Details Form
    with st.form("my_profile_form"):
        new_fn = st.text_input("Full Name", value=current_user_obj.full_name or "")
        new_jt = st.text_input("Job Title", value=current_user_obj.job_title or "")
        new_ci = st.text_input("Contact Info", value=current_user_obj.contact_info or "")
        
        # --- NEW SHIFT SELECTION ---
        shift_options = ["Morning", "Afternoon", "Night", "No Shift"]
        current_shift = getattr(current_user_obj, 'default_shift', "No Shift")
        if current_shift not in shift_options: current_shift = "No Shift"
        new_shift = st.selectbox("Default Shift", shift_options, index=shift_options.index(current_shift))
        
        st.divider()
        old_pwd = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        if st.form_submit_button("Save Profile", width="stretch"):
            success, msg = svc.update_user_profile(st.session_state.current_user, new_fn, new_jt, new_ci, old_pwd, new_pwd)
            if success: 
                # Direct DB update for the new shift field
                with svc.SessionLocal() as db:
                    from src.database import User
                    u = db.query(User).filter_by(username=st.session_state.current_user).first()
                    if u:
                        u.default_shift = new_shift
                        db.commit()
                st.success(msg); time.sleep(0.5); safe_rerun()
            else: st.error(msg)

st.sidebar.divider()
PAGES = st.session_state.allowed_pages
if not PAGES: st.error("No assigned permissions. Please contact an administrator."); st.stop()
if "active_page" not in st.session_state or st.session_state.active_page not in PAGES: st.session_state.active_page = PAGES[0]

selected_page = st.sidebar.radio("Navigation", PAGES, index=PAGES.index(st.session_state.active_page), key="nav_radio")
if selected_page != st.session_state.active_page: st.session_state.active_page = selected_page; safe_rerun()
page = st.session_state.active_page

st.sidebar.divider()
refresh_count = 0
current_refresh_sec = 0

if page in ["Global Dashboards"]:
    refresh_rate = st.sidebar.selectbox("Live Refresh", ["Off", "10 Seconds", "1 Minute", "5 Minutes"], index=0)
    rmap = {"Off": 0, "10 Seconds": 10, "1 Minute": 60, "5 Minutes": 300}
    current_refresh_sec = rmap[refresh_rate]
    if current_refresh_sec > 0: refresh_count = st_autorefresh(interval=current_refresh_sec * 1000)

def format_local_time(utc_dt): return utc_dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S') if utc_dt else "Unknown"
def get_score_badge(score): return f" **[{int(score)}]**" if score >= 80 else f" **[{int(score)}]**" if score >= 50 else f" **[{int(score)}]**"
def get_cat_icon(cat): 
    icons = {
        "Cyber: Exploits & Vulns": "", "Cyber: Malware & Threats": "",
        "ICS/OT & SCADA": "", "Cloud & IT Infra": "",
        "Physical Security": "", "Severe Weather": "",
        "Geopolitics & Policy": "", "AI & Emerging Tech": "",
        "General": ""
    }
    return icons.get(cat, "")

def render_article_feed(feed_articles, key_prefix=""):
    if not feed_articles: st.success("Queue is empty."); return
    for art in feed_articles:
        with st.container(border=True):
            c_title, c_score = st.columns([4, 1])
            c_title.markdown(f"**{get_score_badge(art.score)} [{art.title}]({art.link})**")
            c_title.caption(f" {format_local_time(art.published_date)} |  {art.source} | {get_cat_icon(art.category)} {art.category}")
            
            # --- UPDATED RENDERING LOGIC ---
            if art.ai_bluf: 
                st.success(f"**AI BLUF:** {art.ai_bluf}")
            
            # Always show the snippet, and increase the preview length to 500 characters
            st.caption(art.summary[:500] + "..." if art.summary else "No summary available.")
                
            c1, c2, c3, c4, c5 = st.columns(5)
            if c1.button("Unpin" if art.is_pinned else "Pin", key=f"{key_prefix}pin_{art.id}", disabled=not can_pin): svc.toggle_pin(art.id); safe_rerun()
            if c2.button(" +15 Score", key=f"{key_prefix}boost_{art.id}", disabled=not can_boost): svc.boost_score(art.id, 15); safe_rerun()
            if c3.button("Keep", key=f"{key_prefix}keep_{art.id}", disabled=not can_train): svc.change_status(art.id, 2); safe_rerun()
            if c4.button("Dismiss", key=f"{key_prefix}dism_{art.id}", disabled=not can_train): svc.change_status(art.id, 1); safe_rerun()
            
            if ai_enabled and not art.ai_bluf:
                is_ai_cooling = check_cooldown(f"bluf_{art.id}", 30)
                if c5.button("Generating..." if is_ai_cooling else "BLUF", key=f"{key_prefix}bluf_{art.id}", disabled=not can_trigger_ai or is_ai_cooling):
                    apply_cooldown(f"bluf_{art.id}")
                    with st.spinner("Analyzing..."):
                        b = generate_bluf(art, svc.SessionLocal())
                        if b: svc.save_ai_bluf(art.id, b); safe_rerun()


# ================= 1. GLOBAL DASHBOARDS =================
if page == "Global Dashboards":
    st.title("Global NOC Dashboards")
    dash_tabs = st.tabs(["Operational Dashboard", "Global Risk", "Internal Risk", "Unified Brief"])
    
    with dash_tabs[0]:
        metrics = svc.get_dashboard_metrics()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("High-Threat RSS (24h)", metrics["rss_count"])
        c2.metric("Active KEVs (24h)", metrics["cve_count"])
        c3.metric("Hazards (24h)", metrics["hazard_count"])
        c4.metric("Cloud Outages (24h)", metrics["cloud_count"])
        st.divider()
        
        dash_panels = ["Threat Triage", "Infrastructure Status", "AI Analysis"]
        if "auto_rotate_dash" not in st.session_state: st.session_state.auto_rotate_dash = True
        c_tog, c_space = st.columns([1, 5])
        auto_rotate = c_tog.toggle("Auto-Rotate", key="auto_rotate_dash")

        calculated_index = refresh_count % len(dash_panels) if auto_rotate else 0
        selected_panel = st.radio("Views", dash_panels, index=calculated_index, horizontal=True, label_visibility="collapsed")
        st.write("")

        if selected_panel == "Threat Triage":
            col_pin, col_rss = st.columns([1, 1])
            with col_pin:
                st.subheader("Pinned Intel")
                for art in svc.get_pinned_articles():
                    st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small> {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)
                    if art.ai_bluf: st.success(f"**AI BLUF:** {art.ai_bluf}")
                    st.write("")
            with col_rss:
                st.subheader("Live Feed (Top 15)")
                for art in svc.get_live_articles():
                    st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small> {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)

        elif selected_panel == "Infrastructure Status":
            col_cve, col_cld, col_reg = st.columns(3)
            with col_cve:
                st.subheader("CISA KEVs (Top 15)")
                for cve in svc.get_cves(limit=15):
                    st.markdown(f" **[{cve.cve_id}](https://nvd.nist.gov/vuln/detail/{cve.cve_id})**<br><small>{cve.vendor} {cve.product}</small>", unsafe_allow_html=True)
            with col_cld:
                st.subheader("Active Cloud Outages")
                outages = svc.get_cloud_outages(active_only=True, limit=5)
                if not outages: st.success("Clear.")
                for out in outages: st.markdown(f" **{out.provider}**<br><small>[{out.title}]({out.link})</small>", unsafe_allow_html=True)
            with col_reg:
                st.subheader("Regional Hazards")
                hazards = svc.get_hazards(limit=15)
                if not hazards: st.success("Clear.")
                for haz in hazards:
                    icon = "" if haz.severity in ["Extreme", "Severe"] else "" if haz.severity == "Moderate" else ""
                    st.markdown(f"{icon} **{haz.severity}**<br><small>{haz.title} ({haz.location})</small>", unsafe_allow_html=True)

        elif selected_panel == "AI Analysis":
            col_ai1, col_ai2 = st.columns([2, 1])
            with col_ai1:
                st.subheader("AI Shift Briefing")
                if ai_enabled:
                    now = datetime.utcnow()
                    if not sys_config.rolling_summary or not sys_config.rolling_summary_time or (now - sys_config.rolling_summary_time).total_seconds() > 1800:
                        with st.spinner("Updating..."):
                            ns = generate_rolling_summary(svc.SessionLocal())
                            if ns: svc.save_global_config({"rolling_summary": ns, "rolling_summary_time": now})
                    c_time, c_btn = st.columns([3, 2])
                    c_time.caption(f"Last Sync: {format_local_time(sys_config.rolling_summary_time)}")
                    
                    is_ai_refresh_cooling = check_cooldown("ai_refresh", 120)
                    if c_btn.button("Generating..." if is_ai_refresh_cooling else "Force Refresh Briefing", width="stretch", disabled=not can_trigger_ai or is_ai_refresh_cooling):
                        apply_cooldown("ai_refresh")
                        with st.spinner("Forcing AI Summary..."):
                            ns = generate_rolling_summary(svc.SessionLocal())
                            if ns: svc.save_global_config({"rolling_summary": ns, "rolling_summary_time": datetime.utcnow()}); safe_rerun()
                    st.info(sys_config.rolling_summary if sys_config.rolling_summary else "Initializing...")
                else: st.info("AI Disabled.")
                
            with col_ai2:
                st.subheader("Security Auditor")
                is_scan_cooling = check_cooldown("ai_scan", 60)
                if st.button("Scanning..." if is_scan_cooling else "Scan Stack Against 30-Day KEVs", width="stretch", disabled=not can_trigger_ai or is_scan_cooling):
                    apply_cooldown("ai_scan")
                    with st.spinner("Scanning..."):
                        from src.database import CveItem
                        with svc.SessionLocal() as dbtmp:
                            cves = dbtmp.query(CveItem).filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30)).all()
                            res = cross_reference_cves(cves, dbtmp)
                        if res and ("clear" in res.lower() or "no active" in res.lower()): st.success(" " + res)
                        else: st.error(f" **MATCH DETECTED:**\n{res}")

    with dash_tabs[1]:
        # --- NEW: POP-UP LEGEND DIALOG ---
        @st.dialog("CIS Threat Level Legend")
        def show_cis_legend():
            st.markdown("""
            ### Official MS-ISAC / CIS Alert Levels
            
            **Formula:** `Severity = (Criticality + Lethality)  (System + Network Countermeasures)`
            
            *  **GREEN (LOW | -8 to -5):** Low risk. Normal probing, low-risk viruses. Continue routine monitoring and patching.
            *  **BLUE (GUARDED | -4 to -2):** General risk of increased hacking/malicious activity. No known severe exploits or significant impacts yet.
            *  **YELLOW (ELEVATED | -1 to +2):** Significant risk. Known vulnerabilities being exploited with moderate damage, or high potential for disruption.
            *  **ORANGE (HIGH | +3 to +5):** High risk targeting core infrastructure. Multiple service outages, critical vulnerabilities actively exploited with significant impact.
            *  **RED (SEVERE | +6 to +8):** Severe risk. Widespread outages, destructive compromises to SCADA/critical systems. Potential for actual loss of life or economic security.
            """)
            if st.button("Close", width='stretch'):
                st.rerun()

        st.subheader("Executive Grid Threat Matrix")
        
        # Legend Trigger Button
        col_title, col_leg = st.columns([3, 1])
        col_title.caption("Strategic synthesis of Physical and Cyber telemetry measured against a 14-day operational baseline.")
        if col_leg.button("View CIS Threat Legend", width='stretch'):
            show_cis_legend()
        
        ar_warn = svc.get_cached_geojson()[3] or {}
        oos_warn = svc.get_cached_geojson()[4] or {}
        active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))
        
        crime_data = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
        with svc.SessionLocal() as dbtmp:
            from src.database import ElasticEvent
            recent_siem = dbtmp.query(ElasticEvent).filter(
                ElasticEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).all()
        
        intel = svc.get_executive_grid_intel(active_nws, crime_data)
        
        # Artificially boost the OSINT cyber score based on internal SIEM telemetry
        critical_siem_hits = len([e for e in recent_siem if e.severity == "CRITICAL"])
        if critical_siem_hits > 0:
            siem_penalty = min(critical_siem_hits * 3, 20) # Cap the penalty at +20 points
            intel['current_cyber_pts'] += siem_penalty
            intel['evidence_log'].append(f"**SIEM Telemetry:** Detected {critical_siem_hits} CRITICAL internal alerts via Elastic, resulting in a +{siem_penalty} pt risk penalty.")
        
        # New 5-Tier Color Mapping
        color_map = {"GREEN": "#28a745", "BLUE": "#007bff", "YELLOW": "#ffc107", "ORANGE": "#fd7e14", "RED": "#dc3545"}
        name_map = {"GREEN": "GREEN (LOW)", "BLUE": "BLUE (GUARDED)", "YELLOW": "YELLOW (ELEVATED)", "ORANGE": "ORANGE (HIGH)", "RED": "RED (SEVERE)"}
        
        risk_color = color_map.get(intel['unified_risk'].upper(), "#28a745")
        display_risk = name_map.get(intel['unified_risk'].upper(), "UNKNOWN")
        
        st.markdown(f"""
        <div style='text-align: center; padding: 20px; background-color: #1e1e1e; border-radius: 10px; border: 2px solid {risk_color}; margin-bottom: 20px;'>
            <h3 style='margin:0; color: #a0a0a0;'>GLOBAL THREAT POSTURE (CIS STANDARD)</h3>
            <h1 style='margin:0; font-size: 3rem; color: {risk_color};'>{display_risk}</h1>
            <p style='margin:0; color: #a0a0a0;'>Last Updated: {intel['timestamp']}</p>
        </div>
        """, unsafe_allow_html=True)

        # --- EXECUTIVE TREND GRAPH ---
        with st.expander("View 14-Day CIS Alert Level Trend", expanded=True):
            history = svc.get_historical_threat_scores(14)
            if not history:
                st.info("Gathering baseline telemetry. Graph will populate tomorrow.")
            else:
                import pandas as pd
                dates = [h.record_date for h in history]
                cyber_pts = [h.cyber_points for h in history]
                phys_pts = [h.physical_points for h in history]
                
                # Overlay current live score to complete the trend
                if dates and dates[-1].date() == datetime.utcnow().date():
                    cyber_pts[-1] = intel['current_cyber_pts']
                    phys_pts[-1] = intel['current_phys_pts']
                
                chart_data = pd.DataFrame({
                    "Date": dates, 
                    "Cyber CIS Score": cyber_pts, 
                    "Physical CIS Score": phys_pts
                }).set_index("Date")
                st.line_chart(chart_data, color=["#00b4d8", "#ff9f1c"])
                
                st.caption(f"**Cyber:** {intel['current_cyber_pts']} ({intel['cyber_score']}) | **Physical:** {intel['current_phys_pts']} ({intel['physical_score']}) | **Unified:** {intel['unified_risk']}")
                
                # Show CIS Alert Level reference
                col_ref1, col_ref2, col_ref3, col_ref4, col_ref5 = st.columns(5)
                with col_ref1:
                    st.markdown("<div style='background-color:#28a745;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>GREEN<br>-8 to -5</div>", unsafe_allow_html=True)
                with col_ref2:
                    st.markdown("<div style='background-color:#007bff;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>BLUE<br>-4 to -2</div>", unsafe_allow_html=True)
                with col_ref3:
                    st.markdown("<div style='background-color:#ffc107;padding:5px;border-radius:5px;text-align:center;color:black;font-size:12px;'>YELLOW<br>-1 to +2</div>", unsafe_allow_html=True)
                with col_ref4:
                    st.markdown("<div style='background-color:#fd7e14;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>ORANGE<br>+3 to +5</div>", unsafe_allow_html=True)
                with col_ref5:
                    st.markdown("<div style='background-color:#dc3545;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>RED<br>+6 to +8</div>", unsafe_allow_html=True)

        st.divider()

        col_phys, col_cyber = st.columns(2)
        with col_phys:
            st.subheader("Physical & Perimeter (1 Mile)")
            st.info(f"**Risk Level: {intel['physical_score']}**")
            st.write(intel['physical_brief'])
            
            phys_sources = intel.get('raw_phys_articles', [])
            if phys_sources:
                with st.expander("View Contributing Physical Intelligence"):
                    for src in phys_sources[:15]:
                        st.markdown(f"- [{src.title}]({src.link}) <small>({src.source})</small>", unsafe_allow_html=True)
            
            if intel.get("recent_crimes"):
                st.markdown("** Grid-Relevant Perimeter Incidents:**")
                for c in intel["recent_crimes"][:5]:
                    st.caption(f" **{c.get('fbi_category', 'Incident')}:** {c['raw_title']} ({c['distance_miles']} mi) - *{c['timestamp']}*")
                if len(intel["recent_crimes"]) > 5:
                    st.caption(f"...and {len(intel['recent_crimes']) - 5} more (See Threat Telemetry).")
            
        with col_cyber:
            st.subheader("Cyber & SCADA (48 Hours)")
            st.warning(f"**Risk Level: {intel['cyber_score']}**")
            st.write(intel['cyber_brief'])
            
            # --- UPDATED: MACROSCOPIC EVIDENCE LOG ---
            with st.expander("View CIS Macroscopic Variables"):
                st.markdown("**Formula:** `Severity = (Criticality + Lethality) - (System + Network Countermeasures)`")
                st.markdown(f"**Current Aggregate Score:** `{intel['cis_cyber_score']}`")
                st.divider()
                for log in intel.get('evidence_log', []):
                    st.markdown(log)
            
            cyber_sources = intel.get('raw_cyber_articles', [])
            if cyber_sources:
                with st.expander("View Contributing Cyber Intelligence"):
                    for src in cyber_sources[:15]:
                        tag = "APT" if getattr(src, 'is_apt_related', False) else "Ransomware" if getattr(src, 'is_ransomware', False) else ""
                        st.markdown(f"- **{tag}** [{src.title}]({src.link}) <small>({src.source})</small>", unsafe_allow_html=True)
        st.divider()
        st.subheader("Dynamic Scoring Overview")
        st.caption("AI-generated synthesis of all live telemetry detailing the exact reasoning behind the current threat score.")
        
        c_score_btn, c_score_space = st.columns([1, 3])
        is_scoring_cooling = check_cooldown("ai_scoring_report", 60)
        
        # Generator Button explicitly tied to the current intel object
        if c_score_btn.button("Generating..." if is_scoring_cooling else "Generate Scoring Rationale", disabled=not can_trigger_ai or is_scoring_cooling, width="stretch", type="primary"):
            apply_cooldown("ai_scoring_report")
            with st.spinner("Analyzing threat weights and compiling expansive scoring rationale..."):
                from src.llm import generate_dynamic_scoring_report
                rep = generate_dynamic_scoring_report(svc.SessionLocal(), intel)
                st.session_state.scored_overview = rep
                st.session_state.scored_overview_risk = intel['unified_risk']
        
        # Render the report persistently if it exists in session state
        if "scored_overview" in st.session_state:
            # Check if the matrix has shifted (e.g. Yellow -> Orange) since the text was generated
            if st.session_state.get("scored_overview_risk") != intel['unified_risk']:
                st.warning(f"The Executive Threat Matrix posture has shifted to **{intel['unified_risk']}** since this rationale was generated. Please regenerate the report to reflect the latest telemetry.")
            
            with st.container(border=True):
                st.markdown(st.session_state.scored_overview)
                
        st.divider()
        st.subheader("Dispatch Intelligence Report")
        col_email, col_btn = st.columns([3, 1])
        default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
        target_email = col_email.text_input("Recipient Email Address", value=default_email, label_visibility="collapsed")
        
        can_dispatch = "Action: Dispatch Exec Report" in st.session_state.allowed_actions
        if col_btn.button("Send AI Scoring Report", width='stretch', type="primary", disabled=not can_dispatch):
            if target_email:
                with st.spinner("Generating AI Analysis and Transmitting..."):
                    from src.llm import generate_dynamic_scoring_report
                    from src.mailer import send_alert_email
                    import re
                    
                    # Generate the LLM report if it hasn't been triggered in the UI yet
                    rep = st.session_state.get("scored_overview")
                    if not rep or st.session_state.get("scored_overview_risk") != intel['unified_risk']:
                        rep = generate_dynamic_scoring_report(svc.SessionLocal(), intel)
                        st.session_state.scored_overview = rep
                        st.session_state.scored_overview_risk = intel['unified_risk']
                        
                    # --- NATIVE MARKDOWN TO HTML CONVERTER ---
                    def md_to_html(md):
                        md = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', md) 
                        lines = md.split('\n')
                        html_lines = []
                        in_ul = False
                        
                        for line in lines:
                            stripped = line.strip()
                            if not stripped:
                                if in_ul: html_lines.append("</ul>"); in_ul = False
                                html_lines.append("<br>")
                                continue
                                
                            if stripped.startswith('### '):
                                if in_ul: html_lines.append("</ul>"); in_ul = False
                                html_lines.append(f"<h4 style='color:#34495e; margin-top:15px; margin-bottom:5px;'>{stripped[4:]}</h4>")
                            elif stripped.startswith('## '):
                                if in_ul: html_lines.append("</ul>"); in_ul = False
                                html_lines.append(f"<h3 style='color:#2c3e50; border-bottom:1px solid #ecf0f1; padding-bottom:5px; margin-top:20px;'>{stripped[3:]}</h3>")
                            elif stripped.startswith('# '):
                                if in_ul: html_lines.append("</ul>"); in_ul = False
                                html_lines.append(f"<h2 style='color:#2980b9; margin-top:20px;'>{stripped[2:]}</h2>")
                            elif stripped.startswith('- ') or stripped.startswith('* '):
                                if not in_ul: html_lines.append("<ul style='margin-top:5px; padding-left:20px;'>"); in_ul = True
                                html_lines.append(f"<li style='margin-bottom:8px;'>{stripped[2:]}</li>")
                            elif re.match(r'^\d+\.\s', stripped):
                                if not in_ul: html_lines.append("<ul style='margin-top:5px; padding-left:20px; list-style-type:decimal;'>"); in_ul = True
                                content = re.sub(r'^\d+\.\s', '', stripped)
                                html_lines.append(f"<li style='margin-bottom:8px;'>{content}</li>")
                            else:
                                if in_ul: html_lines.append("</ul>"); in_ul = False
                                html_lines.append(f"<p style='margin-top:0; margin-bottom:10px; line-height:1.6;'>{stripped}</p>")
                                
                        if in_ul: html_lines.append("</ul>")
                        return "".join(html_lines)
                    
                    formatted_content = md_to_html(rep)
                    
                    # Map colors for the email header
                    email_color_map = {
                        "GREEN": "#28a745", "BLUE": "#007bff", "YELLOW": "#ffc107", 
                        "ORANGE": "#fd7e14", "RED": "#dc3545"
                    }
                    uni_color = email_color_map.get(intel['unified_risk'].upper(), "#333333")
                    cyb_color = email_color_map.get(intel['cyber_score'].upper(), "#333333")
                    phy_color = email_color_map.get(intel['physical_score'].upper(), "#333333")
                    
                    # Format the final HTML body with a dynamic scoring banner
                    html_body = f"""
                    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; color: #333;">
                        
                        <table width="100%" cellpadding="15" cellspacing="0" style="margin-bottom: 25px; text-align: center; background: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
                            <tr>
                                <th colspan="2" style="background-color: {uni_color}; color: #ffffff; border-radius: 8px 8px 0 0; padding: 15px; font-size: 22px; font-weight: bold; letter-spacing: 1px;">
                                    UNIFIED THREAT POSTURE: {intel['unified_risk']}
                                </th>
                            </tr>
                            <tr>
                                <td width="50%" style="border-right: 1px solid #e0e0e0;">
                                    <span style="font-size: 11px; color: #7f8c8d; text-transform: uppercase; font-weight: bold;">Cyber & SCADA Risk</span><br>
                                    <strong style="font-size: 20px; color: {cyb_color};">{intel['cyber_score']}</strong>
                                </td>
                                <td width="50%">
                                    <span style="font-size: 11px; color: #7f8c8d; text-transform: uppercase; font-weight: bold;">Physical & Perimeter Risk</span><br>
                                    <strong style="font-size: 20px; color: {phy_color};">{intel['physical_score']}</strong>
                                </td>
                            </tr>
                        </table>

                        <div style="background-color: #f8f9fa; padding: 25px; border-radius: 8px; border-left: 5px solid #2980b9;">
                            {formatted_content}
                        </div>
                        
                        <p style="text-align: center; color: #7f8c8d; font-size: 12px; margin-top: 20px;">Generated dynamically by NOC Intelligence Fusion Center</p>
                    </div>
                    """
                    
                    success, msg = send_alert_email(f"Executive Threat Posture: {intel['unified_risk']}", html_body, recipient_override=target_email, is_html=True)
                    if success: st.success(f"Report dispatched to {target_email}")
                    else: st.error(f"SMTP Error: {msg}")
            else:
                st.warning("Please enter a recipient email address.")

    with dash_tabs[2]:
            col_title, col_admin_btn = st.columns([4, 1])
            
            with col_title:
                st.subheader("Internal Asset Risk Dashboard")
                st.caption("Active correlation of internal assets against OSINT telemetry (Auto-updates every 6 hours).")
                
            with col_admin_btn:
                # Restrict visibility to administrators only
                if st.session_state.current_role == "admin":
                    is_snap_cooling = check_cooldown("force_internal_snap", 30)
                    if st.button("Processing..." if is_snap_cooling else "Force Generate", type="primary", width='stretch', disabled=is_snap_cooling):
                        apply_cooldown("force_internal_snap")
                        with st.spinner("Calculating matrices..."):
                            svc.generate_and_save_internal_risk_snapshot()
                            time.sleep(0.5)
                            safe_rerun()
            
            with svc.SessionLocal() as dbtmp:
                from src.database import InternalRiskSnapshot
                # Fetch up to 28 historical snapshots (7 days of 6-hour intervals)
                snapshots = dbtmp.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).limit(28).all()
                
            if not snapshots:
                st.info("Internal Risk matrices are currently calculating. Please check back in a few minutes.")
                # Give admins a button to force the first calculation without waiting
                if st.button("Trigger Manual Calculation"):
                    svc.generate_and_save_internal_risk_snapshot()
                    st.success("Generated! Refreshing...")
                    time.sleep(1)
                    safe_rerun()
            else:
                import json
                latest = snapshots[0]
                
                # Parse the cached JSON payloads
                hw_data = json.loads(latest.hw_data_json)
                sw_data = json.loads(latest.sw_data_json)

               # --- DASHBOARD METRICS ---
                color_map = {"GREEN": "#28a745", "BLUE": "#007bff", "YELLOW": "#ffc107", "ORANGE": "#fd7e14", "RED": "#dc3545"}
                name_map = {"GREEN": "GREEN (LOW)", "BLUE": "BLUE (GUARDED)", "YELLOW": "YELLOW (ELEVATED)", "ORANGE": "ORANGE (HIGH)", "RED": "RED (SEVERE)"}
                
                safe_risk_level = str(latest.risk_level).upper()
                score_color = color_map.get(safe_risk_level, "#6c757d")
                display_risk = name_map.get(safe_risk_level, "UNKNOWN")
                
                st.markdown(f"""
                <div style='text-align: center; padding: 20px; background-color: #1e1e1e; border-radius: 10px; border: 2px solid {score_color}; margin-bottom: 20px;'>
                    <h3 style='margin:0; color: #a0a0a0;'>INTERNAL ASSET POSTURE (CIS STANDARD)</h3>
                    <h1 style='margin:0; font-size: 3rem; color: {score_color};'>{display_risk} [{latest.score}]</h1>
                    <p style='margin:0; color: #a0a0a0;'>Analyzed {latest.total_assets} total assets against OSINT feeds.</p>
                    <p style='margin:0; color: #a0a0a0; font-size: 0.9em; margin-top: 10px;'><i>Last Updated: {format_local_time(latest.timestamp)}</i></p>
                </div>
                """, unsafe_allow_html=True)
                
                c1, c2, c3 = st.columns(3)
                c1.metric("Total Asset Footprint", latest.total_assets)
                c2.metric("Total OSINT Correlations", latest.total_osint_hits)
                c3.metric("Critical OSINT Hits", latest.critical_osint_hits, delta_color="inverse")
                st.divider()
                
                # --- TIME SERIES GRAPH ---
                st.markdown("###  Historical Threat Trend")
                
                # Prep data for native Streamlit line chart
                df_chart = pd.DataFrame([{"Time": s.timestamp, "CIS Risk Score": s.score} for s in snapshots])
                df_chart.set_index("Time", inplace=True)
                df_chart.sort_index(inplace=True) # Ensure chronological order left-to-right
                
                st.line_chart(df_chart, width='stretch', color="#dc3545")
                st.divider()
        
                # --- HARDWARE TABLE ---
                st.markdown("###  Hardware Assets")
                with st.expander("View Hardware Inventory & OSINT Correlations", expanded=True):
                    at_risk_hw = [h for h in hw_data if h['OSINT Threat Matches'] > 0]
                    
                    if at_risk_hw:
                        df_hw = pd.DataFrame(at_risk_hw)
                        st.warning(f"Detected {len(at_risk_hw)} hardware assets actively exposed to recent OSINT intelligence.")
                        st.dataframe(df_hw, width="stretch", hide_index=True)
                    elif len(hw_data) > 0:
                        st.success("All tracked hardware assets are currently clear of recent OSINT correlations.")
                    else:
                        st.info("No hardware assets loaded. Go to Settings -> Internal Assets to import your inventory.")
    
                st.divider()
    
                # --- SOFTWARE TABLE ---
                st.markdown("###  Software Assets")
                with st.expander("View At-Risk Software", expanded=True):
                    if sw_data:
                        df_sw = pd.DataFrame(sw_data)
                        st.warning(f"Detected {len(df_sw)} software assets actively exposed to recent OSINT intelligence.")
                        st.dataframe(df_sw, width="stretch", hide_index=True)
                    else:
                        st.success("All tracked software assets are currently clear of recent OSINT correlations.")
                        
    with dash_tabs[3]:
        st.subheader("Executive Unified Risk Brief")
        st.caption("AI-generated synthesis of Global OSINT Threats and Internal Asset Vulnerabilities. Auto-updates every 2 hours.")
        
        col_btn, _ = st.columns([1, 4])
        is_brief_cooling = check_cooldown("unified_brief", 60)
        
        # Allow administrators to force a manual refresh of the 2-hour schedule
        if col_btn.button("Generating..." if is_brief_cooling else "Force Refresh Brief", disabled=not can_trigger_ai or is_brief_cooling, type="primary"):
            apply_cooldown("unified_brief")
            with st.spinner("Synthesizing Pre-Calculated Global and Internal telemetry..."):
                from src.database import InternalRiskSnapshot
                with svc.SessionLocal() as dbtmp:
                    latest_internal = dbtmp.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
                
                ar_warn = svc.get_cached_geojson()[3] or {}
                oos_warn = svc.get_cached_geojson()[4] or {}
                active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))
                crime_data = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
                global_intel = svc.get_executive_grid_intel(active_nws, crime_data)
                
                from src.llm import generate_unified_risk_brief
                brief_text = generate_unified_risk_brief(svc.SessionLocal(), global_intel, latest_internal)
                
                # Save the manual run directly to the global database configuration
                svc.save_global_config({
                    "unified_brief": brief_text,
                    "unified_brief_time": datetime.utcnow()
                })
                time.sleep(0.5)
                safe_rerun()
                
        st.divider()
        
        # Render the brief directly from memory
        if sys_config and getattr(sys_config, 'unified_brief', None):
            local_b_time = format_local_time(sys_config.unified_brief_time) if sys_config.unified_brief_time else "Unknown"
            
            with st.container(border=True):
                st.caption(f" **Last Auto-Generated:** {local_b_time}")
                st.markdown(sys_config.unified_brief)
                
            st.divider()
            
            # --- EMAIL BROADCAST FEATURE ---
            st.subheader("Broadcast Executive Brief")
            c_em1, c_em2 = st.columns([3, 1])
            default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
            ub_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="ub_recip")
            
            if c_em2.button("Transmit Brief", type="primary", width='stretch'):
                if not ub_recipients:
                    st.error("Please enter at least one recipient email.")
                else:
                    with st.spinner("Converting formatting and transmitting..."):
                        from src.database import InternalRiskSnapshot
                        current_global = None
                        current_internal = None
                        
                        with svc.SessionLocal() as dbtmp:
                            latest_internal = dbtmp.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
                            if latest_internal:
                                current_internal = latest_internal.risk_level
                            
                            ar_warn, oos_warn, _ = svc.get_cached_geojson()[3:6]
                            active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))
                            crime_data = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
                            global_intel = svc.get_executive_grid_intel(active_nws, crime_data)
                            current_global = global_intel.get('unified_risk')
                        
                        formatted_html = svc.generate_unified_brief_email_html(
                            local_b_time, sys_config.unified_brief,
                            global_risk=current_global,
                            internal_risk=current_internal
                        )
                        from src.mailer import send_alert_email
                        success, msg = send_alert_email("Executive Unified Risk Brief", formatted_html, recipient_override=ub_recipients, is_html=True)
                        if success: st.success("Brief successfully transmitted!")
                        else: st.error(f"SMTP Error: {msg}")
        else:
            st.info("Brief is currently being generated by the background scheduler. Please check back shortly or click Force Refresh.")
        
# ================= 2. THREAT TELEMETRY =================
elif page == "Threat Telemetry":
    st.title("Unified Threat Telemetry")
    tt_tab_names = []
    
    if "Tab: Threat Telemetry -> RSS Triage" in st.session_state.allowed_actions: tt_tab_names.append("RSS Triage")
    if "Tab: Threat Telemetry -> CISA KEV" in st.session_state.allowed_actions: tt_tab_names.append("Exploits (KEV)")
    if "Tab: Threat Telemetry -> Cloud Services" in st.session_state.allowed_actions: tt_tab_names.append("Cloud Services")
    if "Tab: Threat Telemetry -> Perimeter Crime" in st.session_state.allowed_actions: tt_tab_names.append("Perimeter Crime")
    
    if not tt_tab_names: 
        st.warning("No permission to view tabs in this module.")
    else:
        tabs = st.tabs(tt_tab_names)
        tab_idx = 0
        
        if "Tab: Threat Telemetry -> RSS Triage" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col_title, col_btn = st.columns([3, 1])
                is_rss_cooling = check_cooldown("sync_rss", 60)
                if col_btn.button("Syncing..." if is_rss_cooling else "Force Fetch Feeds", width="stretch", disabled=not can_sync or is_rss_cooling):
                    apply_cooldown("sync_rss")
                    with st.spinner("Fetching feeds..."):
                        fetch_feeds(source="User Force")
                        time.sleep(1)
                        safe_rerun()
                cat_filter = st.selectbox("Filter Active Feeds", [
                    "All", "Cyber: Exploits & Vulns", "Cyber: Malware & Threats", 
                    "ICS/OT & SCADA", "Cloud & IT Infra", "Physical Security", 
                    "Severe Weather", "Geopolitics & Policy", "AI & Emerging Tech", "General"
                ])
                st.divider()

                def handle_pagination(feed_id, q_type, pg_size, s_term=None, m_score=0):
                    s_key = f"page_{feed_id}"
                    if s_key not in st.session_state: st.session_state[s_key] = 1
                    items, t_items, t_pages, cur_page = svc.get_paginated_articles(q_type, cat_filter, st.session_state[s_key], pg_size, s_term, m_score)
                    st.session_state[s_key] = cur_page
                    
                    def p_ctrls(loc):
                        c1, c2, c3 = st.columns([1, 2, 1])
                        if c1.button("Previous", key=f"p_{feed_id}_{loc}", disabled=(cur_page<=1), width="stretch"): st.session_state[s_key] -= 1; safe_rerun()
                        c2.markdown(f"<div style='text-align: center; margin-top: 0.4rem;'><b>Page {cur_page} of {t_pages}</b> <span style='font-size: 0.85em; color: gray;'>(Total: {t_items})</span></div>", unsafe_allow_html=True)
                        if c3.button("Next ", key=f"n_{feed_id}_{loc}", disabled=(cur_page>=t_pages), width="stretch"): st.session_state[s_key] += 1; safe_rerun()

                    if t_items > pg_size: p_ctrls("top"); st.divider()
                    elif t_items == 0: st.info("No articles found."); return
                    render_article_feed(items, key_prefix=f"{feed_id}_")
                    if t_items > pg_size: st.divider(); p_ctrls("bot")

                s1, s2, s3, s4 = st.tabs(["Pinned", "Live", "Low", "Search"])
                with s1: handle_pagination("pinned", "pinned", 10)
                with s2: handle_pagination("live", "live", 20)
                with s3: handle_pagination("low", "low", 20)
                with s4:
                    sc1, sc2, sc3 = st.columns([2, 1, 1])
                    s_term = sc1.text_input("Search")
                    m_score = sc2.number_input("Min Score", value=0)
                    pg_sz = sc3.selectbox("Items per Page", [10, 20, 50], index=1)
                    handle_pagination("search", "search", pg_sz, s_term, m_score)
            tab_idx += 1
            
        if "Tab: Threat Telemetry -> CISA KEV" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                is_kev_cooling = check_cooldown("sync_kev", 60)
                if st.button("Syncing..." if is_kev_cooling else "Sync CISA KEV", disabled=not can_sync or is_kev_cooling, width="stretch"):
                    apply_cooldown("sync_kev")
                    with st.spinner("Fetching CISA Database..."):
                        from src.cve_worker import fetch_cisa_kev; fetch_cisa_kev(); safe_rerun()
                for cve in svc.get_cves(limit=50, days_back=30):
                    with st.expander(f" {cve.cve_id} | {cve.vendor} {cve.product}"): st.markdown(f"**{cve.vulnerability_name}**\n\n{cve.description}")
            tab_idx += 1
            
        if "Tab: Threat Telemetry -> Cloud Services" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                is_cloud_cooling = check_cooldown("sync_cloud", 60)
                if st.button("Syncing..." if is_cloud_cooling else "Sync Cloud Status", disabled=not can_sync or is_cloud_cooling, width="stretch"):
                    apply_cooldown("sync_cloud")
                    with st.spinner("Pulling data from Global Providers..."):
                        from src.cloud_worker import fetch_cloud_outages; fetch_cloud_outages(); safe_rerun()
                
                raw_outages = svc.get_cloud_outages(active_only=True)
                active_outages = []
                now = datetime.utcnow()
                today_fmts = [now.strftime("%b %d").lower(), now.strftime("%B %d").lower(), now.strftime("%Y-%m-%d"), now.strftime("%m/%d/%Y")]
                
                for o in raw_outages:
                    text = (o.title + " " + str(o.description)).lower()
                    is_maint = any(k in text for k in ["maintenance", "scheduled", "upcoming", "update"])
                    is_active = any(k in text for k in ["in progress", "started", "currently undergoing"])
                    if is_maint and not is_active and not any(fmt in text for fmt in today_fmts): continue 
                    active_outages.append(o)

                if not active_outages: 
                    st.success("All tracked global SaaS and IaaS providers are reporting Operational status.")
                else:
                    affected_providers = sorted(list(set([o.provider for o in active_outages])))
                    st.warning(f"Active service degradations detected across {len(affected_providers)} providers.")
                    provider_tabs = st.tabs(affected_providers)
                    for p_idx, provider_name in enumerate(affected_providers):
                        with provider_tabs[p_idx]:
                            prov_outs = [o for o in active_outages if o.provider == provider_name]
                            for o in prov_outs:
                                with st.expander(f" {o.service} ({format_local_time(o.updated_at)})"):
                                    st.markdown(f"**[{o.title}]({o.link})**\n\n{o.description}")
                                    
                st.divider()
                with st.expander("View Historical / Resolved Incidents (Last 72 Hours)"):
                    all_recent_outages = svc.get_cloud_outages(active_only=False, limit=100)
                    resolved_outages = [o for o in all_recent_outages if o.is_resolved]
                    if not resolved_outages: st.info("No recently resolved incidents.")
                    for o in resolved_outages:
                        st.markdown(f" **{o.provider}** | {o.service} <br><small>[{o.title}]({o.link})</small>", unsafe_allow_html=True)
            tab_idx += 1

        if "Tab: Threat Telemetry -> Perimeter Crime" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.subheader("Perimeter Crime Telemetry")
                    st.caption("LRPD incident aggregation geofenced around HQ (Last 7 Days - All Categories).")
                with col2:
                    radius_filter = st.selectbox("Geofence Radius", [1, 3, 5, 10], index=0, format_func=lambda x: f"{x} Miles")
                with col3:
                    st.write("")
                    if st.button("Force Fetch LRPD", width='stretch'):
                        with st.spinner("Polling Little Rock Dispatches..."):
                            if svc.force_fetch_crime_data():
                                st.success("Sync Complete!")
                                safe_rerun() 
                            else:
                                st.error("Fetch Failed. Check Logs.")

                # MAP RULE: Shows all crime from the last 168 hours (7 days) based on selected radius
                crime_data = svc.get_recent_crimes(max_distance=radius_filter, grid_only=False, hours_back=168)
                
                if not crime_data:
                    st.success(f"No crime incidents logged within {radius_filter} miles of HQ in the last 7 days.")
                else:
                    # 1. We must instantiate the dataframe first!
                    df_crimes = pd.DataFrame(crime_data)
                    
                    # 2. Check to ensure we have valid coordinates
                    if "lat" not in df_crimes.columns or "lon" not in df_crimes.columns:
                        st.error("Coordinate data missing from cache! Please run `python src/crime_worker.py` in your terminal to fetch fresh geometry.")
                    else:
                        df_crimes = df_crimes.dropna(subset=['lat', 'lon'])
                        layers, view_state = svc.build_crime_map_layers(df_crimes)
                        
                        # Auto-zoom the map slightly if they select a massive radius
                        map_zoom = 15.5 if radius_filter == 1 else 13.5 if radius_filter == 3 else 12.0
                        view_state.zoom = map_zoom
                        
                        # Create a placeholder container for the map so we can draw it AFTER getting table selection
                        map_container = st.container()
                        
                        st.divider()
                        st.subheader(f"Raw Incident Logs ({radius_filter} Mile Radius)")
                        display_crimes = df_crimes[["timestamp", "distance_miles", "category", "severity", "raw_title"]]
                        
                        # Add selection parameters to the dataframe
                        event = st.dataframe(
                            display_crimes, 
                            width='stretch', 
                            hide_index=True,
                            on_select="rerun",
                            selection_mode="single-row"
                        )
                        
                        # Check if a row was clicked, then dynamically alter the map state
                        if event.selection.rows:
                            selected_idx = event.selection.rows[0]
                            selected_crime = df_crimes.iloc[selected_idx]
                            
                            # Re-center and zoom the map onto the crime
                            view_state.latitude = selected_crime['lat']
                            view_state.longitude = selected_crime['lon']
                            view_state.zoom = 17 
                            
                            # Add a high-visibility pulse ring on the selected target
                            highlight_layer = pdk.Layer(
                                "ScatterplotLayer",
                                data=[{"lat": selected_crime['lat'], "lon": selected_crime['lon']}],
                                get_position='[lon, lat]',
                                get_fill_color='[255, 0, 0, 200]',
                                get_line_color='[255, 255, 255, 255]',
                                stroked=True,
                                line_width_min_pixels=3,
                                get_radius=40,
                                pickable=False
                            )
                            layers.append(highlight_layer)
                        
                        # Render the map inside the container we created at the top
                        with map_container:
                            st.pydeck_chart(pdk.Deck(
                                layers=layers, 
                                initial_view_state=view_state, 
                                tooltip={"html": "<b>{raw_title}</b><br/>{timestamp}<br/>Dist: {distance_miles} miles"}
                            ), width='stretch')
            tab_idx += 1

elif page == "Regional Grid":
    st.title("Regional Grid & Hazard Analytics")
    
    col_sync1, col_sync2 = st.columns([3, 1])
    is_infra_cooling = check_cooldown("sync_infra", 60)
    if col_sync2.button("Syncing..." if is_infra_cooling else "Sync Regional Telemetry", disabled=not can_sync or is_infra_cooling, key="tt_sync_infra", width="stretch"):
        apply_cooldown("sync_infra")
        with st.spinner("Pulling Radar & Calculating Geospatial Intersections..."):
            from src.infra_worker import fetch_regional_hazards
            fetch_regional_hazards()
            time.sleep(1)
            svc.get_cached_geojson.clear()
            safe_rerun()
    
    locs = svc.get_cached_locations()
    if st.session_state.allowed_site_types != "ALL":
        locs = [l for l in locs if l.loc_type in st.session_state.allowed_site_types]
        
    df = pd.DataFrame([{
        "id": l.id, "Name": l.name, "Type": l.loc_type, "District": l.district,
        "Priority": l.priority, "Risk": l.current_spc_risk, 
        "Lat": l.lat, "Lon": l.lon
    } for l in locs]) if locs else pd.DataFrame()
    
    # Unpack all 5 variables to support Atmos Weather predictive layers
    spc_d1, spc_d2, spc_d3, ar_data, oos_data, usgs_ar_data, usgs_oos_data = svc.get_cached_geojson()
    spc_data = spc_d1 # Preserve the main grid's dependency on Day 1
    
    active_event_types = set()
    for geo_dataset in [ar_data, oos_data]:
        if geo_dataset:
            for f in geo_dataset.get("features", []):
                active_event_types.add(f.get("properties", {}).get("event", "Unknown"))
    active_event_types = sorted(list(active_event_types))

    rg_tab_names = []
    if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions: rg_tab_names.append("Geospatial Overlay")
    if "Tab: Regional Grid -> Executive Dash" in st.session_state.allowed_actions: rg_tab_names.append("Executive Dashboard")
    if "Tab: Regional Grid -> Hazard Analytics" in st.session_state.allowed_actions: rg_tab_names.append("Deep Hazard Analytics")
    if "Tab: Regional Grid -> Location Matrix" in st.session_state.allowed_actions: rg_tab_names.append("Location Matrix")
    if "Tab: Regional Grid -> Weather Alerts Log" in st.session_state.allowed_actions: rg_tab_names.append("Weather Alerts Log")
    if "Tab: Regional Grid -> Atmos Weather" in st.session_state.allowed_actions: rg_tab_names.append("Atmos Weather")

    if not rg_tab_names:
        st.warning("You do not have permission to view any modules within the Regional Grid.")
    else:
        rg_tabs = st.tabs(rg_tab_names)
        rg_idx = 0
        
        # Define default variables so background tabs still function safely even if the map tab isn't viewed
        map_toggles = {"radar": False, "spc": False, "warn": False, "watch": False, "oos": False, "fire_risk": False, "active_wildfires": False, "earthquakes": True}
        selected_events = active_event_types
        map_df = df.copy()
        show_radar_panel = False

        if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                c_ctrl, c_map_main = st.columns([1, 4])
                
                with c_ctrl:
                    st.subheader("Map Controls")
                    with st.container(border=True):
                        st.markdown("**Master Layers**")
                        map_toggles["radar"] = st.toggle("Radar Overlay", value=False)
                        show_radar_panel = st.toggle("Animated Panel", value=False)
                        st.divider()
                        map_toggles["spc"] = st.toggle("SPC Convective", value=False)
                        map_toggles["warn"] = st.toggle("Warnings (AR)", value=False)
                        map_toggles["watch"] = st.toggle("Watches (AR)", value=False)
                        map_toggles["oos"] = st.toggle("Out-of-State", value=False)
                        
                        st.divider()
                        map_toggles["fire_risk"] = st.toggle("NWS Fire Weather & Red Flags", value=False)
                        map_toggles["active_wildfires"] = st.toggle("Active Wildfires (NIFC)", value=False)
                        map_toggles["earthquakes"] = st.toggle("Earthquakes (USGS)", value=True)
                        
                        if map_toggles["fire_risk"] or map_toggles["active_wildfires"] or map_toggles["earthquakes"]:
                            with st.container(border=True):
                                st.markdown("** Fire Desk Legend:**")
                                if map_toggles["fire_risk"]:
                                    st.markdown(" **Red Flag Warning** *(Extreme/Burn Ban)*")
                                    st.markdown(" **Fire Weather Watch** *(High Risk)*")
                                if map_toggles["active_wildfires"]:
                                    st.markdown(" **Active Wildfire** *(Scales by Acreage)*")
                                if map_toggles["earthquakes"]:
                                    st.markdown(" **Earthquake** *(Blue: M2-3, Yellow: M3-4, Orange: M4-5, Red: M5+)*")
                    
                    with st.container(border=True):
                        st.markdown("**Hazard Isolation**")
                        if not active_event_types:
                            st.info("No active hazards to filter.")
                            selected_events = []
                        else:
                            selected_events = st.multiselect("Active Threats", active_event_types, default=active_event_types, label_visibility="collapsed")
                    
                    with st.container(border=True):
                        st.markdown("**Facility Filters**")
                        if not df.empty:
                            available_types = df['Type'].unique().tolist()
                            available_prios = sorted(df['Priority'].unique().tolist())
                            selected_types = st.multiselect("Facility Type", available_types, default=available_types)
                            selected_prios = st.multiselect("Priority Level", available_prios, default=available_prios)
                            map_df = df[df['Type'].isin(selected_types) & df['Priority'].isin(selected_prios)].copy()
                            map_df['info'] = map_df['Name'] + "\nType: " + map_df['Type'] + "\nRisk: " + map_df['Risk']
                        else:
                            map_df = df.copy()

        # Compile map data globally so other tabs can use master_affected_sites seamlessly
        layers, view_state, map_diagnostics, toggled_affected_sites, master_affected_sites = svc.compile_regional_grid_map(
            map_df, spc_data, ar_data, oos_data, usgs_ar_data, usgs_oos_data, selected_events, map_toggles
        )

        # Now resume rendering the Map tab!
        if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions:
            with c_map_main:
                if show_radar_panel:
                    cm1, cm2 = st.columns([2, 1])
                    with cm1:
                        st.subheader("Live Threat Overlay")
                        st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{info}"}), width="stretch")
                    with cm2:
                        st.subheader("Precipitation Loop")
                        components.html("""<iframe src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" width="100%" height="500" frameborder="0" style="border-radius: 8px;" allowfullscreen></iframe>""", height=500)
                else:
                    st.subheader("Live Threat Overlay")
                    st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{info}"}), width="stretch")
                
                st.divider()
                st.subheader("Sites Impacted by Currently Toggled Layers")
                st.caption("This table dynamically updates based on the layer switches and filters in the left sidebar.")
                
                if not toggled_affected_sites: 
                    st.success("No sites intersect with the specific layers and hazard types currently rendered on the map.")
                else: 
                    st.dataframe(pd.DataFrame(toggled_affected_sites).sort_values(by=['Priority', 'Monitored Site']), hide_index=True, width="stretch")
            rg_idx += 1

        if "Tab: Regional Grid -> Executive Dash" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Executive Infrastructure Threat Dashboard")
                st.markdown("Holistic situational overview of physical asset exposure parsed by District and Priority.")
                
                if map_df.empty:
                    st.info("No monitored locations match current filters.")
                else:
                    import plotly.express as px
                    import plotly.graph_objects as go
                    
                    analytics = svc.get_infrastructure_analytics(map_df, master_affected_sites)
                    
                    p1_at_risk = len(set(site['Monitored Site'] for site in master_affected_sites if site['Priority'] == 1))
                    total_at_risk = analytics.get("at_risk_sites", 0)
                    total_sites = analytics.get("total_sites", 0)
                    risk_pct = round((total_at_risk / total_sites) * 100, 1) if total_sites > 0 else 0
                    
                    with st.container(border=True):
                        c_kpi1, c_kpi2, c_kpi3, c_kpi4 = st.columns(4)
                        c_kpi1.metric("Total Tracked Assets", total_sites)
                        c_kpi2.metric("Assets in Active Risk Zones", total_at_risk, f"{risk_pct}% Exposure", delta_color="inverse")
                        c_kpi3.metric("Critical (P1) Assets at Risk", p1_at_risk, "Immediate Attention" if p1_at_risk > 0 else "Clear", delta_color="inverse")
                        c_kpi4.metric("Highest Regional Risk", analytics["highest_risk"])
                    
                    st.divider()
                    
                    st.markdown("###  AI Executive Weather Briefing")
                    c_ai_text, c_ai_btn = st.columns([4, 1])
                    
                    if "exec_weather_brief" not in st.session_state:
                        st.session_state.exec_weather_brief = "Click 'Generate Briefing' to synthesize current telemetry."
                        
                    if c_ai_btn.button("Generate Briefing", type="primary", width='stretch', disabled=not ai_enabled):
                        with st.spinner("Synthesizing meteorological telemetry..."):
                            st.session_state.exec_weather_brief = generate_executive_weather_brief(analytics, p1_at_risk, sys_config)
                            safe_rerun()
                            
                    st.info(st.session_state.exec_weather_brief)
                    
                    st.divider()
                    
                    c_viz1, c_viz2, c_viz3 = st.columns(3)
                    color_map_spc = {"HIGH": "#dc3545", "MDT": "#e67e22", "ENH": "#f39c12", "SLGT": "#f1c40f", "MRGL": "#17a2b8", "TSTM": "#28a745", "None": "#6c757d"}
                    color_map_nws = {"WARNING": "#dc3545", "WATCH": "#f39c12", "ADVISORY": "#f1c40f", "STATEMENT": "#17a2b8", "None": "#6c757d"}
                    
                    with c_viz1:
                        st.markdown(f"**SPC Risk (Total Sites: {total_sites})**")
                        if not analytics["spc_distribution"].empty:
                            fig_spc = px.pie(analytics["spc_distribution"], values='count', names='SPC Risk', hole=0.6, color='SPC Risk', color_discrete_map=color_map_spc)
                            fig_spc.update_layout(margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5))
                            st.plotly_chart(fig_spc, width='stretch')
                        else: st.success("All Clear.")
                            
                    with c_viz2:
                        st.markdown(f"**NWS Alerts (Total Sites: {total_sites})**")
                        if not analytics["nws_distribution"].empty:
                            fig_nws = px.pie(analytics["nws_distribution"], values='count', names='NWS Alert', hole=0.6, color='NWS Alert', color_discrete_map=color_map_nws)
                            fig_nws.update_layout(margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5))
                            st.plotly_chart(fig_nws, width='stretch')
                        else: st.success("All Clear.")
                            
                    with c_viz3:
                        st.markdown("**At-Risk Assets by District**")
                        if not analytics["district_distribution"].empty:
                            fig_dist = px.bar(analytics["district_distribution"].reset_index(), x='District', y='Count', color_discrete_sequence=['#1f77b4'])
                            fig_dist.update_layout(margin=dict(t=10, b=10, l=10, r=10), xaxis_title="", yaxis_title="")
                            st.plotly_chart(fig_dist, width='stretch')
                        else: st.success("All Clear.")

                    st.divider()
                    
                    st.markdown("###  Broadcast Executive SitRep")
                    st.caption("Dispatches the KPIs, AI Briefing, and HTML Visual Breakdowns directly to leadership.")
                    
                    with st.form("exec_dash_email"):
                        c_em1, c_em2 = st.columns([2, 1])
                        default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
                        target_email = c_em1.text_input("Recipient Email(s)", value=default_email)
                        custom_notes = st.text_area("Additional Analyst Notes (Optional)", placeholder="Add any specific context or instructions here...")
                        
                        if st.form_submit_button("Transmit Report", type="primary", disabled=not ("Action: Dispatch Exec Report" in st.session_state.allowed_actions)):
                            if not target_email:
                                st.error("Please provide a recipient email address.")
                            else:
                                with st.spinner("Compiling HTML visual graphs and transmitting..."):
                                    
                                    # Native HTML Bar Chart Builder for Email Clients
                                    def build_html_bar_chart(df, label_col, count_col, c_map, title):
                                        total = df[count_col].sum()
                                        if total == 0: return ""
                                        html = f"<h3 style='color:#2980b9; margin-bottom: 5px;'>{title}</h3>"
                                        html += "<table style='width:100%; border-collapse: collapse; font-family: Arial, sans-serif; margin-bottom: 20px;'>"
                                        for _, row in df.iterrows():
                                            label, count = row[label_col], row[count_col]
                                            if count == 0: continue
                                            pct = int((count / total) * 100)
                                            color = c_map.get(label, "#6c757d")
                                            html += f"<tr>"
                                            html += f"<td style='width:20%; padding: 4px 0; font-size:13px; font-weight:bold; color:#444;'>{label}</td>"
                                            html += f"<td style='width:70%; padding: 4px 10px;'><div style='background-color:#e9ecef; width:100%; border-radius:3px;'><div style='background-color:{color}; width:{pct}%; height:18px; border-radius:3px;'></div></div></td>"
                                            html += f"<td style='width:10%; padding: 4px 0; font-size:13px; text-align:right; font-weight:bold; color:#333;'>{count}</td>"
                                            html += f"</tr>"
                                        html += "</table>"
                                        return html
                                    
                                    spc_html = build_html_bar_chart(analytics["spc_distribution"], "SPC Risk", "count", color_map_spc, f"SPC Convective Risk (Total Sites: {total_sites})")
                                    nws_html = build_html_bar_chart(analytics["nws_distribution"], "NWS Alert", "count", color_map_nws, f"NWS Hazard Alerts (Total Sites: {total_sites})")

                                    html_body = f"""
                                    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
                                        <h2 style='color:#2c3e50;'>Executive Grid Threat Report</h2>
                                        <div style='background:#f8f9fa; padding:15px; border-left:4px solid #d9534f; margin-bottom: 20px;'>
                                            <b>Total Assets Monitored:</b> {total_sites}<br/>
                                            <b>Assets at Risk:</b> {total_at_risk} ({risk_pct}%)<br/>
                                            <b>Critical (P1) Exposures:</b> {p1_at_risk}<br/>
                                            <b>Highest Threat Level:</b> {analytics["highest_risk"]}
                                        </div>
                                        
                                        {spc_html}
                                        {nws_html}
                                        
                                        <div style="background-color: #ffffff; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px; margin-top: 20px;">
                                            <h3 style='color:#2980b9; margin-top: 0;'>AI Meteorological Brief</h3>
                                            <p style='color: #495057; line-height: 1.5;'>{st.session_state.exec_weather_brief.replace(chr(10), '<br>')}</p>
                                        </div>
                                        
                                        <h3 style='color:#2980b9;'>Analyst Notes</h3>
                                        <p style='color: #495057; line-height: 1.5;'>{custom_notes.replace(chr(10), '<br>') if custom_notes else 'None provided.'}</p>
                                    </div>
                                    """
                                    from src.mailer import send_alert_email
                                    success, msg = send_alert_email("Executive Weather & Infrastructure SitRep", html_body, recipient_override=target_email, is_html=True)
                                    if success: st.success(f"Report dispatched to {target_email}")
                                    else: st.error(f"SMTP Error: {msg}")

                    with st.expander("View Raw Matrices & Export Data"):
                        st.write("")
                        cx1, cx2, cx3 = st.columns(3)
                        with cx1:
                            st.markdown("**Risk by Priority Level**")
                            st.dataframe(analytics["priority_risk_matrix"], width="stretch")
                        with cx2:
                            st.markdown("**Risk by District**")
                            st.dataframe(analytics["district_risk_matrix"], width="stretch")
                        with cx3:
                            st.markdown("**Risk by Facility Type**")
                            st.dataframe(analytics["type_risk_matrix"], width="stretch")
            rg_idx += 1

        if "Tab: Regional Grid -> Hazard Analytics" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Deep Hazard Analytics & Executive Broadcast")
                st.markdown("Comprehensive breakdown of active weather geometry against physical infrastructure.")
                
                if not master_affected_sites:
                    st.success("All infrastructure is currently clear of severe weather geometry based on your current filters.")
                else:
                    analytics_df = pd.DataFrame(master_affected_sites).drop_duplicates()
                    
                    p1_count = len(analytics_df[analytics_df['Priority'] == 1]['Monitored Site'].unique())
                    p2_count = len(analytics_df[analytics_df['Priority'] == 2]['Monitored Site'].unique())
                    
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Total Sites Impacted", len(analytics_df['Monitored Site'].unique()))
                    c2.metric("Critical (P1) Impacts", p1_count, delta="High Risk" if p1_count > 0 else None, delta_color="inverse")
                    c3.metric("High (P2) Impacts", p2_count)
                    c4.metric("Unique Hazards", len(analytics_df['Hazard'].unique()))
                    
                    st.divider()
                    
                    st.write("**Complete Intersectional Dataset**")
                    st.dataframe(analytics_df.sort_values(by=['Priority', 'Severity', 'Monitored Site']), width="stretch", hide_index=True)
                    
                    st.divider()
                    st.subheader("Broadcast Executive HTML SitRep")
                    st.caption("Generates a boardroom-ready HTML email containing the filtered hazard data.")
                    
                    c_em1, c_em2 = st.columns([2, 1])
                    default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
                    sitrep_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="sitrep_recip")
                    
                    if c_em2.button("Transmit Priority SitRep", type="primary", width='stretch'):
                        if not sitrep_recipients:
                            st.error("Please enter at least one recipient email.")
                        else:
                            with st.spinner("Compiling HTML and transmitting..."):
                                html_safe = svc.generate_hazard_sitrep_html(analytics_df)
                                from src.mailer import send_alert_email
                                success, msg = send_alert_email("URGENT: Active Severe Weather Impacting Operations", html_safe, recipient_override=sitrep_recipients, is_html=True)
                                if success: st.success("Executive HTML SitRep successfully transmitted!")
                                else: st.error(f"SMTP Error: {msg}")
            rg_idx += 1

        if "Tab: Regional Grid -> Location Matrix" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Active Infrastructure Matrix")
                st.caption("All tracked locations overlaid with current SPC Convective Outlooks.")
                if not map_df.empty:
                    display_df = map_df.drop(columns=['id', 'Lat', 'Lon', 'info'])
                    st.dataframe(display_df.sort_values(by=['Risk', 'Priority'], ascending=[True, True]), width="stretch", hide_index=True)
            rg_idx += 1

        if "Tab: Regional Grid -> Weather Alerts Log" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Comprehensive Weather Alerts Log")
                st.markdown("Human-readable log of all active NWS Watches, Warnings, and Special Weather Statements.")
                
                all_alert_details = svc.get_weather_alerts_log(ar_data, oos_data, selected_events, usgs_ar_data, usgs_oos_data)
                
                if not all_alert_details:
                    st.success("No active weather alerts matching your current hazard filters.")
                else:
                    df_alerts = pd.DataFrame(all_alert_details)
                    
                    for col in ['Effective', 'Expires']:
                        parsed_dates = pd.to_datetime(df_alerts[col], errors='coerce', utc=True)
                        df_alerts[col] = parsed_dates.dt.tz_convert(LOCAL_TZ).dt.strftime('%Y-%m-%d %H:%M')
                        df_alerts[col] = df_alerts[col].fillna("N/A")
                        
                    st.dataframe(df_alerts[["Event", "Severity", "Affected Area", "Expires", "Headline"]], hide_index=True, width="stretch")
                    
                    st.divider()
                    st.subheader("Deep Dive Inspection")
                    
                    dropdown_options = [f"{a['Event']} - {a['Affected Area'][:40]}..." for a in all_alert_details]
                    sel_alert_idx = st.selectbox("Select Alert to Review Full Details", range(len(dropdown_options)), format_func=lambda x: dropdown_options[x])
                    
                    if sel_alert_idx is not None:
                        details = all_alert_details[sel_alert_idx]
                        with st.container(border=True):
                            st.markdown(f"### {details['Event']}")
                            st.write(f"**Affected Zones/Counties:** {details['Affected Area']}")
                            st.write(f"**Severity:** {details['Severity']} | **Certainty:** {details['Certainty']}")
                            st.write(f"**Effective:** {details['Effective']} | **Expires:** {details['Expires']}")
                            
                            st.divider()
                            st.markdown("**NWS Description:**\n\n> " + details['Description'].replace('\n', '\n> '))
                            
                            if details['Instructions'] and details['Instructions'] != "No explicit instructions provided.":
                                st.error(f"**NWS Actionable Instructions:**\n\n{details['Instructions']}")
            rg_idx += 1

        if "Tab: Regional Grid -> Atmos Weather" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Atmos Weather & Alerts")
                st.markdown("Integrated lightweight weather platform for live US alerts and personalized browser notifications.")
                
                st.components.v1.html("""
                    <div style="text-align: right;">
                        <button onclick="requestPerms()" style="padding: 8px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: sans-serif;"> Enable Browser Notifications</button>
                    </div>
                    <script>
                        function requestPerms() {
                            if ("Notification" in window) {
                                Notification.requestPermission().then(permission => {
                                    if (permission === "granted") {
                                        new Notification("Atmos Weather", {body: "Browser notifications enabled successfully!"});
                                    }
                                });
                            } else {
                                alert("Your browser does not support desktop notifications.");
                            }
                        }
                    </script>
                """, height=50)

                st.divider()
                
                c_prefs, c_alerts = st.columns([1, 2])
                
                with c_prefs:
                    st.markdown("###  Alert Preferences")
                    st.caption("Select which NWS event types should trigger browser push notifications.")
                    
                    user_prefs = svc.get_user_weather_prefs(st.session_state.current_user)
                    available_events = [
                        "Tornado Warning", "Severe Thunderstorm Warning", "Flash Flood Warning", 
                        "Special Marine Warning", "Snow Squall Warning", "Winter Storm Warning",
                        "Ice Storm Warning", "Blizzard Warning", "Red Flag Warning", "Hurricane Warning",
                        "Severe Weather Statement", "Severe Thunderstorm Watch", "Tornado Watch"
                    ]
                    
                    with st.form("atmos_prefs_form"):
                        selected_alerts = st.multiselect("Notify me for:", available_events, default=[e for e in user_prefs if e in available_events])
                        if st.form_submit_button("Save Preferences", width="stretch", type="primary"):
                            svc.set_user_weather_prefs(st.session_state.current_user, selected_alerts)
                            st.success("Preferences saved!")
                            time.sleep(0.5)
                            safe_rerun()
                            
                with c_alerts:
                    st.markdown("###  Active Watched Alerts")
                    
                    if not selected_alerts:
                        st.info("No alert types selected. Update your preferences to track specific warnings.")
                    else:
                        # Use the new spatial filtering logic to populate the visual list
                        all_logs = svc.get_filtered_notification_alerts(
                            st.session_state.current_user, ar_data, oos_data, map_df.to_dict('records') if not map_df.empty else locs
                        )
                        
                        if not all_logs:
                            st.success("No active alerts matching your preferences in the monitored zones.")
                        else:
                            for alert in all_logs:
                                with st.container(border=True):
                                    st.markdown(f"** {alert['Event']}**")
                                    st.caption(f"**Area:** {alert['Affected Area']} | **Expires:** {alert['Expires']}")
                                    with st.expander("Read NWS Description"):
                                        st.write(alert['Description'])
                                        
                    st.divider()

                # --- 7-DAY SITE FORECAST ---
                st.markdown("###  Site-Specific 7-Day Forecast")
                if not map_df.empty:
                    site_names = map_df['Name'].tolist()
                    default_idx = site_names.index("LR - Campus") if "LR - Campus" in site_names else 0
                    
                    target_site = st.selectbox("Select Monitored Facility", site_names, index=default_idx)
                    site_data = map_df[map_df['Name'] == target_site].iloc[0]
                    
                    forecast_data = svc.get_nws_forecast(site_data['Lat'], site_data['Lon'])
                    
                    if forecast_data:
                            # NWS provides up to 14 periods for a 7-day forecast.
                            max_periods = min(len(forecast_data), 14)
                            chunk_size = 7 # Break into rows of 7 to keep the UI clean
                            
                            for i in range(0, max_periods, chunk_size):
                                chunk = forecast_data[i:i + chunk_size]
                                cols = st.columns(len(chunk))
                                
                                for j, col in enumerate(cols):
                                    period = chunk[j]
                                    with col:
                                        with st.container(border=True):
                                            st.markdown(f"<div style='text-align:center; font-weight:bold; font-size:1.05em; color: #333;'>{period['name']}</div>", unsafe_allow_html=True)
                                            
                                            if 'icon' in period:
                                                st.markdown(f"<div style='text-align:center;'><img src='{period['icon']}' style='border-radius:15px; width:65px; height:65px; margin:10px 0; box-shadow: 0px 4px 6px rgba(0,0,0,0.1);'></div>", unsafe_allow_html=True)
                                                
                                            temp_color = "#dc3545" if period['isDaytime'] else "#007bff"
                                            st.markdown(f"<div style='text-align:center; color:{temp_color}; font-size:1.4em; font-weight:bold; margin-bottom:5px;'>{period['temperature']}{period['temperatureUnit']}</div>", unsafe_allow_html=True)
                                            
                                            st.markdown(f"<div style='text-align:center; font-size:0.85em; color:#555; line-height: 1.2;'>{period['shortForecast']}</div>", unsafe_allow_html=True)
                                            st.markdown(f"<div style='text-align:center; font-size:0.75em; color:#888; margin-top:8px;'> {period.get('windSpeed', '')} {period.get('windDirection', '')}</div>", unsafe_allow_html=True)
                                        
                            with st.expander("View Detailed Forecast Descriptions"):
                                # Ensure the detailed view also shows all 14 periods
                                for period in forecast_data[:14]:
                                    border_color = '#dc3545' if period['isDaytime'] else '#007bff'
                                    st.markdown(f"""
                                    <div style="padding: 15px; margin-bottom: 12px; border-left: 5px solid {border_color}; background-color: #f8f9fa; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
                                        <div style="font-size: 1.05em; font-weight: 600; color: #2c3e50; margin-bottom: 6px;">{period['name']}</div>
                                        <div style="font-size: 0.95em; color: #444; line-height: 1.5;">{period['detailedForecast']}</div>
                                    </div>
                                    """, unsafe_allow_html=True)
                    else:
                        st.warning("Forecast unavailable for this location. Ensure coordinates are exact.")
                else:
                    st.info("No facilities loaded. Add facilities in Settings to view site forecasts.")

                st.divider()
                
                # --- PREDICTIVE SPC OUTLOOKS ---
                st.markdown("###  Predictive Convective Outlooks (SPC)")
                st.caption("NOAA Storm Prediction Center risk areas projected out to 72 hours.")
                
                d1_tab, d2_tab, d3_tab = st.tabs(["Day 1 (Today)", "Day 2 (Tomorrow)", "Day 3"])
                
                def render_spc_map(geojson_data):
                    valid_geo = geojson_data if geojson_data and 'features' in geojson_data else {"type": "FeatureCollection", "features": []}
                    
                    if not valid_geo['features']:
                        st.success("No Convective Risk Expected for this period.")
                        
                    color_map = {
                        "TSTM": [192, 232, 192, 150], "MRGL": [124, 205, 124, 180], 
                        "SLGT": [246, 246, 123, 180], "ENH": [230, 153, 0, 180], 
                        "MDT": [255, 0, 0, 180], "HIGH": [255, 0, 255, 180]
                    }
                    
                    for f in valid_geo['features']:
                        lbl = f.get('properties', {}).get('LABEL', '')
                        f['properties']['fill_color'] = color_map.get(lbl, [0, 0, 0, 0])
                        
                    layer = pdk.Layer(
                        "GeoJsonLayer", valid_geo, pickable=True, stroked=True, filled=True,
                        get_fill_color="properties.fill_color", get_line_color=[0, 0, 0, 255], line_width_min_pixels=1
                    )
                    
                    st.pydeck_chart(pdk.Deck(
                        layers=[layer], 
                        initial_view_state=pdk.ViewState(latitude=38.0, longitude=-95.0, zoom=3.5),
                        tooltip={"text": "Risk Level: {LABEL}"}
                    ))

                with d1_tab: render_spc_map(spc_d1)
                with d2_tab: render_spc_map(spc_d2)
                with d3_tab: render_spc_map(spc_d3)

                st.divider()
                
                st.markdown("###  Live Atmospheric Radar")
                st.components.v1.html("""
                    <iframe src="https://embed.windy.com/embed.html?type=map&location=coordinates&metricRain=in&metricTemp=F&metricWind=mph&zoom=5&overlay=radar&product=radar&level=surface&lat=34.746&lon=-92.289" width="100%" height="500" frameborder="0" style="border-radius: 8px;"></iframe>
                """, height=600)
                st.divider()
            rg_idx += 1

# ================= 3. THREAT HUNTING & IOCS =================
elif page == "Threat Hunting & IOCs":
    st.title("Active Threat Hunting & Detection Engineering")
    st.markdown("Automated IOC extraction, 1-Click OSINT Pivoting, and LLM-assisted YARA/SIEM generation.")
    
    th_tab_names = []
    
    if "Tab: Threat Hunting -> Global IOC Matrix" in st.session_state.allowed_actions: th_tab_names.append("Live Global IOC Matrix")
    if "Tab: Threat Hunting -> Deep Hunt Builder" in st.session_state.allowed_actions: th_tab_names.append("Deep Hunt & Detection Builder")
    if "Tab: Reporting -> Elastic SIEM Report" in st.session_state.allowed_actions: th_tab_names.append("Elastic SIEM Report")
    
    if not th_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        th_tabs = st.tabs(th_tab_names)
        th_idx = 0
        
        if "Tab: Threat Hunting -> Global IOC Matrix" in st.session_state.allowed_actions:
            with th_tabs[th_idx]:
                st.subheader("Global Indicators of Compromise (Last 72 Hours)")
                
                ioc_data = svc.get_iocs(days_back=3)
                if not ioc_data:
                    st.info("No active IOCs extracted in the last 72 hours.")
                else:
                    for ioc in ioc_data: 
                        ioc["OSINT Pivot"] = svc.get_osint_pivot_link(ioc["Type"], ioc["Indicator"])
                    
                    df = pd.DataFrame(ioc_data)
                    all_types = sorted(list(set(df["Type"].tolist())))
                    default_types = [t for t in all_types if t in ["IPv4", "SHA256", "Domain", "CVE", "MITRE ATT&CK"]]
                    
                    filter_type = st.multiselect("Filter by Threat Type", all_types, default=default_types if default_types else all_types)
                    filtered_df = df[df["Type"].isin(filter_type)]
                    
                    st.dataframe(
                        filtered_df, width="stretch", hide_index=True,
                        column_config={
                            "Source Article": st.column_config.LinkColumn("Source Intel"),
                            "OSINT Pivot": st.column_config.LinkColumn("Investigate ", display_text="Open Tool"),
                            "Context": st.column_config.TextColumn("Context Snippet", width="large")
                        }
                    )
                    st.download_button(
                        label="Export Hunting Targets (CSV)", 
                        data=filtered_df.drop(columns=["OSINT Pivot"]).to_csv(index=False).encode('utf-8'), 
                        file_name=f"Hunt_Targets_{datetime.now(LOCAL_TZ).strftime('%Y%m%d')}.csv", mime='text/csv', width="stretch"
                    )
            th_idx += 1

        if "Tab: Threat Hunting -> Deep Hunt Builder" in st.session_state.allowed_actions:
            with th_tabs[th_idx]:
                st.subheader("Targeted LLM Deep Hunt & Detection Engine")
                with st.form("manual_hunt_form"):
                    hunt_target = st.text_input("Target Entity (e.g., 'Volt Typhoon', 'Ivanti Connect Secure')")
                    hunt_depth = st.slider("Historical Depth (Days)", min_value=7, max_value=90, value=30)
                    
                    is_hunt_cooling = check_cooldown("deep_hunt", 60)
                    if st.form_submit_button("Compiling..." if is_hunt_cooling else "Compile Detection Package", type="primary", disabled=not can_trigger_ai or is_hunt_cooling, width="stretch"):
                        apply_cooldown("deep_hunt")
                        if not hunt_target: st.error("Please enter a target entity.")
                        elif not ai_enabled: st.error("AI Engine is currently disabled in settings.")
                        else:
                            with st.spinner(f"Scanning the last {hunt_depth} days of telemetry for '{hunt_target}'..."):
                                target_arts = svc.search_articles_for_hunting(hunt_target, hunt_depth)
                                if not target_arts: st.warning(f"No intelligence found matching '{hunt_target}'.")
                                else:
                                    st.success(f"Found {len(target_arts)} distinct reports. Synthesizing...")
                                    hunt_context = "\n\n".join([f"Source: {a.source}\nTitle: {a.title}\nContent: {a.summary[:400]}" for a in target_arts])
                                    
                                    sys_prompt = f"""You are an elite Cyber Threat Detection Engineer. Analyze the reports regarding '{hunt_target}'.
                                    Output EXACTLY:
                                    ### 1. Threat Overview & MITRE TTPs
                                    ### 2. Known Vulnerabilities & Infrastructure
                                    ### 3. Splunk / SIEM Hunt Queries
                                    ### 4. YARA Detection Stub"""
                                    
                                    ai_hunt_result = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": hunt_context}], sys_config, temperature=0.1)
                                    if ai_hunt_result:
                                        st.divider()
                                        st.markdown(f"##  Detection Package: {hunt_target.upper()}")
                                        st.markdown(ai_hunt_result)
                                        st.divider()
                                        st.markdown("###  Reference Intel")
                                        for a in target_arts: st.markdown(f"- [{a.title}]({a.link})")
            th_idx += 1
        
        if "Tab: Reporting -> Elastic SIEM Report" in st.session_state.allowed_actions:
            with th_tabs[th_idx]:
                st.subheader("Advanced SIEM Fusion & Hunt")
                st.caption("Live, bi-directional telemetry hunt utilizing local AI-assisted query generation.")
                
                t_dash, t_hunt, t_ai = st.tabs(["Rolling Cache (Fast)", "Live Hunt (API)", "AI Query Builder"])
                
                # ---------------------------------------------------------
                # TAB 1: THE LOCAL ROLLING CACHE (Fast, safe, offline-capable)
                # ---------------------------------------------------------
                with t_dash:
                    c_sync, c_space = st.columns([1, 4])
                    if c_sync.button("Sync Local Cache", width='stretch', type="primary", key="sync_es_cache"):
                        with st.spinner("Polling Elastic Stack..."):
                            from src.elastic_worker import sync_elastic_telemetry, purge_stale_elastic_data
                            sync_elastic_telemetry(hours_back=24)
                            purge_stale_elastic_data(hours_to_keep=72)
                            st.rerun()

                    with svc.SessionLocal() as dbtmp:
                        from src.database import ElasticEvent
                        raw_events = dbtmp.query(ElasticEvent).filter(
                            ElasticEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
                        ).all()

                    if not raw_events:
                        st.success("No high-severity SIEM alerts logged locally in the last 24 hours.")
                    else:
                        import pandas as pd
                        import plotly.express as px
                        
                        df = pd.DataFrame([{
                            "Time": e.timestamp, "Severity": e.severity, 
                            "Category": e.event_category, "IP": e.source_ip, "Message": e.message
                        } for e in raw_events])
                        
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Local High/Crit Alerts", len(df))
                        c2.metric("Unique Threat IPs", df['IP'].nunique())
                        c3.metric("Critical Density", f"{int((len(df[df['Severity'] == 'CRITICAL']) / len(df)) * 100)}%")
                        
                        st.dataframe(df.sort_values('Time', ascending=False), hide_index=True, use_container_width=True)

                # ---------------------------------------------------------
                # TAB 2: LIVE HUNT & CORRELATION (Direct API)
                # ---------------------------------------------------------
                with t_hunt:
                    st.markdown("###  Live Elastic Hunt")
                    
                    hc1, hc2, hc3 = st.columns(3)
                    hunt_index = hc1.selectbox("Target Index", ["*", "logs-*", ".ds-winlogbeat-*", ".ds-logs-cisco_umbrella*", ".ds-logs-network_traffic*", ".ds-logs-system.security*"])
                    hunt_limit = hc2.number_input("Result Limit (Protect RAM)", min_value=10, max_value=500, value=50)
                    hunt_term = hc3.text_input("Quick Keyword Search", value="")
                    
                    if st.button("Execute Live Hunt", type="primary", use_container_width=True):
                        with st.spinner("Executing query against cluster..."):
                            from src.elastic_worker import execute_live_query
                            import json
                            
                            if hunt_term:
                                query_body = {"query": {"query_string": {"query": f"*{hunt_term}*"}}, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]}
                            else:
                                query_body = {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]}
                                
                            results = execute_live_query(index_pattern=hunt_index, query_body=query_body, size=hunt_limit)
                            
                            if isinstance(results, dict) and "error" in results:
                                st.error(f"Elastic Error: {results['error']}")
                            elif not results:
                                st.warning("0 Results Found.")
                            else:
                                # Parse complex raw JSON into a flat, readable table
                                flat_results = []
                                for r in results:
                                    src = r.get('_source', {})
                                    flat_results.append({
                                        "Time": src.get('@timestamp', ''),
                                        "Severity": src.get('log', {}).get('level', src.get('event', {}).get('severity', 'UNKNOWN')),
                                        "Message": src.get('message', src.get('event', {}).get('original', 'N/A')),
                                        "Source IP": src.get('source', {}).get('ip', 'N/A')
                                    })
                                
                                st.session_state.last_hunt_results = flat_results 
                                st.dataframe(flat_results, use_container_width=True)
                                
                    # --- NATIVE AI SUMMARIZATION TRIGGER ---
                    if hasattr(st.session_state, 'last_hunt_results') and st.session_state.last_hunt_results:
                        if st.button("AI Triage & Summarize Results", use_container_width=True):
                            with st.spinner("Analyzing telemetry payload with local model..."):
                                from src.llm import generate_siem_triage_summary
                                ai_text = generate_siem_triage_summary(svc.SessionLocal(), st.session_state.last_hunt_results)
                                st.info(ai_text)

                # ---------------------------------------------------------
                # TAB 3: AI QUERY AUTO-BUILDER
                # ---------------------------------------------------------
                with t_ai:
                    st.markdown("###  Natural Language to Elastic DSL")
                    st.caption("Tell the AI what you want to find, and it will generate the perfect JSON query for Elastic.")
                    
                    nl_query = st.text_area("What are you looking for?", placeholder="e.g., Show me all failed Windows logins from outside the US in the last 2 hours.", height=100)
                    
                    if st.button("Generate Query", type="primary"):
                        if not nl_query: st.warning("Enter a prompt first.")
                        else:
                            with st.spinner("Translating intent to Elastic DSL..."):
                                from src.llm import generate_elastic_dsl
                                raw_json = generate_elastic_dsl(svc.SessionLocal(), nl_query)
                                
                                st.code(raw_json, language="json")
                                st.success("Query Generated! Copy this and use it in Kibana, or pass it to a custom Live Hunt API call.")
            th_idx += 1

# ================= 4. AIOps RCA =================
elif page == "AIOps RCA":
    st.title("AIOps Root Cause Analysis")
    st.caption("Live correlation of non-uniform monitoring alerts with Regional Intelligence.")
    
    from src.aiops_engine import EnterpriseAIOpsEngine
    ai_engine = EnterpriseAIOpsEngine(svc.SessionLocal())
    
    ai_tab_names = []
    
    if "Tab: AIOps RCA -> Active Board" in st.session_state.allowed_actions: ai_tab_names.append("Active Board")
    if "Tab: AIOps RCA -> Predictive Analytics" in st.session_state.allowed_actions: ai_tab_names.append("Patterns")
    if "Tab: AIOps RCA -> Global Correlation" in st.session_state.allowed_actions: ai_tab_names.append("Global")
    
    if not ai_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        ai_tabs = st.tabs(ai_tab_names)
        ai_idx = 0
        
        if "Tab: AIOps RCA -> Active Board" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                # --- AUTO-REFRESH INJECTION ---
                c_head, c_tog = st.columns([5, 1])
                with c_tog:
                    # Toggle defaults to True, allowing analysts to pause it if they need to type a ticket
                    live_polling = st.toggle("Live 5s Polling", value=True, key="aiops_live_poll")
                
                if live_polling:
                    from streamlit_autorefresh import st_autorefresh
                    st_autorefresh(interval=5000, key="aiops_5sec_refresh")
                # ------------------------------

                alerts, events, grid = svc.get_aiops_dashboard_data()
                c_l, c_s = st.columns([3, 1])
                with c_s:
                    st.subheader("Event Log")
                    st.divider()
                    for e in events:
                        local_time = e.timestamp.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ)
                        time_str = local_time.strftime('%I:%M %p')
                        clean_msg = re.sub(r'[\U00010000-\U0010ffff]', '', e.message)
                        clean_msg = clean_msg.replace('?', '').strip()
                        st.caption(f"{time_str} | {clean_msg}")
                
                with c_l:
                    st.subheader("Overlays")
                    locs = svc.get_cached_locations()
                    if st.session_state.allowed_site_types != "ALL":
                        locs = [l for l in locs if l.loc_type in st.session_state.allowed_site_types]
                        allowed_loc_names = {l.name for l in locs}
                        # Automatically hide alerts for sites the user is not allowed to monitor
                        alerts = [a for a in alerts if a.mapped_location in allowed_loc_names]

                    # --- UNDOCUMENTED TROLLING MECHANISM (OPERATION: DEAN) ---
                    # Only inject the fake alerts if the person viewing the map is the chosen target
                    if black_ops["dean_target"] == st.session_state.current_user:
                        start_t = black_ops["dean_start"]
                        elapsed = time.time() - start_t
                        num_fake_reds = int(elapsed // 30) # 1 new site turns red every 30 seconds
                        
                        if locs and num_fake_reds >= len(locs):
                            black_ops["dean_target"] = None
                            st.toast("Operation: Dean complete. Grid reverted to normal.")
                        elif locs:
                            import random
                            rng = random.Random(int(start_t)) 
                            fake_locs = rng.sample(locs, min(num_fake_reds, len(locs)))
                            
                            class FakeAlert:
                                def __init__(self, name): self.mapped_location = name
                                
                            for fl in fake_locs:
                                alerts.append(FakeAlert(fl.name))
                    # ---------------------------------------------------------

                    layers, view_state = svc.build_aiops_map_layers(alerts, locs)

                    st.pydeck_chart(pdk.Deck(
                        layers=layers, 
                        initial_view_state=view_state, 
                        tooltip={"text": "{name}"}
                    ))
                    
                    st.subheader("Correlation")
                    if not alerts: st.success("Grid Operational.")
                    else:
                        with svc.SessionLocal() as dbtmp:
                            from src.database import RegionalHazard, CloudOutage, BgpAnomaly, SolarWindsAlert
                            wea = dbtmp.query(RegionalHazard).all()
                            cld = dbtmp.query(CloudOutage).filter_by(is_resolved=False).all()
                            bgp = dbtmp.query(BgpAnomaly).filter_by(is_resolved=False).all()
                            raw_alerts = dbtmp.query(SolarWindsAlert).filter(SolarWindsAlert.is_correlated == False, SolarWindsAlert.status != 'Resolved').all()
                            
                        # NEW: Apply RBAC filtering to raw_alerts before passing to the correlation engine
                        if st.session_state.allowed_site_types != "ALL":
                            raw_alerts = [a for a in raw_alerts if a.mapped_location in allowed_loc_names]
                            
                        # 1. Cluster the alerts as usual
                        incidents = ai_engine.analyze_and_cluster(raw_alerts)
                        
                        # --- NEW: 2. Detect Massive Provider/Fleet Outages ---
                        fleet_events = ai_engine.identify_fleet_outages(incidents, threshold=5)
                        
                        # --- NEW: 3. Render the Global Warning Banner ---
                        if fleet_events:
                            for event in fleet_events:
                                st.markdown(f"""
                                <div style='background-color: #4a0000; border: 2px solid #ff4b4b; border-radius: 8px; padding: 15px; margin-bottom: 20px; text-align: center;'>
                                    <h2 style='color: #ff4b4b; margin: 0;'> GLOBAL FLEET EVENT DETECTED</h2>
                                    <p style='color: white; font-size: 1.1rem; margin: 5px 0 0 0;'>
                                        Massive <b>{event['provider']}</b> Carrier Outage affecting <b>{len(event['affected_sites'])}</b> tracked sites. 
                                        Individual downstream RCAs have been automatically overridden.
                                    </p>
                                </div>
                                """, unsafe_allow_html=True)
                                
                        # 4. Process individual site cards
                        for site, data in incidents.items():
                            # --- NEW: 5. Pass fleet_events into the RCA calculator ---
                            c, cf, p, e, b, p0, cs = ai_engine.calculate_root_cause(
                                site_name=site, 
                                data=data, 
                                active_weather=wea, 
                                active_cloud=cld, 
                                active_bgp=bgp, 
                                fleet_events=fleet_events
                            )
                            
                            with st.container(border=True):
                                    st.markdown(f"### {p} | Site: {site}")
                                    st.warning(c)
                                    
                                    if p0: st.error(f"**Patient Zero (Suspected Origin Node):** {p0}")
                                    else: st.info("**Patient Zero:** Indeterminate (Simultaneous Failure)")
                                        
                                    # --- CHECK MAINTENANCE STATUS ---
                                    site_record = next((l for l in locs if l.name == site), None)
                                    if site_record and getattr(site_record, 'under_maintenance', False):
                                        etr_str = site_record.maintenance_etr.strftime('%Y-%m-%d') if site_record.maintenance_etr else "Unknown"
                                        rsn_str = site_record.maintenance_reason or "No reason provided."
                                        st.warning(f" **SITE UNDER MAINTENANCE** (ETR: {etr_str})\n\n**Reason:** {rsn_str}")
                                        
                                    can_dispatch = "Action: Dispatch RCA Tickets" in st.session_state.allowed_actions
                                    can_manage_maint = "Action: Manage Site Maintenance" in st.session_state.allowed_actions
                                    
                                    # --- NEW: RBAC DISPATCHED CHECKBOX ---
                                    is_dispatched = any(getattr(a, 'is_dispatched', False) for a in data['alerts'])
                                    if can_dispatch:
                                        new_dispatch = st.checkbox("Ticket Dispatched", value=is_dispatched, key=f"disp_{site}")
                                        if new_dispatch != is_dispatched:
                                            svc.set_cluster_dispatch([a.id for a in data['alerts']], new_dispatch)
                                            st.rerun()
                                    else:
                                        if is_dispatched:
                                            st.success("Ticket Dispatched")
                                    
                                    # --- NOC TICKET DISPATCH CONTROLS ---
                                    if can_dispatch:
                                        with st.expander(f"Draft & Dispatch Ticket for {site}"):
                                            clean_p = p.replace("??", "").replace("??", "").replace("??", "").replace("??", "").replace("??", "").strip()
                                            clean_c = c.replace("??", "").replace("???", "").replace("?", "").replace("??", "").replace("??", "").strip()
                                            clean_p0 = p0 if p0 else "Indeterminate (Simultaneous Failure)"
                                            
                                            ticket_text = svc.generate_rca_ticket_text(site, data, clean_p, clean_p0, clean_c)
                                            ticket_body = st.text_area("Ticket Notes / RCA Summary", value=ticket_text, height=350, key=f"t_body_{site}")
                                            
                                            fixed_recipients = "remedyforceworkflow@aecc.com, noc@aecc.com"
                                            st.info(f"Ticket will be automatically dispatched to: **{fixed_recipients}**")
                                            
                                            if st.button("Dispatch Ticket", key=f"t_send_{site}", width='stretch'):
                                                from src.mailer import send_alert_email
                                                with st.spinner("Dispatching to RemedyForce & NOC..."):
                                                    success, msg = send_alert_email(f"URGENT: {clean_p} Incident at {site}", ticket_body, fixed_recipients, is_html=False)
                                                    if success: st.success("Ticket Dispatched successfully!")
                                                    else: st.error(f"SMTP Error: {msg}")

                                        if st.button(f"Acknowledge Incident & Clear Board ({site})", key=f"ack_{site}", width="stretch"): 
                                            svc.acknowledge_cluster([a.id for a in data['alerts']])
                                            safe_rerun()
                                            
                                    # --- TOC / NOC MAINTENANCE CONTROLS ---
                                    if can_manage_maint:
                                        if site_record:
                                            with st.expander(f"Maintenance Controls: {site}"):
                                                is_under_maint = getattr(site_record, 'under_maintenance', False)
                                                m_stat = st.selectbox("Maintenance Status", ["Active Maintenance", "No Maintenance"], index=0 if is_under_maint else 1, key=f"ms_{site}")
                                                
                                                # Default ETR to today if none exists
                                                etr_val = site_record.maintenance_etr.date() if getattr(site_record, 'maintenance_etr', None) else datetime.today().date()
                                                m_etr = st.date_input("Estimated Time of Restoration (ETR)", value=etr_val, key=f"metr_{site}")
                                                
                                                m_rsn = st.text_area("Reason / Explanation", value=site_record.maintenance_reason or "", key=f"mrsn_{site}")
                                                
                                                if st.button("Save Maintenance Update", key=f"msave_{site}", type="primary", width="stretch"):
                                                    svc.set_site_maintenance(site, m_stat == "Active Maintenance", m_etr, m_rsn)
                                                    st.success("Maintenance details saved!")
                                                    time.sleep(0.5)
                                                    safe_rerun()
                                        else:
                                            st.info("Site not registered in Facilities database; maintenance cannot be tracked.")
            ai_idx += 1
        if "Tab: AIOps RCA -> Predictive Analytics" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                st.subheader("Predictive Analytics & Chronic Degradation")
                st.markdown("Analyzes historical telemetry to identify degrading hardware and unstable infrastructure *before* catastrophic failure.")
                
                is_analytics_cooling = check_cooldown("ai_analytics", 60)
                if st.button("Processing..." if is_analytics_cooling else "Run Deep Analysis", type="primary", width="stretch", disabled=is_analytics_cooling):
                    apply_cooldown("ai_analytics")
                    with st.spinner("Crunching historical telemetry and calculating failure probabilities..."):
                        f, v, r = ai_engine.generate_chronic_insights()
                        
                        if f is None or (isinstance(f, pd.DataFrame) and f.empty):
                            st.success("No chronic degradation patterns detected in the current telemetry window.")
                        else:
                            st.divider()
                            col_f, col_v = st.columns(2)
                            
                            with col_f:
                                st.markdown("###  Top Offending Nodes")
                                st.caption("Specific devices exhibiting high frequency of state-flapping.")
                                st.dataframe(f, width="stretch", hide_index=True)
                                
                            with col_v:
                                st.markdown("###  Infrastructure Hotspots")
                                st.caption("Sites or regions experiencing chronic instability.")
                                if v is not None and not (isinstance(v, pd.DataFrame) and v.empty):
                                    st.dataframe(v, width="stretch", hide_index=True)
                                else:
                                    st.info("Insufficient data for site heatmapping.")
                                    
                            st.divider()
                            st.markdown("###  AI Predictive Maintenance Forecast")
                            with st.container(border=True):
                                if r is not None:
                                    if isinstance(r, str):
                                        st.markdown(r)
                                    elif isinstance(r, pd.DataFrame):
                                        st.dataframe(r, width="stretch", hide_index=True)
                                    elif isinstance(r, list):
                                        for item in r: st.markdown(f"- {item}")
                                else:
                                    st.info("System is nominal. No preventative actions recommended at this time.")
            ai_idx += 1
            
        if "Tab: AIOps RCA -> Global Correlation" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                st.subheader("Deterministic Global Correlation Engine")
                st.markdown("Calculates causation graphs based on geospatial math and telemetry overlays across all domains.")
                
                c_glob1, c_glob2 = st.columns([3, 1])
                
                is_global_rca_cooling = check_cooldown("global_rca", 60)
                if c_glob2.button("Calculating..." if is_global_rca_cooling else "Run Global Correlation", type="primary", width="stretch", disabled=is_global_rca_cooling):
                    apply_cooldown("global_rca")
                    with st.spinner("Calculating Multi-Domain Causal Links..."):
                        report = svc.generate_global_sitrep(sys_config)
                        st.session_state.last_global_rca = report

                if "last_global_rca" in st.session_state:
                    st.divider()
                    with st.container(border=True):
                        st.markdown(st.session_state.last_global_rca)
                    
                    c_em1, c_em2 = st.columns([1, 4])
                    if c_em1.button("Broadcast SitRep", width="stretch"):
                        from src.mailer import send_alert_email
                        with st.spinner("Transmitting via SMTP..."):
                            success, msg = send_alert_email("URGENT: Multi-Domain Global SitRep", st.session_state.last_global_rca)
                            if success: st.success(msg)
                            else: st.error(msg)
            ai_idx += 1

# ================= NEW: SHIFT LOGBOOK =================
elif page == "Shift Logbook":
    st.title("NOC Running Shift Log & Calendar")
    st.markdown("Incident-based running log isolated by operational role. Logs are aggregated into an automated shift summary upon handoff.")

# --- MODAL POP-OUT DEFINITION ---
    @st.dialog("Shift Log Details")
    def open_log_modal(log_entry):
        is_del = getattr(log_entry, 'is_deleted', False)
        if is_del: 
            st.error("THIS LOG HAS BEEN SOFT-DELETED AND OMITTED FROM SUMMARIES.")
            
        st.markdown(f"**Analyst:** {log_entry.analyst} | **Role:** {log_entry.author_role.upper()}")
        st.markdown(f"**Date:** {format_local_time(log_entry.created_at)}")
        st.markdown(f"**Shift:** {log_entry.shift_period}")
        st.divider()
        st.markdown(log_entry.content)
        
        # Soft Delete / Restore Controls
        st.divider()
        
        if not is_del:
            # ANY user (Analyst or Admin) can soft-delete an active log
            if st.button("Soft Delete Log", type="primary", width='stretch'):
                with svc.SessionLocal() as session:
                    from src.database import ShiftLogEntry
                    db_log = session.query(ShiftLogEntry).get(log_entry.id)
                    if db_log:
                        db_log.is_deleted = True
                        session.commit()
                st.rerun()
        else:
            # ONLY Admins can restore a log that has been deleted
            if st.session_state.current_role == "admin":
                if st.button("Restore Log", width='stretch'):
                    with svc.SessionLocal() as session:
                        from src.database import ShiftLogEntry
                        db_log = session.query(ShiftLogEntry).get(log_entry.id)
                        if db_log:
                            db_log.is_deleted = False
                            session.commit()
                    st.rerun()
    
    # --- 1. NEW INCIDENT ENTRY FORM ---
    st.subheader("Log Active Incident / Update")
    c_entry, c_aiops = st.columns([2, 1])
    
    with c_aiops:
        st.write("**AIOps Telemetry Integration**")
        st.caption("Pulls active outages and automatically calculates the duration of the event.")
        if st.button("Auto-Draft Active Outages", width="stretch"):
            alerts, events, grid = svc.get_aiops_dashboard_data()
            from src.aiops_engine import EnterpriseAIOpsEngine
            ai_engine = EnterpriseAIOpsEngine(svc.SessionLocal())
            
            if not alerts:
                st.success("No active AIOps infrastructure incidents.")
            else:
                incidents = ai_engine.analyze_and_cluster(alerts)
                lines = []
                for site, data in incidents.items():
                    p0 = data['patient_zero']
                    duration = datetime.utcnow() - p0.received_at
                    hours, remainder = divmod(int(duration.total_seconds()), 3600)
                    mins, _ = divmod(remainder, 60)
                    dur_str = f"{hours}h {mins}m" if hours > 0 else f"{mins}m"
                    
                    lines.append(f"AIOps Auto-Log: {site} offline (Origin: {p0.node_name}). Down for {dur_str}.")
                
                if "aiops_draft" not in st.session_state: st.session_state.aiops_draft = ""
                st.session_state.aiops_draft += "\n".join(lines) + "\n\n"
                safe_rerun()
    
    with c_entry:
        with st.form("incident_entry_form", clear_on_submit=True):
            c_sh1, c_sh2 = st.columns(2)
            
            # --- NEW DYNAMIC SHIFT/DATE LOGIC ---
            user_shift = getattr(current_user_obj, 'default_shift', 'No Shift')
            custom_shift_date = None # Track the custom date

            if user_shift == "No Shift":
                shift_val = c_sh1.date_input("Active Shift Date", value=datetime.now(LOCAL_TZ).date())
                shift_period = f"Date: {shift_val.strftime('%Y-%m-%d')}"
                custom_shift_date = shift_val # Capture it here
            else:
                shift_choices = ["Morning", "Afternoon", "Night"]
                default_idx = shift_choices.index(user_shift) if user_shift in shift_choices else 0
                shift_period = c_sh1.selectbox("Active Shift", shift_choices, index=default_idx)
            
            analyst_name = c_sh2.text_input("Analyst", value=current_user_obj.full_name or st.session_state.current_user)
            
            default_text = st.session_state.get("aiops_draft", "")
            incident_notes = st.text_area("Incident Update / Running Notes", value=default_text, height=120, placeholder="Logged circuit flap on MAIN-1, dispatched ticket #12345...")
            
            can_submit = "Action: Submit Shift Log" in st.session_state.allowed_actions
            if st.form_submit_button("Append to Running Log", type="primary", disabled=not can_submit, width="stretch"):
                if incident_notes.strip():
                    # Pass the custom_shift_date to the service function
                    svc.save_shift_log(analyst_name, st.session_state.current_role, shift_period, incident_notes.strip(), custom_date=custom_shift_date)
                    if "aiops_draft" in st.session_state: del st.session_state.aiops_draft
                    st.success("Incident appended to shift log!")
                    time.sleep(0.5); safe_rerun()
                else:
                    st.error("Cannot submit empty log.")

    st.divider()
    
    # --- 1.5 PERSISTENT DAILY SUMMARIES ---
    st.subheader("Daily Persistent Summaries")
    st.caption("Auto-generated executive handoffs for the Morning Shift and the entire Day. These persist until overwritten.")

    # Unique, role-bound keys that do NOT expire at midnight
    eom_key = f"latest_eom_{st.session_state.current_role}"
    eod_key = f"latest_eod_{st.session_state.current_role}"

    with st.expander("End of Morning Report", expanded=False):
        if st.button("Generate Morning Report", key="gen_eom", type="primary", disabled=not ai_enabled):
            with st.spinner("Synthesizing morning shift logs..."):
                today_start = datetime.now(LOCAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
                utc_start = today_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                utc_end = utc_start 
                
                morn_logs = [l for l in svc.get_shift_logs(st.session_state.current_role, utc_start, utc_end) if "Morning" in l.shift_period and not getattr(l, 'is_deleted', False)]
                
                if not morn_logs:
                    st.warning("No active morning logs found for today.")
                else:
                    log_text = "\n".join([f"[{format_local_time(l.created_at)}] {l.analyst}: {l.content}" for l in morn_logs])
                    sys_prompt = "You are a NOC Shift Supervisor. Read the following chronologically ordered running log for the Morning shift. Write a concise, professional End of Morning Shift Handoff Summary combining the key incidents, ongoing outages, and resolutions. Do NOT use pleasantries. Format with markdown."
                    
                    from src.llm import call_llm
                    summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": log_text}], sys_config)
                    if summary:
                        st.session_state[eom_key] = {
                            "timestamp": datetime.now(LOCAL_TZ).strftime('%B %d, %Y at %I:%M %p %Z'),
                            "content": summary
                        }
                        # Auto-Append to Shift Log
                        with svc.SessionLocal() as session:
                            from src.database import ShiftLogEntry
                            new_log = ShiftLogEntry(
                                analyst=current_user_obj.full_name or st.session_state.current_user,
                                author_role=st.session_state.current_role,
                                shift_period="Morning (06:00 - 14:30)",
                                content=f" **AUTO-GENERATED MORNING HANDOFF REPORT:**\n\n{summary}"
                            )
                            session.add(new_log)
                            session.commit()
                        st.success("Morning report generated and appended to the shift log!")

        if eom_key in st.session_state:
            st.caption(f" **Last Generated:** {st.session_state[eom_key]['timestamp']}")
            st.markdown(st.session_state[eom_key]['content'])

    with st.expander("End of Day Report", expanded=False):
        if st.button("Generate End of Day Report", key="gen_eod", type="primary", disabled=not ai_enabled):
            with st.spinner("Synthesizing all logs for the day..."):
                today_start = datetime.now(LOCAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
                utc_start = today_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                utc_end = utc_start 
                
                day_logs = [l for l in svc.get_shift_logs(st.session_state.current_role, utc_start, utc_end) if not getattr(l, 'is_deleted', False)]
                
                if not day_logs:
                    st.warning("No active logs found for today.")
                else:
                    log_text = "\n".join([f"[{format_local_time(l.created_at)}] {l.shift_period} | {l.analyst}: {l.content}" for l in day_logs])
                    sys_prompt = "You are a NOC Shift Supervisor. Read the following chronologically ordered running log for the entire day. Write a comprehensive, professional End of Day Shift Handoff Summary combining the key incidents, ongoing outages, and resolutions. Do NOT use pleasantries. Format with markdown."
                    
                    from src.llm import call_llm
                    summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": log_text}], sys_config)
                    if summary:
                        st.session_state[eod_key] = {
                            "timestamp": datetime.now(LOCAL_TZ).strftime('%B %d, %Y at %I:%M %p %Z'),
                            "content": summary
                        }
                        # Auto-Append to Shift Log
                        with svc.SessionLocal() as session:
                            from src.database import ShiftLogEntry
                            new_log = ShiftLogEntry(
                                analyst=current_user_obj.full_name or st.session_state.current_user,
                                author_role=st.session_state.current_role,
                                shift_period="Afternoon/Evening (11:30 - 20:00)",
                                content=f" **AUTO-GENERATED END OF DAY REPORT:**\n\n{summary}"
                            )
                            session.add(new_log)
                            session.commit()
                        st.success("End of Day report generated and appended to the shift log!")

        if eod_key in st.session_state:
            st.caption(f" **Last Generated:** {st.session_state[eod_key]['timestamp']}")
            st.markdown(st.session_state[eod_key]['content'])

    # --- ADMIN RETROACTIVE REPORTING ---
    if st.session_state.current_role == "admin":
        with st.expander("Admin: Retroactive End of Day Report", expanded=False):
            st.caption("Generate a missing End of Day report for a previous day and inject it into that day's log.")
            c_ret1, c_ret2 = st.columns(2)
            retro_date = c_ret1.date_input("Select Previous Date", value=datetime.now(LOCAL_TZ).date() - timedelta(days=1), key="retro_eod_date")
            retro_role = c_ret2.selectbox("Target Role", [r.name for r in svc.get_all_roles()], key="retro_eod_role")
            
            if st.button("Generate Retroactive EOD Report", key="gen_retro_eod", type="primary", disabled=not ai_enabled, width='stretch'):
                with st.spinner(f"Synthesizing logs for {retro_date}..."):
                    retro_dt_start = datetime.combine(retro_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                    retro_dt_end = retro_dt_start + timedelta(days=1)
                    
                    retro_logs = [l for l in svc.get_shift_logs(retro_role, retro_dt_start, retro_dt_end) if not getattr(l, 'is_deleted', False)]
                    
                    if not retro_logs:
                        st.warning(f"No active logs found for {retro_date} under the {retro_role} role.")
                    else:
                        log_text = "\n".join([f"[{format_local_time(l.created_at)}] {l.shift_period} | {l.analyst}: {l.content}" for l in retro_logs])
                        sys_prompt = "You are a NOC Shift Supervisor. Read the following chronologically ordered running log for the entire day. Write a comprehensive, professional End of Day Shift Handoff Summary combining the key incidents, ongoing outages, and resolutions. Do NOT use pleasantries. Format with markdown."
                        
                        from src.llm import call_llm
                        retro_summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": log_text}], sys_config)
                        
                        if retro_summary:
                            # Set the timestamp to 23:59:59 of the targeted day
                            target_local = datetime.combine(retro_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ)
                            target_utc = target_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                            
                            with svc.SessionLocal() as session:
                                from src.database import ShiftLogEntry
                                new_log = ShiftLogEntry(
                                    analyst=current_user_obj.full_name or st.session_state.current_user,
                                    author_role=retro_role,
                                    shift_date=target_utc,
                                    shift_period="Afternoon/Evening (11:30 - 20:00)",
                                    content=f" **RETROACTIVE END OF DAY REPORT:**\n\n{retro_summary}",
                                    created_at=target_utc
                                )
                                session.add(new_log)
                                session.commit()
                            st.success(f"Retroactive EOD report generated and appended to the {retro_date} shift log!")
    st.subheader("Aggregated Executive Summaries")
    st.caption("Compiles historical shift logs into comprehensive Weekly or Monthly executive overviews using Map-Reduce AI.")
    
    c_agg1, c_agg2, c_agg3 = st.columns([2, 2, 1.5])
    agg_period = c_agg1.selectbox("Select Reporting Period", ["Current Week", "Previous Week", "Current Month", "Previous Month"], label_visibility="collapsed")
    
    # --- NEW: ROLE BINDING LOGIC ---
    if st.session_state.current_role == "admin":
        available_roles = ["All"] + [r.name for r in svc.get_all_roles()]
        agg_target_role = c_agg2.selectbox("Target Role", available_roles, key="agg_target_role", label_visibility="collapsed")
    else:
        agg_target_role = st.session_state.current_role
        c_agg2.text_input("Target Role", value=agg_target_role.upper(), disabled=True, label_visibility="collapsed")
    
    is_agg_cooling = check_cooldown("ai_agg_summary", 60)
    if c_agg3.button("Generating..." if is_agg_cooling else "Generate Summary", width="stretch", type="primary", disabled=not ai_enabled or is_agg_cooling):
        apply_cooldown("ai_agg_summary")
        with st.spinner(f"Reading historical logs and synthesizing {agg_period} summary for {agg_target_role.upper()}..."):
            today = datetime.now(LOCAL_TZ).date()
            
            if agg_period == "Current Week":
                start_dt = today - timedelta(days=today.weekday())
                end_dt = start_dt + timedelta(days=6)
            elif agg_period == "Previous Week":
                start_dt = today - timedelta(days=today.weekday()) - timedelta(weeks=1)
                end_dt = start_dt + timedelta(days=6)
            elif agg_period == "Current Month":
                start_dt = today.replace(day=1)
                next_month = start_dt.replace(day=28) + timedelta(days=4)
                end_dt = next_month - timedelta(days=next_month.day)
            elif agg_period == "Previous Month":
                last_day_prev_month = today.replace(day=1) - timedelta(days=1)
                start_dt = last_day_prev_month.replace(day=1)
                end_dt = last_day_prev_month
            
            utc_start = datetime.combine(start_dt, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            utc_end = datetime.combine(end_dt, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None) + timedelta(days=1)
            
            # Fetch strictly bound by the target role
            raw_logs = svc.get_shift_logs(agg_target_role, utc_start, utc_end)
            valid_logs = [l for l in raw_logs if not getattr(l, 'is_deleted', False)]
            
            if not valid_logs:
                st.warning(f"No valid {agg_target_role.upper()} logs found for {agg_period} ({start_dt.strftime('%m/%d')} - {end_dt.strftime('%m/%d')}).")
            else:
                from src.llm import generate_aggregated_shift_summary
                summary = generate_aggregated_shift_summary(svc.SessionLocal(), valid_logs, agg_period, agg_target_role)
                # Store dynamically using the role name so multiple roles can be generated/viewed independently
                st.session_state[f"agg_summary_{agg_period.replace(' ', '_')}_{agg_target_role}"] = summary
                
    # Display the summary if it exists in session state
    state_key = f"agg_summary_{agg_period.replace(' ', '_')}_{agg_target_role}"
    if state_key in st.session_state:
        with st.container(border=True):
            st.markdown(st.session_state[state_key])

    
    st.divider()

    # --- 3. LOG EXPLORER & CALENDAR ---
    st.subheader("Shift Log Explorer")
    
    if "log_view_mode" not in st.session_state: st.session_state.log_view_mode = "Day View"
    if "selected_log_date" not in st.session_state: st.session_state.selected_log_date = datetime.now(LOCAL_TZ).date()
        
    c_mode1, c_mode2 = st.columns([1, 4])
    view_selection = c_mode1.radio("Layout", ["Day View", "Week View"], horizontal=True, label_visibility="collapsed")
    
    if view_selection != st.session_state.log_view_mode:
        st.session_state.log_view_mode = view_selection
        safe_rerun()
        
    st.divider()
    
    # ================= DAY VIEW =================
    if st.session_state.log_view_mode == "Day View":
        c_nav1, c_nav2, c_nav3 = st.columns([1, 2, 1])
        if c_nav1.button("Previous Day", width='stretch'): 
            st.session_state.selected_log_date -= timedelta(days=1); safe_rerun()
            
        new_date = c_nav2.date_input("Select Date", value=st.session_state.selected_log_date, label_visibility="collapsed")
        if new_date != st.session_state.selected_log_date:
            st.session_state.selected_log_date = new_date; safe_rerun()
            
        is_today = st.session_state.selected_log_date >= datetime.now(LOCAL_TZ).date()
        if c_nav3.button("Next Day ", width='stretch', disabled=is_today): 
            st.session_state.selected_log_date += timedelta(days=1); safe_rerun()
            
        st.markdown(f"<h4 style='text-align: center;'>Logs for {st.session_state.selected_log_date.strftime('%A, %B %d, %Y')}</h4>", unsafe_allow_html=True)
        
        dt_start = datetime.combine(st.session_state.selected_log_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        
        # FIX: Set dt_end exactly to dt_start. 
        # The backend (services.py) will automatically pad this by exactly 24 hours.
        dt_end = dt_start 
        
        raw_day_logs = svc.get_shift_logs(st.session_state.current_role, dt_start, dt_end)
        
        # --- FILTER DELETED LOGS (Admins can still see them) ---
        day_logs = [l for l in raw_day_logs if not getattr(l, 'is_deleted', False) or st.session_state.current_role == "admin"]
        
        if not day_logs:
            st.info(f"No active shift logs recorded for {st.session_state.selected_log_date.strftime('%m/%d/%Y')}.")
        else:
            ch1, ch2, ch3, ch4, ch5 = st.columns([1.2, 1, 1.5, 6, 1.2])
            ch1.markdown("**Time**")
            ch2.markdown("**Shift**")
            ch3.markdown("**Analyst**")
            ch4.markdown("**Log Message**")
            ch5.markdown("**Action**")
            st.divider()

            for l in day_logs:
                is_del = getattr(l, 'is_deleted', False)
                local_time = format_local_time(l.created_at).split(' ')[1]
                shift_abbr = "Morning" if "Morning" in l.shift_period else "Evening"
                preview_text = l.content.replace('\n', ' ')

                c1, c2, c3, c4, c5 = st.columns([1.2, 1, 1.5, 6, 1.2])
                c1.caption(local_time)
                c2.caption(shift_abbr)
                c3.caption(l.analyst)
                
                display_msg = preview_text[:250] + "..." if len(preview_text) > 250 else preview_text
                
                # --- STRIKETHROUGH FOR DELETED LOGS (Admins only) ---
                if is_del:
                    display_msg = f"<span style='color: #dc3545;'><s>{display_msg}</s> (DELETED)</span>"
                    
                c4.markdown(f"<span style='font-size: 0.9rem;'>{display_msg}</span>", unsafe_allow_html=True)
                
                if c5.button("Expand", key=f"btn_day_{l.id}", width='stretch'):
                    open_log_modal(l)
                    
                st.markdown("<hr style='margin: 0.3rem 0; opacity: 0.3;'/>", unsafe_allow_html=True)
                    
    # ================= WEEK VIEW =================
    elif st.session_state.log_view_mode == "Week View":
        if "week_offset" not in st.session_state: st.session_state.week_offset = 0
        
        c_nav1, c_nav2, c_nav3 = st.columns([1, 2, 1])
        if c_nav1.button("Previous Week", width='stretch'): st.session_state.week_offset -= 1; safe_rerun()
        
        today = datetime.now(LOCAL_TZ).date()
        target_week_start = today - timedelta(days=today.weekday()) + timedelta(weeks=st.session_state.week_offset)
        target_week_end = target_week_start + timedelta(days=6)
        
        c_nav2.markdown(f"<h4 style='text-align: center; margin-top: 0;'>Week of {target_week_start.strftime('%B %d, %Y')}</h4>", unsafe_allow_html=True)
        
        if c_nav3.button("Next Week ", width='stretch', disabled=(st.session_state.week_offset >= 0)): st.session_state.week_offset += 1; safe_rerun()
        
        dt_start = datetime.combine(target_week_start, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        dt_end = datetime.combine(target_week_end, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        
        week_logs = svc.get_shift_logs(st.session_state.current_role, dt_start, dt_end)
        
        days_of_week = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        cal_cols = st.columns(7)
        
        for i, col in enumerate(cal_cols):
            current_day_date = target_week_start + timedelta(days=i)
            with col:
                if st.button(f"{days_of_week[i][:3]}\n{current_day_date.strftime('%m/%d')}", key=f"day_btn_{i}", width='stretch'):
                    st.session_state.selected_log_date = current_day_date
                    st.session_state.log_view_mode = "Day View"
                    safe_rerun()
                
                # --- FILTER DELETED LOGS ON WEEK VIEW ---
                day_logs = [l for l in week_logs if l.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).date() == current_day_date and (not getattr(l, 'is_deleted', False) or st.session_state.current_role == "admin")]
                
                if not day_logs:
                    st.caption("<div style='text-align: center; color: gray;'>No entries</div>", unsafe_allow_html=True)
                else:
                    for l in day_logs: 
                        shift_abbr = "Morn" if "Morning" in l.shift_period else "Eve"
                        local_time = format_local_time(l.created_at).split(' ')[1]
                        
                        if st.button(f"{local_time} | {shift_abbr}", key=f"btn_wk_{l.id}", help="Click to read full log", width='stretch'):
                            open_log_modal(l)

    # ================= ADMIN DATA EXPORT =================
    if st.session_state.current_role == "admin":
        st.divider()
        st.subheader("Admin Log Export Utility")
        
        c_exp1, c_exp2, c_exp3 = st.columns([2, 1, 1])
        available_roles = ["All"] + [r.name for r in svc.get_all_roles()]
        
        exp_role = c_exp1.selectbox("Role Filter", available_roles, key="exp_role")
        exp_start = c_exp2.date_input("Start Date", value=datetime.now(LOCAL_TZ).date() - timedelta(days=7), key="exp_start")
        exp_end = c_exp3.date_input("End Date", value=datetime.now(LOCAL_TZ).date(), key="exp_end")
        
        dt_start_exp = datetime.combine(exp_start, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        dt_end_exp = datetime.combine(exp_end, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        
        # --- EXCLUDE DELETED LOGS FROM CSV EXPORT ---
        exp_logs = [l for l in svc.get_shift_logs(exp_role, dt_start_exp, dt_end_exp) if not getattr(l, 'is_deleted', False)]
        
        if exp_logs:
            export_data = pd.DataFrame([{
                "Local_Time": format_local_time(l.created_at),
                "Analyst": l.analyst, 
                "Role": l.author_role.upper(),
                "Shift_Period": l.shift_period, 
                "Content": l.content
            } for l in exp_logs])
            
            st.download_button(
                label="Download CSV Export", 
                data=export_data.to_csv(index=False).encode('utf-8'), 
                file_name=f"NOC_ShiftLogs_{exp_role.upper()}_{exp_start.strftime('%Y%m%d')}.csv", 
                mime="text/csv", 
                width="stretch",
                type="primary"
            )
        else:
            st.info("No logs match the current export criteria.")
# ================= 5. REPORTING & BRIEFINGS =================
elif page == "Reporting & Briefings":
    st.title("Intelligence Reporting & Briefings")
    
    rc_tab_names = []
    
    if "Tab: Reporting -> Daily Fusion" in st.session_state.allowed_actions: rc_tab_names.append("Daily Fusion Briefing")
    if "Tab: Reporting -> Report Builder" in st.session_state.allowed_actions: rc_tab_names.append("Custom Report Builder")
    if "Tab: Reporting -> Shared Library" in st.session_state.allowed_actions: rc_tab_names.append("Shared Library")
    
    
    if not rc_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        tabs = st.tabs(rc_tab_names)
        tab_idx = 0
        
        if "Tab: Reporting -> Daily Fusion" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                st.subheader("Daily Master Fusion Report")
                st.markdown("AI-synthesized situational report covering Cyber, Vulnerabilities, Physical Hazards, and Cloud Infrastructure.")
                
                yesterday_local = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
                yesterday_str = yesterday_local.strftime('%Y-%m-%d')
                all_reports = svc.get_all_daily_briefings()
                has_yesterday = any(r.report_date.strftime('%Y-%m-%d') == yesterday_str for r in all_reports)
                
                col1, col2 = st.columns([3, 1])
                with col2:
                    if not has_yesterday:
                        is_report_cooling = check_cooldown("gen_report", 300) 
                        if st.button("Compiling Data..." if is_report_cooling else "Generate Yesterday's Report", width="stretch", type="primary", disabled=not can_trigger_ai or is_report_cooling):
                            if not ai_enabled: 
                                st.error("AI is disabled.")
                            else:
                                apply_cooldown("gen_report")
                                with st.spinner("Processing massive datasets..."):
                                    date_obj, report_markdown = generate_daily_fusion_report(svc.SessionLocal())
                                    if report_markdown:
                                        svc.save_daily_briefing(date_obj, report_markdown)
                                        st.success("Report Generated!"); time.sleep(1); safe_rerun()
                    else:
                        st.success("Latest report is ready for review.")

                st.divider()
                
                if not all_reports:
                    st.info("No historical reports found. Click the generation button above to synthesize your first shift briefing.")
                else:
                    report_options = {r.report_date.strftime('%A, %B %d, %Y'): r for r in all_reports}
                    c_sel, c_space = st.columns([2, 3])
                    selected_date = c_sel.selectbox("Select Historical Briefing", options=list(report_options.keys()), index=0)
                    selected_report = report_options[selected_date]
                    
                    with st.container(border=True): 
                        st.markdown(selected_report.content)
                        
                    st.divider()
                    st.subheader("Broadcast Report")
                    st.caption("Send this report via email. Markdown formatting will be natively converted to HTML and emojis will be preserved.")
                    
                    c_em1, c_em2 = st.columns([3, 1])
                    default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
                    report_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="report_recip")
                    
                    if c_em2.button("Transmit Report", type="primary", width='stretch'):
                        if not report_recipients:
                            st.error("Please enter at least one recipient email.")
                        else:
                            with st.spinner("Converting formatting and transmitting report..."):
                                formatted_html = svc.generate_daily_report_email_html(selected_date, selected_report.content)
                                from src.mailer import send_alert_email
                                success, msg = send_alert_email(f"Daily Fusion Report - {selected_date}", formatted_html, recipient_override=report_recipients, is_html=True)
                                if success: st.success("Report successfully transmitted!")
                                else: st.error(f"SMTP Error: {msg}")
            tab_idx += 1

        if "Tab: Reporting -> Report Builder" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                st.subheader("Custom Intel Report Builder")
                if "generated_report" not in st.session_state: st.session_state.generated_report = None
                
                c_s, c_l = st.columns([3, 1])
                sq = c_s.text_input("Search Articles")
                sl = c_l.selectbox("Limit", [20, 50, 100])
                
                res = svc.search_articles(sq, sl)
                
                if res:
                    amap = {f"[{a.published_date.strftime('%Y-%m-%d')}] {a.title}": a for a in res}
                    sels = st.multiselect("Select Articles:", options=list(amap.keys()))
                    
                    st.divider()
                    cm1, cm2 = st.columns(2)
                    aname = cm1.text_input("Analyst", value=current_user_obj.full_name or st.session_state.current_user)
                    cinfo = cm2.text_input("Contact", value=current_user_obj.contact_info or "")
                    obj = st.text_area("AI Objective", value="Generate an exhaustive technical report.")
                    
                    is_rep_cooling = check_cooldown("gen_report_custom", 60)
                    if st.button("Synthesizing..." if is_rep_cooling else "Generate Report", type="primary", disabled=not can_trigger_ai or is_rep_cooling, width="stretch"):
                        apply_cooldown("gen_report_custom")
                        if not sels: st.error("Select at least one article.")
                        else:
                            arts = [amap[t] for t in sels]
                            with st.spinner("Synthesizing Intelligence..."):
                                md = build_custom_intel_report(arts, obj, svc.SessionLocal())
                                if md:
                                    now = datetime.now(LOCAL_TZ).strftime("%A, %B %d, %Y at %I:%M %p %Z")
                                    st.session_state.generated_report = f"#  NOC Report\n**Date:** {now}\n**Analyst:** {aname}\n\n---\n\n{md}"
                                    st.success("Complete!")

                if st.session_state.generated_report:
                    st.divider()
                    st.markdown(st.session_state.generated_report)
                    sv_t = st.text_input("Report Title", value=f"Report - {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}")
                    if st.button("Save to Library", width="stretch"):
                        svc.save_custom_report(sv_t, st.session_state.current_user, st.session_state.generated_report)
                        st.success("Saved!")
            tab_idx += 1

            
        if "Tab: Reporting -> Shared Library" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                st.subheader("Organization Shared Library")
                reps = svc.get_saved_reports()
                if not reps: st.info("No reports saved yet.")
                else:
                    for r in reps:
                        with st.expander(f" **{r.title}** | {format_local_time(r.created_at)}"):
                            st.markdown(r.content)
                            if st.button("Delete", key=f"del_lib_{r.id}", width="stretch"):
                                svc.delete_record("SavedReport", r.id); safe_rerun()
            tab_idx += 1

# ================= 6. SETTINGS & ADMIN =================
elif page == "Settings & Admin":
    st.title("Settings & Engine Room")
    
    set_tab_names = []
    
    if "Tab: Settings -> Facility Locations" in st.session_state.allowed_actions: set_tab_names.append("Facilities")
    if "Tab: Settings -> Internal Assets" in st.session_state.allowed_actions: set_tab_names.append("Internal Assets")
    if "Tab: Settings -> RSS Sources" in st.session_state.allowed_actions: set_tab_names.append("RSS Sources")
    if "Tab: Settings -> ML Training" in st.session_state.allowed_actions: set_tab_names.append("ML Training")
    if "Tab: Settings -> AI & SMTP" in st.session_state.allowed_actions: set_tab_names.append("AI & SMTP")
    if "Tab: Settings -> Users & Roles" in st.session_state.allowed_actions: set_tab_names.append("Users & Roles")
    if "Tab: Settings -> Backup & Restore" in st.session_state.allowed_actions: set_tab_names.append("Backup & Restore")
    if "Tab: Settings -> Danger Zone" in st.session_state.allowed_actions: set_tab_names.append("Danger Zone")
    
    if not set_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        set_tabs = st.tabs(set_tab_names)
        set_idx = 0

        if "Tab: Settings -> Facility Locations" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Facility Database Management")
                c_up, c_ed = st.columns([1, 2])
                with c_up:
                    st.markdown("**Mass Import (JSON)**")
                    st.caption("Requires 'name', 'lat', 'lon'. Optional: 'type', 'priority'.")
                    uploaded_file = st.file_uploader("Upload Sites", type=["json"], key="loc_uploader")
                    if uploaded_file is not None:
                        if st.button("Import Data", width="stretch"):
                            import json
                            try:
                                data = json.load(uploaded_file)
                                added = svc.import_locations(data)
                                st.success(f"Imported {added} new locations!"); time.sleep(1.5); safe_rerun()
                            except Exception as e: st.error(f"Import failed: {e}")
                            
                with c_ed:
                    st.markdown("**Manual Adjustments**")
                    locs = svc.get_cached_locations()
                    df_locs = pd.DataFrame([{
                        "id": l.id, 
                        "Name": l.name, 
                        "Type": l.loc_type, 
                        "District": l.district, 
                        "Priority": l.priority, 
                        "Lat": l.lat, 
                        "Lon": l.lon
                    } for l in locs]) if locs else pd.DataFrame()
                    if not df_locs.empty:
                        edited_df = st.data_editor(df_locs, hide_index=True, disabled=["id"], width="stretch", key="loc_editor")
                        if st.button("Save Manual Adjustments", width="stretch"):
                            svc.update_locations(edited_df)
                            st.success("Changes saved!"); time.sleep(1); safe_rerun()
            set_idx += 1

        if "Tab: Settings -> Internal Assets" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Internal Asset CSV Ingestion")
                col_sw, col_hw = st.columns(2)
                
                with col_sw:
                    st.markdown("**Software Assets**")
                    sw_csv = st.file_uploader("Upload Software CSV (Must contain 'name' column)", type=["csv"], key="sw_upload")
                    if sw_csv and st.button("Sync Software Inventory", width="stretch"):
                        import pandas as pd
                        try:
                            df = pd.read_csv(sw_csv)
                            if 'name' not in df.columns.str.lower(): st.error("CSV must contain a 'name' column.")
                            else:
                                df.columns = df.columns.str.lower()
                                with svc.SessionLocal() as session:
                                    from src.database import SoftwareAsset
                                    session.query(SoftwareAsset).delete() 
                                    for _, row in df.iterrows(): session.add(SoftwareAsset(name=str(row['name'])))
                                    session.commit()
                                st.success(f"Imported {len(df)} software assets!"); time.sleep(1); safe_rerun()
                        except Exception as e: st.error(f"Error parsing CSV: {e}")

                with col_hw:
                    st.markdown("**Hardware Assets**")
                    hw_csv = st.file_uploader("Upload Hardware CSV", type=["csv"], key="hw_upload")
                    if hw_csv and st.button("Sync Hardware Inventory", width="stretch"):
                        import pandas as pd
                        import numpy as np
                        try:
                            df = pd.read_csv(hw_csv)
                            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
                            col_mapping = {
                                'operating_system_architecture': 'os_architecture',
                                'operating_system_family': 'os_family',
                                'operating_system_product': 'os_product',
                                'operating_system_vendor': 'os_vendor',
                                'operating_system_version': 'os_version'
                            }
                            df.rename(columns=col_mapping, inplace=True)
                            
                            if 'ip_address' not in df.columns:
                                st.error("CSV must contain an 'IP Address' column.")
                            else:
                                numeric_cols = ['instances', 'critical_instances', 'severe_instances', 'moderate_instances', 'vulnerabilities', 'critical_vulnerabilities', 'severe_vulnerabilities', 'moderate_vulnerabilities', 'exploit_count', 'malware_count', 'raw_risk_score', 'risk_score']
                                for col in numeric_cols:
                                    if col in df.columns: df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
                                        
                                df.replace(r'^\s*$', np.nan, regex=True, inplace=True)
                                df.replace({np.nan: None}, inplace=True)
                                
                                from src.database import HardwareAsset
                                valid_columns = {c.name for c in HardwareAsset.__table__.columns}
                                
                                with svc.SessionLocal() as session:
                                    session.query(HardwareAsset).delete()
                                    for _, row in df.iterrows():
                                        row_dict = {k: v for k, v in row.to_dict().items() if k in valid_columns}
                                        if row_dict.get('ip_address'):
                                            session.add(HardwareAsset(**row_dict))
                                    session.commit()
                                st.success(f"Imported {len(df)} hardware assets!"); time.sleep(1); safe_rerun()
                        except Exception as e: st.error(f"Error parsing CSV: {e}")
            set_idx += 1
        
        if "Tab: Settings -> RSS Sources" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                col1, col2 = st.columns(2)
                kws, feeds, usrs = svc.get_admin_lists()
                
                with col1:
                    st.subheader("Manage Keywords")
                    with st.form("bulk_kw"):
                        raw_text = st.text_area("Bulk Add Keywords (word, weight)", placeholder="infrastructure, 80", key="set_kw_bulk")
                        if st.form_submit_button("Add Keywords", width="stretch"):
                            svc.add_bulk_keywords(raw_text); safe_rerun()
                    with st.expander("Active Keywords"):
                        for k in kws:
                            c_a, c_b, c_c = st.columns([3, 1, 1])
                            c_a.code(k.word); c_b.write(f"**{k.weight}**")
                            if c_c.button("", key=f"del_kw_{k.id}", width="stretch"): 
                                svc.delete_record("Keyword", k.id); safe_rerun()

                with col2:
                    st.subheader("Manage RSS Feeds")
                    with st.form("bulk_feed"):
                        raw_text_feeds = st.text_area("Bulk Add Feeds (URL, Name)", placeholder="https://site.com/feed, Tech News", key="set_feed_bulk")
                        if st.form_submit_button("Add Sources", width="stretch"):
                            svc.add_bulk_feeds(raw_text_feeds); safe_rerun()
                    with st.expander("Active Feeds"):
                        for f in feeds:
                            st.text(f.name); st.caption(f.url)
                            if st.button("Delete", key=f"del_src_{f.id}", width="stretch"): 
                                svc.delete_record("FeedSource", f.id); safe_rerun()
            set_idx += 1

        if "Tab: Settings -> ML Training" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Smart Filter Training")
                pos, neg, total = svc.get_ml_counts()
                c1, c2, c3 = st.columns(3)
                c1.metric("Total Samples", total); c2.metric("Positives (Keep)", pos); c3.metric("Negatives (Dismiss)", neg)
                
                is_train_cooling = check_cooldown("ml_train", 60)
                if st.button("Training..." if is_train_cooling else "Retrain Model Now", type="primary", disabled=not can_train or is_train_cooling, key="set_ml_retrain", width="stretch"):
                    apply_cooldown("ml_train")
                    if total < 10: st.error("Not enough data! Please review at least 10 articles.")
                    else:
                        with st.spinner("Training neural pathways..."):
                            try: 
                                from src.train_model import train
                                train()
                                st.success("Model retrained successfully!")
                            except Exception as e: st.error(f"Training failed: {e}")
            set_idx += 1
                
        if "Tab: Settings -> AI & SMTP" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Universal LLM, System Integrations & Scoring")
                config_dict = sys_config or {}
                    
                with st.form("llm_config"):
                    st.markdown("### LLM Configuration")
                    endpoint = st.text_input("Endpoint URL", value=config_dict.get('llm_endpoint', ''))
                    api_key = st.text_input("API Key", value=config_dict.get('llm_api_key', ''), type="password")
                    model_name = st.text_input("Model Name", value=config_dict.get('llm_model_name', ''))
                    tech_stack_input = st.text_area("Internal Tech Stack", value=config_dict.get('tech_stack', 'SolarWinds, Cisco SD-WAN'), height=100)
                    is_active = st.checkbox("Enable AI Features", value=config_dict.get('is_active', False))
                    
                    st.divider()
                    st.markdown("### SMTP Broadcast Configuration")
                    c_s1, c_s2 = st.columns([3, 1])
                    smtp_server = c_s1.text_input("SMTP Server (e.g. smtp.office365.com)", value=config_dict.get('smtp_server', ''))
                    smtp_port = c_s2.number_input("Port", value=config_dict.get('smtp_port', 587))
                    c_s3, c_s4 = st.columns(2)
                    smtp_user = c_s3.text_input("SMTP Username", value=config_dict.get('smtp_username', ''))
                    smtp_pass = c_s4.text_input("SMTP Password", value=config_dict.get('smtp_password', ''), type="password")
                    c_s5, c_s6 = st.columns(2)
                    smtp_sender = c_s5.text_input("Sender Address", value=config_dict.get('smtp_sender', ''))
                    smtp_recip = c_s6.text_input("Default Recipient List", value=config_dict.get('smtp_recipient', ''))
                    smtp_enabled = st.checkbox("Enable SMTP Broadcasts", value=config_dict.get('smtp_enabled', False))

                    st.divider()
                    st.markdown("###  Threat Matrix Baseline Overrides")
                    st.caption("Leave at 0 to use the automatic 14-day moving average. Values > 0 will lock the baseline to that specific number.")
                    c_b1, c_b2 = st.columns(2)
                    base_cyb = c_b1.number_input("Cyber Baseline Override", value=float(config_dict.get('baseline_override_cyber', 0.0)), step=5.0)
                    base_phy = c_b2.number_input("Physical Baseline Override", value=float(config_dict.get('baseline_override_phys', 0.0)), step=5.0)
                    
                    st.divider()
                    st.markdown("### CIS Alert Level Countermeasures")
                    st.caption("Configure your organization's security posture per the CIS Alert Level framework. Higher values = better defenses = lower overall risk.")
                    c_c1, c_c2 = st.columns(2)
                    
                    sys_counter_val = config_dict.get('sys_countermeasures', 3)
                    net_counter_val = config_dict.get('net_countermeasures', 3)
                    
                    with c_c1:
                        st.markdown("**System Countermeasures** (Host-based security)")
                        st.caption("1=Old OS/no AV | 2=Missing patches | 3=Patched/AV | 4=Hardened | 5=Patched+Hardened+IDS")
                        sys_counter = st.select_slider("sys_counter", options=[1, 2, 3, 4, 5], value=sys_counter_val)
                    with c_c2:
                        st.markdown("**Network Countermeasures** (Network security)")
                        st.caption("1=No firewall | 2=Permissive FW | 3=Restrictive FW | 4=FW+validated | 5=FW+IDS+validated")
                        net_counter = st.select_slider("net_counter", options=[1, 2, 3, 4, 5], value=net_counter_val)

                    if st.form_submit_button("Save Global Config", width="stretch"):
                        new_config = {
                            "llm_endpoint": endpoint, "llm_api_key": api_key, "llm_model_name": model_name,
                            "tech_stack": tech_stack_input, "is_active": is_active, "smtp_server": smtp_server, 
                            "smtp_port": smtp_port, "smtp_username": smtp_user, "smtp_password": smtp_pass, 
                            "smtp_sender": smtp_sender, "smtp_recipient": smtp_recip, "smtp_enabled": smtp_enabled,
                            "baseline_override_cyber": base_cyb, "baseline_override_phys": base_phy,
                            "sys_countermeasures": sys_counter, "net_countermeasures": net_counter
                        }
                        svc.save_global_config(new_config)
                        st.success("Configuration Saved!"); time.sleep(1); safe_rerun()
            set_idx += 1

        if "Tab: Settings -> Users & Roles" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("User & Role Management")
                col_u1, col_u2 = st.columns(2)
                with col_u1:
                    available_roles = [r.name for r in svc.get_all_roles()]
                    with st.container(border=True):
                        st.markdown("###  Create New User")
                        with st.form("new_user_form"):
                            new_username = st.text_input("Username").strip()
                            new_password = st.text_input("Password", type="password")
                            new_role = st.selectbox("Assign Role", available_roles)
                            if st.form_submit_button("Create User", width="stretch"):
                                if not new_username or not new_password: st.error("Username and password required.")
                                else:
                                    if svc.create_user(new_username, new_password, new_role): 
                                        st.success(f"User '{new_username}' created!"); safe_rerun()
                                    else: st.error("Username already exists.")

                    with st.container(border=True):
                        st.markdown("###  Change User Role")
                        with st.form("update_user_role_form"):
                            usrs = svc.get_admin_lists()[2] if 'usrs' not in locals() else usrs
                            target_user = st.selectbox("Select User", [u.username for u in usrs])
                            new_assigned_role = st.selectbox("Assign New Role", available_roles)
                            if st.form_submit_button("Update Role", width="stretch"):
                                svc.update_user_role(target_user, new_assigned_role)
                                st.success(f"Updated {target_user} to role: {new_assigned_role}"); safe_rerun()
                                
                    with st.container(border=True):
                        st.markdown("###  Create Custom Role")
                        with st.form("new_role_form", clear_on_submit=True):
                            new_role_name = st.text_input("Role Name").strip().lower()
                            new_role_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES)
                            new_role_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS)
                            
                            # --- NEW: SITE TYPE CONFIGURATION ---
                            avail_types = svc.get_all_site_types()
                            new_role_site_types = st.multiselect("Allowed Site Types", avail_types, default=avail_types)
                            
                            if st.form_submit_button("Create Role", width="stretch"):
                                if not new_role_name or not new_role_pages: st.error("Role name and at least one page required.")
                                else:
                                    if svc.create_role(new_role_name, new_role_pages, new_role_actions, new_role_site_types):
                                        if hasattr(svc.get_all_roles, "clear"): svc.get_all_roles.clear()
                                        st.success(f"Role '{new_role_name}' created!"); time.sleep(1); safe_rerun()
                                    else: st.error("Role name already exists.")
                                    
                    with st.container(border=True):
                        st.markdown("###  Edit Existing Role")
                        editable_roles = [r for r in available_roles if r != "admin"]
                        if editable_roles:
                            role_to_edit = st.selectbox("Select Role to Edit", editable_roles)
                            if role_to_edit:
                                selected_role_obj = next((r for r in svc.get_all_roles() if r.name == role_to_edit), None)
                                current_pages = selected_role_obj.allowed_pages if selected_role_obj and selected_role_obj.allowed_pages else []
                                current_actions = selected_role_obj.allowed_actions if selected_role_obj and selected_role_obj.allowed_actions else []
                                
                                with st.form(f"edit_role_form_{role_to_edit}"):
                                    valid_default_pages = [p for p in current_pages if p in ALL_POSSIBLE_PAGES]
                                    valid_default_actions = [a for a in current_actions if a in ALL_POSSIBLE_ACTIONS]
                                    
                                    # --- NEW: SITE TYPE CONFIGURATION ---
                                    avail_types = svc.get_all_site_types()
                                    current_types = getattr(selected_role_obj, 'allowed_site_types', []) or []
                                    valid_default_types = [t for t in current_types if t in avail_types]
                                    
                                    updated_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES, default=valid_default_pages)
                                    updated_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS, default=valid_default_actions)
                                    updated_site_types = st.multiselect("Allowed Site Types", avail_types, default=valid_default_types)
                                    
                                    if st.form_submit_button("Update Role", width="stretch"):
                                        if not updated_pages: st.error("A role must have at least one allowed page.")
                                        else:
                                            svc.update_role(role_to_edit, updated_pages, updated_actions, updated_site_types)
                                            if hasattr(svc.get_all_roles, "clear"): svc.get_all_roles.clear()
                                            st.success(f"Role '{role_to_edit}' updated!"); time.sleep(1); safe_rerun()
                        else: st.info("No editable roles available.")

                with col_u2:
                    usrs = svc.get_admin_lists()[2] if 'usrs' not in locals() else usrs
                    with st.container(border=True):
                        st.markdown("### Active Users")
                        for u in usrs:
                            c_name, c_role, c_act = st.columns([3, 2, 1])
                            c_name.write(f"**{u.username}**"); c_role.caption(u.role.upper())
                            if u.username != st.session_state.current_user:
                                if c_act.button("", key=f"del_u_{u.id}", width="stretch"):
                                    svc.delete_record("User", u.id); safe_rerun()
                                    
                    with st.container(border=True):
                        st.markdown("###  Force Reset Password")
                        with st.form("admin_reset_pwd_form"):
                            target_user = st.selectbox("Select User ", [u.username for u in usrs])
                            force_new_pwd = st.text_input("New Password", type="password")
                            if st.form_submit_button("Reset Password", width="stretch"):
                                if force_new_pwd:
                                    svc.force_reset_pwd(target_user, force_new_pwd)
                                    st.success(f"Password reset for {target_user}.")

                    with st.container(border=True):
                        st.markdown("### Active Roles")
                        for r in svc.get_all_roles():
                            c_name, c_pages, c_act = st.columns([2, 3, 1])
                            c_name.write(f"**{r.name}**")
                            action_count = len(r.allowed_actions) if r.allowed_actions else 0
                            c_pages.caption(f"{len(r.allowed_pages)} pages | {action_count} perms")
                            if r.name not in ["admin", "analyst"]:
                                if c_act.button("", key=f"del_role_{r.id}", width="stretch"):
                                    svc.delete_record("Role", r.id); safe_rerun()
            set_idx += 1
                                    
        if "Tab: Settings -> Backup & Restore" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Database Export & Import")
                st.write("Backup or restore configurations, keywords, RSS feeds, and location mappings.")
                
                c_exp, c_imp = st.columns(2)
                with c_exp:
                    st.markdown("### Export Data")
                    if st.button("Generate Backup JSON", width="stretch"):
                        backup_data = svc.get_backup_data()
                        json_str = json.dumps(backup_data, indent=4)
                        st.download_button("Download System_Backup.json", data=json_str, file_name=f"NOC_Backup_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json", width="stretch")
                
                with c_imp:
                    st.markdown("### Import Data")
                    uploaded_backup = st.file_uploader("Upload JSON Backup File", type=["json"])
                    if uploaded_backup is not None:
                        if st.button("Execute Import", width="stretch", type="primary"):
                            try:
                                data = json.load(uploaded_backup)
                                added = svc.restore_backup_data(data)
                                st.success(f"Restored: {added['kw']} Keywords, {added['feeds']} Feeds, {added['locs']} Locations.")
                            except Exception as e:
                                st.error(f"Import Failed: {e}")
            set_idx += 1

        if "Tab: Settings -> Danger Zone" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.error("Database Maintenance & Irreversible Actions")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write("**Routine Maintenance**")
                    st.caption("Safely sweeps stale alerts & intel.")
                    is_gc_cooling = check_cooldown("gc_run", 60)
                    if st.button("Sweeping..." if is_gc_cooling else "Run Garbage Collector", width="stretch", disabled=is_gc_cooling):
                        apply_cooldown("gc_run")
                        with st.spinner("Purging stale data and vacuuming database..."):
                            from src.scheduler import run_database_maintenance
                            run_database_maintenance()
                            st.success("Swept and optimized!"); time.sleep(1); safe_rerun()
                            
                    st.write("**Reset Cloud Telemetry**")
                    st.caption("Wipes all cloud outages to force a clean sync.")
                    is_nuke_cloud_cooling = check_cooldown("nuke_cloud", 60)
                    if st.button("Purging..." if is_nuke_cloud_cooling else "Purge Cloud Data", width="stretch", disabled=is_nuke_cloud_cooling):
                        apply_cooldown("nuke_cloud")
                        svc.nuke_tables(["CloudOutage"])
                        st.success("Cloud data purged! Go to Threat Telemetry -> Cloud Services to repull."); time.sleep(1.5); safe_rerun()
                    
                    st.write("**Data Migration**")
                    st.caption("Applies new categories to historical 'General' data.")
                    is_recat_cooling = check_cooldown("recategorize", 60)
                    if st.button("Scanning..." if is_recat_cooling else "Recategorize Articles", width="stretch", disabled=is_recat_cooling):
                        apply_cooldown("recategorize")
                        with st.spinner("Scanning database..."):
                            updated_count = svc.recategorize_all_articles()
                            st.success(f"Successfully recategorized {updated_count} articles!"); time.sleep(2); safe_rerun()
                            
                with col2:
                    st.write("**Clear History**")
                    st.caption("Deletes all articles & IOCs.")
                    if st.button("Delete All Articles", width="stretch"):
                        svc.nuke_tables(["Article", "ExtractedIOC"])
                        safe_rerun()
                        
                    st.write("**Clear Locations**")
                    st.caption("Deletes all monitored facilities.")
                    if st.button("Delete All Locations", width="stretch"):
                        svc.nuke_tables(["MonitoredLocation"])
                        svc.get_cached_locations.clear()
                        safe_rerun()

                    st.write("**Crime Data Reset**")
                    st.caption("Purges all local LRPD dispatch and crime records from the database.")
                    if st.button("PURGE CRIME DATA", width="stretch"):
                        success, count = svc.nuke_crime_data()
                        if success:
                            st.toast(f"Successfully purged {count} crime records.")
                            safe_rerun()
                        else:
                            st.error(f"Failed to purge crime data: {count}")
                        
                with col3:

                    st.markdown("####  Weather & Fire Telemetry")
                    st.caption("Instantly drops all active NWS warnings, SPC outlooks, and Fire polygons from the map.")
                    if st.button("PURGE WEATHER & FIRE DATA", type="primary", width="stretch"):
                        success, count = svc.nuke_weather_data()
                        if success:
                            st.success(f"Erased {count} hazard records and cleared map cache."); time.sleep(1); safe_rerun()
                        else:
                            st.error(f"Failed: {count}")

                    st.divider()
                    st.write("**Factory Reset**")
                    st.caption("Destroys all data entirely.")
                    if st.button("FULL RESET", width="stretch"):
                        svc.nuke_tables(["Article", "ExtractedIOC", "FeedSource", "Keyword", "MonitoredLocation"])
                        svc.get_cached_locations.clear()
                        safe_rerun()

                    

                st.divider()
                st.markdown("###  Black Ops (Undocumented Features)")
                c_troll1, c_troll2 = st.columns(2)
                
                with c_troll1:
                    if st.session_state.current_user == "pwest":
                        with st.container(border=True):
                            st.write("**Operation: Nick**")
                            st.caption("Target: `nwilson`. 15% chance on refresh to lock their screen.")
                            tn = st.toggle("Enable Nick Troll", value=black_ops["nick_enabled"])
                            if tn != black_ops["nick_enabled"]:
                                black_ops["nick_enabled"] = tn
                                safe_rerun()
                    else:
                        st.info("Classified Operations Area.")
                        
                with c_troll2:
                    if st.session_state.current_role == "admin":
                        with st.container(border=True):
                            st.write("**Operation: Dean**")
                            st.caption("Targeted silent cascading failure simulation (2 sites/min until 100%).")
                            
                            # Get all active users to populate the target list
                            usrs = [u.username for u in svc.get_admin_lists()[2]] if svc.get_admin_lists()[2] else []
                            tgt_idx = usrs.index(black_ops["dean_target"]) if black_ops["dean_target"] in usrs else 0
                            
                            selected_target = st.selectbox("Select Target User", ["None"] + usrs, index=(tgt_idx + 1 if black_ops["dean_target"] else 0))
                            td = st.toggle("Engage Protocol", value=(black_ops["dean_target"] is not None))
                            
                            # Logic to trigger and save to global memory
                            if td and selected_target != "None":
                                if black_ops["dean_target"] != selected_target:
                                    black_ops["dean_target"] = selected_target
                                    black_ops["dean_start"] = time.time()
                                    safe_rerun()
                            elif not td and black_ops["dean_target"] is not None:
                                black_ops["dean_target"] = None
                                safe_rerun()
                        
            set_idx += 1
