import streamlit as st
import time
from streamlit_cookies_controller import CookieController
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import src.services as svc

LOCAL_TZ = ZoneInfo("America/Chicago")
cookie_controller = CookieController()

ALL_POSSIBLE_PAGES = [
    "Global Dashboards", "Threat Telemetry", "Regional Grid",
    "Threat Hunting & IOCs", "AIOps RCA", "Shift Logbook",
    "Reporting & Briefings", "Settings & Admin"
]

ALL_POSSIBLE_ACTIONS = [
    "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score",
    "Action: Trigger AI Functions", "Action: Manually Sync Data", "Action: Dispatch Exec Report",
    "Action: Submit Shift Log", "Action: Dispatch RCA Tickets", "Action: Manage Site Maintenance",
    "Tab: Dashboards -> Operational", "Tab: Dashboards -> Global Risk", "Tab: Dashboards -> Internal Risk",
    "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV",
    "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Perimeter Crime",
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
    "Tab: Reporting -> Elastic SIEM Report", "Tab: Regional Grid -> Hazard Analytics",
    "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log",
    "Tab: Regional Grid -> Atmos Weather", "Tab: Threat Hunting -> Global IOC Matrix",
    "Tab: Threat Hunting -> Deep Hunt Builder", "Tab: AIOps RCA -> Active Board",
    "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
    "Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History",
    "Tab: Reporting -> Daily Fusion", "Tab: Reporting -> Report Builder",
    "Tab: Reporting -> Shared Library", "Tab: Settings -> Facility Locations",
    "Tab: Settings -> Internal Assets", "Tab: Settings -> RSS Sources",
    "Tab: Settings -> AI & SMTP", "Tab: Settings -> Users & Roles",
    "Tab: Settings -> Backup & Restore", "Tab: Settings -> Danger Zone"
]

def safe_rerun():
    st.rerun()

def check_cooldown(key, cooldown_seconds=60):
    last_click = st.session_state.get(f"cooldown_{key}", 0)
    return (time.time() - last_click) < cooldown_seconds

def apply_cooldown(key):
    st.session_state[f"cooldown_{key}"] = time.time()

def format_local_time(utc_dt):
    if not utc_dt:
        return "Unknown"
    return utc_dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')

def get_score_badge(score):
    if score >= 80:
        return f" **[{int(score)}]**"
    elif score >= 50:
        return f" **[{int(score)}]**"
    return f" **[{int(score)}]**"

def get_cat_icon(cat):
    icons = {
        "Cyber: Exploits & Vulns": "", "Cyber: Malware & Threats": "",
        "ICS/OT & SCADA": "", "Cloud & IT Infra": "",
        "Physical Security": "", "Severe Weather": "",
        "Geopolitics & Policy": "", "AI & Emerging Tech": "",
        "General": ""
    }
    return icons.get(cat, "")

def init_session_state():
    if "current_user" not in st.session_state:
        st.session_state.current_user = None
        st.session_state.current_role = None
        st.session_state.allowed_pages = []
        st.session_state.allowed_actions = []

def authenticate_with_token():
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

def render_login_form():
    c_space1, c_login, c_space2 = st.columns([1, 2, 1])
    with c_login:
        st.title("NOC Intelligence Fusion Center")
        st.markdown("### Authentication Required")
        with st.form("login_form", clear_on_submit=True):
            username = st.text_input("Username").strip()
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Authenticate", width="stretch", type="primary"):
                try:
                    user, token = svc.authenticate_user(username, password)
                    if user:
                        try:
                            cookie_controller.set("noc_session_token", token, max_age=30 * 86400)
                        except Exception:
                            pass
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
                        st.rerun()
                    else:
                        st.error("Invalid credentials.")
                except Exception as e:
                    st.error(f"Login error: {e}")
    st.stop()

def ensure_admin_permissions():
    if st.session_state.current_role == "admin":
        st.session_state.allowed_pages = ALL_POSSIBLE_PAGES
        st.session_state.allowed_actions = ALL_POSSIBLE_ACTIONS
        st.session_state.allowed_site_types = "ALL"

def get_permission_flags():
    return {
        "can_pin": "Action: Pin Articles" in st.session_state.allowed_actions,
        "can_train": "Action: Train ML Model" in st.session_state.allowed_actions,
        "can_boost": "Action: Boost Threat Score" in st.session_state.allowed_actions,
        "can_trigger_ai": "Action: Trigger AI Functions" in st.session_state.allowed_actions,
        "can_sync": "Action: Manually Sync Data" in st.session_state.allowed_actions,
        "can_dispatch_report": "Action: Dispatch Exec Report" in st.session_state.allowed_actions,
        "can_dispatch_rca": "Action: Dispatch RCA Tickets" in st.session_state.allowed_actions,
        "can_manage_maint": "Action: Manage Site Maintenance" in st.session_state.allowed_actions,
        "can_submit_log": "Action: Submit Shift Log" in st.session_state.allowed_actions,
    }

def get_theme_css():
    theme_options = [
        "Standard", "NOC Terminal", "High Contrast (Dark)",
        "Cyberpunk", "Solarized Dark", "Midnight Ocean"
    ]
    theme_cookie_key = f"noc_theme_{st.session_state.current_user}" if st.session_state.current_user else "noc_theme_guest"
    saved_theme = cookie_controller.get(theme_cookie_key)

    if "ui_theme" not in st.session_state:
        st.session_state.ui_theme = saved_theme if saved_theme in theme_options else "Standard"

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
    base_css = f"""
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
    """
    return base_css, theme_options, theme_cookie_key

def render_article_feed(feed_articles, key_prefix=""):
    from src.utils.llm import generate_bluf
    if not feed_articles:
        st.success("Queue is empty.")
        return
    for art in feed_articles:
        with st.container(border=True):
            c_title, c_score = st.columns([4, 1])
            c_title.markdown(f"**{get_score_badge(art.score)} [{art.title}]({art.link})**")
            c_title.caption(f" {format_local_time(art.published_date)} |  {art.source} | {get_cat_icon(art.category)} {art.category}")
            if art.ai_bluf:
                st.success(f"**AI BLUF:** {art.ai_bluf}")
            st.caption(art.summary[:500] + "..." if art.summary else "No summary available.")
            perms = get_permission_flags()
            c1, c2, c3, c4, c5 = st.columns(5)
            if c1.button("Unpin" if art.is_pinned else "Pin", key=f"{key_prefix}pin_{art.id}", disabled=not perms["can_pin"]):
                svc.toggle_pin(art.id)
                safe_rerun()
            if c2.button(" +15 Score", key=f"{key_prefix}boost_{art.id}", disabled=not perms["can_boost"]):
                svc.boost_score(art.id, 15)
                safe_rerun()
            if c3.button("Keep", key=f"{key_prefix}keep_{art.id}", disabled=not perms["can_train"]):
                svc.change_status(art.id, 2)
                safe_rerun()
            if c4.button("Dismiss", key=f"{key_prefix}dism_{art.id}", disabled=not perms["can_train"]):
                svc.change_status(art.id, 1)
                safe_rerun()
            sys_config = svc.get_cached_config()
            ai_enabled = sys_config.is_active if sys_config else False
            if ai_enabled and not art.ai_bluf:
                is_ai_cooling = check_cooldown(f"bluf_{art.id}", 30)
                if c5.button("Generating..." if is_ai_cooling else "BLUF", key=f"{key_prefix}bluf_{art.id}", disabled=not perms["can_trigger_ai"] or is_ai_cooling):
                    apply_cooldown(f"bluf_{art.id}")
                    with st.spinner("Analyzing..."):
                        with svc.SessionLocal() as session:
                            b = generate_bluf(art, session)
                        if b:
                            svc.save_ai_bluf(art.id, b)
                            safe_rerun()


@st.cache_resource
def get_black_ops_state():
    return {"nick_enabled": False, "dean_target": None, "dean_start": 0}
