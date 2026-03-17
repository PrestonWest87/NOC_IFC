import streamlit as st
import pandas as pd
import time
import bcrypt
import uuid
from streamlit_cookies_controller import CookieController
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from sqlalchemy import text
from streamlit_autorefresh import st_autorefresh
import streamlit.components.v1 as components
from shapely.geometry import Point, shape

from src.database import SessionLocal, Article, FeedSource, Keyword, SystemConfig, engine, init_db, CveItem, RegionalHazard, CloudOutage, User, Role, SavedReport, DailyBriefing, ExtractedIOC, MonitoredLocation, SolarWindsAlert, TimelineEvent, RegionalOutage, NodeAlias, BgpAnomaly
from src.train_model import train 
from src.scheduler import fetch_feeds
from src.llm import generate_briefing, generate_bluf, analyze_cascading_impacts, cross_reference_cves, build_custom_intel_report, generate_feed_overview, generate_rolling_summary, generate_daily_fusion_report
from shapely.geometry import Point

@st.cache_resource
def setup_database():
    init_db()
    return True

setup_database()
st.set_page_config(page_title="Intelligence Fusion Center", layout="wide")

def get_db(): return SessionLocal()
session = get_db()
LOCAL_TZ = ZoneInfo("America/Chicago")
cookie_controller = CookieController()

def safe_rerun():
    try: session.close()
    except Exception: pass
    st.rerun()

@st.cache_data(ttl=60)
def get_dashboard_metrics():
    db_session = SessionLocal()
    try:
        twenty_four_hours_ago = datetime.utcnow() - timedelta(days=1)
        return {
            "rss_count": db_session.query(Article).filter(Article.published_date >= twenty_four_hours_ago, Article.score >= 50).count(),
            "cve_count": db_session.query(CveItem).filter(CveItem.date_added >= twenty_four_hours_ago).count(),
            "hazard_count": db_session.query(RegionalHazard).filter(RegionalHazard.updated_at >= twenty_four_hours_ago).count(),
            "cloud_count": db_session.query(CloudOutage).filter(CloudOutage.updated_at >= twenty_four_hours_ago, CloudOutage.is_resolved == False).count()
        }
    finally:
        db_session.close()

ALL_POSSIBLE_PAGES = [
    "🌐 Operational Dashboard", 
    "📰 Daily Fusion Report",
    "📡 Threat Telemetry", 
    "🎯 Threat Hunting & IOCs",
    "⚡ AIOps RCA", 
    "📑 Report Center", 
    "⚙️ Settings & Admin"
]

ALL_POSSIBLE_ACTIONS = [
    "action_pin", "action_train_ml", "action_boost_threat", "action_trigger_ai", "action_sync_data",
    "tab_tt_rss", "tab_tt_kev", "tab_tt_cloud", "tab_tt_infra",
    "tab_rc_build", "tab_rc_lib"
]

if "current_user" not in st.session_state:
    st.session_state.current_user = None
    st.session_state.current_role = None
    st.session_state.allowed_pages = []
    st.session_state.allowed_actions = []

if st.session_state.current_user is None:
    saved_token = cookie_controller.get("noc_session_token")
    if saved_token:
        user = session.query(User).filter(User.session_token == saved_token).first()
        if user:
            st.session_state.current_user = user.username
            st.session_state.current_role = user.role
            role_obj = session.query(Role).filter(Role.name == user.role).first()
            if role_obj:
                if "⚡ AIOps RCA (Staging)" in role_obj.allowed_pages:
                    role_obj.allowed_pages = [p if p != "⚡ AIOps RCA (Staging)" else "⚡ AIOps RCA" for p in role_obj.allowed_pages]
                    session.commit()
                st.session_state.allowed_pages = role_obj.allowed_pages
                st.session_state.allowed_actions = role_obj.allowed_actions or []
            safe_rerun()

if st.session_state.current_user is None:
    st.title("🔐 NOC Fusion Center")
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Authenticate", width="stretch"):
                user = session.query(User).filter(User.username == username).first()
                if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                    new_token = str(uuid.uuid4())
                    user.session_token = new_token
                    session.commit()
                    cookie_controller.set("noc_session_token", new_token, max_age=30*86400)
                    st.session_state.current_user = user.username
                    st.session_state.current_role = user.role
                    time.sleep(0.5); safe_rerun()
                else: st.error("❌ Invalid credentials.")
    st.stop() 

role_obj = session.query(Role).filter(Role.name == st.session_state.current_role).first()
if role_obj:
    if "⚡ AIOps RCA (Staging)" in role_obj.allowed_pages:
        role_obj.allowed_pages = [p if p != "⚡ AIOps RCA (Staging)" else "⚡ AIOps RCA" for p in role_obj.allowed_pages]
        session.commit()
    st.session_state.allowed_pages = role_obj.allowed_pages
    st.session_state.allowed_actions = role_obj.allowed_actions or []

can_pin = "action_pin" in st.session_state.allowed_actions
can_train = "action_train_ml" in st.session_state.allowed_actions
can_boost = "action_boost_threat" in st.session_state.allowed_actions
can_trigger_ai = "action_trigger_ai" in st.session_state.allowed_actions
can_sync = "action_sync_data" in st.session_state.allowed_actions

current_user_obj = session.query(User).filter(User.username == st.session_state.current_user).first()

st.markdown("""
    <style>
        .block-container { padding-top: 1rem; padding-bottom: 0rem; padding-left: 1rem; padding-right: 1rem; max-width: 100%; }
        h1 { font-size: 1.8rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }
        h2 { font-size: 1.4rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }
        h3 { font-size: 1.1rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }
        [data-testid="stVerticalBlockBorderWrapper"] p, 
        [data-testid="stVerticalBlockBorderWrapper"] li,
        [data-testid="stExpanderDetails"] p,
        [data-testid="stExpanderDetails"] li { font-size: 0.9rem !important; margin-bottom: 0.2rem !important; line-height: 1.3 !important; }
        hr { margin-top: 0.5rem; margin-bottom: 0.5rem; }
        .stButton>button { padding: 0rem 0.5rem !important; min-height: 2rem !important; }
    </style>
""", unsafe_allow_html=True)

def get_score_badge(score):
    if score >= 80: return f"🔴 **[{int(score)}]**"
    elif score >= 50: return f"🟠 **[{int(score)}]**"
    else: return f"🔵 **[{int(score)}]**"

def get_cat_icon(cat):
    if cat == "Cyber": return "💻"
    elif cat == "Physical/Weather": return "🌪️"
    elif cat == "Geopolitics/News": return "🌍"
    return "📰"

def toggle_pin(art_id):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art: art.is_pinned = not art.is_pinned; session.commit()

def boost_score(art_id, amount=15):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art: art.score = min(100.0, art.score + amount); session.commit()

def format_local_time(utc_dt):
    if not utc_dt: return "Unknown"
    return utc_dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')

def change_status(art_id, new_feedback, bubble_status=None):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art:
        if art.human_feedback == 0 and new_feedback in [1, 2] and art.keywords_found:
            for kw in art.keywords_found:
                keyword_db = session.query(Keyword).filter_by(word=kw).first()
                if keyword_db:
                    if new_feedback == 2: keyword_db.weight += 1
                    elif new_feedback == 1: keyword_db.weight = max(1, keyword_db.weight - 1)
        art.human_feedback = new_feedback
        if bubble_status is not None: art.is_bubbled = bubble_status
        session.commit()

sys_config = session.query(SystemConfig).first()
ai_enabled = sys_config and sys_config.is_active

def render_article_feed(feed_articles, key_prefix=""):
    if not feed_articles: 
        st.success("Queue is empty.")
        return
        
    for art in feed_articles:
        with st.container(border=True):
            c_title, c_score = st.columns([4, 1])
            c_title.markdown(f"**{get_score_badge(art.score)} [{art.title}]({art.link})**")
            c_title.caption(f"📅 {format_local_time(art.published_date)} | 📡 {art.source} | {get_cat_icon(art.category)} {art.category}")
            
            if art.ai_bluf: st.success(f"**AI BLUF:** {art.ai_bluf}")
            else: st.caption(art.summary[:250] + "..." if art.summary else "No summary.")
                
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.button("📍 Unpin" if art.is_pinned else "📌 Pin", key=f"{key_prefix}pin_{art.id}", disabled=not can_pin, on_click=toggle_pin, args=(art.id,))
            c2.button("⏫ +15 Score", key=f"{key_prefix}boost_{art.id}", disabled=not can_boost, on_click=boost_score, args=(art.id, 15))
            c3.button("🧠 Keep", key=f"{key_prefix}keep_{art.id}", disabled=not can_train, on_click=change_status, args=(art.id, 2))
            c4.button("🧠 Dismiss", key=f"{key_prefix}dism_{art.id}", disabled=not can_train, on_click=change_status, args=(art.id, 1))
            
            if ai_enabled and not art.ai_bluf:
                if c5.button("🤖 BLUF", key=f"{key_prefix}bluf_{art.id}", disabled=not can_trigger_ai):
                    with st.spinner("Analyzing..."):
                        b = generate_bluf(art, session)
                        if b: art.ai_bluf = b; session.commit(); safe_rerun()

st.sidebar.title("NOC Fusion")
display_name = current_user_obj.full_name if current_user_obj and current_user_obj.full_name else st.session_state.current_user.capitalize()
display_title = current_user_obj.job_title if current_user_obj and current_user_obj.job_title else st.session_state.current_role.upper()
st.sidebar.markdown(f"👤 **{display_name}**\n\n<small>{display_title}</small>", unsafe_allow_html=True)

if st.sidebar.button("🚪 Log Out", width="stretch"):
    if current_user_obj: current_user_obj.session_token = None
    session.commit()
    cookie_controller.remove("noc_session_token")
    st.session_state.current_user = None; st.session_state.current_role = None
    time.sleep(0.5); safe_rerun()

with st.sidebar.expander("📝 My Profile"):
    with st.form("my_profile_form"):
        new_fn = st.text_input("Full Name", value=current_user_obj.full_name if current_user_obj.full_name else "")
        new_jt = st.text_input("Job Title", value=current_user_obj.job_title if current_user_obj.job_title else "")
        new_ci = st.text_input("Contact Info", value=current_user_obj.contact_info if current_user_obj.contact_info else "")
        st.divider()
        old_pwd = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        if st.form_submit_button("Save Profile", width="stretch"):
            current_user_obj.full_name = new_fn; current_user_obj.job_title = new_jt; current_user_obj.contact_info = new_ci
            if new_pwd:
                if bcrypt.checkpw(old_pwd.encode('utf-8'), current_user_obj.password_hash.encode('utf-8')):
                    current_user_obj.password_hash = bcrypt.hashpw(new_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    st.success("Updated!")
                else: st.error("Incorrect password.")
            else: st.success("Updated!")
            session.commit(); time.sleep(0.5); safe_rerun()

# --- CONTEXT AWARE NAVIGATION & REFRESH ---
st.sidebar.divider()
PAGES = st.session_state.allowed_pages

if not PAGES: st.error("No assigned permissions."); st.stop()
if "active_page" not in st.session_state or st.session_state.active_page not in PAGES: st.session_state.active_page = PAGES[0]

# Render Navigation First
selected_page = st.sidebar.radio("Navigation", PAGES, index=PAGES.index(st.session_state.active_page), key="nav_radio")
if selected_page != st.session_state.active_page: st.session_state.active_page = selected_page; safe_rerun()
page = st.session_state.active_page

st.sidebar.divider()
refresh_count = 0
current_refresh_sec = 0

# Render Page-Specific Refresh Controls
if page == "⚡ AIOps RCA":
    refresh_rate = st.sidebar.selectbox("🔴 RCA Live Sync", ["5 Seconds", "10 Seconds", "30 Seconds", "Paused"], index=0, key="aiops_refresh")
    rmap = {"5 Seconds": 5, "10 Seconds": 10, "30 Seconds": 30, "Paused": 0}
    current_refresh_sec = rmap[refresh_rate]
    if current_refresh_sec > 0:
        refresh_count = st_autorefresh(interval=current_refresh_sec * 1000, key="aiops_timer")
        
elif page == "🌐 Operational Dashboard":
    refresh_rate = st.sidebar.selectbox("🔄 Dashboard Refresh", ["Off", "1 Minute", "2 Minutes", "5 Minutes"], index=2, key="dash_refresh")
    rmap = {"Off": 0, "1 Minute": 60, "2 Minutes": 120, "5 Minutes": 300}
    current_refresh_sec = rmap[refresh_rate]
    if current_refresh_sec > 0:
        refresh_count = st_autorefresh(interval=current_refresh_sec * 1000, key="dash_timer")

# ================= 1. OPERATIONAL DASHBOARD =================
if page == "🌐 Operational Dashboard":
    st.title("🌐 Operational Dashboard")
    twenty_four_hours_ago = datetime.utcnow() - timedelta(days=1)
    
    metrics = get_dashboard_metrics()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("High-Threat RSS (24h)", metrics["rss_count"])
    c2.metric("Active KEVs (24h)", metrics["cve_count"])
    c3.metric("Hazards (24h)", metrics["hazard_count"])
    c4.metric("Cloud Outages (24h)", metrics["cloud_count"])
    st.divider()
    
    dash_panels = ["🔥 Threat Triage", "🛡️ Infrastructure Status", "🤖 AI Analysis"]
    if "auto_rotate_dash" not in st.session_state: st.session_state.auto_rotate_dash = True
    c_tog, c_space = st.columns([1, 5])
    auto_rotate = c_tog.toggle("🔄 Auto-Rotate", key="auto_rotate_dash")

    calculated_index = refresh_count % len(dash_panels) if auto_rotate else 0
    selected_panel = st.radio("Views", dash_panels, index=calculated_index, horizontal=True, label_visibility="collapsed")
    st.write("")

    if selected_panel == "🔥 Threat Triage":
        col_pin, col_rss = st.columns([1, 1])
        with col_pin:
            st.subheader("📌 Pinned Intel")
            pinned_arts = session.query(Article).filter(Article.is_pinned == True).order_by(Article.published_date.desc()).all()
            for art in pinned_arts:
                st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small>📡 {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)
                if art.ai_bluf: st.success(f"**AI BLUF:** {art.ai_bluf}")
                st.write("")
        with col_rss:
            st.subheader("🚨 Live Feed (Top 15)")
            top_rss = session.query(Article).filter(Article.published_date >= twenty_four_hours_ago, Article.score >= 50.0, Article.is_pinned == False).order_by(Article.score.desc(), Article.published_date.desc()).limit(15).all()
            for art in top_rss:
                st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small>📡 {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)

    elif selected_panel == "🛡️ Infrastructure Status":
        col_cve, col_cld, col_reg = st.columns(3)
        with col_cve:
            st.subheader("🪲 CISA KEVs (Top 15)")
            for cve in session.query(CveItem).order_by(CveItem.date_added.desc()).limit(15).all():
                st.markdown(f"🚨 **[{cve.cve_id}](https://nvd.nist.gov/vuln/detail/{cve.cve_id})**<br><small>{cve.vendor} {cve.product}</small>", unsafe_allow_html=True)
        with col_cld:
            st.subheader("☁️ Active Cloud Outages")
            outages = session.query(CloudOutage).filter(CloudOutage.is_resolved == False).order_by(CloudOutage.updated_at.desc()).limit(5).all()
            if not outages: st.success("Clear.")
            for out in outages:
                st.markdown(f"🚨 **{out.provider}**<br><small>[{out.title}]({out.link})</small>", unsafe_allow_html=True)
        with col_reg:
            st.subheader("🌪️ Regional Hazards")
            hazards = session.query(RegionalHazard).order_by(RegionalHazard.updated_at.desc()).limit(15).all()
            if not hazards: st.success("Clear.")
            for haz in hazards:
                icon = "🔴" if haz.severity in ["Extreme", "Severe"] else "🟠" if haz.severity == "Moderate" else "🔵"
                st.markdown(f"{icon} **{haz.severity}**<br><small>{haz.title} ({haz.location})</small>", unsafe_allow_html=True)

    elif selected_panel == "🤖 AI Analysis":
        col_ai1, col_ai2 = st.columns([2, 1])
        with col_ai1:
            st.subheader("🤖 AI Shift Briefing")
            if ai_enabled:
                now = datetime.utcnow()
                if not sys_config.rolling_summary or not sys_config.rolling_summary_time or (now - sys_config.rolling_summary_time).total_seconds() > 1800:
                    with st.spinner("🤖 Updating..."):
                        ns = generate_rolling_summary(session)
                        if ns: sys_config.rolling_summary = ns; sys_config.rolling_summary_time = now; session.commit()
                c_time, c_btn = st.columns([3, 2])
                c_time.caption(f"Last Sync: {format_local_time(sys_config.rolling_summary_time)}")
                if c_btn.button("🔄 Force Refresh Briefing", width="stretch", disabled=not can_trigger_ai, key="dash_refresh_ai"):
                    with st.spinner("🤖 Forcing AI Summary Update..."):
                        ns = generate_rolling_summary(session)
                        if ns: sys_config.rolling_summary = ns; sys_config.rolling_summary_time = datetime.utcnow(); session.commit(); safe_rerun()
                st.info(sys_config.rolling_summary if sys_config.rolling_summary else "Initializing...")
            else: st.info("AI Disabled.")
            
        with col_ai2:
            st.subheader("🤖 Security Auditor")
            st.caption("Checks active tech stack against KEVs.")
            if st.button("Scan Stack Against 30-Day KEVs", width="stretch", disabled=not can_trigger_ai, key="dash_scan_stack"):
                with st.spinner("Scanning..."):
                    cves = session.query(CveItem).filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30)).all()
                    res = cross_reference_cves(cves, session)
                    if res and ("clear" in res.lower() or "no active" in res.lower()): st.success("✅ " + res)
                    else: st.error(f"⚠️ **MATCH DETECTED:**\n{res}")

# ================= 2. DAILY FUSION REPORT =================
elif page == "📰 Daily Fusion Report":
    st.title("📰 Daily Master Fusion Report")
    st.markdown("AI-synthesized situational report covering Cyber, Vulnerabilities, Physical Hazards, and Cloud Infrastructure.")
    yesterday_local = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    existing_report = session.query(DailyBriefing).filter(DailyBriefing.report_date == yesterday_local).first()
    
    col1, col2 = st.columns([3, 1])
    if col2.button("🤖 Generate Yesterday's Report", width="stretch", type="primary", disabled=not can_trigger_ai, key="br_gen_report"):
        if not ai_enabled: st.error("AI is disabled.")
        else:
            with st.spinner("Processing massive datasets..."):
                date_obj, report_markdown = generate_daily_fusion_report(session)
                if report_markdown:
                    if existing_report: existing_report.content = report_markdown; existing_report.created_at = datetime.utcnow()
                    else: session.add(DailyBriefing(report_date=date_obj, content=report_markdown))
                    session.commit(); st.success("Report Generated!"); time.sleep(1); safe_rerun()

    st.divider()
    if existing_report:
        with st.container(border=True): st.markdown(existing_report.content)
    else: st.info("No report generated for yesterday yet.")

# ================= 3. THREAT TELEMETRY =================
elif page == "📡 Threat Telemetry":
    st.title("📡 Unified Threat Telemetry")
    
    tt_tab_names = []
    if "tab_tt_rss" in st.session_state.allowed_actions: tt_tab_names.append("📰 RSS Triage")
    if "tab_tt_kev" in st.session_state.allowed_actions: tt_tab_names.append("🪲 Exploits (KEV)")
    if "tab_tt_cloud" in st.session_state.allowed_actions: tt_tab_names.append("☁️ Cloud Services")
    if "tab_tt_infra" in st.session_state.allowed_actions: tt_tab_names.append("🗺️ Regional Grid")
    
    if not tt_tab_names:
        st.warning("You do not have permission to view any Telemetry modules.")
    else:
        tabs = st.tabs(tt_tab_names)
        tab_idx = 0
        
        if "tab_tt_rss" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col_title, col_btn = st.columns([3, 1])
                if col_btn.button("🔄 Force Fetch Feeds", width="stretch", disabled=not can_sync, key="tt_fetch_feeds"):
                    fetch_feeds(source="User Force"); time.sleep(1); safe_rerun()
                
                st.write("")
                cat_filter = st.selectbox("🎯 Filter Active Feeds by Category", ["All", "Cyber", "Physical/Weather", "Geopolitics/News", "General"], key="rss_cat_filter")
                st.divider()

                def render_paginated_feed(base_query, feed_id, page_size=20):
                    state_key = f"page_{feed_id}"
                    if state_key not in st.session_state: st.session_state[state_key] = 1
                    total_items = base_query.count()
                    total_pages = max(1, (total_items + page_size - 1) // page_size)
                    if st.session_state[state_key] > total_pages: st.session_state[state_key] = max(1, total_pages)
                    current_page = st.session_state[state_key]
                    
                    def pagination_controls(loc):
                        col1, col2, col3 = st.columns([1, 2, 1])
                        with col1:
                            if st.button("⬅️ Previous", key=f"prev_{feed_id}_{loc}", disabled=(current_page <= 1), width="stretch"):
                                st.session_state[state_key] -= 1; safe_rerun()
                        with col2:
                            st.markdown(f"<div style='text-align: center; margin-top: 0.4rem;'><b>Page {current_page} of {total_pages}</b> <span style='font-size: 0.85em; color: gray;'>(Total: {total_items})</span></div>", unsafe_allow_html=True)
                        with col3:
                            if st.button("Next ➡️", key=f"next_{feed_id}_{loc}", disabled=(current_page >= total_pages), width="stretch"):
                                st.session_state[state_key] += 1; safe_rerun()

                    if total_items > page_size: pagination_controls("top"); st.divider()
                    elif total_items == 0: st.info("No articles found matching this criteria."); return
                    
                    offset = (current_page - 1) * page_size
                    items = base_query.offset(offset).limit(page_size).all()
                    render_article_feed(items, key_prefix=f"{feed_id}_")
                    if total_items > page_size: st.divider(); pagination_controls("bottom")

                sub_tab_pinned, sub_tab_live, sub_tab_low, sub_tab_search = st.tabs(["📌 Pinned", "📡 Live Feed (>50)", "📉 Below Threshold (<50)", "🔍 Deep Search"])
                
                with sub_tab_pinned:
                    q_pinned = session.query(Article).filter(Article.is_pinned == True)
                    if cat_filter != "All": q_pinned = q_pinned.filter(Article.category == cat_filter)
                    render_paginated_feed(q_pinned.order_by(Article.published_date.desc()), feed_id="pinned", page_size=10)

                with sub_tab_live: 
                    q_live = session.query(Article).filter(Article.score >= 50.0, Article.is_pinned == False)
                    if cat_filter != "All": q_live = q_live.filter(Article.category == cat_filter)
                    render_paginated_feed(q_live.order_by(Article.published_date.desc()), feed_id="live", page_size=20)
                    
                with sub_tab_low: 
                    q_low = session.query(Article).filter(Article.score < 50.0, Article.is_pinned == False)
                    if cat_filter != "All": q_low = q_low.filter(Article.category == cat_filter)
                    render_paginated_feed(q_low.order_by(Article.published_date.desc()), feed_id="low", page_size=20)
                    
                with sub_tab_search:
                    s1, s2, s3 = st.columns([2, 1, 1])
                    search_term = s1.text_input("Search (Keywords or Source)", key="tt_search_kw")
                    min_score = s2.number_input("Min Score", value=0, key="tt_search_min")
                    page_size_sel = s3.selectbox("Items per Page", [10, 20, 50], index=1, key="tt_search_lim")
                    q_search = session.query(Article).filter(Article.score >= min_score)
                    if search_term: q_search = q_search.filter(Article.title.ilike(f"%{search_term}%") | Article.summary.ilike(f"%{search_term}%"))
                    if cat_filter != "All": q_search = q_search.filter(Article.category == cat_filter)
                    render_paginated_feed(q_search.order_by(Article.score.desc(), Article.published_date.desc()), feed_id="search", page_size=page_size_sel)
            tab_idx += 1
            
        if "tab_tt_kev" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                if st.button("🔄 Sync CISA KEV", disabled=not can_sync, key="tt_sync_kev", width="stretch"):
                    with st.spinner("Pulling..."):
                        from src.cve_worker import fetch_cisa_kev; fetch_cisa_kev(); time.sleep(1); safe_rerun()
                db = st.radio("Filter:", ["7 Days", "30 Days", "Archive"], horizontal=True, key="tt_vuln_db")
                q = session.query(CveItem)
                if db == "7 Days": q = q.filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=7))
                elif db == "30 Days": q = q.filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30))
                for cve in q.order_by(CveItem.date_added.desc()).limit(50).all():
                    with st.expander(f"🚨 {cve.cve_id} | {cve.vendor} {cve.product}"):
                        st.markdown(f"**{cve.vulnerability_name}**\n\n{cve.description}")
            tab_idx += 1
            
        if "tab_tt_cloud" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                if st.button("🔄 Sync Cloud Status", disabled=not can_sync, key="tt_sync_cloud", width="stretch"):
                    with st.spinner("Pulling data from Global Providers..."):
                        from src.cloud_worker import fetch_cloud_outages; fetch_cloud_outages(); time.sleep(1); safe_rerun()
                
                active_outages = session.query(CloudOutage).filter(CloudOutage.is_resolved == False).order_by(CloudOutage.updated_at.desc()).all()
                
                if not active_outages:
                    st.success("✅ All tracked global SaaS and IaaS providers are reporting Operational status.")
                else:
                    affected_providers = sorted(list(set([o.provider for o in active_outages])))
                    st.warning(f"⚠️ Active service degradations detected across {len(affected_providers)} providers.")
                    
                    provider_tabs = st.tabs(affected_providers)
                    
                    for p_idx, provider_name in enumerate(affected_providers):
                        with provider_tabs[p_idx]:
                            prov_outs = [o for o in active_outages if o.provider == provider_name]
                            for o in prov_outs:
                                with st.expander(f"🚨 {o.service} ({format_local_time(o.updated_at)})"):
                                    st.markdown(f"**[{o.title}]({o.link})**\n\n{o.description}")
                                    
                st.divider()
                with st.expander("📚 View Historical / Resolved Incidents (Last 72 Hours)"):
                    resolved_outages = session.query(CloudOutage).filter(CloudOutage.is_resolved == True).order_by(CloudOutage.updated_at.desc()).limit(50).all()
                    if not resolved_outages:
                        st.info("No recently resolved incidents.")
                    for o in resolved_outages:
                        st.markdown(f"✅ **{o.provider}** | {o.service} <br><small>[{o.title}]({o.link})</small>", unsafe_allow_html=True)
            tab_idx += 1
            
        if "tab_tt_infra" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col_sync1, col_sync2 = st.columns([3, 1])
                if col_sync2.button("🔄 Sync Regional Telemetry", disabled=not can_sync, key="tt_sync_infra", width="stretch"):
                    with st.spinner("Pulling Radar & Calculating Geospatial Intersections..."):
                        from src.infra_worker import fetch_regional_hazards; fetch_regional_hazards(); time.sleep(1); st.cache_data.clear(); safe_rerun()
                
                locs = session.query(MonitoredLocation).all()
                df = pd.DataFrame([{"id": l.id, "Name": l.name, "Type": l.loc_type, "Priority": l.priority, "Risk": l.current_spc_risk, "Lat": l.lat, "Lon": l.lon} for l in locs]) if locs else pd.DataFrame()
                
                # --- MEMORY CACHE FOR INSTANT TOGGLES ---
                @st.cache_data(ttl=120)
                def get_cached_geo():
                    import requests
                    spc, ar, oos = None, None, None
                    try: spc = requests.get("https://www.spc.noaa.gov/products/outlook/day1otlk_cat.lyr.geojson", timeout=5).json()
                    except: pass
                    try: ar = requests.get("https://api.weather.gov/alerts/active?area=AR", headers={"User-Agent": "NOC_Fusion_App"}, timeout=5).json()
                    except: pass
                    try: oos = requests.get("https://api.weather.gov/alerts/active?area=OK,MS,MO", headers={"User-Agent": "NOC_Fusion_App"}, timeout=5).json()
                    except: pass
                    return spc, ar, oos

                spc_data, ar_data, oos_data = get_cached_geo()
                
                # Extract all unique NWS event types currently active to populate the new filter
                active_event_types = set()
                for geo_dataset in [ar_data, oos_data]:
                    if geo_dataset:
                        for f in geo_dataset.get("features", []):
                            active_event_types.add(f.get("properties", {}).get("event", "Unknown"))
                active_event_types = sorted(list(active_event_types))

                # ==========================
                # INNER SIDEBAR LAYOUT
                # ==========================
                ctrl_panel, main_panel = st.columns([1, 4])
                
                with ctrl_panel:
                    st.subheader("⚙️ Map Controls")
                    with st.container(border=True):
                        st.markdown("**Master Layers**")
                        show_radar_overlay = st.toggle("📡 Radar Overlay", value=True)
                        show_radar_panel = st.toggle("📺 Animated Panel", value=False)
                        st.divider()
                        show_spc = st.toggle("⛈️ SPC Convective", value=True)
                        show_warn = st.toggle("🚨 Warnings (AR)", value=True)
                        show_watch = st.toggle("⚠️ Watches (AR)", value=True)
                        show_oos = st.toggle("🌍 Out-of-State", value=True)
                    
                    with st.container(border=True):
                        st.markdown("**Hazard Isolation**")
                        if not active_event_types:
                            st.info("No active hazards to filter.")
                            selected_events = []
                        else:
                            st.caption("Select specific warnings to render:")
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
                            selected_types, selected_prios = [], []

                with main_panel:
                    tab_map, tab_dash, tab_analytics, tab_matrix, tab_manage = st.tabs([
                        "🗺️ Geospatial Overlay", "📊 Executive Dashboard", "🌪️ Deep Hazard Analytics", "🗄️ Location Matrix", "📍 Manage Locations"
                    ])
                    
                    # ==========================
                    # PRE-CALCULATE GEOMETRY
                    # ==========================
                    master_polygons = []   # Analytics
                    toggled_polygons = []  # Map
                    layers = []
                    import pydeck as pdk
                    from shapely.geometry import Point, shape

                    # 0. LIVE NEXRAD RADAR TILE LAYER
                    if show_radar_overlay:
                        layers.append(pdk.Layer(
                            "TileLayer",
                            data=["https://mesonet.agron.iastate.edu/cache/tile.py/1.0.0/nexrad-n0q-900913/{z}/{x}/{y}.png"],
                            opacity=0.6,
                            pickable=False
                        ))

                    # 1. SPC LAYER
                    if spc_data:
                        color_map = {"TSTM": [192, 232, 192, 100], "MRGL": [124, 205, 124, 150], "SLGT": [246, 246, 123, 150], "ENH": [230, 153, 0, 150], "MDT": [255, 0, 0, 150], "HIGH": [255, 0, 255, 150]}
                        for f in spc_data.get('features', []):
                            label = f.get('properties', {}).get('LABEL', '')
                            f['properties']['fill_color'] = color_map.get(label, [0, 0, 0, 0])
                            f['properties']['info'] = f"SPC Risk: {label}"
                            try:
                                poly_shape = shape(f.get("geometry"))
                                poly_dict = {"event": f"SPC: {label}", "shape": poly_shape, "severity": "Watch"}
                                master_polygons.append(poly_dict)
                                if show_spc: toggled_polygons.append(poly_dict)
                            except Exception: pass
                        if show_spc:
                            layers.append(pdk.Layer("GeoJsonLayer", spc_data, pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color=[0, 0, 0, 255], line_width_min_pixels=1))

                    # 2. NWS LAYERS
                    def process_nws_alerts(data, is_oos=False):
                        if not data: return None, None
                        warn_geo, watch_geo = {"type": "FeatureCollection", "features": []}, {"type": "FeatureCollection", "features": []}
                        for f in data.get("features", []):
                            geom = f.get("geometry")
                            if not geom: continue
                            event_type = f.get("properties", {}).get("event", "")
                            
                            if event_type not in selected_events: continue
                            
                            prefix = "[OOS]" if is_oos else "[AR]"
                            f['properties']['info'] = f"{prefix} {event_type}"
                            
                            try:
                                poly_shape = shape(geom)
                                poly_dict = {"event": f"{prefix} {event_type}", "shape": poly_shape, "severity": "Warning" if "Warning" in event_type else "Watch"}
                                master_polygons.append(poly_dict)
                                
                                if "Warning" in event_type:
                                    f['properties']['fill_color'] = [139, 0, 0, 60] if is_oos else [255, 0, 0, 60] 
                                    f['properties']['line_color'] = [139, 0, 0, 255] if is_oos else [255, 0, 0, 255]
                                    warn_geo["features"].append(f)
                                    if (is_oos and show_oos) or (not is_oos and show_warn): toggled_polygons.append(poly_dict)
                                elif "Watch" in event_type or "Advisory" in event_type:
                                    f['properties']['fill_color'] = [204, 119, 34, 60] if is_oos else [255, 165, 0, 60]
                                    f['properties']['line_color'] = [204, 119, 34, 255] if is_oos else [255, 165, 0, 255]
                                    watch_geo["features"].append(f)
                                    if (is_oos and show_oos) or (not is_oos and show_watch): toggled_polygons.append(poly_dict)
                            except Exception: continue
                        return warn_geo, watch_geo

                    ar_warn, ar_watch = process_nws_alerts(ar_data, is_oos=False)
                    oos_warn, oos_watch = process_nws_alerts(oos_data, is_oos=True)

                    if show_warn and ar_warn and ar_warn["features"]: layers.append(pdk.Layer("GeoJsonLayer", ar_warn, pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
                    if show_watch and ar_watch and ar_watch["features"]: layers.append(pdk.Layer("GeoJsonLayer", ar_watch, pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
                    if show_oos and oos_warn and oos_warn["features"]: layers.append(pdk.Layer("GeoJsonLayer", oos_warn, pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
                    if show_oos and oos_watch and oos_watch["features"]: layers.append(pdk.Layer("GeoJsonLayer", oos_watch, pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))

                    # GEOSPATIAL INTERSECTION ENGINE
                    toggled_affected_sites = []
                    master_affected_sites = []
                    
                    if not map_df.empty:
                        for index, row in map_df.iterrows():
                            if pd.notna(row['Lat']) and pd.notna(row['Lon']):
                                site_pt = Point(row['Lon'], row['Lat'])
                                
                                act_toggled = [p["event"] for p in toggled_polygons if site_pt.within(p["shape"])]
                                if act_toggled:
                                    toggled_affected_sites.append({"Monitored Site": row['Name'], "Facility Type": row['Type'], "Priority": row['Priority'], "Intersecting Hazards": ", ".join(list(set(act_toggled)))})
                                
                                for p in master_polygons:
                                    if site_pt.within(p["shape"]):
                                        master_affected_sites.append({
                                            "Monitored Site": row['Name'], "Facility Type": row['Type'], 
                                            "Priority": row['Priority'], "Hazard": p["event"], "Severity": p["severity"]
                                        })

                    # ==========================
                    # RENDER UI MAP TABS
                    # ==========================
                    with tab_map:
                        if not map_df.empty:
                            layers.append(pdk.Layer("ScatterplotLayer", map_df, pickable=True, opacity=0.9, stroked=True, filled=True, radius_scale=6, radius_min_pixels=4, radius_max_pixels=12, line_width_min_pixels=1, get_position="[Lon, Lat]", get_fill_color=[255, 255, 255], get_line_color=[0, 0, 0]))
                        
                        # Dynamic Columns based on Animated Radar Panel Toggle
                        if show_radar_panel:
                            c_map_main, c_map_side = st.columns([2, 1])
                        else:
                            c_map_main, c_map_side = st.columns([1, 0.0001]) # Effectively hides the side panel
                            
                        with c_map_main:
                            st.subheader("Live Threat Overlay")
                            view_state = pdk.ViewState(latitude=34.8, longitude=-92.2, zoom=5.5, pitch=0)
                            st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{info}"}), width="stretch")
                            
                        if show_radar_panel:
                            with c_map_side:
                                st.subheader("Precipitation Loop")
                                components.html("""<iframe src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" width="100%" height="500" frameborder="0" style="border-radius: 8px;" allowfullscreen></iframe>""", height=500)
                            
                        st.divider()
                        st.subheader("⚠️ Sites Impacted by Currently Toggled Layers")
                        st.caption("This table dynamically updates based on the layer switches and filters in the left sidebar.")
                        if not toggled_affected_sites: st.success("✅ No sites intersect with the specific layers and hazard types currently rendered on the map.")
                        else: st.dataframe(pd.DataFrame(toggled_affected_sites).sort_values(by=['Priority', 'Monitored Site']), hide_index=True, width="stretch")

                    with tab_analytics:
                        st.subheader("🌪️ Deep Hazard Analytics & Executive Broadcast")
                        st.markdown("Comprehensive breakdown of active weather geometry against physical infrastructure. **This data is live-linked to your left-hand hazard filters.**")
                        
                        if not master_affected_sites:
                            st.success("🎉 All infrastructure is currently clear of severe weather geometry based on your current filters.")
                        else:
                            analytics_df = pd.DataFrame(master_affected_sites)
                            analytics_df.drop_duplicates(inplace=True)
                            
                            p1_count = len(analytics_df[analytics_df['Priority'] == 1]['Monitored Site'].unique())
                            p2_count = len(analytics_df[analytics_df['Priority'] == 2]['Monitored Site'].unique())
                            
                            c1, c2, c3, c4 = st.columns(4)
                            c1.metric("Total Sites Impacted", len(analytics_df['Monitored Site'].unique()))
                            c2.metric("Critical (P1) Impacts", p1_count, delta="High Risk" if p1_count > 0 else None, delta_color="inverse")
                            c3.metric("High (P2) Impacts", p2_count)
                            c4.metric("Unique Hazards", len(analytics_df['Hazard'].unique()))
                            
                            st.divider()
                            st.markdown("### 🧮 Infrastructure Threat Matrices")
                            
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.write("**Site Priority vs. Hazard Type**")
                                # Deep cross-tabulation showing exactly how many P1/P2/P3 sites are hit by each specific storm type
                                pivot_priority = pd.crosstab(analytics_df['Hazard'], analytics_df['Priority'], margins=True, margins_name="Total Sites")
                                # Rename columns nicely if they exist
                                pivot_priority.columns = [f"Priority {c}" if isinstance(c, int) else c for c in pivot_priority.columns]
                                st.dataframe(pivot_priority, use_container_width=True)
                                
                            with col_b:
                                st.write("**Facility Type vs. Hazard Type**")
                                pivot_facility = pd.crosstab(analytics_df['Hazard'], analytics_df['Facility Type'], margins=True, margins_name="Total Sites")
                                st.dataframe(pivot_facility, use_container_width=True)
                                
                            st.write("**Complete Intersectional Dataset**")
                            st.dataframe(analytics_df.sort_values(by=['Priority', 'Severity', 'Monitored Site']), use_container_width=True, hide_index=True)
                            
                            st.divider()
                            st.subheader("📧 Broadcast Executive HTML SitRep")
                            st.caption("Generates a boardroom-ready HTML email containing the filtered hazard data.")
                            
                            if st.button("🚀 Transmit Priority SitRep via SMTP", type="primary"):
                                with st.spinner("Compiling HTML and transmitting..."):
                                    
                                    # Generate inline-styled HTML rows for the email
                                    rows_html = ""
                                    for _, r in analytics_df.sort_values(by=['Priority', 'Monitored Site']).iterrows():
                                        # Color code the priority badge in the email
                                        if r['Priority'] == 1:
                                            p_style = "background-color: #d9534f; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;"
                                        elif r['Priority'] == 2:
                                            p_style = "background-color: #f0ad4e; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;"
                                        else:
                                            p_style = "background-color: #6c757d; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;"
                                            
                                        rows_html += f"""
                                        <tr>
                                            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; font-weight: bold; color: #333333;">{r['Monitored Site']}</td>
                                            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; color: #555555;">{r['Facility Type']}</td>
                                            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; text-align: center;"><span style="{p_style}">P{r['Priority']}</span></td>
                                            <td style="padding: 12px; border-bottom: 1px solid #e0e0e0; color: #d9534f; font-weight: bold;">{r['Hazard']}</td>
                                        </tr>"""

                                    # The Master HTML Wrapper with ultra-strict inline CSS for email clients like Outlook
                                    html_body = f"""
                                    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 850px; margin: 0 auto; background-color: #f4f7f6; padding: 20px;">
                                        <div style="background-color: #ffffff; border-radius: 8px; border-top: 6px solid #d9534f; box-shadow: 0 4px 6px rgba(0,0,0,0.1); overflow: hidden;">
                                            
                                            <div style="padding: 25px; border-bottom: 1px solid #eeeeee; background-color: #fafafa;">
                                                <h2 style="margin: 0; color: #333333; font-size: 24px;">🚨 SEVERE WEATHER INFRASTRUCTURE IMPACT</h2>
                                                <p style="margin: 5px 0 0 0; color: #777777; font-size: 14px;">Automated NOC Intelligence Broadcast | {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M %Z')}</p>
                                            </div>
                                            
                                            <div style="padding: 25px;">
                                                <h3 style="color: #2c3e50; margin-top: 0; font-size: 18px; border-bottom: 2px solid #e9ecef; padding-bottom: 8px;">Executive Overview</h3>
                                                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                                                    <tr>
                                                        <td style="padding: 15px; background-color: #f8f9fa; border-radius: 6px; text-align: center; border: 1px solid #e9ecef;">
                                                            <div style="font-size: 28px; font-weight: bold; color: #333333;">{len(analytics_df['Monitored Site'].unique())}</div>
                                                            <div style="font-size: 12px; color: #6c757d; text-transform: uppercase; letter-spacing: 1px;">Total Sites Impacted</div>
                                                        </td>
                                                        <td style="width: 15px;"></td>
                                                        <td style="padding: 15px; background-color: #fff5f5; border-radius: 6px; text-align: center; border: 1px solid #ffe3e3;">
                                                            <div style="font-size: 28px; font-weight: bold; color: #d9534f;">{p1_count}</div>
                                                            <div style="font-size: 12px; color: #d9534f; text-transform: uppercase; letter-spacing: 1px;">Critical (P1) Exposures</div>
                                                        </td>
                                                    </tr>
                                                </table>
                                                
                                                <h3 style="color: #2c3e50; margin-top: 30px; font-size: 18px; border-bottom: 2px solid #e9ecef; padding-bottom: 8px;">Detailed Impact Matrix</h3>
                                                <table style="width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; text-align: left;">
                                                    <thead>
                                                        <tr style="background-color: #343a40; color: #ffffff;">
                                                            <th style="padding: 12px; font-weight: 600;">Monitored Site</th>
                                                            <th style="padding: 12px; font-weight: 600;">Facility Type</th>
                                                            <th style="padding: 12px; font-weight: 600; text-align: center;">Priority</th>
                                                            <th style="padding: 12px; font-weight: 600;">Active Hazard</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {rows_html}
                                                    </tbody>
                                                </table>
                                                
                                                <div style="margin-top: 40px; text-align: center; font-size: 12px; color: #adb5bd; border-top: 1px solid #eeeeee; padding-top: 20px;">
                                                    CONFIDENTIAL & PROPRIETARY<br>
                                                    Generated autonomously by the Intelligence Fusion Center.
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    """
                                    
                                    # Strip line breaks so they aren't parsed as text breaks by basic email clients
                                    html_safe = html_body.replace("\n", "")
                                    
                                    from src.mailer import send_alert_email
                                    success, msg = send_alert_email("URGENT: Active Severe Weather Impacting Operations", html_safe)
                                    if success: st.success("✅ Executive HTML SitRep successfully transmitted to distribution list!")
                                    else: st.error(f"❌ SMTP Error: {msg}")

                    with tab_dash:
                        st.subheader("📊 Infrastructure Threat Dashboard")
                        with st.expander("ℹ️ Understanding SPC Convective Risk Categories"):
                            st.markdown("""
                            The **Storm Prediction Center (SPC)** issues national forecasts for severe thunderstorms, tornadoes, and extreme winds:
                            * 🌩️ **TSTM:** General, non-severe thunderstorms.
                            * 🟩 **MRGL (1/5):** Isolated severe thunderstorms possible.
                            * 🟨 **SLGT (2/5):** Scattered severe thunderstorms possible.
                            * 🟧 **ENH (3/5):** Numerous severe thunderstorms possible.
                            * 🟥 **MDT (4/5):** Widespread severe thunderstorms likely.
                            * 🟪 **HIGH (5/5):** Widespread, long-lived, particularly dangerous outbreak expected.
                            """)

                        if map_df.empty:
                            st.info("No monitored locations match current filters.")
                        else:
                            risk_order = ["HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "None"]
                            map_df['Risk'] = pd.Categorical(map_df['Risk'], categories=risk_order, ordered=True)
                            risk_df = map_df[map_df['Risk'] != 'None']
                            
                            st.download_button(
                                label="📥 Export Infrastructure Risk Report (CSV)",
                                data=map_df.sort_values(by=['Risk', 'Priority']).to_csv(index=False).encode('utf-8'),
                                file_name=f"Infrastructure_Risk_{datetime.now(LOCAL_TZ).strftime('%Y%m%d_%H%M')}.csv",
                                mime='text/csv', width="stretch"
                            )
                            st.divider()
                            
                            c_m1, c_m2, c_m3 = st.columns(3)
                            c_m1.metric("Total Tracked Sites", len(map_df))
                            c_m2.metric("Sites in Active Risk Areas", len(risk_df))
                            highest_risk = risk_df['Risk'].sort_values().iloc[0] if not risk_df.empty else "None"
                            c_m3.metric("Highest Current Risk", highest_risk)
                            st.write("")
                            
                            c1, c2 = st.columns(2)
                            with c1:
                                st.markdown("**Sites by Risk Level**")
                                if not risk_df.empty:
                                    risk_counts = risk_df['Risk'].value_counts().reset_index()
                                    risk_counts.columns = ['Risk Level', 'Count']
                                    st.bar_chart(risk_counts.set_index('Risk Level'), color="#ff4b4b", width="stretch")
                                else: st.success("All monitored sites are clear.")
                            with c2:
                                st.markdown("**Sites by Facility Type**")
                                type_counts = map_df['Type'].value_counts().reset_index()
                                type_counts.columns = ['Location Type', 'Count']
                                st.bar_chart(type_counts.set_index('Location Type'), color="#1f77b4", width="stretch")

                            st.divider()
                            c3, c4 = st.columns(2)
                            with c3:
                                st.markdown("**Risk by Priority Level**")
                                st.dataframe(pd.crosstab(map_df['Priority'], map_df['Risk']), width="stretch")
                            with c4:
                                st.markdown("**Risk by Facility Type**")
                                st.dataframe(pd.crosstab(map_df['Type'], map_df['Risk']), width="stretch")

                    with tab_matrix:
                        st.subheader("Active Infrastructure Matrix")
                        st.caption("All tracked locations overlaid with current SPC Convective Outlooks.")
                        if not map_df.empty:
                            display_df = map_df.drop(columns=['id', 'Lat', 'Lon', 'info'])
                            st.dataframe(display_df.sort_values(by=['Risk', 'Priority'], ascending=[True, True]), width="stretch", hide_index=True)

                    with tab_manage:
                        c_up, c_ed = st.columns([1, 2])
                        with c_up:
                            st.subheader("Mass Import (JSON)")
                            st.caption("Requires 'name', 'lat', 'lon'. Optional: 'type', 'priority'.")
                            uploaded_file = st.file_uploader("Upload Sites", type=["json"], key="loc_uploader")
                            if uploaded_file is not None:
                                if st.button("📥 Import Data", width="stretch"):
                                    import json
                                    try:
                                        data = json.load(uploaded_file)
                                        added = 0
                                        existing_names = {l[0] for l in session.query(MonitoredLocation.name).all()}
                                        for item in data:
                                            name = item.get("name")
                                            lat, lon = item.get("lat"), item.get("lon")
                                            if name and lat is not None and lon is not None and name not in existing_names:
                                                session.add(MonitoredLocation(
                                                    name=name, lat=float(lat), lon=float(lon),
                                                    loc_type=item.get("type", "General"), priority=int(item.get("priority", 3))
                                                ))
                                                existing_names.add(name)
                                                added += 1
                                        session.commit()
                                        st.success(f"Imported {added} new locations!"); time.sleep(1.5); st.cache_data.clear(); safe_rerun()
                                    except Exception as e:
                                        st.error(f"Import failed: {e}"); session.rollback()
                                        
                        with c_ed:
                            st.subheader("Manual Adjustments")
                            if not df.empty:
                                edited_df = st.data_editor(df, hide_index=True, disabled=["id", "Risk"], width="stretch", key="loc_editor")
                                if st.button("💾 Save Manual Adjustments", width="stretch"):
                                    for index, row in edited_df.iterrows():
                                        db_loc = session.query(MonitoredLocation).filter_by(id=row['id']).first()
                                        if db_loc:
                                            db_loc.name = row['Name']
                                            db_loc.loc_type = row['Type']
                                            db_loc.priority = row['Priority']
                                            db_loc.lat = row['Lat']
                                            db_loc.lon = row['Lon']
                                    session.commit()
                                    st.success("Changes saved!"); time.sleep(1); st.cache_data.clear(); safe_rerun()
                            
                            st.divider()
                            st.write("**Danger Zone**")
                            if st.button("🗑️ Delete All Locations", width="stretch"):
                                session.execute(text("TRUNCATE TABLE monitored_locations RESTART IDENTITY CASCADE;"))
                                session.commit()
                                st.success("All locations deleted!"); time.sleep(1); st.cache_data.clear(); safe_rerun()
                tab_idx += 1

# ================= 6. THREAT HUNTING & IOCS =================
elif page == "🎯 Threat Hunting & IOCs":
    st.title("🎯 Active Threat Hunting & Detection Engineering")
    st.markdown("Automated IOC extraction, 1-Click OSINT Pivoting, and LLM-assisted YARA/SIEM generation.")
    
    tab_matrix, tab_manual = st.tabs(["🧮 Live Global IOC Matrix", "🔬 Deep Hunt & Detection Builder"])
    
    with tab_matrix:
        st.subheader("Global Indicators of Compromise (Last 72 Hours)")
        st.caption("Auto-extracted via Regex from ML-verified (Score > 50) Cyber Intelligence feeds. Automatically refanged.")
        
        seventy_two_hrs_ago = datetime.utcnow() - timedelta(days=3)
        recent_iocs = session.query(ExtractedIOC).filter(ExtractedIOC.detected_at >= seventy_two_hrs_ago).order_by(ExtractedIOC.detected_at.desc()).all()
        
        if not recent_iocs:
            st.info("No active IOCs extracted in the last 72 hours.")
        else:
            # Generate Pivot Links dynamically based on IOC type
            def generate_pivot_link(ioc_type, value):
                if ioc_type in ["SHA256", "MD5", "SHA1"]: return f"https://www.virustotal.com/gui/file/{value}"
                elif ioc_type == "IPv4": return f"https://www.shodan.io/host/{value}"
                elif ioc_type == "Domain": return f"https://www.virustotal.com/gui/domain/{value}"
                elif ioc_type == "CVE": return f"https://nvd.nist.gov/vuln/detail/{value}"
                elif ioc_type == "MITRE ATT&CK": return f"https://attack.mitre.org/techniques/{value.replace('.', '/')}"
                return None

            ioc_data = []
            for ioc in recent_iocs:
                art = session.query(Article).filter(Article.id == ioc.article_id).first()
                source_link = art.link if art else "Unknown"
                pivot_url = generate_pivot_link(ioc.indicator_type, ioc.indicator_value)
                
                ioc_data.append({
                    "Type": ioc.indicator_type,
                    "Indicator": ioc.indicator_value,
                    "OSINT Pivot": pivot_url,
                    "Source Article": source_link,
                    "Detected": format_local_time(ioc.detected_at)
                })
            
            df = pd.DataFrame(ioc_data)
            
            # Dynamic filtering
            all_types = sorted(list(set(df["Type"].tolist())))
            default_types = [t for t in all_types if t in ["IPv4", "SHA256", "Domain", "CVE", "MITRE ATT&CK"]]
            
            filter_type = st.multiselect("Filter by Threat Type", all_types, default=default_types if default_types else all_types)
            filtered_df = df[df["Type"].isin(filter_type)]
            
            st.dataframe(
                filtered_df, 
                width="stretch", 
                column_config={
                    "Source Article": st.column_config.LinkColumn("Source Intel"),
                    "OSINT Pivot": st.column_config.LinkColumn("Investigate 🔗", display_text="Open Tool")
                }, 
                hide_index=True
            )
            
            st.download_button(
                label="📥 Export Hunting Targets (CSV)", 
                data=filtered_df.drop(columns=["OSINT Pivot"]).to_csv(index=False).encode('utf-8'), 
                file_name=f"Hunt_Targets_{datetime.now(LOCAL_TZ).strftime('%Y%m%d')}.csv", 
                mime='text/csv', 
                width="stretch"
            )

    with tab_manual:
        st.subheader("Targeted LLM Deep Hunt & Detection Engine")
        st.markdown("Search historical telemetry for a specific threat and instruct the AI to build **YARA Patterns**, **Splunk/SIEM Queries**, and **TTP Assessments**.")
        with st.form("manual_hunt_form"):
            hunt_target = st.text_input("Target Entity (e.g., 'Volt Typhoon', 'Ivanti Connect Secure', 'RansomHub')")
            hunt_depth = st.slider("Historical Depth (Days)", min_value=7, max_value=90, value=30)
            
            if st.form_submit_button("🚀 Compile Detection Package", type="primary", disabled=not can_trigger_ai, width="stretch"):
                if not hunt_target: st.error("Please enter a target entity.")
                elif not ai_enabled: st.error("AI Engine is currently disabled in settings.")
                else:
                    with st.spinner(f"Scanning the last {hunt_depth} days of telemetry for '{hunt_target}'..."):
                        cutoff_date = datetime.utcnow() - timedelta(days=hunt_depth)
                        target_arts = session.query(Article).filter(
                            Article.published_date >= cutoff_date,
                            (Article.title.ilike(f"%{hunt_target}%") | Article.summary.ilike(f"%{hunt_target}%"))
                        ).limit(30).all()
                        
                        if not target_arts: st.warning(f"No intelligence found matching '{hunt_target}' in the requested timeframe.")
                        else:
                            st.success(f"Found {len(target_arts)} distinct reports. Handing off to AI for synthesis...")
                            hunt_context = "\n\n".join([f"Source: {a.source}\nTitle: {a.title}\nContent: {a.summary}" for a in target_arts])
                            
                            sys_prompt = f"""You are an elite Cyber Threat Detection Engineer. Analyze the provided intelligence reports regarding '{hunt_target}'.
                            Synthesize the data and generate a highly technical Detection & Hunt Package.
                            
                            Your output MUST strictly follow this Markdown structure:
                            ### 1. Threat Overview & MITRE TTPs
                            (Provide a technical summary and list suspected MITRE ATT&CK techniques)
                            ### 2. Known Vulnerabilities & Infrastructure
                            (List CVEs, exploited software, or command-and-control behavior)
                            ### 3. Splunk / SIEM Hunt Queries
                            (Write generic SPL/KQL queries to hunt for this behavior)
                            ### 4. YARA Detection Stub
                            (Write a valid YARA rule stub based on strings, filenames, or behaviors mentioned in the text)
                            
                            Do not hallucinate external facts. Base your engineering ONLY on the provided context."""
                            
                            messages = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": hunt_context}]
                            from src.llm import call_llm
                            ai_hunt_result = call_llm(messages, sys_config, temperature=0.1)
                            
                            if ai_hunt_result:
                                st.divider()
                                st.markdown(f"## 🎯 Detection Package: {hunt_target.upper()}")
                                st.markdown(ai_hunt_result)
                                st.divider()
                                st.markdown("### 🔗 Reference Intel")
                                for a in target_arts: st.markdown(f"- [{a.title}]({a.link})")

# ================= 6. AIOps RCA (ENTERPRISE MASTER BLOCK) =================
elif page == "⚡ AIOps RCA":
    st.title("⚡ AIOps Root Cause Analysis")
    st.markdown("Live correlation of non-uniform monitoring alerts with Regional Intelligence.")
    
    status_indicator = f"🔴 **LIVE** (Refreshing every {current_refresh_sec}s)" if current_refresh_sec > 0 else "⏸️ **PAUSED**"
    st.caption(f"{status_indicator} | Webhook Listener Active on Port 8100")
    
    from src.database import TimelineEvent, RegionalOutage, SolarWindsAlert, MonitoredLocation, CloudOutage, RegionalHazard, BgpAnomaly, SystemConfig
    from src.aiops_engine import EnterpriseAIOpsEngine
    import pydeck as pdk
    import pandas as pd
    import uuid

    # Initialize Engine
    ai_engine = EnterpriseAIOpsEngine(session)
    sys_config = session.query(SystemConfig).first()
    
    tab_active, tab_patterns, tab_learning, tab_global = st.tabs([
        "🔴 Active Incident Board", 
        "📈 Chronic Pattern Analysis", 
        "🧠 ML Alias Learning", 
        "🌍 Global Correlation Engine"
    ])
    
    with tab_active:
        # Fetch active alerts
        active_alerts = session.query(SolarWindsAlert).filter(SolarWindsAlert.status != 'Resolved', SolarWindsAlert.is_correlated == False).all()
        
        c_live, c_sw = st.columns([3, 1])
        
        with c_sw:
            st.subheader("⏱️ Live Event Log")
            c_btn1, c_btn2 = st.columns(2)
            if c_btn1.button("🧹 Clear Log", use_container_width=True):
                session.query(TimelineEvent).delete(); session.commit(); safe_rerun()
            if c_btn2.button("🗑️ Nuke Alerts", use_container_width=True):
                session.query(SolarWindsAlert).delete(); session.commit(); safe_rerun()
            
            st.divider()
            with st.container(height=600):
                events = session.query(TimelineEvent).order_by(TimelineEvent.timestamp.desc()).limit(50).all()
                if not events: st.info("Listening for network telemetry...")
                else:
                    for e in events:
                        icon = "🔴" if e.event_type == "Alert" else "🟢" if e.event_type == "Resolution" else "🤖" if e.source == "AI" else "🔵"
                        st.markdown(f"<small>**{e.timestamp.strftime('%H:%M:%S')}** | {icon} {e.source}</small><br>{e.message}", unsafe_allow_html=True)
                        st.divider()

        with c_live:
            # --- 🗺️ GEOSPATIAL OVERLAY (AUTO-FOCUSING) ---
            st.subheader("🗺️ Dynamic Geospatial Overlays")
            locs = session.query(MonitoredLocation).all()
            grid_issues = session.query(RegionalOutage).filter_by(is_resolved=False).all()
            
            if not locs:
                st.info("No monitored locations configured.")
            else:
                alert_mapped_sites = [a.mapped_location for a in active_alerts]
                site_down_counts = {site: alert_mapped_sites.count(site) for site in set(alert_mapped_sites)}
                
                map_data, alert_pulses = [], []
                active_lats, active_lons = [], []
                
                for l in locs:
                    down_count = site_down_counts.get(l.name, 0)
                    is_down = down_count > 0
                    color = [255, 0, 0, 200] if is_down else [0, 255, 0, 160]
                    
                    map_data.append({"Name": l.name, "Lat": l.lat, "Lon": l.lon, "Status": f"{down_count} Alerts" if is_down else "Online", "Color": color})
                    
                    if is_down:
                        alert_pulses.append({"lat": l.lat, "lon": l.lon, "radius": 4000 + (down_count * 2500)})
                        active_lats.append(l.lat)
                        active_lons.append(l.lon)
                
                # Dynamic Camera Pivot
                if active_lats and active_lons:
                    center_lat, center_lon, map_zoom = sum(active_lats) / len(active_lats), sum(active_lons) / len(active_lons), 8.0
                else:
                    center_lat, center_lon, map_zoom = 34.8, -92.2, 6.8

                layers = []
                layer_id = str(uuid.uuid4())[:6]

                if grid_issues:
                    isp_df = pd.DataFrame([{"lat": i.lat, "lon": i.lon, "radius": i.radius_km * 1000} for i in grid_issues if i.outage_type in ["ISP", "Cellular"]])
                    if not isp_df.empty: layers.append(pdk.Layer("ScatterplotLayer", isp_df, id=f"isp_{layer_id}", get_position="[lon, lat]", get_fill_color=[128, 0, 128, 60], get_radius="radius"))

                    pwr_df = pd.DataFrame([{"lat": i.lat, "lon": i.lon, "radius": i.radius_km * 1000} for i in grid_issues if i.outage_type == "Power"])
                    if not pwr_df.empty: layers.append(pdk.Layer("ScatterplotLayer", pwr_df, id=f"pwr_{layer_id}", get_position="[lon, lat]", get_fill_color=[255, 191, 0, 80], get_radius="radius"))

                if alert_pulses:
                    layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(alert_pulses), id=f"pulse_{layer_id}", get_position="[lon, lat]", get_fill_color=[255, 0, 0, 40], get_radius="radius"))

                layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(map_data), id=f"sites_{layer_id}", get_position="[Lon, Lat]", get_fill_color="Color", get_radius=1800, pickable=True))

                st.pydeck_chart(pdk.Deck(
                    layers=layers, 
                    initial_view_state=pdk.ViewState(latitude=center_lat, longitude=center_lon, zoom=map_zoom, transition_duration=1000), 
                    tooltip={"text": "{Name}\n{Status}"}
                ))

            st.divider()

            # --- 🧠 SITE-BASED CORRELATION MATRIX ---
            st.subheader("⚡ Enterprise Correlation & ITSM Dispatch")
            if not active_alerts:
                st.success("✅ Grid operational. No active site incidents.")
            else:
                active_weather = session.query(RegionalHazard).all()
                active_cloud = session.query(CloudOutage).filter_by(is_resolved=False).all()
                active_bgp = session.query(BgpAnomaly).filter_by(is_resolved=False).all()

                incidents = ai_engine.analyze_and_cluster(active_alerts)
                
                for site_name, data in incidents.items():
                    # Unpack the 7 new variables from the Ontological Engine
                    cause, conf, priority, evidence, blast, p0, cascade_str = ai_engine.calculate_root_cause(
                        site_name, data, active_weather, active_cloud, active_bgp
                    )
                    
                    p_icon = "🔴" if "P1" in priority else "🟠" if "P2" in priority else "🟡"
                    
                    with st.container(border=True):
                        st.markdown(f"### {p_icon} {priority} | Site: {site_name}")
                        
                        m = data['site_metadata']
                        # UI Updates for Patient Zero and Cascade metrics
                        c_info1, c_info2, c_info3 = st.columns([1, 1, 1])
                        c_info1.caption(f"🛰️ **Blast Radius:** {blast}")
                        c_info2.caption(f"⏱️ **Cascade Time:** {cascade_str}")
                        c_info3.caption(f"🚨 **Patient Zero:** `{p0}`")
                        
                        st.progress(conf / 100.0, text=f"AI Confidence Score: {conf}%")
                        st.warning(f"**Forensic Conclusion:** {cause}")
                        
                        # Generate the payload with the new metrics
                        ticket_payload = ai_engine.generate_itsm_payload(
                            site_name, data, cause, conf, priority, evidence, blast, p0, cascade_str
                        )
                        
                        with st.expander(f"📝 Review Forensic Ticket ({len(data['alerts'])} Nodes, {len(data['domains_affected'])} Domains)"):
                            edited_ticket = st.text_area("Ticket Body", value=ticket_payload, height=350, key=f"ed_{site_name}")
                        
                        btn_c1, btn_c2 = st.columns([3, 1])
                        if btn_c1.button(f"📤 Dispatch Ticket to ITSM", type="primary", key=f"send_{site_name}", use_container_width=True):
                            success, msg = ai_engine.send_to_ticketing_system(sys_config, f"NOC ALARM: {priority} - {site_name}", edited_ticket)
                            if success:
                                for a in data['alerts']: a.is_correlated = True
                                session.commit(); st.success("Dispatched!"); time.sleep(1); safe_rerun()
                            else: st.error(msg)
                            
                        if btn_c2.button(f"🤫 Acknowledge", type="secondary", key=f"ack_{site_name}", use_container_width=True):
                            for a in data['alerts']: a.is_correlated = True
                            session.commit(); st.info("Incident Silenced."); time.sleep(1); safe_rerun()
                            
    # --- 📈 CHRONIC PATTERN ANALYSIS TAB ---
    with tab_patterns:
        st.subheader("📈 Predictive Analytics & Chronic Pattern Recognition")
        st.markdown("Analyzes historical telemetry to identify degrading hardware, environmental vulnerabilities, and chronic micro-outages before they cause catastrophic failure.")
        
        c_pat1, c_pat2 = st.columns([1, 3])
        days_to_analyze = c_pat1.slider("Historical Lookback (Days)", min_value=7, max_value=90, value=30)
        
        if c_pat1.button("🔍 Run Pattern Recognition", type="primary", use_container_width=True):
            with st.spinner(f"Analyzing telemetry over the last {days_to_analyze} days..."):
                flap_df, vsat_df, reboot_df = ai_engine.generate_chronic_insights(days_back=days_to_analyze)
                
                if flap_df is None:
                    st.warning("Not enough historical data collected yet to establish patterns.")
                else:
                    st.divider()
                    
                    # Row 1: Cellular & Reboots
                    col_insight1, col_insight2 = st.columns(2)
                    
                    with col_insight1:
                        st.markdown("### 📶 Cellular Micro-Blips (< 5 Mins)")
                        st.caption("Sites with chronic cellular failover instability.")
                        if flap_df.empty:
                            st.success("✅ No chronic cellular flapping detected.")
                        else:
                            st.dataframe(
                                flap_df, 
                                hide_index=True, 
                                use_container_width=True,
                                column_config={
                                    "Micro_Blips (<5m)": st.column_config.ProgressColumn(
                                        "Flap Count", format="%d", min_value=0, max_value=50
                                    )
                                }
                            )
                            
                    with col_insight2:
                        st.markdown("### 🔄 Chronic Hardware Reboots")
                        st.caption("Nodes experiencing recurring unexpected reboots or crashes.")
                        if reboot_df.empty:
                            st.success("✅ Hardware stability nominal.")
                        else:
                            st.dataframe(reboot_df, hide_index=True, use_container_width=True)

                    st.divider()
                    
                    # Row 2: VSAT Environmental Vulnerability
                    st.markdown("### 🛰️ VSAT Environmental Vulnerability Matrix")
                    st.caption("Identifies VSAT/Satellite sites highly susceptible to regional weather fade.")
                    
                    if vsat_df.empty:
                        st.success("✅ No severe VSAT rain/weather fade patterns detected.")
                    else:
                        c_v1, c_v2 = st.columns([2, 1])
                        with c_v1:
                            st.dataframe(
                                vsat_df, 
                                hide_index=True, 
                                use_container_width=True,
                                column_config={
                                    "Vulnerability_Score": st.column_config.NumberColumn(
                                        "Fade Risk Score", format="%d/100"
                                    )
                                }
                            )
                        with c_v2:
                            st.info("💡 **AIOps Suggestion:** Sites with a Risk Score > 75 should be evaluated for secondary terrestrial circuits or larger dish alignments to mitigate ongoing weather isolation.")

    # --- ML ALIAS LEARNING TAB ---
    with tab_learning:
        st.subheader("🧠 ML Node Mapping Matrix")
        from src.database import NodeAlias
        aliases = session.query(NodeAlias).order_by(NodeAlias.confidence_score.asc()).all()
        if not aliases: 
            st.info("No learned aliases yet. Send a webhook payload to begin training.")
        else:
            all_locs = ["Unknown"] + [l.name for l in session.query(MonitoredLocation).all()]
            for a in aliases:
                with st.container(border=True):
                    c_a1, c_a2, c_a3, c_a4 = st.columns([2, 3, 1, 1])
                    c_a1.code(a.node_pattern)
                    new_mapping = c_a2.selectbox("Mapped Site", all_locs, index=all_locs.index(a.mapped_location_name) if a.mapped_location_name in all_locs else 0, key=f"sel_al_{a.id}")
                    if a.is_verified: c_a3.success("Verified")
                    else: c_a3.warning(f"AI Guess ({int(a.confidence_score)}%)")
                    if c_a4.button("💾 Save", key=f"sv_al_{a.id}", use_container_width=True):
                        a.mapped_location_name = new_mapping
                        a.is_verified = True
                        a.confidence_score = 100.0 
                        session.commit()
                        st.success("Rule Saved!")
                        st.rerun()

    # --- GLOBAL SITREP TAB ---
    with tab_global:
        st.subheader("🌍 Deterministic Global Correlation Engine")
        st.markdown("Calculates causation graphs based on geospatial math and telemetry overlays across all domains.")
        
        c_glob1, c_glob2 = st.columns([3, 1])
        
        if c_glob2.button("🔍 Run Global Correlation", type="primary", use_container_width=True):
            with st.spinner("Calculating Multi-Domain Causal Links..."):
                down_nodes = session.query(SolarWindsAlert).filter(SolarWindsAlert.is_correlated == False).all()
                active_clouds = session.query(CloudOutage).filter(CloudOutage.is_resolved == False).all()
                active_weather = session.query(RegionalHazard).all()
                active_grid = session.query(RegionalOutage).filter_by(is_resolved=False).all()
                locs_db = session.query(MonitoredLocation).all()
                
                report = f"### 🌍 Global Situation Report (SitRep)\n\n"
                report += f"**Active Node Failures:** {len(down_nodes)} | "
                report += f"**Cloud Outages:** {len(active_clouds)} | "
                report += f"**Grid/Weather Anomalies:** {len(active_weather) + len(active_grid)}\n\n"
                
                report += "#### 🔗 Deterministic Causal Links\n"
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
                
                if ai_enabled and can_trigger_ai:
                    sys_prompt = "You are an elite NOC AIOps Engine. Summarize the following deterministic IT SitRep into a technical 2-sentence executive summary."
                    from src.llm import call_llm
                    ai_summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": report}], sys_config, temperature=0.1)
                    if ai_summary:
                        report = f"### 🤖 AI Executive Summary\n> {ai_summary}\n\n---\n\n" + report
                
                st.session_state.last_global_rca = report

        if "last_global_rca" in st.session_state:
            st.divider()
            with st.container(border=True):
                st.markdown(st.session_state.last_global_rca)
            
            c_em1, c_em2 = st.columns([1, 4])
            if c_em1.button("✉️ Broadcast SitRep", use_container_width=True):
                from src.mailer import send_alert_email
                with st.spinner("Transmitting via SMTP..."):
                    success, msg = send_alert_email("URGENT: Multi-Domain Global SitRep", st.session_state.last_global_rca)
                    if success: st.success(msg)
                    else: st.error(msg)

# ================= 4. REPORT CENTER =================
elif page == "📑 Report Center":
    st.title("📑 Report Center")
    
    rc_tab_names = []
    if "tab_rc_build" in st.session_state.allowed_actions: rc_tab_names.append("📝 Report Builder")
    if "tab_rc_lib" in st.session_state.allowed_actions: rc_tab_names.append("📚 Shared Library")
    
    if not rc_tab_names:
        st.warning("You do not have permission to view the Report Center.")
    else:
        tabs = st.tabs(rc_tab_names)
        tab_idx = 0
        
        if "tab_rc_build" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                if "generated_report" not in st.session_state: st.session_state.generated_report = None
                
                c_s, c_l = st.columns([3, 1])
                sq = c_s.text_input("🔍 Search Articles", key="rc_sq")
                sl = c_l.selectbox("Limit", [20, 50, 100], key="rc_sl")
                
                q = session.query(Article)
                if sq: q = q.filter(Article.title.ilike(f"%{sq}%") | Article.summary.ilike(f"%{sq}%"))
                res = q.order_by(Article.published_date.desc()).limit(sl).all()
                
                if res:
                    amap = {f"[{a.published_date.strftime('%Y-%m-%d')}] {a.title} ({a.source})": a for a in res}
                    sels = st.multiselect("Select Articles:", options=list(amap.keys()), key="rc_sels")
                    
                    st.divider()
                    dn = current_user_obj.full_name if current_user_obj and current_user_obj.full_name else st.session_state.current_user.capitalize()
                    dc = current_user_obj.contact_info if current_user_obj and current_user_obj.contact_info else ""
                    
                    cm1, cm2 = st.columns(2)
                    aname = cm1.text_input("Analyst", value=dn, key="rc_aname")
                    cinfo = cm2.text_input("Contact", value=dc, key="rc_cinfo")
                    msys = st.text_area("Manual Systems (Optional)", height=80, key="rc_msys")
                    obj = st.text_area("AI Objective", value="Generate an exhaustive, detailed technical intelligence report.", height=80, key="rc_obj")
                    
                    if st.button("🚀 Generate Report", type="primary", disabled=not can_trigger_ai, key="rc_gen_btn", width="stretch"):
                        if not sels: st.error("Select at least one article.")
                        else:
                            arts = [amap[t] for t in sels]
                            with st.spinner("Synthesizing Intelligence..."):
                                md = build_custom_intel_report(arts, obj, session)
                                if md:
                                    now = datetime.now(LOCAL_TZ).strftime("%A, %B %d, %Y at %I:%M %p %Z")
                                    mr = f"# 🛡️ NOC Intelligence Report\n**Date:** {now}\n**Analyst:** {aname}\n**Contact:** {cinfo}\n\n---\n\n"
                                    if msys.strip(): mr += f"## 🎯 Internal Systems (Manual Entry)\n{msys}\n\n---\n\n"
                                    mr += md
                                    mr += "\n\n---\n\n## 🔗 Intelligence Sources\n"
                                    for a in arts: mr += f"- **{a.source}**: [{a.title}]({a.link})\n"
                                    st.session_state.generated_report = mr
                                    st.success("Complete!")

                if st.session_state.generated_report:
                    st.divider()
                    with st.container(border=True): st.markdown(st.session_state.generated_report)
                    st.divider()
                    sv_t = st.text_input("Report Title", value=f"Report - {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}", key="rc_sv_t")
                    c_s1, c_s2, c_s3 = st.columns([1, 1, 1])
                    if c_s1.button("💾 Save to Library", width="stretch", key="rc_sv_btn"):
                        session.add(SavedReport(title=sv_t, author=st.session_state.current_user, content=st.session_state.generated_report))
                        session.commit(); st.success("Saved!")
                    c_s2.download_button("⬇️ Download (.md)", data=st.session_state.generated_report, file_name=f"{sv_t}.md", width="stretch", key="rc_dl_btn")
                    if c_s3.button("🗑️ Clear", type="secondary", width="stretch", key="rc_clr_btn"):
                        st.session_state.generated_report = None; safe_rerun()
            tab_idx += 1
            
        if "tab_rc_lib" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                reps = session.query(SavedReport).order_by(SavedReport.created_at.desc()).all()
                if not reps: st.info("No reports saved yet.")
                else:
                    for r in reps:
                        with st.expander(f"📄 **{r.title}** | {r.author.capitalize()} | {format_local_time(r.created_at)}"):
                            st.markdown(r.content)
                            c_d1, c_d2, c_sp = st.columns([1, 1, 4])
                            c_d1.download_button("⬇️ Download", data=r.content, file_name=f"{r.title}.md", width="stretch", key=f"dl_lib_{r.id}")
                            if st.session_state.current_user == r.author or st.session_state.current_role == "admin":
                                if c_d2.button("🗑️ Delete", width="stretch", key=f"del_lib_{r.id}"):
                                    session.delete(r); session.commit(); safe_rerun()
            tab_idx += 1

# ================= 5. SETTINGS & ADMIN =================
elif page == "⚙️ Settings & Admin":
    st.title("⚙️ Settings & Engine Room")
    tab_rss, tab_ml, tab_ai, tab_users, tab_backup, tab_danger = st.tabs(["📡 RSS Sources", "🧠 ML Training", "🤖 AI & SMTP", "👥 Users & Roles", "💾 Backup & Restore", "⚠️ Danger Zone"])
    
    with tab_rss:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Manage Keywords")
            with st.form("bulk_kw"):
                raw_text = st.text_area("Bulk Add Keywords (word, weight)", placeholder="infrastructure, 80", key="set_kw_bulk")
                if st.form_submit_button("Add Keywords", width="stretch"):
                    for line in raw_text.split('\n'):
                        if line.strip():
                            parts = line.split(',')
                            word = parts[0].strip().lower()
                            weight = int(parts[1].strip()) if len(parts) > 1 and parts[1].strip().isdigit() else 10
                            if not session.query(Keyword).filter_by(word=word).first(): session.add(Keyword(word=word, weight=weight))
                    session.commit(); safe_rerun()
            with st.expander("Active Keywords"):
                for k in session.query(Keyword).order_by(Keyword.weight.desc()).all():
                    c_a, c_b, c_c = st.columns([3, 1, 1])
                    c_a.code(k.word); c_b.write(f"**{k.weight}**")
                    if c_c.button("🗑️", key=f"del_kw_{k.id}", width="stretch"): session.delete(k); session.commit(); safe_rerun()

        with col2:
            st.subheader("Manage RSS Feeds")
            with st.form("bulk_feed"):
                raw_text_feeds = st.text_area("Bulk Add Feeds (URL, Name)", placeholder="https://site.com/feed, Tech News", key="set_feed_bulk")
                if st.form_submit_button("Add Sources", width="stretch"):
                    for line in raw_text_feeds.split('\n'):
                        if line.strip():
                            parts = line.split(',')
                            url = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else "New Feed"
                            if not session.query(FeedSource).filter_by(url=url).first(): session.add(FeedSource(url=url, name=name))
                    session.commit(); safe_rerun()
            with st.expander("Active Feeds"):
                for s in session.query(FeedSource).all():
                    st.text(s.name); st.caption(s.url)
                    if st.button("Delete", key=f"del_src_{s.id}", width="stretch"): session.delete(s); session.commit(); safe_rerun()
                        
    with tab_ml:
        st.subheader("Smart Filter Training")
        count_pos = session.query(Article).filter(Article.human_feedback == 2).count()
        count_neg = session.query(Article).filter(Article.human_feedback == 1).count()
        total = count_pos + count_neg
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Samples", total); c2.metric("Positives (Keep)", count_pos); c3.metric("Negatives (Dismiss)", count_neg)
        if st.button("🚀 Retrain Model Now", type="primary", disabled=not can_train, key="set_ml_retrain", width="stretch"):
            if total < 10: st.error("Not enough data! Please review at least 10 articles.")
            else:
                with st.spinner("Training neural pathways..."):
                    try: train(); st.success("Model retrained successfully!")
                    except Exception as e: st.error(f"Training failed: {e}")
        
    with tab_ai:
        st.subheader("Universal LLM & System Integrations")
        
        # --- THIS WAS THE MISSING LINE ---
        config = session.query(SystemConfig).first() or SystemConfig()
        if not config.id: 
            session.add(config)
            session.commit()
            
        with st.form("llm_config"):
            st.markdown("### LLM Configuration")
            endpoint = st.text_input("Endpoint URL", value=config.llm_endpoint, key="set_llm_end")
            api_key = st.text_input("API Key", value=config.llm_api_key, type="password", key="set_llm_api")
            model_name = st.text_input("Model Name", value=config.llm_model_name, key="set_llm_mod")
            current_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN"
            tech_stack_input = st.text_area("Internal Tech Stack", value=current_stack, height=100, key="set_llm_stack")
            is_active = st.checkbox("Enable AI Features", value=config.is_active, key="set_llm_active")
            
            st.divider()
            st.markdown("### SMTP Broadcast Configuration")
            c_s1, c_s2 = st.columns([3, 1])
            smtp_server = c_s1.text_input("SMTP Server (e.g. smtp.office365.com)", value=config.smtp_server)
            smtp_port = c_s2.number_input("Port", value=config.smtp_port if config.smtp_port else 587)
            c_s3, c_s4 = st.columns(2)
            smtp_user = c_s3.text_input("SMTP Username", value=config.smtp_username)
            smtp_pass = c_s4.text_input("SMTP Password", value=config.smtp_password, type="password")
            c_s5, c_s6 = st.columns(2)
            smtp_sender = c_s5.text_input("Sender Address", value=config.smtp_sender)
            smtp_recip = c_s6.text_input("Default Recipient List", value=config.smtp_recipient)
            smtp_enabled = st.checkbox("Enable SMTP Broadcasts", value=config.smtp_enabled)

            if st.form_submit_button("Save Global Config", width="stretch"):
                config.llm_endpoint = endpoint; config.llm_api_key = api_key; config.llm_model_name = model_name
                config.tech_stack = tech_stack_input; config.is_active = is_active
                config.smtp_server = smtp_server; config.smtp_port = smtp_port
                config.smtp_username = smtp_user; config.smtp_password = smtp_pass
                config.smtp_sender = smtp_sender; config.smtp_recipient = smtp_recip
                config.smtp_enabled = smtp_enabled
                session.commit(); st.success("✅ Configuration Saved!"); time.sleep(1); safe_rerun()

    with tab_users:
        st.subheader("👥 User & Role Management")
        col_u1, col_u2 = st.columns(2)
        with col_u1:
            available_roles = [r.name for r in session.query(Role).all()]
            with st.container(border=True):
                st.markdown("### ➕ Create New User")
                with st.form("new_user_form"):
                    new_username = st.text_input("Username").strip()
                    new_password = st.text_input("Password", type="password")
                    new_role = st.selectbox("Assign Role", available_roles)
                    if st.form_submit_button("Create User", width="stretch"):
                        if not new_username or not new_password: st.error("Username and password required.")
                        elif session.query(User).filter(User.username == new_username).first(): st.error("Username already exists.")
                        else:
                            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                            session.add(User(username=new_username, password_hash=hashed, role=new_role))
                            session.commit(); st.success(f"User '{new_username}' created!"); safe_rerun()

            with st.container(border=True):
                st.markdown("### 🔄 Change User Role")
                with st.form("update_user_role_form"):
                    target_user = st.selectbox("Select User", [u.username for u in session.query(User).all()])
                    new_assigned_role = st.selectbox("Assign New Role", available_roles)
                    if st.form_submit_button("Update Role", width="stretch"):
                        u_obj = session.query(User).filter(User.username == target_user).first()
                        if u_obj:
                            u_obj.role = new_assigned_role; u_obj.session_token = None
                            session.commit(); st.success(f"✅ Updated {target_user} to role: {new_assigned_role}"); safe_rerun()
                            
            with st.container(border=True):
                st.markdown("### 🛠️ Create Custom Role")
                with st.form("new_role_form"):
                    new_role_name = st.text_input("Role Name").strip().lower()
                    new_role_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES)
                    new_role_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS)
                    if st.form_submit_button("Create Role", width="stretch"):
                        if not new_role_name or not new_role_pages: st.error("Role name and at least one page required.")
                        elif session.query(Role).filter(Role.name == new_role_name).first(): st.error("Role name already exists.")
                        else:
                            session.add(Role(name=new_role_name, allowed_pages=new_role_pages, allowed_actions=new_role_actions))
                            session.commit(); st.success(f"Role '{new_role_name}' created!"); safe_rerun()
                            
            with st.container(border=True):
                st.markdown("### ✏️ Edit Existing Role")
                editable_roles = [r.name for r in session.query(Role).all() if r.name != "admin"]
                if editable_roles:
                    role_to_edit = st.selectbox("Select Role to Edit", editable_roles, key="edit_role_sel")
                    if role_to_edit:
                        selected_role_obj = session.query(Role).filter(Role.name == role_to_edit).first()
                        current_pages = selected_role_obj.allowed_pages if selected_role_obj.allowed_pages else []
                        current_actions = selected_role_obj.allowed_actions if selected_role_obj.allowed_actions else []
                        
                        default_pages = [p for p in current_pages if p in ALL_POSSIBLE_PAGES]
                        default_actions = [a for a in current_actions if a in ALL_POSSIBLE_ACTIONS]
                        
                        with st.form("edit_role_form"):
                            updated_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES, default=default_pages)
                            updated_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS, default=default_actions)
                            
                            if st.form_submit_button("Update Role", width="stretch"):
                                if not updated_pages: 
                                    st.error("A role must have at least one allowed page.")
                                else:
                                    selected_role_obj.allowed_pages = updated_pages
                                    selected_role_obj.allowed_actions = updated_actions
                                    session.commit()
                                    st.success(f"Role '{role_to_edit}' updated!")
                                    time.sleep(1)
                                    safe_rerun()
                else:
                    st.info("No editable roles available.")

        with col_u2:
            with st.container(border=True):
                st.markdown("### Active Users")
                for u in session.query(User).all():
                    c_name, c_role, c_act = st.columns([3, 2, 1])
                    c_name.write(f"**{u.username}**"); c_role.caption(u.role.upper())
                    if u.username != st.session_state.current_user:
                        if c_act.button("🗑️", key=f"del_u_{u.id}", width="stretch"):
                            session.delete(u); session.commit(); safe_rerun()
                            
            with st.container(border=True):
                st.markdown("### 🔑 Force Reset Password")
                with st.form("admin_reset_pwd_form"):
                    target_user = st.selectbox("Select User", [u.username for u in session.query(User).all()])
                    force_new_pwd = st.text_input("New Password", type="password")
                    if st.form_submit_button("Reset Password", width="stretch"):
                        if force_new_pwd:
                            t_user = session.query(User).filter(User.username == target_user).first()
                            t_user.password_hash = bcrypt.hashpw(force_new_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                            t_user.session_token = None
                            session.commit(); st.success(f"✅ Password reset for {target_user}.")

            with st.container(border=True):
                st.markdown("### Active Roles")
                for r in session.query(Role).all():
                    c_name, c_pages, c_act = st.columns([2, 3, 1])
                    c_name.write(f"**{r.name}**")
                    action_count = len(r.allowed_actions) if r.allowed_actions else 0
                    c_pages.caption(f"{len(r.allowed_pages)} pages | {action_count} perms")
                    if r.name not in ["admin", "analyst"]:
                        if c_act.button("🗑️", key=f"del_role_{r.id}", width="stretch"):
                            if session.query(User).filter(User.role == r.name).count() > 0: st.error("Users are assigned this role.")
                            else: session.delete(r); session.commit(); safe_rerun()
                            
    with tab_backup:
        st.subheader("💾 Database Export & Import")
        st.write("Backup or restore configurations, keywords, RSS feeds, and location mappings.")
        
        c_exp, c_imp = st.columns(2)
        with c_exp:
            st.markdown("### Export Data")
            if st.button("📦 Generate Backup JSON", width="stretch"):
                import json
                backup_data = {
                    "keywords": [{"word": k.word, "weight": k.weight} for k in session.query(Keyword).all()],
                    "feeds": [{"url": f.url, "name": f.name} for f in session.query(FeedSource).all()],
                    "locations": [{"name": l.name, "lat": l.lat, "lon": l.lon, "type": l.loc_type, "prio": l.priority} for l in session.query(MonitoredLocation).all()],
                    "aliases": [{"pattern": a.node_pattern, "mapped": a.mapped_location_name, "conf": a.confidence_score, "ver": a.is_verified} for a in session.query(NodeAlias).all()]
                }
                json_str = json.dumps(backup_data, indent=4)
                st.download_button("⬇️ Download System_Backup.json", data=json_str, file_name=f"NOC_Backup_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json", width="stretch")
        
        with c_imp:
            st.markdown("### Import Data")
            uploaded_backup = st.file_uploader("Upload JSON Backup File", type=["json"])
            if uploaded_backup is not None:
                if st.button("📥 Execute Import", width="stretch", type="primary"):
                    import json
                    try:
                        data = json.load(uploaded_backup)
                        added_stats = {"kw": 0, "feeds": 0, "locs": 0, "alias": 0}
                        
                        for kw in data.get("keywords", []):
                            if not session.query(Keyword).filter_by(word=kw["word"]).first():
                                session.add(Keyword(word=kw["word"], weight=kw["weight"])); added_stats["kw"] += 1
                        for f in data.get("feeds", []):
                            if not session.query(FeedSource).filter_by(url=f["url"]).first():
                                session.add(FeedSource(url=f["url"], name=f["name"])); added_stats["feeds"] += 1
                        for l in data.get("locations", []):
                            if not session.query(MonitoredLocation).filter_by(name=l["name"]).first():
                                session.add(MonitoredLocation(name=l["name"], lat=l["lat"], lon=l["lon"], loc_type=l.get("type", "General"), priority=l.get("prio", 3))); added_stats["locs"] += 1
                        for a in data.get("aliases", []):
                            if not session.query(NodeAlias).filter_by(node_pattern=a["pattern"]).first():
                                session.add(NodeAlias(node_pattern=a["pattern"], mapped_location_name=a["mapped"], confidence_score=a["conf"], is_verified=a["ver"])); added_stats["alias"] += 1
                        
                        session.commit()
                        st.success(f"Restored: {added_stats['kw']} Keywords, {added_stats['feeds']} Feeds, {added_stats['locs']} Locations, {added_stats['alias']} Aliases.")
                    except Exception as e:
                        st.error(f"Import Failed: {e}")

    with tab_danger:
        st.error("Database Maintenance & Irreversible Actions")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.write("**Routine Maintenance**")
            st.caption("Safely sweeps stale alerts & intel.")
            if st.button("🧹 Run Garbage Collector", width="stretch", key="set_danger_gc"):
                with st.spinner("Purging stale data and vacuuming database..."):
                    from src.scheduler import run_database_maintenance
                    run_database_maintenance()
                    st.success("✅ Swept and optimized!"); time.sleep(1); safe_rerun()
            
            st.write("**Data Migration**")
            st.caption("Applies new categories to historical 'General' data.")
            if st.button("🔄 Recategorize Old Articles", width="stretch", key="set_danger_recat"):
                with st.spinner("Scanning historical database..."):
                    from src.categorizer import categorize_text
                    arts = session.query(Article).filter(Article.category == "General").all()
                    updated_count = 0
                    for a in arts:
                        full_text = f"{a.title} {a.summary}"
                        new_cat = categorize_text(full_text)
                        if new_cat != "General":
                            a.category = new_cat
                            updated_count += 1
                    session.commit()
                    st.success(f"✅ Successfully recategorized {updated_count} historical articles!")
                    time.sleep(2); safe_rerun()
                    
        with col2:
            st.write("**Clear History**")
            st.caption("Deletes all articles & IOCs.")
            if st.button("🗑️ Delete All Articles", width="stretch", key="set_danger_clear"):
                session.execute(text("TRUNCATE TABLE articles, extracted_iocs RESTART IDENTITY CASCADE;"))
                session.commit(); safe_rerun()
        with col3:
            st.write("**Factory Reset**")
            st.caption("Destroys all data entirely.")
            if st.button("☢️ FULL RESET", width="stretch", key="set_danger_factory"):
                session.execute(text("TRUNCATE TABLE articles, extracted_iocs, feed_sources, keywords, monitored_locations RESTART IDENTITY CASCADE;"))
                session.commit(); safe_rerun()

session.close()