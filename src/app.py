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
                        from src.infra_worker import fetch_regional_hazards; fetch_regional_hazards(); time.sleep(1); safe_rerun()
                
                locs = session.query(MonitoredLocation).all()
                df = pd.DataFrame([{"id": l.id, "Name": l.name, "Type": l.loc_type, "Priority": l.priority, "Risk": l.current_spc_risk, "Lat": l.lat, "Lon": l.lon} for l in locs]) if locs else pd.DataFrame()
                
                tab_map, tab_dash, tab_matrix, tab_manage = st.tabs(["🗺️ Geospatial Overlay", "📊 Executive Dashboard", "🗄️ Location Matrix", "📍 Manage Locations"])
                
                with tab_map:
                    map_df = df.copy()
                    if not df.empty:
                        cf1, cf2 = st.columns(2)
                        available_types = df['Type'].unique().tolist()
                        available_prios = sorted(df['Priority'].unique().tolist())
                        selected_types = cf1.multiselect("Filter by Location Type", available_types, default=available_types, key="map_filt_type")
                        selected_prios = cf2.multiselect("Filter by Priority", available_prios, default=available_prios, key="map_filt_prio")
                        map_df = df[df['Type'].isin(selected_types) & df['Priority'].isin(selected_prios)]
                        st.write("")
                    
                    c_map1, c_map2 = st.columns([2, 1])
                    with c_map1:
                        st.subheader("Live SPC & Infrastructure Overlay")
                        import pydeck as pdk
                        import requests
                        layers = []
                        try:
                            spc_res = requests.get("https://www.spc.noaa.gov/products/outlook/day1otlk_cat.lyr.geojson", timeout=5)
                            if spc_res.status_code == 200:
                                spc_geo = spc_res.json()
                                color_map = {
                                    "TSTM": [192, 232, 192, 100], "MRGL": [124, 205, 124, 150],
                                    "SLGT": [246, 246, 123, 150], "ENH": [230, 153, 0, 150],
                                    "MDT": [255, 0, 0, 150], "HIGH": [255, 0, 255, 150]
                                }
                                for f in spc_geo.get('features', []):
                                    label = f.get('properties', {}).get('LABEL', '')
                                    f['properties']['fill_color'] = color_map.get(label, [0, 0, 0, 0])
                                layers.append(pdk.Layer(
                                    "GeoJsonLayer", spc_geo, pickable=True, stroked=True,
                                    filled=True, get_fill_color="properties.fill_color",
                                    get_line_color=[0, 0, 0, 255], line_width_min_pixels=1
                                ))
                        except Exception: pass
                        
                        if not map_df.empty:
                            layers.append(pdk.Layer(
                                "ScatterplotLayer", map_df, pickable=True, opacity=0.9, stroked=True,
                                filled=True, radius_scale=6, radius_min_pixels=4, radius_max_pixels=12,
                                line_width_min_pixels=1, get_position="[Lon, Lat]",
                                get_fill_color=[255, 255, 255], get_line_color=[0, 0, 0],
                            ))
                            
                        view_state = pdk.ViewState(latitude=34.8, longitude=-92.2, zoom=6, pitch=0)
                        st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{Name}\nType: {Type}\nRisk: {Risk}"} if not map_df.empty else {"text": "{LABEL}"}), width="stretch")
                    
                    with c_map2:
                        st.subheader("Precipitation Radar")
                        components.html("""<iframe src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" width="100%" height="450" frameborder="0" style="border-radius: 8px;" allowfullscreen></iframe>""", height=450)
                        
                    st.divider()
                    st.subheader("Active NWS Warnings (Arkansas)")
                    nws_alerts = session.query(RegionalHazard).order_by(RegionalHazard.updated_at.desc()).all()
                    if not nws_alerts: st.success("No active NWS alerts for the region.")
                    for haz in nws_alerts:
                        ic = "🔴" if haz.severity in ["Extreme", "Severe"] else "🟠" if haz.severity == "Moderate" else "🔵"
                        with st.expander(f"{ic} [{haz.severity}] {haz.title}"):
                            st.markdown(f"**Area:** {haz.location}\n\n{haz.description}")

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

                    if df.empty:
                        st.info("No monitored locations found.")
                    else:
                        risk_order = ["HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "None"]
                        df['Risk'] = pd.Categorical(df['Risk'], categories=risk_order, ordered=True)
                        risk_df = df[df['Risk'] != 'None']
                        
                        st.download_button(
                            label="📥 Export Infrastructure Risk Report (CSV)",
                            data=df.sort_values(by=['Risk', 'Priority']).to_csv(index=False).encode('utf-8'),
                            file_name=f"Infrastructure_Risk_{datetime.now(LOCAL_TZ).strftime('%Y%m%d_%H%M')}.csv",
                            mime='text/csv', width="stretch"
                        )
                        st.divider()
                        
                        c_m1, c_m2, c_m3 = st.columns(3)
                        c_m1.metric("Total Tracked Sites", len(df))
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
                            type_counts = df['Type'].value_counts().reset_index()
                            type_counts.columns = ['Location Type', 'Count']
                            st.bar_chart(type_counts.set_index('Location Type'), color="#1f77b4", width="stretch")

                        st.divider()
                        c3, c4 = st.columns(2)
                        with c3:
                            st.markdown("**Risk by Priority Level**")
                            st.dataframe(pd.crosstab(df['Priority'], df['Risk']), width="stretch")
                        with c4:
                            st.markdown("**Risk by Facility Type**")
                            st.dataframe(pd.crosstab(df['Type'], df['Risk']), width="stretch")

                with tab_matrix:
                    st.subheader("Active Infrastructure Matrix")
                    st.caption("All tracked locations overlaid with current SPC Convective Outlooks.")
                    if not df.empty:
                        display_df = df.drop(columns=['id', 'Lat', 'Lon'])
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
                                    st.success(f"Imported {added} new locations!"); time.sleep(1.5); safe_rerun()
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
                                st.success("Changes saved!"); time.sleep(1); safe_rerun()
                        
                        st.divider()
                        st.write("**Danger Zone**")
                        if st.button("🗑️ Delete All Locations", width="stretch"):
                            session.execute(text("TRUNCATE TABLE monitored_locations RESTART IDENTITY CASCADE;"))
                            session.commit()
                            st.success("All locations deleted!"); time.sleep(1); safe_rerun()
            tab_idx += 1

elif page == "🎯 Threat Hunting & IOCs":
    st.title("🎯 Active Threat Hunting")
    st.markdown("Automated IOC extraction and LLM-assisted deep scanning for specific threat actors, malwares, or target infrastructure.")
    
    tab_matrix, tab_manual = st.tabs(["🧮 Live IOC Matrix", "🔬 Manual Deep Hunt (LLM)"])
    
    with tab_matrix:
        st.subheader("Global Indicators of Compromise (Last 72 Hours)")
        st.caption("Auto-extracted via Regex from ML-verified (Score > 50) Cyber Intelligence feeds only.")
        
        seventy_two_hrs_ago = datetime.utcnow() - timedelta(days=3)
        recent_iocs = session.query(ExtractedIOC).filter(ExtractedIOC.detected_at >= seventy_two_hrs_ago).order_by(ExtractedIOC.detected_at.desc()).all()
        
        if not recent_iocs:
            st.info("No active IOCs extracted in the last 72 hours.")
        else:
            ioc_data = []
            for ioc in recent_iocs:
                art = session.query(Article).filter(Article.id == ioc.article_id).first()
                source_link = art.link if art else "Unknown"
                ioc_data.append({
                    "Type": ioc.indicator_type,
                    "Indicator": ioc.indicator_value,
                    "Source Article": source_link,
                    "Detected": format_local_time(ioc.detected_at)
                })
            
            df = pd.DataFrame(ioc_data)
            col_filter1, col_filter2 = st.columns(2)
            filter_type = col_filter1.multiselect("Filter by Type", ["IPv4", "SHA256", "MD5", "CVE"], default=["IPv4", "SHA256", "MD5", "CVE"])
            filtered_df = df[df["Type"].isin(filter_type)]
            
            st.dataframe(filtered_df, width="stretch", column_config={"Source Article": st.column_config.LinkColumn("Source")}, hide_index=True)
            st.download_button(label="📥 Export IOCs (CSV)", data=filtered_df.to_csv(index=False).encode('utf-8'), file_name=f"IOC_Export_{datetime.now(LOCAL_TZ).strftime('%Y%m%d')}.csv", mime='text/csv', width="stretch")

    with tab_manual:
        st.subheader("Targeted LLM Deep Hunt")
        st.markdown("Search the historical database for a specific threat and use the AI to generate YARA patterns, SIEM queries, and TTP assessments.")
        with st.form("manual_hunt_form"):
            hunt_target = st.text_input("Target Entity (e.g., 'Volt Typhoon', 'Ivanti Connect Secure', 'RansomHub')")
            hunt_depth = st.slider("Historical Depth (Days)", min_value=7, max_value=90, value=30)
            
            if st.form_submit_button("🚀 Execute Deep Hunt", type="primary", disabled=not can_trigger_ai, width="stretch"):
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
                            sys_prompt = f"""You are an elite Cyber Threat Hunter. Analyze the provided intelligence reports regarding '{hunt_target}'.
                            Synthesize the data and generate an actionable Threat Hunt Package.
                            Your output MUST strictly follow this Markdown structure:
                            ### 1. Threat Overview & TTPs
                            ### 2. Known Targets & Vulnerabilities
                            ### 3. Hunt Queries & Detection Logic
                            Do not hallucinate. Base your response ONLY on the provided text."""
                            
                            messages = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": hunt_context}]
                            from src.llm import call_llm
                            ai_hunt_result = call_llm(messages, sys_config, temperature=0.1)
                            
                            if ai_hunt_result:
                                st.divider()
                                st.markdown(f"## 🎯 Hunt Package: {hunt_target.upper()}")
                                st.markdown(ai_hunt_result)
                                st.divider()
                                st.markdown("### 🔗 Reference Intel")
                                for a in target_arts: st.markdown(f"- [{a.title}]({a.link})")

# ================= NEW MODULE: AIOps RCA LIVE =================
elif page == "⚡ AIOps RCA":
    st.title("⚡ AIOps Root Cause Analysis")
    st.markdown("Live correlation of non-uniform monitoring alerts with Regional Intelligence.")
    status_indicator = f"🔴 **LIVE** (Refreshing every {current_refresh_sec}s)" if current_refresh_sec > 0 else "⏸️ **PAUSED**"
    st.caption(f"{status_indicator} | Webhook Listener Active on Port 8100")
    st.write("")
    
    from src.database import TimelineEvent, RegionalOutage
    from shapely.geometry import Point
    
    tab_active, tab_learning, tab_global = st.tabs(["🔴 Active Incident Board", "🧠 ML Alias Learning", "🌍 Global Correlation Engine"])
    
    with tab_active:
        active_alerts = session.query(SolarWindsAlert).filter(SolarWindsAlert.status != 'Resolved').order_by(SolarWindsAlert.received_at.desc()).all()
        c_live, c_sw = st.columns([3, 1])
        
        with c_sw:
            st.subheader("⏱️ Live Event Log")
            st.caption("Descending Chronological")
            
            c_btn1, c_btn2 = st.columns(2)
            if c_btn1.button("🧹 Clear Log", width="stretch"):
                session.query(TimelineEvent).delete(); session.commit(); safe_rerun()
            if c_btn2.button("🗑️ Nuke Alerts", width="stretch"):
                session.query(SolarWindsAlert).delete(); session.commit(); safe_rerun()
            
            st.divider()
            
            with st.container(height=800):
                events = session.query(TimelineEvent).order_by(TimelineEvent.timestamp.desc()).limit(50).all()
                if not events:
                    st.info("Listening for network telemetry...")
                else:
                    for e in events:
                        icon = "🔴" if e.event_type == "Alert" else "🟢" if e.event_type == "Resolution" else "🤖" if e.source == "AI" else "🔵"
                        st.markdown(f"<small>**{e.timestamp.strftime('%H:%M:%S')}** | {icon} {e.source}</small><br>{e.message}", unsafe_allow_html=True)
                        st.divider()

        with c_live:
            # --- MAP RENDERED FIRST ---
            st.subheader("🗺️ Dynamic Geospatial Overlays")
            import pydeck as pdk
            
            locs = session.query(MonitoredLocation).all()
            grid_issues = session.query(RegionalOutage).filter_by(is_resolved=False).all()
            
            if not locs:
                st.info("No monitored locations configured. Map cannot be rendered.")
            else:
                # --- NEW: MAP TYPE FILTER ---
                available_types = sorted(list(set([l.loc_type for l in locs if l.loc_type])))
                selected_types = st.multiselect("Filter Sites by Type", available_types, default=available_types, key="rca_map_type_filt")
                
                filtered_locs = [l for l in locs if l.loc_type in selected_types]
                
                alert_mapped_sites = [a.mapped_location for a in active_alerts if a.mapped_location != "Unknown"]
                site_down_counts = {site: alert_mapped_sites.count(site) for site in set(alert_mapped_sites)}
                down_locs = [l for l in filtered_locs if l.name in alert_mapped_sites]
                
                map_data, node_radii = [], []
                
                for l in filtered_locs:
                    down_count = site_down_counts.get(l.name, 0)
                    is_down = down_count > 0
                    color = [255, 0, 0] if is_down else [0, 255, 0]
                    status_text = f"{down_count} NODE(S) OFFLINE" if is_down else "Online"
                    
                    map_data.append({"Name": l.name, "Lat": l.lat, "Lon": l.lon, "Status": status_text, "Color": color})
                    
                    if is_down:
                        base_radius = 5000 + ((down_count - 1) * 3000)
                        nearby_bonus = 0
                        for other_l in down_locs:
                            if other_l.name != l.name:
                                dist_deg = ((l.lon - other_l.lon)**2 + (l.lat - other_l.lat)**2)**0.5
                                dist_km = dist_deg * 111
                                if dist_km < 50:
                                    nearby_bonus += 8000
                                    
                        total_radius = base_radius + nearby_bonus
                        node_radii.append({"lat": l.lat, "lon": l.lon, "radius": total_radius})
                        
                layers = []
                
                isp_data = [{"lat": i.lat, "lon": i.lon, "radius": i.radius_km * 1000} for i in grid_issues if i.outage_type in ["ISP", "Cellular"]]
                if isp_data:
                    layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(isp_data), get_position="[lon, lat]", get_fill_color=[128, 0, 128, 60], get_radius="radius", pickable=False))
                    
                pwr_data = [{"lat": i.lat, "lon": i.lon, "radius": i.radius_km * 1000} for i in grid_issues if i.outage_type == "Power"]
                if pwr_data:
                    layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(pwr_data), get_position="[lon, lat]", get_fill_color=[255, 200, 0, 60], get_radius="radius", pickable=False))
                
                if node_radii:
                    layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(node_radii), get_position="[lon, lat]", get_fill_color=[255, 0, 0, 40], get_radius="radius", pickable=False))
                    
                layers.append(pdk.Layer("ScatterplotLayer", pd.DataFrame(map_data), get_position="[Lon, Lat]", get_fill_color="Color", get_radius=1500, pickable=True))
                
                center_lat, center_lon = (node_radii[0]['lat'], node_radii[0]['lon']) if node_radii else (34.8, -92.2)
                st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=pdk.ViewState(latitude=center_lat, longitude=center_lon, zoom=6.5, pitch=0), tooltip={"text": "{Name}\nStatus: {Status}"}), width="stretch", height=600)
            
            st.divider()

            # --- CLUSTERED ALERT MATRIX ---
            st.subheader("🧠 Site-Based Correlation Matrix")
            
            if not active_alerts:
                st.success("✅ All monitored infrastructure is operational.")
            else:
                # Group alerts by their mapped site
                from collections import defaultdict
                site_clusters = defaultdict(list)
                for alert in active_alerts:
                    site_clusters[alert.mapped_location].append(alert)
                
                # Render each site as a unified block
                for site_name, alerts in site_clusters.items():
                    with st.container(border=True):
                        st.markdown(f"### 📍 Site Cluster: [{site_name}]")
                        
                        # Calculate impact radius at this site
                        device_counts = {}
                        category_counts = {}
                        for a in alerts:
                            device_counts[a.device_type] = device_counts.get(a.device_type, 0) + 1
                            category_counts[a.event_category] = category_counts.get(a.event_category, 0) + 1
                            
                        st.markdown(f"**Total Active Alerts:** {len(alerts)}")
                        
                        c_stat1, c_stat2 = st.columns(2)
                        with c_stat1:
                            st.caption("Hardware Affected")
                            for k, v in device_counts.items(): st.write(f"- {v}x {k}")
                        with c_stat2:
                            st.caption("Event Categories")
                            for k, v in category_counts.items(): st.write(f"- {v}x {k}")
                        
                        st.divider()
                        
                        # Site-level external telemetry context
                        node_record = session.query(MonitoredLocation).filter(MonitoredLocation.name == site_name).first()
                        node_risk = node_record.current_spc_risk if node_record else "Unknown"
                        active_cloud = session.query(CloudOutage).filter_by(is_resolved=False).count()
                        
                        nearby_power = 0
                        nearby_isp = 0
                        if node_record and node_record.lat and node_record.lon:
                            active_grid_issues = session.query(RegionalOutage).filter_by(is_resolved=False).all()
                            for issue in active_grid_issues:
                                if issue.lat and issue.lon:
                                    dist_deg = ((node_record.lon - issue.lon)**2 + (node_record.lat - issue.lat)**2)**0.5
                                    dist_km = dist_deg * 111
                                    if dist_km <= issue.radius_km:
                                        if issue.outage_type == "Power": nearby_power += 1
                                        elif issue.outage_type in ["ISP", "Cellular"]: nearby_isp += 1
                                        
                        c_rca1, c_rca2, c_rca3 = st.columns(3)
                        c_rca1.metric("Local SPC Risk", node_risk)
                        c_rca2.metric("Nearby Power Outages", nearby_power)
                        c_rca3.metric("Nearby Telecom Outages", nearby_isp)
                        
                        # Heuristic Rule Engine (No API required)
                        prog_factors = []
                        if nearby_power > 0: prog_factors.append("Grid Power Loss")
                        if nearby_isp > 0: prog_factors.append("ISP Backbone Cut")
                        if active_cloud > 0: prog_factors.append("Upstream Cloud Outage")
                        if node_risk not in ["None", "Unknown"]: prog_factors.append(f"Severe Weather Hazard ({node_risk})")
                        
                        if len(device_counts) > 2 and category_counts.get("Hard Down", 0) > 1:
                            prog_factors.append("Catastrophic Local Hardware Cascade (Multiple Device Types Down)")
                        
                        if prog_factors:
                            st.warning(f"⚙️ **Deterministic Site RCA:** Multiple vectors found ➔ **{', '.join(prog_factors)}**")
                        else:
                            st.error("⚙️ **Deterministic Site RCA:** No external factors found. Isolated internal site failure.")
                        
                        # Expandable Alert Details
                        with st.expander("🔍 View Granular Node Details"):
                            for alert in alerts:
                                c_a1, c_a2 = st.columns([4, 1])
                                c_a1.error(f"**{alert.node_name}** | {alert.device_type} | {alert.event_category} | IP: {alert.ip_address}")
                                if c_a2.button("✅ Resolve", key=f"res_{alert.id}", width="stretch"):
                                    alert.status = 'Resolved'
                                    session.add(TimelineEvent(source="User", event_type="Resolution", message=f"🟢 Operator manually resolved {alert.node_name}"))
                                    session.commit(); safe_rerun()

    with tab_learning:
        st.subheader("🧠 ML Node Mapping Matrix")
        st.markdown("The system uses Fuzzy Logic to guess which Site a cryptic Node Name belongs to. Review and verify the AI's guesses here.")
        
        from src.database import NodeAlias
        aliases = session.query(NodeAlias).order_by(NodeAlias.confidence_score.asc()).all()
        
        if not aliases: st.info("No learned aliases yet. Send a webhook payload to begin training.")
        else:
            all_locs = ["Unknown"] + [l.name for l in session.query(MonitoredLocation).all()]
            for a in aliases:
                with st.container(border=True):
                    c_a1, c_a2, c_a3, c_a4 = st.columns([2, 3, 1, 1])
                    c_a1.code(a.node_pattern)
                    
                    new_mapping = c_a2.selectbox("Mapped Site", all_locs, index=all_locs.index(a.mapped_location_name) if a.mapped_location_name in all_locs else 0, key=f"sel_al_{a.id}")
                    
                    if a.is_verified: c_a3.success("Verified")
                    else: c_a3.warning(f"AI Guess ({int(a.confidence_score)}%)")
                    
                    if c_a4.button("💾 Save", key=f"sv_al_{a.id}", width="stretch"):
                        a.mapped_location_name = new_mapping
                        a.is_verified = True
                        a.confidence_score = 100.0 
                        session.commit()
                        st.success("Rule Saved!"); time.sleep(0.5); safe_rerun()

    with tab_global:
        st.subheader("🌍 Deterministic Global Correlation Engine")
        st.markdown("Calculates causation graphs based on geospatial math and telemetry overlays. Works 100% locally. AI summarization is optional.")
        
        c_glob1, c_glob2 = st.columns([3, 1])
        
        if c_glob2.button("🔍 Run Global Correlation", type="primary", width="stretch"):
            with st.spinner("Calculating Multi-Domain Causal Links..."):
                down_nodes = session.query(SolarWindsAlert).filter(SolarWindsAlert.status != 'Resolved').all()
                active_clouds = session.query(CloudOutage).filter(CloudOutage.is_resolved == False).all()
                active_weather = session.query(RegionalHazard).all()
                active_grid = session.query(RegionalOutage).filter_by(is_resolved=False).all()
                locs_db = session.query(MonitoredLocation).all()
                
                # --- PHASE 1: PROGRAMMATIC CORRELATION (NO LLM REQUIRED) ---
                report = "### 🌍 Global Situation Report (SitRep)\n\n"
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
                        if any(c in str(alert.details).lower() or c in str(alert.event_type).lower() for c in c_names):
                            causation_factors.append("☁️ Upstream Cloud Outage match found in payload")
                            
                    if n_loc and n_loc.lat and n_loc.lon:
                        for issue in active_grid:
                            if issue.lat and issue.lon:
                                dist_km = (((n_loc.lon - issue.lon)**2 + (n_loc.lat - issue.lat)**2)**0.5) * 111
                                if dist_km <= issue.radius_km:
                                    causation_factors.append(f"⚡ Geospatial overlap with {issue.outage_type} outage ({issue.provider})")
                                    
                    if causation_factors:
                        report += f"- **{alert.node_name}** ({alert.mapped_location}) is likely degraded due to: " + ", ".join(causation_factors) + "\n"
                    else:
                        isolated_nodes.append(f"**{alert.node_name}** ({alert.mapped_location})")
                        
                report += "\n#### 🛠️ Isolated Anomalies (Network Faults)\n"
                if isolated_nodes:
                    report += "No external factors detected. Treat as localized hardware/software failures:\n"
                    for n in isolated_nodes: report += f"- {n}\n"
                else:
                    report += "- None detected.\n"
                    
                # --- PHASE 2: OPTIONAL AI SUMMARIZATION ---
                if ai_enabled and can_trigger_ai:
                    sys_prompt = "You are an elite AIOps Engine. Summarize the following deterministic IT SitRep into a 2-sentence executive summary highlighting the most critical impacts."
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
            if c_em1.button("✉️ Broadcast via Email", width="stretch"):
                from src.mailer import send_alert_email
                with st.spinner("Transmitting via SMTP..."):
                    success, msg = send_alert_email("Critical Multi-Domain SitRep", st.session_state.last_global_rca)
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