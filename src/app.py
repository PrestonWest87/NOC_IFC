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

from src.database import SessionLocal, Article, FeedSource, Keyword, SystemConfig, engine, init_db, CveItem, RegionalHazard, CloudOutage, User, Role, SavedReport, DailyBriefing
from src.train_model import train 
from src.scheduler import fetch_feeds
from src.llm import generate_briefing, generate_bluf, analyze_cascading_impacts, cross_reference_cves, build_custom_intel_report, generate_feed_overview, generate_rolling_summary, generate_daily_fusion_report

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

# --- EFFICIENCY UPGRADE: CONNECTION POOL LEAK FIX ---
def safe_rerun():
    """Safely closes the database connection before forcing a UI reload to prevent pool exhaustion deadlocks."""
    try:
        session.close()
    except Exception:
        pass
    st.rerun()

# --- EFFICIENCY UPGRADE: Metric Caching ---
@st.cache_data(ttl=60)
def get_dashboard_metrics():
    """Fetches top-level metrics from the DB. Cached in RAM for 60 seconds across all user sessions."""
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
    "📑 Report Center", 
    "⚙️ Settings & Admin"
]

ALL_POSSIBLE_ACTIONS = [
    "action_pin", "action_train_ml", "action_boost_threat", "action_trigger_ai", "action_sync_data",
    "tab_tt_rss", "tab_tt_kev", "tab_tt_cloud", "tab_tt_infra",
    "tab_rc_build", "tab_rc_lib"
]

# ================= AUTHENTICATION WALL =================
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
            if st.form_submit_button("Authenticate", use_container_width=True):
                user = session.query(User).filter(User.username == username).first()
                if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                    new_token = str(uuid.uuid4())
                    user.session_token = new_token
                    session.commit()
                    cookie_controller.set("noc_session_token", new_token, max_age=30*86400)
                    st.session_state.current_user = user.username
                    st.session_state.current_role = user.role
                    time.sleep(0.5) 
                    safe_rerun()
                else: st.error("❌ Invalid credentials.")
    st.stop() 

role_obj = session.query(Role).filter(Role.name == st.session_state.current_role).first()
if role_obj:
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
        [data-testid="stExpanderDetails"] li { 
            font-size: 0.9rem !important; 
            margin-bottom: 0.2rem !important; 
            line-height: 1.3 !important;
        }
        hr { margin-top: 0.5rem; margin-bottom: 0.5rem; }
        .stButton>button { padding: 0rem 0.5rem !important; min-height: 2rem !important; }
    </style>
""", unsafe_allow_html=True)

# ================= GLOBAL UI HELPERS =================
def get_score_badge(score):
    if score >= 80: return f"🔴 **[{int(score)}]**"
    elif score >= 50: return f"🟠 **[{int(score)}]**"
    else: return f"🔵 **[{int(score)}]**"

def toggle_pin(art_id):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art: art.is_pinned = not art.is_pinned; session.commit()

def boost_score(art_id, amount=15):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art: art.score = min(100.0, art.score + amount); session.commit()

def format_local_time(utc_dt):
    if not utc_dt: return "Unknown"
    return utc_dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M')

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
    """Renders the UI block and guarantees perfect state sync on button clicks."""
    if not feed_articles: 
        st.success("Queue is empty.")
        return
        
    for art in feed_articles:
        with st.container(border=True):
            c_title, c_score = st.columns([4, 1])
            c_title.markdown(f"**{get_score_badge(art.score)} [{art.title}]({art.link})**")
            c_title.caption(f"📅 {format_local_time(art.published_date)} | 📡 {art.source}")
            
            if art.ai_bluf: 
                st.success(f"**AI BLUF:** {art.ai_bluf}")
            else: 
                st.caption(art.summary[:250] + "..." if art.summary else "No summary.")
                
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.button("📍 Unpin" if art.is_pinned else "📌 Pin", key=f"{key_prefix}pin_{art.id}", disabled=not can_pin, on_click=toggle_pin, args=(art.id,))
            c2.button("⏫ +15 Score", key=f"{key_prefix}boost_{art.id}", disabled=not can_boost, on_click=boost_score, args=(art.id, 15))
            c3.button("🧠 Keep", key=f"{key_prefix}keep_{art.id}", disabled=not can_train, on_click=change_status, args=(art.id, 2))
            c4.button("🧠 Dismiss", key=f"{key_prefix}dism_{art.id}", disabled=not can_train, on_click=change_status, args=(art.id, 1))
            
            if ai_enabled and not art.ai_bluf:
                if c5.button("🤖 BLUF", key=f"{key_prefix}bluf_{art.id}", disabled=not can_trigger_ai):
                    with st.spinner("Analyzing..."):
                        b = generate_bluf(art, session)
                        if b: 
                            art.ai_bluf = b
                            session.commit()
                            safe_rerun()

# ================= SIDEBAR & NAVIGATION =================
st.sidebar.title("NOC Fusion")

display_name = current_user_obj.full_name if current_user_obj and current_user_obj.full_name else st.session_state.current_user.capitalize()
display_title = current_user_obj.job_title if current_user_obj and current_user_obj.job_title else st.session_state.current_role.upper()
st.sidebar.markdown(f"👤 **{display_name}**\n\n<small>{display_title}</small>", unsafe_allow_html=True)

if st.sidebar.button("🚪 Log Out", use_container_width=True):
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
        if st.form_submit_button("Save Profile", use_container_width=True):
            current_user_obj.full_name = new_fn; current_user_obj.job_title = new_jt; current_user_obj.contact_info = new_ci
            if new_pwd:
                if bcrypt.checkpw(old_pwd.encode('utf-8'), current_user_obj.password_hash.encode('utf-8')):
                    current_user_obj.password_hash = bcrypt.hashpw(new_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    st.success("Updated!")
                else: st.error("Incorrect password.")
            else: st.success("Updated!")
            session.commit(); time.sleep(0.5); safe_rerun()

st.sidebar.divider()
refresh_minutes = st.sidebar.number_input("🔄 Auto-Refresh (Mins)", min_value=0, max_value=60, value=2, key="sidebar_refresh_mins")
PAGES = st.session_state.allowed_pages

if not PAGES: st.error("No assigned permissions."); st.stop()
if "active_page" not in st.session_state or st.session_state.active_page not in PAGES: st.session_state.active_page = PAGES[0]

selected_page = st.sidebar.radio("Navigation", PAGES, index=PAGES.index(st.session_state.active_page), key="nav_radio")
if selected_page != st.session_state.active_page: st.session_state.active_page = selected_page; safe_rerun()
page = st.session_state.active_page

refresh_count = 0
if refresh_minutes > 0:
    if page not in ["📑 Report Center", "⚙️ Settings & Admin", "📰 Daily Fusion Report"]:
        refresh_count = st_autorefresh(interval=refresh_minutes * 60 * 1000, key="noc_refresh")

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
                st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small>📡 {art.source} | {format_local_time(art.published_date)}</small>", unsafe_allow_html=True)
                if art.ai_bluf: st.success(f"**AI BLUF:** {art.ai_bluf}")
                st.write("")
        with col_rss:
            st.subheader("🚨 Live Feed (Top 15)")
            top_rss = session.query(Article).filter(Article.published_date >= twenty_four_hours_ago, Article.score >= 50.0, Article.is_pinned == False).order_by(Article.score.desc(), Article.published_date.desc()).limit(15).all()
            for art in top_rss:
                st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small>📡 {art.source} | {format_local_time(art.published_date)}</small>", unsafe_allow_html=True)

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
                if c_btn.button("🔄 Force Refresh Briefing", use_container_width=True, disabled=not can_trigger_ai, key="dash_refresh_ai"):
                    with st.spinner("🤖 Forcing AI Summary Update..."):
                        ns = generate_rolling_summary(session)
                        if ns:
                            sys_config.rolling_summary = ns
                            sys_config.rolling_summary_time = datetime.utcnow()
                            session.commit()
                            safe_rerun()
                            
                st.info(sys_config.rolling_summary if sys_config.rolling_summary else "Initializing...")
            else: st.info("AI Disabled.")
            
        with col_ai2:
            st.subheader("🤖 Security Auditor")
            st.caption("Checks active tech stack against KEVs.")
            if st.button("Scan Stack Against 30-Day KEVs", use_container_width=True, disabled=not can_trigger_ai, key="dash_scan_stack"):
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
    if col2.button("🤖 Generate Yesterday's Report", use_container_width=True, type="primary", disabled=not can_trigger_ai, key="br_gen_report"):
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
                if col_btn.button("🔄 Force Fetch Feeds", use_container_width=True, disabled=not can_sync, key="tt_fetch_feeds"):
                    fetch_feeds(source="User Force"); time.sleep(1); safe_rerun()

                def render_paginated_feed(base_query, feed_id, page_size=20):
                    state_key = f"page_{feed_id}"
                    if state_key not in st.session_state: st.session_state[state_key] = 1
                    
                    total_items = base_query.count()
                    total_pages = max(1, (total_items + page_size - 1) // page_size)
                    
                    if st.session_state[state_key] > total_pages: 
                        st.session_state[state_key] = max(1, total_pages)
                        
                    current_page = st.session_state[state_key]
                    
                    def pagination_controls(loc):
                        col1, col2, col3 = st.columns([1, 2, 1])
                        with col1:
                            if st.button("⬅️ Previous", key=f"prev_{feed_id}_{loc}", disabled=(current_page <= 1), use_container_width=True):
                                st.session_state[state_key] -= 1; safe_rerun()
                        with col2:
                            st.markdown(f"<div style='text-align: center; margin-top: 0.4rem;'><b>Page {current_page} of {total_pages}</b> <span style='font-size: 0.85em; color: gray;'>(Total: {total_items})</span></div>", unsafe_allow_html=True)
                        with col3:
                            if st.button("Next ➡️", key=f"next_{feed_id}_{loc}", disabled=(current_page >= total_pages), use_container_width=True):
                                st.session_state[state_key] += 1; safe_rerun()

                    if total_items > page_size: 
                        pagination_controls("top")
                        st.divider()
                    elif total_items == 0:
                        st.info("No articles found matching this criteria.")
                        return
                    
                    offset = (current_page - 1) * page_size
                    items = base_query.offset(offset).limit(page_size).all()
                    
                    render_article_feed(items, key_prefix=f"{feed_id}_")
                    
                    if total_items > page_size: 
                        st.divider()
                        pagination_controls("bottom")

                sub_tab_pinned, sub_tab_live, sub_tab_low, sub_tab_search = st.tabs(["📌 Pinned", "📡 Live Feed (>50)", "📉 Below Threshold (<50)", "🔍 Deep Search"])
                
                with sub_tab_pinned:
                    q_pinned = session.query(Article).filter(Article.is_pinned == True).order_by(Article.published_date.desc())
                    render_paginated_feed(q_pinned, feed_id="pinned", page_size=10)

                with sub_tab_live: 
                    q_live = session.query(Article).filter(Article.score >= 50.0, Article.is_pinned == False).order_by(Article.published_date.desc())
                    render_paginated_feed(q_live, feed_id="live", page_size=20)
                    
                with sub_tab_low: 
                    q_low = session.query(Article).filter(Article.score < 50.0, Article.is_pinned == False).order_by(Article.published_date.desc())
                    render_paginated_feed(q_low, feed_id="low", page_size=20)
                    
                with sub_tab_search:
                    s1, s2, s3 = st.columns([2, 1, 1])
                    search_term = s1.text_input("Search (Keywords or Source)", key="tt_search_kw")
                    min_score = s2.number_input("Min Score", value=0, key="tt_search_min")
                    page_size_sel = s3.selectbox("Items per Page", [10, 20, 50], index=1, key="tt_search_lim")
                    
                    q_search = session.query(Article).filter(Article.score >= min_score)
                    if search_term: 
                        q_search = q_search.filter(Article.title.ilike(f"%{search_term}%") | Article.summary.ilike(f"%{search_term}%"))
                    
                    render_paginated_feed(q_search.order_by(Article.score.desc(), Article.published_date.desc()), feed_id="search", page_size=page_size_sel)
            tab_idx += 1
            
        if "tab_tt_kev" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                if st.button("🔄 Sync CISA KEV", disabled=not can_sync, key="tt_sync_kev"):
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
                if st.button("🔄 Sync Cloud Status", disabled=not can_sync, key="tt_sync_cloud"):
                    with st.spinner("Pulling..."):
                        from src.cloud_worker import fetch_cloud_outages; fetch_cloud_outages(); time.sleep(1); safe_rerun()
                sa, sg, sz, sc = st.tabs(["AWS", "Google Cloud", "Azure", "Cisco"])
                def rnd_cld(prov, t):
                    with t:
                        outs = session.query(CloudOutage).filter(CloudOutage.provider.like(prov)).order_by(CloudOutage.is_resolved.asc(), CloudOutage.updated_at.desc()).all()
                        if not outs: st.success("Operational.")
                        for o in outs:
                            ic = "✅ RESOLVED" if o.is_resolved else "🚨 ACTIVE"
                            with st.expander(f"[{ic}] {o.service} ({format_local_time(o.updated_at)})"):
                                st.markdown(f"[{o.title}]({o.link})\n\n{o.description}")
                rnd_cld("AWS", sa); rnd_cld("Google Cloud", sg); rnd_cld("Azure", sz); rnd_cld("Cisco%", sc)
            tab_idx += 1
            
        if "tab_tt_infra" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                if st.button("🔄 Sync Regional Telemetry", disabled=not can_sync, key="tt_sync_infra"):
                    with st.spinner("Pulling..."):
                        from src.infra_worker import fetch_regional_hazards; fetch_regional_hazards(); time.sleep(1); safe_rerun()
                components.html("""<iframe src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" width="100%" height="600" frameborder="0" style="border-radius: 8px;" allowfullscreen></iframe>""", height=600)
                for haz in session.query(RegionalHazard).order_by(RegionalHazard.updated_at.desc()).all():
                    ic = "🔴" if haz.severity in ["Extreme", "Severe"] else "🟠" if haz.severity == "Moderate" else "🔵"
                    with st.expander(f"{ic} [{haz.severity}] {haz.title}"):
                        st.markdown(f"**Area:** {haz.location}\n\n{haz.description}")
            tab_idx += 1

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
                    
                    if st.button("🚀 Generate Report", type="primary", disabled=not can_trigger_ai, key="rc_gen_btn"):
                        if not sels: 
                            st.error("Select at least one article.")
                        else:
                            arts = [amap[t] for t in sels]
                            with st.spinner("Synthesizing Intelligence..."):
                                md = build_custom_intel_report(arts, obj, session)
                                if md:
                                    now = datetime.now(LOCAL_TZ).strftime("%A, %B %d, %Y at %I:%M %p %Z")
                                    mr = f"# 🛡️ NOC Intelligence Report\n**Date:** {now}\n**Analyst:** {aname}\n**Contact:** {cinfo}\n\n---\n\n"
                                    if msys.strip(): 
                                        mr += f"## 🎯 Internal Systems (Manual Entry)\n{msys}\n\n---\n\n"
                                    
                                    mr += md
                                    mr += "\n\n---\n\n## 🔗 Intelligence Sources\n"
                                    for a in arts:
                                        mr += f"- **{a.source}**: [{a.title}]({a.link})\n"

                                    st.session_state.generated_report = mr
                                    st.success("Complete!")

                if st.session_state.generated_report:
                    st.divider()
                    with st.container(border=True): st.markdown(st.session_state.generated_report)
                    st.divider()
                    sv_t = st.text_input("Report Title", value=f"Report - {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}", key="rc_sv_t")
                    c_s1, c_s2, c_s3 = st.columns([1, 1, 1])
                    if c_s1.button("💾 Save to Library", use_container_width=True, key="rc_sv_btn"):
                        session.add(SavedReport(title=sv_t, author=st.session_state.current_user, content=st.session_state.generated_report))
                        session.commit(); st.success("Saved!")
                    c_s2.download_button("⬇️ Download (.md)", data=st.session_state.generated_report, file_name=f"{sv_t}.md", use_container_width=True, key="rc_dl_btn")
                    if c_s3.button("🗑️ Clear", type="secondary", use_container_width=True, key="rc_clr_btn"):
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
                            c_d1.download_button("⬇️ Download", data=r.content, file_name=f"{r.title}.md", use_container_width=True, key=f"dl_lib_{r.id}")
                            if st.session_state.current_user == r.author or st.session_state.current_role == "admin":
                                if c_d2.button("🗑️ Delete", use_container_width=True, key=f"del_lib_{r.id}"):
                                    session.delete(r); session.commit(); safe_rerun()
            tab_idx += 1

# ================= 5. SETTINGS & ADMIN =================
elif page == "⚙️ Settings & Admin":
    st.title("⚙️ Settings & Engine Room")
    tab_rss, tab_ml, tab_ai, tab_users, tab_danger = st.tabs(["📡 RSS Sources", "🧠 ML Training", "🤖 AI Engine", "👥 Users & Roles", "⚠️ Danger Zone"])
    
    with tab_rss:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Manage Keywords")
            with st.form("bulk_kw"):
                raw_text = st.text_area("Bulk Add Keywords (word, weight)", placeholder="infrastructure, 80", key="set_kw_bulk")
                if st.form_submit_button("Add Keywords"):
                    for line in raw_text.split('\n'):
                        if line.strip():
                            parts = line.split(',')
                            word = parts[0].strip().lower()
                            weight = int(parts[1].strip()) if len(parts) > 1 and parts[1].strip().isdigit() else 10
                            if not session.query(Keyword).filter_by(word=word).first(): session.add(Keyword(word=word, weight=weight))
                    session.commit()
                    safe_rerun()
            with st.expander("Active Keywords"):
                for k in session.query(Keyword).order_by(Keyword.weight.desc()).all():
                    c_a, c_b, c_c = st.columns([3, 1, 1])
                    c_a.code(k.word); c_b.write(f"**{k.weight}**")
                    if c_c.button("🗑️", key=f"del_kw_{k.id}"): session.delete(k); session.commit(); safe_rerun()

        with col2:
            st.subheader("Manage RSS Feeds")
            with st.form("bulk_feed"):
                raw_text_feeds = st.text_area("Bulk Add Feeds (URL, Name)", placeholder="https://site.com/feed, Tech News", key="set_feed_bulk")
                if st.form_submit_button("Add Sources"):
                    for line in raw_text_feeds.split('\n'):
                        if line.strip():
                            parts = line.split(',')
                            url = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else "New Feed"
                            if not session.query(FeedSource).filter_by(url=url).first(): session.add(FeedSource(url=url, name=name))
                    session.commit()
                    safe_rerun()
            with st.expander("Active Feeds"):
                for s in session.query(FeedSource).all():
                    st.text(s.name); st.caption(s.url)
                    if st.button("Delete", key=f"del_src_{s.id}"): session.delete(s); session.commit(); safe_rerun()
                        
    with tab_ml:
        st.subheader("Smart Filter Training")
        count_pos = session.query(Article).filter(Article.human_feedback == 2).count()
        count_neg = session.query(Article).filter(Article.human_feedback == 1).count()
        total = count_pos + count_neg
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Samples", total); c2.metric("Positives (Keep)", count_pos); c3.metric("Negatives (Dismiss)", count_neg)
        if st.button("🚀 Retrain Model Now", type="primary", disabled=not can_train, key="set_ml_retrain"):
            if total < 10: st.error("Not enough data! Please review at least 10 articles.")
            else:
                with st.spinner("Training neural pathways..."):
                    try: train(); st.success("Model retrained successfully!")
                    except Exception as e: st.error(f"Training failed: {e}")
        
    with tab_ai:
        st.subheader("Universal LLM Integration")
        config = session.query(SystemConfig).first() or SystemConfig()
        if not config.id: session.add(config); session.commit()
        with st.form("llm_config"):
            endpoint = st.text_input("Endpoint URL", value=config.llm_endpoint, key="set_llm_end")
            api_key = st.text_input("API Key", value=config.llm_api_key, type="password", key="set_llm_api")
            model_name = st.text_input("Model Name", value=config.llm_model_name, key="set_llm_mod")
            st.divider()
            current_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN"
            tech_stack_input = st.text_area("Internal Tech Stack", value=current_stack, height=100, key="set_llm_stack")
            is_active = st.checkbox("Enable AI Features", value=config.is_active, key="set_llm_active")
            if st.form_submit_button("Save AI Config"):
                config.llm_endpoint = endpoint; config.llm_api_key = api_key; config.llm_model_name = model_name
                config.tech_stack = tech_stack_input; config.is_active = is_active
                session.commit(); st.success("✅ AI Configuration Saved!"); time.sleep(1); safe_rerun()

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
                    if st.form_submit_button("Create User"):
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
                    if st.form_submit_button("Update Role"):
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
                    if st.form_submit_button("Create Role"):
                        if not new_role_name or not new_role_pages: st.error("Role name and at least one page required.")
                        elif session.query(Role).filter(Role.name == new_role_name).first(): st.error("Role name already exists.")
                        else:
                            session.add(Role(name=new_role_name, allowed_pages=new_role_pages, allowed_actions=new_role_actions))
                            session.commit(); st.success(f"Role '{new_role_name}' created!"); safe_rerun()

        with col_u2:
            with st.container(border=True):
                st.markdown("### Active Users")
                for u in session.query(User).all():
                    c_name, c_role, c_act = st.columns([3, 2, 1])
                    c_name.write(f"**{u.username}**"); c_role.caption(u.role.upper())
                    if u.username != st.session_state.current_user:
                        if c_act.button("🗑️", key=f"del_u_{u.id}"):
                            session.delete(u); session.commit(); safe_rerun()
                            
            with st.container(border=True):
                st.markdown("### 🔑 Force Reset Password")
                with st.form("admin_reset_pwd_form"):
                    target_user = st.selectbox("Select User", [u.username for u in session.query(User).all()])
                    force_new_pwd = st.text_input("New Password", type="password")
                    if st.form_submit_button("Reset Password"):
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
                        if c_act.button("🗑️", key=f"del_role_{r.id}"):
                            if session.query(User).filter(User.role == r.name).count() > 0: st.error("Users are assigned this role.")
                            else: session.delete(r); session.commit(); safe_rerun()

    with tab_danger:
        st.error("Database Maintenance & Irreversible Actions")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.write("**Routine Maintenance**")
            st.caption("Safely sweeps stale >48h alerts & >30-day intel.")
            if st.button("🧹 Run Garbage Collector", use_container_width=True, key="set_danger_gc"):
                with st.spinner("Purging stale data and vacuuming database..."):
                    from src.scheduler import run_database_maintenance
                    run_database_maintenance()
                    st.success("✅ Database swept and optimized!")
                    time.sleep(1)
                    safe_rerun()
                    
        with col2:
            st.write("**Clear History**")
            st.caption("Deletes all articles, keeping feeds/users.")
            if st.button("🗑️ Delete All Articles", use_container_width=True, key="set_danger_clear"):
                session.execute(text("TRUNCATE TABLE articles RESTART IDENTITY CASCADE;"))
                session.commit(); safe_rerun()
                
        with col3:
            st.write("**Factory Reset**")
            st.caption("Destroys all intel, keywords, and feeds.")
            if st.button("☢️ FULL RESET", use_container_width=True, key="set_danger_factory"):
                session.execute(text("TRUNCATE TABLE articles, feed_sources, keywords RESTART IDENTITY CASCADE;"))
                session.commit(); safe_rerun()

# This acts as the final cleanup for any run where a button IS NOT clicked.
session.close()