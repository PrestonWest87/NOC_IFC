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
from shapely.geometry import Point, shape 
import streamlit.components.v1 as components

# --- IMPORT SERVICES ONLY (No Database Models Allowed) ---
import src.services as svc
from src.database import init_db
from src.scheduler import fetch_feeds
from src.llm import generate_briefing, generate_bluf, analyze_cascading_impacts, cross_reference_cves, build_custom_intel_report, generate_feed_overview, generate_rolling_summary, generate_daily_fusion_report, call_llm

@st.cache_resource
def setup_database():
    init_db()
    return True

setup_database()
st.set_page_config(page_title="Intelligence Fusion Center", layout="wide")

LOCAL_TZ = ZoneInfo("America/Chicago")
cookie_controller = CookieController()

def safe_rerun():
    st.rerun()

# --- RATE LIMITING / DEBOUNCE HELPERS ---
def check_cooldown(key, cooldown_seconds=60):
    """Checks if a button was clicked recently to prevent spamming."""
    last_click = st.session_state.get(f"cooldown_{key}", 0)
    return (time.time() - last_click) < cooldown_seconds

def apply_cooldown(key):
    """Activates the cooldown timer for a specific button."""
    st.session_state[f"cooldown_{key}"] = time.time()

# --- DESCRIPTIVE RBAC CONSTANTS ---
ALL_POSSIBLE_PAGES = [
    "🌐 Operational Dashboard", 
    "📊 Executive Dashboard", 
    "📰 Daily Fusion Report",
    "📡 Threat Telemetry", 
    "🚨 Crime Intelligence",
    "🎯 Threat Hunting & IOCs",
    "⚡ AIOps RCA", 
    "📑 Report Center", 
    "⚙️ Settings & Admin"
]

ALL_POSSIBLE_ACTIONS = [
    "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score", 
    "Action: Trigger AI Functions", "Action: Manually Sync Data",
    "Action: Dispatch Exec Report",
    "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV", 
    "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Regional Grid",
    "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash", "Tab: Regional Grid -> Hazard Analytics", 
    "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log", 
    "Tab: Regional Grid -> Manage Locations", "Tab: Threat Hunting -> Global IOC Matrix", 
    "Tab: Threat Hunting -> Deep Hunt Builder", "Tab: AIOps RCA -> Active Board", 
    "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
    "Tab: Report Center -> Report Builder", "Tab: Report Center -> Shared Library",
    "Tab: Settings -> RSS Sources", "Tab: Settings -> ML Training", "Tab: Settings -> AI & SMTP", 
    "Tab: Settings -> Users & Roles", "Tab: Settings -> Backup & Restore", "Tab: Settings -> Danger Zone"
]

if "current_user" not in st.session_state:
    st.session_state.current_user = None
    st.session_state.current_role = None
    st.session_state.allowed_pages = []
    st.session_state.allowed_actions = []

# --- AUTHENTICATION & ADMIN OVERRIDE ---
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
            else:
                roles = svc.get_all_roles()
                role_obj = next((r for r in roles if r.name == user.role), None)
                if role_obj:
                    st.session_state.allowed_pages = [p if p != "⚡ AIOps RCA (Staging)" else "⚡ AIOps RCA" for p in role_obj.allowed_pages]
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
                user, token = svc.authenticate_user(username, password)
                if user:
                    cookie_controller.set("noc_session_token", token, max_age=30*86400)
                    st.session_state.current_user = user.username
                    st.session_state.current_role = user.role
                    time.sleep(0.5); safe_rerun()
                else: st.error("❌ Invalid credentials.")
    st.stop() 

# --- SESSION REFRESH ---
if st.session_state.current_role == "admin":
    st.session_state.allowed_pages = ALL_POSSIBLE_PAGES
    st.session_state.allowed_actions = ALL_POSSIBLE_ACTIONS
else:
    roles = svc.get_all_roles()
    role_obj = next((r for r in roles if r.name == st.session_state.current_role), None)
    if role_obj:
        st.session_state.allowed_pages = role_obj.allowed_pages
        st.session_state.allowed_actions = role_obj.allowed_actions or []

# Corrected Action Checks
can_pin = "Action: Pin Articles" in st.session_state.allowed_actions
can_train = "Action: Train ML Model" in st.session_state.allowed_actions
can_boost = "Action: Boost Threat Score" in st.session_state.allowed_actions
can_trigger_ai = "Action: Trigger AI Functions" in st.session_state.allowed_actions
can_sync = "Action: Manually Sync Data" in st.session_state.allowed_actions

current_user_obj = svc.get_user_by_username(st.session_state.current_user)
sys_config = svc.get_cached_config()
ai_enabled = sys_config.is_active if sys_config else False

st.markdown("""
    <style>
        .block-container { padding-top: 1rem; padding-bottom: 0rem; padding-left: 1rem; padding-right: 1rem; max-width: 100%; }
        h1 { font-size: 1.8rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }
        h2 { font-size: 1.4rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }
        h3 { font-size: 1.1rem !important; margin-bottom: 0rem !important; padding-bottom: 0rem !important; }
        [data-testid="stVerticalBlockBorderWrapper"] p, [data-testid="stVerticalBlockBorderWrapper"] li, [data-testid="stExpanderDetails"] p, [data-testid="stExpanderDetails"] li { font-size: 0.9rem !important; margin-bottom: 0.2rem !important; line-height: 1.3 !important; }
        hr { margin-top: 0.5rem; margin-bottom: 0.5rem; }
        .stButton>button { padding: 0rem 0.5rem !important; min-height: 2rem !important; }
    </style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
st.sidebar.title("NOC Fusion")
display_name = current_user_obj.full_name if current_user_obj and current_user_obj.full_name else st.session_state.current_user.capitalize()
display_title = current_user_obj.job_title if current_user_obj and current_user_obj.job_title else st.session_state.current_role.upper()
st.sidebar.markdown(f"👤 **{display_name}**\n\n<small>{display_title}</small>", unsafe_allow_html=True)

if st.sidebar.button("🚪 Log Out", width="stretch"):
    svc.logout_user(st.session_state.current_user)
    cookie_controller.remove("noc_session_token")
    st.session_state.current_user = None; st.session_state.current_role = None
    time.sleep(0.5); safe_rerun()

with st.sidebar.expander("📝 My Profile"):
    with st.form("my_profile_form"):
        new_fn = st.text_input("Full Name", value=current_user_obj.full_name or "")
        new_jt = st.text_input("Job Title", value=current_user_obj.job_title or "")
        new_ci = st.text_input("Contact Info", value=current_user_obj.contact_info or "")
        st.divider()
        old_pwd = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        if st.form_submit_button("Save Profile", width="stretch"):
            success, msg = svc.update_user_profile(st.session_state.current_user, new_fn, new_jt, new_ci, old_pwd, new_pwd)
            if success: st.success(msg); time.sleep(0.5); safe_rerun()
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

if page == "⚡ AIOps RCA":
    refresh_rate = st.sidebar.selectbox("🔴 RCA Live Sync", ["5 Seconds", "10 Seconds", "30 Seconds", "Paused"], index=0)
    rmap = {"5 Seconds": 5, "10 Seconds": 10, "30 Seconds": 30, "Paused": 0}
    current_refresh_sec = rmap[refresh_rate]
    if current_refresh_sec > 0: refresh_count = st_autorefresh(interval=current_refresh_sec * 1000)
elif page == "🌐 Operational Dashboard":
    refresh_rate = st.sidebar.selectbox("🔄 Dashboard Refresh", ["Off", "1 Minute", "2 Minutes", "5 Minutes"], index=2)
    rmap = {"Off": 0, "1 Minute": 60, "2 Minutes": 120, "5 Minutes": 300}
    current_refresh_sec = rmap[refresh_rate]
    if current_refresh_sec > 0: refresh_count = st_autorefresh(interval=current_refresh_sec * 1000)

def format_local_time(utc_dt): return utc_dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S') if utc_dt else "Unknown"
def get_score_badge(score): return f"🔴 **[{int(score)}]**" if score >= 80 else f"🟠 **[{int(score)}]**" if score >= 50 else f"🔵 **[{int(score)}]**"
def get_cat_icon(cat): 
    icons = {
        "Cyber: Exploits & Vulns": "🪲", "Cyber: Malware & Threats": "👾",
        "ICS/OT & SCADA": "🏭", "Cloud & IT Infra": "☁️",
        "Physical Security": "🚨", "Severe Weather": "🌪️",
        "Geopolitics & Policy": "🌍", "AI & Emerging Tech": "🤖",
        "General": "📰"
    }
    return icons.get(cat, "📰")

def render_article_feed(feed_articles, key_prefix=""):
    if not feed_articles: st.success("Queue is empty."); return
    for art in feed_articles:
        with st.container(border=True):
            c_title, c_score = st.columns([4, 1])
            c_title.markdown(f"**{get_score_badge(art.score)} [{art.title}]({art.link})**")
            c_title.caption(f"📅 {format_local_time(art.published_date)} | 📡 {art.source} | {get_cat_icon(art.category)} {art.category}")
            if art.ai_bluf: st.success(f"**AI BLUF:** {art.ai_bluf}")
            else: st.caption(art.summary[:250] + "..." if art.summary else "No summary.")
                
            c1, c2, c3, c4, c5 = st.columns(5)
            if c1.button("📍 Unpin" if art.is_pinned else "📌 Pin", key=f"{key_prefix}pin_{art.id}", disabled=not can_pin): svc.toggle_pin(art.id); safe_rerun()
            if c2.button("⏫ +15 Score", key=f"{key_prefix}boost_{art.id}", disabled=not can_boost): svc.boost_score(art.id, 15); safe_rerun()
            
            # --- RESTORED ML BUTTONS ---
            if c3.button("🧠 Keep", key=f"{key_prefix}keep_{art.id}", disabled=not can_train): svc.change_status(art.id, 2); safe_rerun()
            if c4.button("🧠 Dismiss", key=f"{key_prefix}dism_{art.id}", disabled=not can_train): svc.change_status(art.id, 1); safe_rerun()
            
            if ai_enabled and not art.ai_bluf:
                is_ai_cooling = check_cooldown(f"bluf_{art.id}", 30)
                if c5.button("⏳ Generating..." if is_ai_cooling else "🤖 BLUF", key=f"{key_prefix}bluf_{art.id}", disabled=not can_trigger_ai or is_ai_cooling):
                    apply_cooldown(f"bluf_{art.id}")
                    with st.spinner("Analyzing..."):
                        b = generate_bluf(art, svc.SessionLocal())
                        if b: svc.save_ai_bluf(art.id, b); safe_rerun()

# ================= 1. OPERATIONAL DASHBOARD =================
if page == "🌐 Operational Dashboard":
    st.title("🌐 Operational Dashboard")
    metrics = svc.get_dashboard_metrics()
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
            for art in svc.get_pinned_articles():
                st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small>📡 {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)
                if art.ai_bluf: st.success(f"**AI BLUF:** {art.ai_bluf}")
                st.write("")
        with col_rss:
            st.subheader("🚨 Live Feed (Top 15)")
            for art in svc.get_live_articles():
                st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small>📡 {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)

    elif selected_panel == "🛡️ Infrastructure Status":
        col_cve, col_cld, col_reg = st.columns(3)
        with col_cve:
            st.subheader("🪲 CISA KEVs (Top 15)")
            for cve in svc.get_cves(limit=15):
                st.markdown(f"🚨 **[{cve.cve_id}](https://nvd.nist.gov/vuln/detail/{cve.cve_id})**<br><small>{cve.vendor} {cve.product}</small>", unsafe_allow_html=True)
        with col_cld:
            st.subheader("☁️ Active Cloud Outages")
            outages = svc.get_cloud_outages(active_only=True, limit=5)
            if not outages: st.success("Clear.")
            for out in outages: st.markdown(f"🚨 **{out.provider}**<br><small>[{out.title}]({out.link})</small>", unsafe_allow_html=True)
        with col_reg:
            st.subheader("🌪️ Regional Hazards")
            hazards = svc.get_hazards(limit=15)
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
                        ns = generate_rolling_summary(svc.SessionLocal())
                        if ns: svc.save_global_config({"rolling_summary": ns, "rolling_summary_time": now})
                c_time, c_btn = st.columns([3, 2])
                c_time.caption(f"Last Sync: {format_local_time(sys_config.rolling_summary_time)}")
                
                is_ai_refresh_cooling = check_cooldown("ai_refresh", 120)
                if c_btn.button("⏳ Generating..." if is_ai_refresh_cooling else "🔄 Force Refresh Briefing", width="stretch", disabled=not can_trigger_ai or is_ai_refresh_cooling):
                    apply_cooldown("ai_refresh")
                    with st.spinner("🤖 Forcing AI Summary..."):
                        ns = generate_rolling_summary(svc.SessionLocal())
                        if ns: svc.save_global_config({"rolling_summary": ns, "rolling_summary_time": datetime.utcnow()}); safe_rerun()
                st.info(sys_config.rolling_summary if sys_config.rolling_summary else "Initializing...")
            else: st.info("AI Disabled.")
            
        with col_ai2:
            st.subheader("🤖 Security Auditor")
            is_scan_cooling = check_cooldown("ai_scan", 60)
            if st.button("⏳ Scanning..." if is_scan_cooling else "Scan Stack Against 30-Day KEVs", width="stretch", disabled=not can_trigger_ai or is_scan_cooling):
                apply_cooldown("ai_scan")
                with st.spinner("Scanning..."):
                    from src.database import CveItem
                    with svc.SessionLocal() as dbtmp:
                        cves = dbtmp.query(CveItem).filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30)).all()
                        res = cross_reference_cves(cves, dbtmp)
                    if res and ("clear" in res.lower() or "no active" in res.lower()): st.success("✅ " + res)
                    else: st.error(f"⚠️ **MATCH DETECTED:**\n{res}")


# ================= 2. DAILY FUSION REPORT =================
elif page == "📰 Daily Fusion Report":
    st.title("📰 Daily Master Fusion Report")
    st.markdown("AI-synthesized situational report covering Cyber, Vulnerabilities, Physical Hazards, and Cloud Infrastructure.")
    
    yesterday_local = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_str = yesterday_local.strftime('%Y-%m-%d')
    all_reports = svc.get_all_daily_briefings()
    has_yesterday = any(r.report_date.strftime('%Y-%m-%d') == yesterday_str for r in all_reports)
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        if not has_yesterday:
            is_report_cooling = check_cooldown("gen_report", 300) 
            if st.button("⏳ Compiling Data..." if is_report_cooling else "🤖 Generate Yesterday's Report", width="stretch", type="primary", disabled=not can_trigger_ai or is_report_cooling):
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
            st.success("✅ Latest report is ready for review.")

    st.divider()
    
    if not all_reports:
        st.info("No historical reports found. Click the generation button above to synthesize your first shift briefing.")
    else:
        report_options = {r.report_date.strftime('%A, %B %d, %Y'): r for r in all_reports}
        c_sel, c_space = st.columns([2, 3])
        selected_date = c_sel.selectbox(
            "📅 Select Historical Briefing", 
            options=list(report_options.keys()), 
            index=0
        )
        selected_report = report_options[selected_date]
        
        with st.container(border=True): 
            st.markdown(selected_report.content)
            
        st.divider()
        st.subheader("📧 Broadcast Report")
        st.caption("Send this report via email. Markdown formatting will be natively converted to HTML and emojis will be preserved.")
        
        c_em1, c_em2 = st.columns([3, 1])
        default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
        report_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="report_recip")
        
        if c_em2.button("✉️ Transmit Report", type="primary", use_container_width=True):
            if not report_recipients:
                st.error("Please enter at least one recipient email.")
            else:
                with st.spinner("Converting formatting and transmitting report..."):
                    # Offloaded HTML Processing to services.py
                    formatted_html = svc.generate_daily_report_email_html(selected_date, selected_report.content)
                    
                    from src.mailer import send_alert_email
                    success, msg = send_alert_email(f"Daily Fusion Report - {selected_date}", formatted_html, recipient_override=report_recipients, is_html=True)
                    
                    if success: st.success("✅ Report successfully transmitted!")
                    else: st.error(f"❌ SMTP Error: {msg}")

# ================= NEW: EXECUTIVE DASHBOARD =================
elif page == "📊 Executive Dashboard":
    st.title("📊 Executive Grid Threat Matrix")
    st.caption("Real-time synthesis of Physical, Cyber, and Crime telemetry for Bulk Electric System (BES) infrastructure.")
    
    active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", [])) if 'ar_warn' in locals() else 0
    crime_data = svc.get_recent_crimes()
    
    # Pass the actual list of crimes to the engine
    intel = svc.get_executive_grid_intel(active_nws, crime_data)
    
    risk_color = "red" if intel['unified_risk'] == "HIGH" else "orange" if intel['unified_risk'] == "MEDIUM" else "green"
    
    st.markdown(f"""
    <div style='text-align: center; padding: 20px; background-color: #1e1e1e; border-radius: 10px; border: 2px solid {risk_color}; margin-bottom: 30px;'>
        <h3 style='margin:0; color: #a0a0a0;'>UNIFIED THREAT POSTURE</h3>
        <h1 style='margin:0; font-size: 3rem; color: {risk_color};'>{intel['unified_risk']}</h1>
        <p style='margin:0; color: #a0a0a0;'>Last Updated: {intel['timestamp']}</p>
    </div>
    """, unsafe_allow_html=True)

    col_phys, col_cyber = st.columns(2)
    with col_phys:
        st.subheader("⚡ Physical & Perimeter (1 Mile)")
        st.info(f"**Risk Level: {intel['physical_score']}**")
        st.write(intel['physical_brief'])
        
        # EXPLICITLY LIST THE 1-MILE INCIDENTS
        if intel["recent_crimes"]:
            st.markdown("**🚨 Recent Perimeter Incidents:**")
            for c in intel["recent_crimes"][:5]: # Show top 5 to save space
                icon = "🔴" if c['severity'] == "High" else "🟠"
                st.caption(f"{icon} **{c['raw_title']}** ({c['distance_miles']} mi away) - *{c['timestamp']}*")
            if len(intel["recent_crimes"]) > 5:
                st.caption(f"...and {len(intel['recent_crimes']) - 5} more (See Crime Intel tab).")
        
    with col_cyber:
        st.subheader("🛡️ Cyber & SCADA (48 Hours)")
        st.warning(f"**Risk Level: {intel['cyber_score']}**")
        st.write(intel['cyber_brief'])
        
    st.divider()
    
    st.subheader("📤 Dispatch Intelligence Report")
    col_email, col_btn = st.columns([3, 1])
    default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
    target_email = col_email.text_input("Recipient Email Address", value=default_email, label_visibility="collapsed")
    
    can_dispatch = "Action: Dispatch Exec Report" in st.session_state.allowed_actions
    if col_btn.button("📧 Send Outlook HTML Report", use_container_width=True, type="primary", disabled=not can_dispatch):
        if target_email:
            with st.spinner("Compiling and transmitting..."):
                success, msg = svc.send_executive_report(target_email, intel, sys_config)
                if success: st.success(f"Report dispatched to {target_email}")
                else: st.error(msg)
        else:
            st.warning("Please enter a recipient email address.")

    st.divider()
    with st.expander("🗄️ Intelligence Sources & Telemetry Feeds", expanded=True):
        
        st.markdown("**🛡️ CISA ICS-CERT Advisories (Last 14 Days):**")
        if intel.get("ics_advisories"):
            for adv in intel["ics_advisories"]:
                icon = "🚨 **[CRITICAL VENDOR]**" if adv["is_critical"] else "⚠️"
                st.markdown(f"- {icon} [{adv['title']}]({adv['link']}) *(Pub: {adv['published']})*")
        else:
            st.markdown("*No active ICS-CERT advisories in the reporting window.*")
        
        st.markdown("---")
            
        st.markdown("**🌐 General Cyber OSINT (48-Hour Filtered Pipeline):**")
        if intel.get("cyber_articles"):
            for a in intel["cyber_articles"]:
                st.markdown(f"- **[{int(a['score'])}]** [{a['title']}]({a['link']}) *(Source: {a['source']})*")
        else:
            st.markdown("*No active high-priority general cyber articles in the last 48h.*")
            
        st.markdown("---")
        
        # --- UPDATED LOCAL PHYSICAL OSINT BLOCK ---
        st.markdown("**⚡ Local Physical & Geopolitical OSINT (48-Hour Filtered):**")
        if intel.get("phys_articles"):
            for a in intel["phys_articles"]:
                st.markdown(f"- 🚨 **[{int(a['score'])}]** [{a['title']}]({a['link']}) *(Source: {a['source']})*")
        else:
            st.markdown("*No Arkansas-specific infrastructure or physical threat articles detected in the last 48h.*")
            
        st.markdown("""
        **⚡ Utility Baseline Telemetry:**
        * **NWS:** National Weather Service (Severe Weather).
        * **Crime:** LRPD Open Data API (Geofenced Perimeter).
        """)
# ================= NEW: CRIME INTELLIGENCE =================
elif page == "🚨 Crime Intelligence":
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("🚨 Perimeter Crime Telemetry")
        st.caption("LRPD incident aggregation geofenced to 1-Mile radius around HQ.")
    
    with col2:
        st.write("") # Padding
        if st.button("🔄 Force Fetch LRPD", use_container_width=True):
            with st.spinner("Polling Little Rock Data Gov..."):
                if svc.force_fetch_crime_data():
                    st.success("Sync Complete!")
                    st.rerun() # Refresh the map with new data
                else:
                    st.error("Fetch Failed. Check Logs.")

    crime_data = svc.get_recent_crimes()
    
    if not crime_data:
        st.success("✅ No crime incidents logged within 1 mile of HQ in the last 7 days.")
    else:
        df_crimes = pd.DataFrame(crime_data)
        
        # SAFETY CHECK: Ensure coordinates exist before feeding to PyDeck
        if "lat" not in df_crimes.columns or "lon" not in df_crimes.columns:
            st.error("🚨 Coordinate data missing from cache! Please run `python src/crime_worker.py` in your terminal to fetch fresh geometry.")
        else:
            # Drop any random null coordinates
            df_crimes = df_crimes.dropna(subset=['lat', 'lon'])
            
            # Map Rendering - Offloaded to services.py
            layers, view_state = svc.build_crime_map_layers(df_crimes)
            
            st.pydeck_chart(pdk.Deck(
                layers=layers, 
                initial_view_state=view_state, 
                tooltip={"html": "<b>{raw_title}</b><br/>{timestamp}<br/>Dist: {distance_miles} miles"}
            ), use_container_width=True)
            
            st.divider()
            st.pydeck_chart(pdk.Deck(
                initial_view_state=pdk.ViewState(
                    latitude=34.6755, # Recentered slightly for the new polygon
                    longitude=-92.3235, 
                    zoom=15.5, # Tighter zoom for the specific campus footprint
                    pitch=45 
                ),
                layers=[
                    # Campus Perimeter Layer
                    pdk.Layer(
                        "PolygonLayer",
                        polygon_df,
                        get_polygon="coordinates",
                        get_fill_color=[0, 255, 100, 45], # Subtle green tint
                        get_line_color=[0, 255, 100, 255], # Solid green border
                        line_width_min_pixels=2,
                        stroked=True,
                        filled=True,
                    ),
                    # Crime Incident Points
                    pdk.Layer(
                        "ScatterplotLayer",
                        data=df_crimes,
                        get_position="[lon, lat]",
                        get_radius=50, # Smaller radius since we are zoomed in tighter
                        get_fill_color=[255, 69, 0, 220],
                        pickable=True,
                        auto_highlight=True
                    )
                ],
                tooltip={"html": "<b>{raw_title}</b><br/>{timestamp}<br/>Dist: {distance_miles} miles"}
            ), use_container_width=True)
            
            st.divider()
            st.subheader("Raw Incident Logs (1 Mile Radius)")
            display_crimes = df_crimes[["timestamp", "distance_miles", "category", "severity", "raw_title"]]
            st.dataframe(display_crimes, use_container_width=True, hide_index=True)
            
# ================= 3. THREAT TELEMETRY =================
elif page == "📡 Threat Telemetry":
    st.title("📡 Unified Threat Telemetry")
    tt_tab_names = []
    
    if "Tab: Threat Telemetry -> RSS Triage" in st.session_state.allowed_actions: tt_tab_names.append("📰 RSS Triage")
    if "Tab: Threat Telemetry -> CISA KEV" in st.session_state.allowed_actions: tt_tab_names.append("🪲 Exploits (KEV)")
    if "Tab: Threat Telemetry -> Cloud Services" in st.session_state.allowed_actions: tt_tab_names.append("☁️ Cloud Services")
    if "Tab: Threat Telemetry -> Regional Grid" in st.session_state.allowed_actions: tt_tab_names.append("🗺️ Regional Grid")
    
    if not tt_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        tabs = st.tabs(tt_tab_names)
        tab_idx = 0
        
        if "Tab: Threat Telemetry -> RSS Triage" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col_title, col_btn = st.columns([3, 1])
                is_rss_cooling = check_cooldown("sync_rss", 60)
                if col_btn.button("⏳ Syncing..." if is_rss_cooling else "🔄 Force Fetch Feeds", width="stretch", disabled=not can_sync or is_rss_cooling):
                    apply_cooldown("sync_rss")
                    with st.spinner("Fetching feeds..."):
                        fetch_feeds(source="User Force")
                        time.sleep(1)
                        safe_rerun()
                cat_filter = st.selectbox("🎯 Filter Active Feeds", [
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
                        if c1.button("⬅️ Previous", key=f"p_{feed_id}_{loc}", disabled=(cur_page<=1), width="stretch"): st.session_state[s_key] -= 1; safe_rerun()
                        c2.markdown(f"<div style='text-align: center; margin-top: 0.4rem;'><b>Page {cur_page} of {t_pages}</b> <span style='font-size: 0.85em; color: gray;'>(Total: {t_items})</span></div>", unsafe_allow_html=True)
                        if c3.button("Next ➡️", key=f"n_{feed_id}_{loc}", disabled=(cur_page>=t_pages), width="stretch"): st.session_state[s_key] += 1; safe_rerun()

                    if t_items > pg_size: p_ctrls("top"); st.divider()
                    elif t_items == 0: st.info("No articles found."); return
                    render_article_feed(items, key_prefix=f"{feed_id}_")
                    if t_items > pg_size: st.divider(); p_ctrls("bot")

                s1, s2, s3, s4 = st.tabs(["📌 Pinned", "📡 Live", "📉 Low", "🔍 Search"])
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
                if st.button("⏳ Syncing..." if is_kev_cooling else "🔄 Sync CISA KEV", disabled=not can_sync or is_kev_cooling, width="stretch"):
                    apply_cooldown("sync_kev")
                    with st.spinner("Fetching CISA Database..."):
                        from src.cve_worker import fetch_cisa_kev; fetch_cisa_kev(); safe_rerun()
                for cve in svc.get_cves(limit=50, days_back=30):
                    with st.expander(f"🚨 {cve.cve_id} | {cve.vendor} {cve.product}"): st.markdown(f"**{cve.vulnerability_name}**\n\n{cve.description}")
            tab_idx += 1
            
        if "Tab: Threat Telemetry -> Cloud Services" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                is_cloud_cooling = check_cooldown("sync_cloud", 60)
                if st.button("⏳ Syncing..." if is_cloud_cooling else "🔄 Sync Cloud Status", disabled=not can_sync or is_cloud_cooling, width="stretch"):
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
                    
                    if is_maint and not is_active and not any(fmt in text for fmt in today_fmts):
                        continue 
                    
                    active_outages.append(o)

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
                    all_recent_outages = svc.get_cloud_outages(active_only=False, limit=100)
                    resolved_outages = [o for o in all_recent_outages if o.is_resolved]
                    
                    if not resolved_outages:
                        st.info("No recently resolved incidents.")
                    for o in resolved_outages:
                        st.markdown(f"✅ **{o.provider}** | {o.service} <br><small>[{o.title}]({o.link})</small>", unsafe_allow_html=True)
            tab_idx += 1
            
        if "Tab: Threat Telemetry -> Regional Grid" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col_sync1, col_sync2 = st.columns([3, 1])
                is_infra_cooling = check_cooldown("sync_infra", 60)
                if col_sync2.button("⏳ Syncing..." if is_infra_cooling else "🔄 Sync Regional Telemetry", disabled=not can_sync or is_infra_cooling, key="tt_sync_infra", width="stretch"):
                    apply_cooldown("sync_infra")
                    with st.spinner("Pulling Radar & Calculating Geospatial Intersections..."):
                        from src.infra_worker import fetch_regional_hazards
                        fetch_regional_hazards()
                        time.sleep(1)
                        svc.get_cached_geojson.clear()
                        safe_rerun()
                
                locs = svc.get_cached_locations()
                df = pd.DataFrame([{
                    "id": l.id, "Name": l.name, "Type": l.loc_type, 
                    "Priority": l.priority, "Risk": l.current_spc_risk, 
                    "Lat": l.lat, "Lon": l.lon
                } for l in locs]) if locs else pd.DataFrame()
                
                spc_data, ar_data, oos_data = svc.get_cached_geojson()
                
                active_event_types = set()
                for geo_dataset in [ar_data, oos_data]:
                    if geo_dataset:
                        for f in geo_dataset.get("features", []):
                            active_event_types.add(f.get("properties", {}).get("event", "Unknown"))
                active_event_types = sorted(list(active_event_types))

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
                        
                        # --- FIRE DESK CONTROLS ---
                        st.divider()
                        show_fire_risk = st.toggle("🔥 NWS Fire Weather & Red Flags", value=False)
                        show_active_wildfires = st.toggle("🚒 Active Wildfires (NIFC)", value=False)
                        
                        # Dynamic Fire Legend
                        if show_fire_risk or show_active_wildfires:
                            with st.container(border=True):
                                st.markdown("**🔥 Fire Desk Legend:**")
                                if show_fire_risk:
                                    st.markdown("🔴 **Red Flag Warning** *(Extreme/Burn Ban)*")
                                    st.markdown("🟠 **Fire Weather Watch** *(High Risk)*")
                                if show_active_wildfires:
                                    st.markdown("🚨 **Active Wildfire** *(Scales by Acreage)*")
                        # ------------------------------------
                    
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

                with main_panel:
                    rg_tab_names = []
                    if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions: rg_tab_names.append("🗺️ Geospatial Overlay")
                    if "Tab: Regional Grid -> Executive Dash" in st.session_state.allowed_actions: rg_tab_names.append("📊 Executive Dashboard")
                    if "Tab: Regional Grid -> Hazard Analytics" in st.session_state.allowed_actions: rg_tab_names.append("🌪️ Deep Hazard Analytics")
                    if "Tab: Regional Grid -> Location Matrix" in st.session_state.allowed_actions: rg_tab_names.append("🗄️ Location Matrix")
                    if "Tab: Regional Grid -> Weather Alerts Log" in st.session_state.allowed_actions: rg_tab_names.append("📜 Weather Alerts Log")
                    if "Tab: Regional Grid -> Manage Locations" in st.session_state.allowed_actions: rg_tab_names.append("📍 Manage Locations")

                    if not rg_tab_names:
                        st.warning("You do not have permission to view any modules within the Regional Grid.")
                    else:
                        rg_tabs = st.tabs(rg_tab_names)
                        rg_idx = 0

                        master_polygons = []
                        toggled_polygons = []
                        layers = []
                        layer_id = str(uuid.uuid4())[:6]

                        if show_radar_overlay:
                            layers.append(pdk.Layer("TileLayer", data=["https://mesonet.agron.iastate.edu/cache/tile.py/1.0.0/nexrad-n0q-900913/{z}/{x}/{y}.png"], opacity=0.6, pickable=False))

                        # 1. PROCESS SPC DATA
                        spc_micro_collection = {"type": "FeatureCollection", "features": []}
                        if spc_data:
                            color_map = {"TSTM": [192, 232, 192, 100], "MRGL": [124, 205, 124, 150], "SLGT": [246, 246, 123, 150], "ENH": [230, 153, 0, 150], "MDT": [255, 0, 0, 150], "HIGH": [255, 0, 255, 150]}
                            
                            for f in spc_data.get('features', []):
                                label = f.get('properties', {}).get('LABEL', '')
                                try:
                                    poly_shape = shape(f.get("geometry"))
                                    poly_dict = {"event": f"SPC: {label}", "shape": poly_shape, "severity": "Watch"}
                                    master_polygons.append(poly_dict)
                                    if show_spc: toggled_polygons.append(poly_dict)
                                    
                                    micro_feature = {
                                        "type": "Feature",
                                        "geometry": f.get("geometry"),
                                        "properties": {
                                            "fill_color": color_map.get(label, [0, 0, 0, 0]),
                                            "line_color": [0, 0, 0, 255],
                                            "info": f"SPC Risk: {label}"
                                        }
                                    }
                                    spc_micro_collection["features"].append(micro_feature)
                                except Exception: pass
                            
                            if show_spc and spc_micro_collection["features"]:
                                layers.append(pdk.Layer("GeoJsonLayer", spc_micro_collection, id=f"spc_layer_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=1))

                        # 2. PROCESS NWS ALERTS
                        ar_warn, ar_watch, ar_zonewide, ar_logs = svc.process_nws_alerts(ar_data, selected_events, is_oos=False)
                        oos_warn, oos_watch, oos_zonewide, oos_logs = svc.process_nws_alerts(oos_data, selected_events, is_oos=True)

                        all_zonewide = (ar_zonewide or []) + (oos_zonewide or [])
                        map_diagnostics = ar_logs + oos_logs

                        for f in ar_warn["features"] + ar_watch["features"] + oos_warn["features"] + oos_watch["features"]:
                            master_polygons.append({"event": f['properties']['info'], "shape": f['properties']['shapely_obj'], "severity": f['properties']['severity']})
                            is_oos_feature = "[OOS]" in f['properties']['info']
                            is_severe_feature = f['properties']['severity'] == "Warning"
                            if (is_oos_feature and show_oos) or (not is_oos_feature and is_severe_feature and show_warn) or (not is_oos_feature and not is_severe_feature and show_watch):
                                toggled_polygons.append({"event": f['properties']['info'], "shape": f['properties']['shapely_obj'], "severity": f['properties']['severity']})
                            f['properties'].pop('shapely_obj', None)

                        # --- NWS FIRE WEATHER POLYGONS ---
                        if show_fire_risk:
                            ar_fire_geo = {"type": "FeatureCollection", "features": []}
                            ar_counties = svc.get_ar_counties_mapping()
                            
                            fire_events = {}
                            for geo_ds in [ar_data, oos_data]:
                                if geo_ds:
                                    for f in geo_ds.get('features', []):
                                        event = f.get('properties', {}).get('event', '')
                                        area_desc = f.get('properties', {}).get('areaDesc', '')
                                        
                                        if any(k in event for k in ["Fire Weather", "Red Flag", "Fire Warning", "Extreme Fire"]):
                                            severity = "Extreme (Burn Ban / Red Flag)" if "Red Flag" in event or "Warning" in event else "High (Fire Weather Watch)"
                                            fill_color = [139, 0, 0, 160] if "Red Flag" in event or "Warning" in event else [255, 140, 0, 120]
                                            line_color = [255, 0, 0, 255] if "Red Flag" in event or "Warning" in event else [255, 140, 0, 255]
                                            
                                            counties = [c.strip().lower().replace(" county", "").replace(" parish", "") for c in re.split(r'[;,]', area_desc)]
                                            for c in counties:
                                                fire_events[c] = {"severity": severity, "color": fill_color, "line_color": line_color, "event": event}

                            for c_name, geom in ar_counties.items():
                                if c_name in fire_events:
                                    info = fire_events[c_name]
                                    feature = {
                                        "type": "Feature",
                                        "geometry": geom,
                                        "properties": {
                                            "info": f"{c_name.title()} County\nRisk Level: {info['severity']}\nNWS Alert: {info['event']}",
                                            "fill_color": info["color"],
                                            "line_color": info["line_color"]
                                        }
                                    }
                                    ar_fire_geo["features"].append(feature)
                                    
                                    try:
                                        poly_dict = {"event": f"Wildfire Risk: {info['event']}", "shape": shape(geom), "severity": "High"}
                                        master_polygons.append(poly_dict)
                                        toggled_polygons.append(poly_dict)
                                    except: pass

                            if ar_fire_geo["features"]:
                                layers.append(pdk.Layer(
                                    "GeoJsonLayer", 
                                    data=ar_fire_geo, 
                                    id=f"fire_risk_layer_{layer_id}", 
                                    pickable=True, 
                                    stroked=True, 
                                    filled=True, 
                                    get_fill_color="properties.fill_color", 
                                    get_line_color="properties.line_color", 
                                    line_width_min_pixels=2
                                ))
                        # ------------------------------------

                        # Render Standard NWS layers
                        if show_warn and ar_warn["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=ar_warn, id=f"ar_warn_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
                        if show_watch and ar_watch["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=ar_watch, id=f"ar_watch_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
                        if show_oos and oos_warn["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=oos_warn, id=f"oos_warn_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))
                        if show_oos and oos_watch["features"]: layers.append(pdk.Layer("GeoJsonLayer", data=oos_watch, id=f"oos_watch_{layer_id}", pickable=True, stroked=True, filled=True, get_fill_color="properties.fill_color", get_line_color="properties.line_color", line_width_min_pixels=2))

                        # --- NEW: NIFC ACTIVE WILDFIRES ---
                        if show_active_wildfires:
                            nifc_data = svc.get_active_wildfires()
                            if nifc_data:
                                df_fires = pd.DataFrame(nifc_data)
                                df_fires['info'] = "🔥 " + df_fires['name'] + " (" + df_fires['state'] + ")\nAcres: " + df_fires['acres'].astype(str) + "\nContainment: " + df_fires['contained'].astype(str) + "%"
                                
                                layers.append(pdk.Layer(
                                    "ScatterplotLayer",
                                    data=df_fires,
                                    id=f"nifc_active_fires_{layer_id}",
                                    pickable=True,
                                    opacity=0.9,
                                    stroked=True,
                                    filled=True,
                                    get_radius="1500 + (acres * 15)", # Radius scales up as the fire grows
                                    radius_min_pixels=5,
                                    radius_max_pixels=35,
                                    line_width_min_pixels=1,
                                    get_position="[lon, lat]",
                                    get_fill_color="color",
                                    get_line_color=[0, 0, 0, 255]
                                ))
                                
                                # Add exact fire points (with a 2-mile buffer) into the Site Hazard Matrix
                                for _, row in df_fires.iterrows():
                                    try:
                                        fire_poly = Point(row['lon'], row['lat']).buffer(0.03)
                                        poly_dict = {"event": f"Active Wildfire: {row['name']}", "shape": fire_poly, "severity": "High"}
                                        master_polygons.append(poly_dict)
                                        toggled_polygons.append(poly_dict)
                                    except: pass
                        # ------------------------------------

                        
                        # 3. CALCULATE INTERSECTIONS 
                        toggled_affected_sites, master_affected_sites = svc.calculate_site_intersections(map_df, toggled_polygons)

                        # --- RENDER ROLE-GATED TABS ---
                        if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions:
                            with rg_tabs[rg_idx]:
                                if not map_df.empty:
                                    layers.append(pdk.Layer("ScatterplotLayer", map_df, pickable=True, opacity=0.9, stroked=True, filled=True, radius_scale=6, radius_min_pixels=4, radius_max_pixels=12, line_width_min_pixels=1, get_position="[Lon, Lat]", get_fill_color=[255, 255, 255], get_line_color=[0, 0, 0]))
                                
                                if show_radar_panel: c_map_main, c_map_side = st.columns([2, 1])
                                else: c_map_main, c_map_side = st.columns([1, 0.0001])
                                    
                                with c_map_main:
                                    st.subheader("Live Threat Overlay")
                                    view_state = pdk.ViewState(latitude=34.8, longitude=-92.2, zoom=5.5, pitch=0)
                                    st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{info}"}), width="stretch")
                                    
                                if show_radar_panel:
                                    with c_map_side:
                                        st.subheader("Precipitation Loop")
                                        components.html("""<iframe src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" width="100%" height="500" frameborder="0" style="border-radius: 8px;" allowfullscreen></iframe>""", height=500)
                                    
                                st.divider()
                                
                                with st.expander("🛠️ Map Diagnostics & Parsing Logs"):
                                    for log_msg in map_diagnostics: st.text(log_msg)
                                
                                st.subheader("⚠️ Sites Impacted by Currently Toggled Layers")
                                st.caption("This table dynamically updates based on the layer switches and filters in the left sidebar.")
                                if not toggled_affected_sites: st.success("✅ No sites intersect with the specific layers and hazard types currently rendered on the map.")
                                else: st.dataframe(pd.DataFrame(toggled_affected_sites).sort_values(by=['Priority', 'Monitored Site']), hide_index=True, width="stretch")
                            rg_idx += 1

                        if "Tab: Regional Grid -> Executive Dash" in st.session_state.allowed_actions:
                            with rg_tabs[rg_idx]:
                                st.subheader("📊 Infrastructure Threat Dashboard")
                                
                                if map_df.empty:
                                    st.info("No monitored locations match current filters.")
                                else:
                                    # Fetch pre-calculated analytics from the service layer
                                    analytics = svc.get_infrastructure_analytics(map_df.copy())
                                    
                                    st.download_button(
                                        label="📥 Export Infrastructure Risk Report (CSV)",
                                        data=map_df.sort_values(by=['Risk', 'Priority']).to_csv(index=False).encode('utf-8'),
                                        file_name=f"Infrastructure_Risk_{datetime.now(LOCAL_TZ).strftime('%Y%m%d_%H%M')}.csv",
                                        mime='text/csv', width="stretch"
                                    )
                                    st.divider()
                                    
                                    # Top Level Metrics
                                    c_m1, c_m2, c_m3 = st.columns(3)
                                    c_m1.metric("Total Tracked Sites", len(map_df))
                                    c_m2.metric("Sites in Active Risk Areas", analytics["at_risk_sites"])
                                    c_m3.metric("Highest Current Risk", analytics["highest_risk"])
                                    st.write("")
                                    
                                    # The Pretty Bar Charts
                                    c1, c2, c3 = st.columns(3)
                                    with c1:
                                        st.markdown("**Sites by Risk Level**")
                                        if not analytics["risk_distribution"].empty:
                                            st.bar_chart(analytics["risk_distribution"], color="#ff4b4b", width="stretch")
                                        else: st.success("All clear.")
                                    with c2:
                                        st.markdown("**Sites by Regional Zone**")
                                        st.bar_chart(analytics["region_distribution"], color="#28a745", width="stretch")
                                    with c3:
                                        st.markdown("**Sites by Facility Type**")
                                        st.bar_chart(analytics["type_distribution"], color="#1f77b4", width="stretch")

                                    st.divider()
                                    
                                    # The Deep Data Cuts
                                    st.markdown("### 🧮 Advanced Data Intersections")
                                    cx1, cx2, cx3 = st.columns(3)
                                    with cx1:
                                        st.markdown("**Risk by Priority Level**")
                                        st.dataframe(analytics["priority_risk_matrix"], width="stretch")
                                    with cx2:
                                        st.markdown("**Risk by Regional Zone**")
                                        st.dataframe(analytics["region_risk_matrix"], width="stretch")
                                    with cx3:
                                        st.markdown("**Risk by Facility Type**")
                                        st.dataframe(analytics["type_risk_matrix"], width="stretch")
                            rg_idx += 1

                        if "Tab: Regional Grid -> Hazard Analytics" in st.session_state.allowed_actions:
                            with rg_tabs[rg_idx]:
                                st.subheader("🌪️ Deep Hazard Analytics & Executive Broadcast")
                                st.markdown("Comprehensive breakdown of active weather geometry against physical infrastructure.")
                                
                                if not master_affected_sites:
                                    st.success("🎉 All infrastructure is currently clear of severe weather geometry based on your current filters.")
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
                                    
                                    if c_em2.button("Transmit Priority SitRep", type="primary", use_container_width=True):
                                        if not sitrep_recipients:
                                            st.error("Please enter at least one recipient email.")
                                        else:
                                            with st.spinner("Compiling HTML and transmitting..."):
                                                # Call the offloaded HTML generator from services.py!
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
                                st.subheader("📜 Comprehensive Weather Alerts Log")
                                st.markdown("Human-readable log of all active NWS Watches, Warnings, and Special Weather Statements.")
                                
                                # Offloaded to services.py
                                all_alert_details = svc.get_weather_alerts_log(ar_data, oos_data, selected_events)
                                
                                if not all_alert_details:
                                    st.success("✅ No active weather alerts matching your current hazard filters.")
                                else:
                                    df_alerts = pd.DataFrame(all_alert_details)
                                    
                                    # Format dates if they exist
                                    for col in ['Effective', 'Expires']:
                                        df_alerts[col] = pd.to_datetime(df_alerts[col], errors='coerce').dt.strftime('%Y-%m-%d %H:%M')
                                        df_alerts[col] = df_alerts[col].fillna("N/A")
                                        
                                    st.dataframe(df_alerts[["Event", "Severity", "Affected Area", "Expires", "Headline"]], hide_index=True, width="stretch")
                                    
                                    st.divider()
                                    st.subheader("🔍 Deep Dive Inspection")
                                    
                                    # Create a dropdown that includes the area so analysts can differentiate between similarly named events
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

                        if "Tab: Regional Grid -> Manage Locations" in st.session_state.allowed_actions:
                            with rg_tabs[rg_idx]:
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
                                                added = svc.import_locations(data)
                                                st.success(f"Imported {added} new locations!"); time.sleep(1.5); safe_rerun()
                                            except Exception as e: st.error(f"Import failed: {e}")
                                                
                                with c_ed:
                                    st.subheader("Manual Adjustments")
                                    if not df.empty:
                                        edited_df = st.data_editor(df, hide_index=True, disabled=["id", "Risk"], width="stretch", key="loc_editor")
                                        if st.button("💾 Save Manual Adjustments", width="stretch"):
                                            svc.update_locations(edited_df)
                                            st.success("Changes saved!"); time.sleep(1); safe_rerun()
                                    
                                    st.divider()
                                    st.write("**Danger Zone**")
                                    if st.button("🗑️ Delete All Locations", width="stretch"):
                                        svc.nuke_tables(["MonitoredLocation"])
                                        svc.get_cached_locations.clear()
                                        st.success("All locations deleted!"); time.sleep(1); safe_rerun()
                            rg_idx += 1
            tab_idx += 1

# ================= 4. THREAT HUNTING & IOCS =================
elif page == "🎯 Threat Hunting & IOCs":
    st.title("🎯 Active Threat Hunting & Detection Engineering")
    st.markdown("Automated IOC extraction, 1-Click OSINT Pivoting, and LLM-assisted YARA/SIEM generation.")
    
    th_tab_names = []
    
    if "Tab: Threat Hunting -> Global IOC Matrix" in st.session_state.allowed_actions: th_tab_names.append("🧮 Live Global IOC Matrix")
    if "Tab: Threat Hunting -> Deep Hunt Builder" in st.session_state.allowed_actions: th_tab_names.append("🔬 Deep Hunt & Detection Builder")
    
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
                        # Offloaded to services.py
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
                            "OSINT Pivot": st.column_config.LinkColumn("Investigate 🔗", display_text="Open Tool"),
                            "Context": st.column_config.TextColumn("Context Snippet", width="large")
                        }
                    )
                    st.download_button(
                        label="📥 Export Hunting Targets (CSV)", 
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
                    if st.form_submit_button("⏳ Compiling..." if is_hunt_cooling else "🚀 Compile Detection Package", type="primary", disabled=not can_trigger_ai or is_hunt_cooling, width="stretch"):
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
                                        st.markdown(f"## 🎯 Detection Package: {hunt_target.upper()}")
                                        st.markdown(ai_hunt_result)
                                        st.divider()
                                        st.markdown("### 🔗 Reference Intel")
                                        for a in target_arts: st.markdown(f"- [{a.title}]({a.link})")
            th_idx += 1

# ================= 5. AIOps RCA =================
elif page == "⚡ AIOps RCA":
    st.title("⚡ AIOps Root Cause Analysis")
    st.caption("Live correlation of non-uniform monitoring alerts with Regional Intelligence.")
    
    from src.aiops_engine import EnterpriseAIOpsEngine
    ai_engine = EnterpriseAIOpsEngine(svc.SessionLocal())
    
    ai_tab_names = []
    
    if "Tab: AIOps RCA -> Active Board" in st.session_state.allowed_actions: ai_tab_names.append("🔴 Active Board")
    if "Tab: AIOps RCA -> Predictive Analytics" in st.session_state.allowed_actions: ai_tab_names.append("📈 Patterns")
    if "Tab: AIOps RCA -> Global Correlation" in st.session_state.allowed_actions: ai_tab_names.append("🌍 Global")
    
    if not ai_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        ai_tabs = st.tabs(ai_tab_names)
        ai_idx = 0
        
        if "Tab: AIOps RCA -> Active Board" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                alerts, events, grid = svc.get_aiops_dashboard_data()
                c_l, c_s = st.columns([3, 1])
                with c_s:
                    st.subheader("⏱️ Event Log")
                    if st.button("🧹 Clear", width="stretch"): svc.clear_timeline_events(); safe_rerun()
                    if st.button("🗑️ Nuke", width="stretch"): svc.nuke_active_alerts(); safe_rerun()
                    for e in events:
                        # 1. Convert UTC database time to Local Time (12-hour AM/PM format)
                        local_time = e.timestamp.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ)
                        time_str = local_time.strftime('%I:%M %p')
                        
                        # 2. Strip emojis and corrupted '??' characters
                        clean_msg = re.sub(r'[\U00010000-\U0010ffff]', '', e.message)
                        clean_msg = clean_msg.replace('?', '').strip()
                        
                        st.caption(f"{time_str} | {clean_msg}")
                
                with c_l:
                    st.subheader("🗺️ Overlays")
                    locs = svc.get_cached_locations()
                    
                    # Map Generation - Offloaded to services.py
                    layers, view_state = svc.build_aiops_map_layers(alerts, locs)

                    st.pydeck_chart(pdk.Deck(
                        layers=layers, 
                        initial_view_state=view_state, 
                        tooltip={"text": "{name}"}
                    ))
                    
                    st.subheader("⚡ Correlation")
                    if not alerts: st.success("Grid Operational.")
                    else:
                        with svc.SessionLocal() as dbtmp:
                            from src.database import RegionalHazard, CloudOutage, BgpAnomaly, SolarWindsAlert
                            wea = dbtmp.query(RegionalHazard).all()
                            cld = dbtmp.query(CloudOutage).filter_by(is_resolved=False).all()
                            bgp = dbtmp.query(BgpAnomaly).filter_by(is_resolved=False).all()
                            raw_alerts = dbtmp.query(SolarWindsAlert).filter(SolarWindsAlert.is_correlated == False, SolarWindsAlert.status != 'Resolved').all()
                            
                        incidents = ai_engine.analyze_and_cluster(raw_alerts)
                        for site, data in incidents.items():
                            # NOTE: Passing wea, cld, and bgp into the new advanced correlation engine
                            c, cf, p, e, b, p0, cs = ai_engine.calculate_root_cause(site, data, wea, cld, bgp)
                            
                            with st.container(border=True):
                                    st.markdown(f"### {p} | Site: {site}")
                                    st.warning(c)
                                    
                                    if p0:
                                        st.error(f"**Patient Zero (Suspected Origin Node):** {p0}")
                                    else:
                                        st.info("**Patient Zero:** Indeterminate (Simultaneous Failure)")
                                        
                                    with st.expander(f"Draft & Dispatch Ticket for {site}"):
                                        clean_p = p.replace("??", "").replace("??", "").replace("??", "").replace("??", "").replace("??", "").strip()
                                        clean_c = c.replace("??", "").replace("???", "").replace("?", "").replace("??", "").replace("??", "").strip()
                                        clean_p0 = p0 if p0 else "Indeterminate (Simultaneous Failure)"
                                        
                                        # Offloaded massive ticket generation to services.py!
                                        ticket_text = svc.generate_rca_ticket_text(site, data, clean_p, clean_p0, clean_c)
                                        
                                        ticket_body = st.text_area("Ticket Notes / RCA Summary", value=ticket_text, height=350, key=f"t_body_{site}")
                                        
                                        # Hardcoded Default Emails (No user input option)
                                        fixed_recipients = "remedyforceworkflow@aecc.com, noc@aecc.com"
                                        st.info(f"Ticket will be automatically dispatched to: **{fixed_recipients}**")
                                        
                                        if st.button("Dispatch Ticket", key=f"t_send_{site}", use_container_width=True):
                                            from src.mailer import send_alert_email
                                            with st.spinner("Dispatching to RemedyForce & NOC..."):
                                                success, msg = send_alert_email(f"URGENT: {clean_p} Incident at {site}", ticket_body, fixed_recipients, is_html=False)
                                                if success: st.success("? Ticket Dispatched successfully!")
                                                else: st.error(f"? SMTP Error: {msg}")

                                    if st.button(f"Acknowledge Incident & Clear Board ({site})", key=f"ack_{site}", width="stretch"): 
                                        svc.acknowledge_cluster([a.id for a in data['alerts']])
                                        safe_rerun()
            ai_idx += 1

        if "Tab: AIOps RCA -> Predictive Analytics" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                st.subheader("📈 Predictive Analytics & Chronic Degradation")
                st.markdown("Analyzes historical telemetry to identify degrading hardware and unstable infrastructure *before* catastrophic failure.")
                
                is_analytics_cooling = check_cooldown("ai_analytics", 60)
                if st.button("⏳ Processing..." if is_analytics_cooling else "🔍 Run Deep Analysis", type="primary", width="stretch", disabled=is_analytics_cooling):
                    apply_cooldown("ai_analytics")
                    with st.spinner("Crunching historical telemetry and calculating failure probabilities..."):
                        f, v, r = ai_engine.generate_chronic_insights()
                        
                        if f is None or (isinstance(f, pd.DataFrame) and f.empty):
                            st.success("✅ No chronic degradation patterns detected in the current telemetry window.")
                        else:
                            st.divider()
                            col_f, col_v = st.columns(2)
                            
                            with col_f:
                                st.markdown("### ⚠️ Top Offending Nodes")
                                st.caption("Specific devices exhibiting high frequency of state-flapping.")
                                st.dataframe(f, width="stretch", hide_index=True)
                                
                            with col_v:
                                st.markdown("### 🏢 Infrastructure Hotspots")
                                st.caption("Sites or regions experiencing chronic instability.")
                                if v is not None and not (isinstance(v, pd.DataFrame) and v.empty):
                                    st.dataframe(v, width="stretch", hide_index=True)
                                else:
                                    st.info("Insufficient data for site heatmapping.")
                                    
                            st.divider()
                            st.markdown("### 🤖 AI Predictive Maintenance Forecast")
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
                st.subheader("🌍 Deterministic Global Correlation Engine")
                st.markdown("Calculates causation graphs based on geospatial math and telemetry overlays across all domains.")
                
                c_glob1, c_glob2 = st.columns([3, 1])
                
                is_global_rca_cooling = check_cooldown("global_rca", 60)
                if c_glob2.button("⏳ Calculating..." if is_global_rca_cooling else "🔍 Run Global Correlation", type="primary", width="stretch", disabled=is_global_rca_cooling):
                    apply_cooldown("global_rca")
                    with st.spinner("Calculating Multi-Domain Causal Links..."):
                        report = svc.generate_global_sitrep(sys_config)
                        st.session_state.last_global_rca = report

                if "last_global_rca" in st.session_state:
                    st.divider()
                    with st.container(border=True):
                        st.markdown(st.session_state.last_global_rca)
                    
                    c_em1, c_em2 = st.columns([1, 4])
                    if c_em1.button("✉️ Broadcast SitRep", width="stretch"):
                        from src.mailer import send_alert_email
                        with st.spinner("Transmitting via SMTP..."):
                            success, msg = send_alert_email("URGENT: Multi-Domain Global SitRep", st.session_state.last_global_rca)
                            if success: st.success(msg)
                            else: st.error(msg)
            ai_idx += 1

# ================= 6. REPORT CENTER =================
elif page == "📑 Report Center":
    st.title("📑 Report Center")
    
    rc_tab_names = []
    
    if "Tab: Report Center -> Report Builder" in st.session_state.allowed_actions: rc_tab_names.append("📝 Report Builder")
    if "Tab: Report Center -> Shared Library" in st.session_state.allowed_actions: rc_tab_names.append("📚 Shared Library")
    
    if not rc_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        tabs = st.tabs(rc_tab_names)
        tab_idx = 0
        
        if "Tab: Report Center -> Report Builder" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                if "generated_report" not in st.session_state: st.session_state.generated_report = None
                
                c_s, c_l = st.columns([3, 1])
                sq = c_s.text_input("🔍 Search Articles")
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
                    
                    is_rep_cooling = check_cooldown("gen_report", 60)
                    if st.button("⏳ Synthesizing..." if is_rep_cooling else "🚀 Generate Report", type="primary", disabled=not can_trigger_ai or is_rep_cooling, width="stretch"):
                        apply_cooldown("gen_report")
                        if not sels: st.error("Select at least one article.")
                        else:
                            arts = [amap[t] for t in sels]
                            with st.spinner("Synthesizing Intelligence..."):
                                md = build_custom_intel_report(arts, obj, svc.SessionLocal())
                                if md:
                                    now = datetime.now(LOCAL_TZ).strftime("%A, %B %d, %Y at %I:%M %p %Z")
                                    st.session_state.generated_report = f"# 🛡️ NOC Report\n**Date:** {now}\n**Analyst:** {aname}\n\n---\n\n{md}"
                                    st.success("Complete!")

                if st.session_state.generated_report:
                    st.divider()
                    st.markdown(st.session_state.generated_report)
                    sv_t = st.text_input("Report Title", value=f"Report - {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}")
                    if st.button("💾 Save to Library", width="stretch"):
                        svc.save_custom_report(sv_t, st.session_state.current_user, st.session_state.generated_report)
                        st.success("Saved!")
            tab_idx += 1
            
        if "Tab: Report Center -> Shared Library" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                reps = svc.get_saved_reports()
                if not reps: st.info("No reports saved yet.")
                else:
                    for r in reps:
                        with st.expander(f"📄 **{r.title}** | {format_local_time(r.created_at)}"):
                            st.markdown(r.content)
                            if st.button("🗑️ Delete", key=f"del_lib_{r.id}", width="stretch"):
                                svc.delete_record("SavedReport", r.id); safe_rerun()
            tab_idx += 1

# ================= 7. SETTINGS & ADMIN =================
elif page == "⚙️ Settings & Admin":
    st.title("⚙️ Settings & Engine Room")
    
    set_tab_names = []
    
    if "Tab: Settings -> RSS Sources" in st.session_state.allowed_actions: set_tab_names.append("📡 RSS Sources")
    if "Tab: Settings -> ML Training" in st.session_state.allowed_actions: set_tab_names.append("🧠 ML Training")
    if "Tab: Settings -> AI & SMTP" in st.session_state.allowed_actions: set_tab_names.append("🤖 AI & SMTP")
    if "Tab: Settings -> Users & Roles" in st.session_state.allowed_actions: set_tab_names.append("👥 Users & Roles")
    if "Tab: Settings -> Backup & Restore" in st.session_state.allowed_actions: set_tab_names.append("💾 Backup & Restore")
    if "Tab: Settings -> Danger Zone" in st.session_state.allowed_actions: set_tab_names.append("⚠️ Danger Zone")
    
    if not set_tab_names: st.warning("No permission to view tabs in this module.")
    else:
        set_tabs = st.tabs(set_tab_names)
        set_idx = 0
        
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
                            if c_c.button("🗑️", key=f"del_kw_{k.id}", width="stretch"): 
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
                if st.button("⏳ Training..." if is_train_cooling else "🚀 Retrain Model Now", type="primary", disabled=not can_train or is_train_cooling, key="set_ml_retrain", width="stretch"):
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
                st.subheader("Universal LLM & System Integrations")
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

                    if st.form_submit_button("Save Global Config", width="stretch"):
                        new_config = {
                            "llm_endpoint": endpoint, "llm_api_key": api_key, "llm_model_name": model_name,
                            "tech_stack": tech_stack_input, "is_active": is_active, "smtp_server": smtp_server, 
                            "smtp_port": smtp_port, "smtp_username": smtp_user, "smtp_password": smtp_pass, 
                            "smtp_sender": smtp_sender, "smtp_recipient": smtp_recip, "smtp_enabled": smtp_enabled
                        }
                        svc.save_global_config(new_config)
                        st.success("✅ Configuration Saved!"); time.sleep(1); safe_rerun()
            set_idx += 1

        if "Tab: Settings -> Users & Roles" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("👥 User & Role Management")
                col_u1, col_u2 = st.columns(2)
                with col_u1:
                    available_roles = [r.name for r in svc.get_all_roles()]
                    with st.container(border=True):
                        st.markdown("### ➕ Create New User")
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
                        st.markdown("### 🔄 Change User Role")
                        with st.form("update_user_role_form"):
                            usrs = svc.get_admin_lists()[2] if 'usrs' not in locals() else usrs
                            target_user = st.selectbox("Select User", [u.username for u in usrs])
                            new_assigned_role = st.selectbox("Assign New Role", available_roles)
                            if st.form_submit_button("Update Role", width="stretch"):
                                svc.update_user_role(target_user, new_assigned_role)
                                st.success(f"✅ Updated {target_user} to role: {new_assigned_role}"); safe_rerun()
                                
                    with st.container(border=True):
                        st.markdown("### 🛠️ Create Custom Role")
                        with st.form("new_role_form", clear_on_submit=True):
                            new_role_name = st.text_input("Role Name").strip().lower()
                            new_role_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES)
                            new_role_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS)
                            if st.form_submit_button("Create Role", width="stretch"):
                                if not new_role_name or not new_role_pages: st.error("Role name and at least one page required.")
                                else:
                                    if svc.create_role(new_role_name, new_role_pages, new_role_actions):
                                        if hasattr(svc.get_all_roles, "clear"): svc.get_all_roles.clear()
                                        st.success(f"Role '{new_role_name}' created!"); time.sleep(1); safe_rerun()
                                    else: st.error("Role name already exists.")
                                    
                    with st.container(border=True):
                        st.markdown("### ✏️ Edit Existing Role")
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
                                    
                                    updated_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES, default=valid_default_pages)
                                    updated_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS, default=valid_default_actions)
                                    
                                    if st.form_submit_button("Update Role", width="stretch"):
                                        if not updated_pages: st.error("A role must have at least one allowed page.")
                                        else:
                                            svc.update_role(role_to_edit, updated_pages, updated_actions)
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
                                if c_act.button("🗑️", key=f"del_u_{u.id}", width="stretch"):
                                    svc.delete_record("User", u.id); safe_rerun()
                                    
                    with st.container(border=True):
                        st.markdown("### 🔑 Force Reset Password")
                        with st.form("admin_reset_pwd_form"):
                            target_user = st.selectbox("Select User ", [u.username for u in usrs])
                            force_new_pwd = st.text_input("New Password", type="password")
                            if st.form_submit_button("Reset Password", width="stretch"):
                                if force_new_pwd:
                                    svc.force_reset_pwd(target_user, force_new_pwd)
                                    st.success(f"✅ Password reset for {target_user}.")

                    with st.container(border=True):
                        st.markdown("### Active Roles")
                        for r in svc.get_all_roles():
                            c_name, c_pages, c_act = st.columns([2, 3, 1])
                            c_name.write(f"**{r.name}**")
                            action_count = len(r.allowed_actions) if r.allowed_actions else 0
                            c_pages.caption(f"{len(r.allowed_pages)} pages | {action_count} perms")
                            if r.name not in ["admin", "analyst"]:
                                if c_act.button("🗑️", key=f"del_role_{r.id}", width="stretch"):
                                    svc.delete_record("Role", r.id); safe_rerun()
            set_idx += 1
                                    
        if "Tab: Settings -> Backup & Restore" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("💾 Database Export & Import")
                st.write("Backup or restore configurations, keywords, RSS feeds, and location mappings.")
                
                c_exp, c_imp = st.columns(2)
                with c_exp:
                    st.markdown("### Export Data")
                    if st.button("📦 Generate Backup JSON", width="stretch"):
                        backup_data = svc.get_backup_data()
                        json_str = json.dumps(backup_data, indent=4)
                        st.download_button("⬇️ Download System_Backup.json", data=json_str, file_name=f"NOC_Backup_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json", width="stretch")
                
                with c_imp:
                    st.markdown("### Import Data")
                    uploaded_backup = st.file_uploader("Upload JSON Backup File", type=["json"])
                    if uploaded_backup is not None:
                        if st.button("📥 Execute Import", width="stretch", type="primary"):
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
                    if st.button("⏳ Sweeping..." if is_gc_cooling else "🧹 Run Garbage Collector", width="stretch", disabled=is_gc_cooling):
                        apply_cooldown("gc_run")
                        with st.spinner("Purging stale data and vacuuming database..."):
                            from src.scheduler import run_database_maintenance
                            run_database_maintenance()
                            st.success("✅ Swept and optimized!"); time.sleep(1); safe_rerun()
                            
                    st.write("**Reset Cloud Telemetry**")
                    st.caption("Wipes all cloud outages to force a clean sync.")
                    is_nuke_cloud_cooling = check_cooldown("nuke_cloud", 60)
                    if st.button("⏳ Purging..." if is_nuke_cloud_cooling else "🌩️ Purge Cloud Data", width="stretch", disabled=is_nuke_cloud_cooling):
                        apply_cooldown("nuke_cloud")
                        svc.nuke_tables(["CloudOutage"])
                        st.success("Cloud data purged! Go to Threat Telemetry -> Cloud Services to repull."); time.sleep(1.5); safe_rerun()
                    
                    st.write("**Data Migration**")
                    st.caption("Applies new categories to historical 'General' data.")
                    is_recat_cooling = check_cooldown("recategorize", 60)
                    if st.button("⏳ Scanning..." if is_recat_cooling else "🔄 Recategorize Articles", width="stretch", disabled=is_recat_cooling):
                        apply_cooldown("recategorize")
                        with st.spinner("Scanning database..."):
                            updated_count = svc.recategorize_all_articles()
                            st.success(f"✅ Successfully recategorized {updated_count} articles!"); time.sleep(2); safe_rerun()
                            
                with col2:
                    st.write("**Clear History**")
                    st.caption("Deletes all articles & IOCs.")
                    if st.button("🗑️ Delete All Articles", width="stretch"):
                        svc.nuke_tables(["Article", "ExtractedIOC"])
                        safe_rerun()
                        
                    st.write("**Clear Locations**")
                    st.caption("Deletes all monitored facilities.")
                    if st.button("🗑️ Delete All Locations", width="stretch"):
                        svc.nuke_tables(["MonitoredLocation"])
                        svc.get_cached_locations.clear()
                        safe_rerun()
                        
                with col3:
                    st.write("**Factory Reset**")
                    st.caption("Destroys all data entirely.")
                    if st.button("☢️ FULL RESET", width="stretch"):
                        svc.nuke_tables(["Article", "ExtractedIOC", "FeedSource", "Keyword", "MonitoredLocation"])
                        svc.get_cached_locations.clear()
                        safe_rerun()
            set_idx += 1
