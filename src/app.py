import streamlit as st
import pandas as pd
import math
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from sqlalchemy import text
from streamlit_autorefresh import st_autorefresh
import streamlit.components.v1 as components

from src.database import SessionLocal, Article, FeedSource, Keyword, SystemConfig, engine, init_db, CveItem, RegionalHazard, CloudOutage
from src.train_model import train 
from src.scheduler import fetch_feeds
from src.llm import generate_briefing, generate_bluf, analyze_cascading_impacts, cross_reference_cves, build_custom_intel_report, generate_feed_overview, generate_rolling_summary

@st.cache_resource
def setup_database():
    init_db()
    return True

setup_database()

st.set_page_config(page_title="Intelligence Fusion Center", layout="wide")

def get_db():
    return SessionLocal()

session = get_db()
LOCAL_TZ = ZoneInfo("America/Chicago")

st.markdown("""
    <style>
        .block-container { padding-top: 1rem; padding-bottom: 0rem; max-width: 98%; }
        h1, h2, h3 { margin-bottom: 0.2rem; padding-bottom: 0.2rem; }
        hr { margin-top: 0.5rem; margin-bottom: 0.5rem; }
    </style>
""", unsafe_allow_html=True)

def get_score_badge(score):
    """Returns a streamlined, color-coded score indicator."""
    if score >= 80: return f"🔴 **[{int(score)}]**"
    elif score >= 50: return f"🟠 **[{int(score)}]**"
    else: return f"🔵 **[{int(score)}]**"

def toggle_pin(art_id):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art:
        art.is_pinned = not art.is_pinned
        session.commit()

def boost_score(art_id, amount=15):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art:
        art.score = min(100.0, art.score + amount)
        session.commit()

def format_local_time(utc_dt):
    if not utc_dt: return "Unknown"
    return utc_dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).strftime('%Y-%m-%d %H:%M %Z')

def change_status(art_id, new_feedback, bubble_status=None):
    art = session.query(Article).filter(Article.id == art_id).first()
    if art:
        if art.human_feedback == 0 and new_feedback in [1, 2]:
            if art.keywords_found and isinstance(art.keywords_found, list):
                for kw in art.keywords_found:
                    keyword_db = session.query(Keyword).filter_by(word=kw).first()
                    if keyword_db:
                        if new_feedback == 2:
                            keyword_db.weight += 1
                        elif new_feedback == 1:
                            keyword_db.weight = max(1, keyword_db.weight - 1)
                            
        art.human_feedback = new_feedback
        if bubble_status is not None:
            art.is_bubbled = bubble_status
        session.commit()

llm_config = session.query(SystemConfig).filter_by(is_active=True).first()
ai_enabled = llm_config is not None

st.sidebar.title("NOC Fusion Center")

refresh_minutes = st.sidebar.number_input("🔄 Auto-Refresh (Minutes, 0 to disable)", min_value=0, max_value=60, value=2)
if refresh_minutes > 0:
    st_autorefresh(interval=refresh_minutes * 60 * 1000, key="noc_refresh")

st.sidebar.divider()

# --- NEW MODULAR NAVIGATION WITH SESSION STATE ---
PAGES = [
    "🌐 Main Dashboard", 
    "📊 The Briefing Room", 
    "📰 RSS Triage", 
    "🪲 Vulnerabilities & Exploits", 
    "🗺️ Regional Infrastructure", 
    "☁️ Cloud Services Status",
    "📝 Report Builder",
    "⚙️ Settings & Training"
]

# Initialize the session state for navigation if it doesn't exist
if "active_page" not in st.session_state:
    st.session_state.active_page = PAGES[0]

# Render the radio button, tying its value to our session state
selected_page = st.sidebar.radio("Navigation", PAGES, index=PAGES.index(st.session_state.active_page))

# If the user clicks a different page in the sidebar, update the state and rerun
if selected_page != st.session_state.active_page:
    st.session_state.active_page = selected_page
    st.rerun()

# Set the current page variable for the rest of the app to use
page = st.session_state.active_page
# Audio Ping Logic
latest_article = session.query(Article).order_by(Article.id.desc()).first()
latest_id = latest_article.id if latest_article else 0

if "last_seen_id" not in st.session_state:
    st.session_state.last_seen_id = latest_id

if latest_id > st.session_state.last_seen_id:
    ping_js = """
    <script>
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    function playPing() {
        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();
        oscillator.type = 'sine';
        oscillator.frequency.setValueAtTime(880, audioCtx.currentTime);
        oscillator.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.5);
        gainNode.gain.setValueAtTime(0.5, audioCtx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.5);
        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        oscillator.start();
        oscillator.stop(audioCtx.currentTime + 0.5);
    }
    playPing();
    </script>
    """
    components.html(ping_js, width=0, height=0)
    st.session_state.last_seen_id = latest_id


# ================= 1. MAIN DASHBOARD (HIGH DENSITY) =================
if page == "🌐 Main Dashboard":
    st.title("🌐 NOC Intelligence Fusion Center")
    
    # --- 1. Compact Metrics Row (Strict 24h Filter) ---
    twenty_four_hours_ago = datetime.utcnow() - timedelta(days=1)
    
    pending_rss_24h = session.query(Article).filter(Article.published_date >= twenty_four_hours_ago, Article.score >= 50).count()
    cves_24h = session.query(CveItem).filter(CveItem.date_added >= twenty_four_hours_ago).count()
    active_hazards_24h = session.query(RegionalHazard).filter(RegionalHazard.updated_at >= twenty_four_hours_ago).count()
    active_cloud_24h = session.query(CloudOutage).filter(CloudOutage.updated_at >= twenty_four_hours_ago, CloudOutage.is_resolved == False).count()
    
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("High-Threat RSS (24h)", pending_rss_24h)
    c2.metric("Active KEVs (24h)", cves_24h)
    c3.metric("Regional Hazards (24h)", active_hazards_24h)
    c4.metric("Active Cloud Outages (24h)", active_cloud_24h)
    
    st.divider()
    
    # --- 2. Collapsible Rolling AI Shift Summary ---
    if "rolling_summary" not in st.session_state:
        st.session_state.rolling_summary = "Initializing AI Shift Summary..."
        st.session_state.rolling_summary_time = datetime.utcnow() - timedelta(hours=1)
        
    now = datetime.utcnow()
    time_since_update = (now - st.session_state.rolling_summary_time).total_seconds()
    
    if ai_enabled and time_since_update > 1800:
        with st.spinner("🤖 Updating Rolling AI Summary..."):
            new_summary = generate_rolling_summary(session)
            if new_summary:
                st.session_state.rolling_summary = new_summary
                st.session_state.rolling_summary_time = now

    local_time_str = format_local_time(st.session_state.rolling_summary_time)
    
    # st.expander creates a collapsible container
    with st.expander(f"🤖 **AI Shift Briefing** (Last Sync: {local_time_str})", expanded=True):
        st.info(st.session_state.rolling_summary)
        col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
        if col_btn2.button("🔄 Force Refresh AI Briefing", use_container_width=True):
            st.session_state.rolling_summary_time = datetime.utcnow() - timedelta(hours=1)
            st.rerun()

    st.divider()

    # --- 3. Pinned Intelligence (Full Width) ---
    pinned_arts = session.query(Article).filter(Article.is_pinned == True).order_by(Article.published_date.desc()).all()
    if pinned_arts:
        st.subheader("📌 Pinned Intelligence")
        for art in pinned_arts:
            st.markdown(f"**{get_score_badge(art.score)} [{art.title}]({art.link})**")
            st.caption(f"📡 {art.source} | 📅 {format_local_time(art.published_date)}")
        st.divider()

    # --- 4. Classic 2-Column Data Layout ---
    col_a, col_b = st.columns(2)
    
    with col_a:
        with st.container(border=True):
            st.subheader("🚨 High-Threat Intel (Last 24h)")
            top_rss_24h = session.query(Article).filter(
                Article.published_date >= twenty_four_hours_ago,
                Article.score >= 50.0,
                Article.is_pinned == False
            ).order_by(Article.score.desc(), Article.published_date.desc()).limit(10).all()
            
            if not top_rss_24h:
                st.success("No high-threat intelligence in the last 24 hours.")
            else:
                for art in top_rss_24h:
                    st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link})")
                    st.caption(f"📡 {art.source} | 📅 {format_local_time(art.published_date)}")
                    st.write("---")
                
        with st.container(border=True):
            st.subheader("🪲 Active Exploits (KEV)")
            latest_cves = session.query(CveItem).order_by(CveItem.date_added.desc()).limit(5).all()
            for cve in latest_cves:
                st.markdown(f"🚨 **[{cve.cve_id}](https://nvd.nist.gov/vuln/detail/{cve.cve_id})** - {cve.vendor} {cve.product}")
                st.caption(f"*{cve.vulnerability_name}*")
                st.write("---")

    with col_b:
        with st.container(border=True):
            st.subheader("☁️ Cloud Services")
            latest_cloud = session.query(CloudOutage).filter(CloudOutage.is_resolved == False).order_by(CloudOutage.updated_at.desc()).limit(5).all()
            if not latest_cloud:
                st.success("All monitored cloud systems are operational.")
            else:
                for out in latest_cloud:
                    st.markdown(f"🚨 **{out.provider} | {out.service}**")
                    st.markdown(f"[{out.title}]({out.link})")
                    st.write("---")
                
        with st.container(border=True):
            st.subheader("🌪️ Regional Hazards")
            latest_hazards = session.query(RegionalHazard).order_by(RegionalHazard.updated_at.desc()).limit(5).all()
            if not latest_hazards:
                st.success("The regional grid is clear.")
            else:
                for haz in latest_hazards:
                    sev_icon = "🔴" if haz.severity in ["Extreme", "Severe"] else "🟠" if haz.severity == "Moderate" else "🔵"
                    st.markdown(f"{sev_icon} **{haz.severity}**: {haz.title}")
                    st.caption(f"📍 {haz.location}")
                    st.write("---")
        
        with st.container(border=True):
            st.subheader("🤖 AI Security Auditor")
            if ai_enabled:
                if st.button("Scan Stack Against 30-Day KEVs", use_container_width=True):
                    with st.spinner("Scanning..."):
                        audit_cves = session.query(CveItem).filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30)).all()
                        xref_result = cross_reference_cves(audit_cves, session)
                        if xref_result and ("clear" in xref_result.lower() or "no active" in xref_result.lower()):
                            st.success("✅ " + xref_result)
                        else:
                            st.error(f"⚠️ **MATCH DETECTED:**\n{xref_result}")
                        
# ================= 2. THE BRIEFING ROOM =================
elif page == "📊 The Briefing Room":
    st.title("📊 The Briefing Room")
    st.markdown("Your daily AI-synthesized situational report covering Cyber, Vulnerabilities, Physical Hazards, and Cloud Infrastructure.")
    
    from src.database import DailyBriefing
    from src.llm import generate_daily_fusion_report
    
    now_local = datetime.now(LOCAL_TZ)
    yesterday_local = (now_local - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Check if a report for yesterday already exists
    existing_report = session.query(DailyBriefing).filter(DailyBriefing.report_date == yesterday_local).first()
    
    col1, col2 = st.columns([3, 1])
    if col2.button("🤖 Generate Yesterday's Report", use_container_width=True, type="primary"):
        if not ai_enabled:
            st.error("AI is disabled. Check Settings.")
        else:
            with st.spinner("Processing massive datasets... (This will take a few minutes as the AI processes 4 distinct sectors)"):
                date_obj, report_markdown = generate_daily_fusion_report(session)
                if report_markdown:
                    # Save or update the database
                    if existing_report:
                        existing_report.content = report_markdown
                        existing_report.created_at = datetime.utcnow()
                    else:
                        new_rep = DailyBriefing(report_date=date_obj, content=report_markdown)
                        session.add(new_rep)
                    session.commit()
                    st.success("Report Generated!")
                    time.sleep(1)
                    st.rerun()

    st.divider()
    
    if existing_report:
        st.markdown(existing_report.content)
    else:
        st.info("No report generated for yesterday yet. Click the button above to begin the AI synthesis.")

# ================= 3. RSS TRIAGE (LIVE FEED) =================
elif page == "📰 RSS Triage":
    col_title, col_btn = st.columns([3, 1])
    col_title.title("📰 Live Intelligence Feed")
    if col_btn.button("🔄 Force Fetch Feeds", use_container_width=True):
        from src.scheduler import fetch_feeds
        fetch_feeds(source="User Force") 
        time.sleep(1)
        st.rerun()

    # --- NEW HELPER FUNCTION TO DRAW THE ARTICLE CARDS ---
    # --- UPDATE HELPER FUNCTION WITH KEY PREFIX ---
    def render_article_feed(feed_articles, key_prefix=""):
        if not feed_articles:
            st.success("Queue is empty.")
            return
            
        for art in feed_articles:
            with st.container(border=True):
                c_title, c_score = st.columns([4, 1])
                c_title.markdown(f"### {get_score_badge(art.score)} [{art.title}]({art.link})")
                c_title.caption(f"📅 {format_local_time(art.published_date)} | 📡 {art.source} | 🤖 ML Training: {'Kept' if art.human_feedback == 2 else 'Dismissed' if art.human_feedback == 1 else 'Untrained'}")
                
                if art.ai_bluf:
                    st.success(f"**AI BLUF:** {art.ai_bluf}")
                else:
                    st.write(art.summary)
                    
                # Action Buttons - ADDED key_prefix
                c1, c2, c3, c4, c5 = st.columns(5)
                
                pin_label = "📍 Unpin" if art.is_pinned else "📌 Pin to Dash"
                c1.button(pin_label, key=f"{key_prefix}pin_{art.id}", on_click=toggle_pin, args=(art.id,))
                
                c2.button("⏫ +15 Threat", key=f"{key_prefix}boost_{art.id}", on_click=boost_score, args=(art.id, 15))
                
                c3.button("🧠 Learn: Keep", key=f"{key_prefix}keep_{art.id}", on_click=change_status, args=(art.id, 2))
                c4.button("🧠 Learn: Dismiss", key=f"{key_prefix}dism_{art.id}", on_click=change_status, args=(art.id, 1))
                
                if ai_enabled and not art.ai_bluf:
                    if c5.button("🤖 Generate BLUF", key=f"{key_prefix}bluf_{art.id}"):
                        with st.spinner("Analyzing..."):
                            bluf_text = generate_bluf(art, session)
                            if bluf_text:
                                art.ai_bluf = bluf_text
                                session.commit()
                                st.rerun()

    tab_pinned, tab_feed, tab_low, tab_search, tab_overview = st.tabs([
        "📌 Pinned",
        "📡 Live Feed (>50)", 
        "📉 Below Threshold (<50)", 
        "🔍 Deep Search", 
        "🧠 AI Overviews"
    ])
    
    with tab_pinned:
        st.markdown("Intelligence manually pinned to the Main Dashboard. Unpin items here to clear them from your HUD.")
        pinned_articles = session.query(Article).filter(Article.is_pinned == True).order_by(Article.published_date.desc()).all()
        render_article_feed(pinned_articles, key_prefix="pinned_")

    with tab_feed:
        st.markdown("High-priority intelligence scoring 50 or above.")
        high_threat_articles = session.query(Article).filter(Article.score >= 50.0).order_by(Article.published_date.desc()).limit(50).all()
        render_article_feed(high_threat_articles, key_prefix="live_")
        
    with tab_low:
        st.markdown("Low-priority intelligence, vendor noise, and general news.")
        low_threat_articles = session.query(Article).filter(Article.score < 50.0).order_by(Article.published_date.desc()).limit(50).all()
        render_article_feed(low_threat_articles, key_prefix="low_")
        
    with tab_search:
        st.subheader("🔍 Threat Database Search")
        col_s1, col_s2, col_s3 = st.columns([2, 1, 1])
        search_term = col_s1.text_input("Keyword Search", placeholder="e.g., Ransomware, Cisco")
        min_score = col_s2.number_input("Minimum Threat Score", min_value=0, max_value=100, value=0)
        limit = col_s3.selectbox("Result Limit", [20, 50, 100])
        
        query = session.query(Article).filter(Article.score >= min_score)
        if search_term:
            query = query.filter(Article.title.ilike(f"%{search_term}%") | Article.summary.ilike(f"%{search_term}%"))
            
        search_results = query.order_by(Article.score.desc(), Article.published_date.desc()).limit(limit).all()
        for art in search_results:
            st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link})")
            st.caption(f"📡 {art.source} | 📅 {format_local_time(art.published_date)}")
            st.write("---")

    with tab_overview:
        # Keep your existing AI macro overview logic here
        st.info("AI Macro Overviews retained from previous setup.")
        st.subheader("🧠 Intelligence Narrative Overviews")
        st.markdown("Use Dolphin-Phi to read the headlines of recent batches and synthesize the current threat landscape.")
        
        from src.llm import generate_feed_overview
        
        col_o1, col_o2 = st.columns(2)
        
        with col_o1:
            with st.container(border=True):
                st.markdown("### 🌐 General Threat Landscape")
                st.caption("Synthesizes the last 50 articles ingested, regardless of score.")
                if st.button("Generate Landscape Overview", use_container_width=True):
                    recent_50 = session.query(Article).order_by(Article.published_date.desc()).limit(50).all()
                    with st.spinner("Synthesizing 50 articles..."):
                        focus = "Provide a general overview of the global cybersecurity and infrastructure landscape based on these recent events."
                        overview = generate_feed_overview(recent_50, focus, session)
                        if overview: st.info(overview)
                        else: st.error("Generation failed.")
                        
        with col_o2:
            with st.container(border=True):
                st.markdown("### 🚨 Critical Threat Narrative")
                st.caption("Synthesizes the most recent 25 articles with a Threat Score > 70.")
                if st.button("Generate Critical Narrative", use_container_width=True):
                    top_25 = session.query(Article).filter(Article.score >= 70).order_by(Article.published_date.desc()).limit(25).all()
                    if not top_25:
                        st.warning("Not enough articles scoring over 70 to generate a narrative.")
                    else:
                        with st.spinner("Synthesizing critical threats..."):
                            focus = "Focus strictly on high-severity vulnerabilities, active breaches, and major disruptions. Identify the most critical attack vectors."
                            overview = generate_feed_overview(top_25, focus, session)
                            if overview: st.error(overview)
                            else: st.error("Generation failed.")


# ================= 4. VULNERABILITIES & EXPLOITS =================
elif page == "🪲 Vulnerabilities & Exploits":
    col_title, col_btn = st.columns([3, 1])
    col_title.title("🪲 Known Exploited Vulnerabilities")
    
    if col_btn.button("🔄 Sync CISA KEV"):
        with st.spinner("Pulling latest active exploits from CISA..."):
            from src.cve_worker import fetch_cisa_kev
            fetch_cisa_kev()
            time.sleep(1)
            st.rerun()

    st.markdown("This feed tracks vulnerabilities that are **actively being exploited in the wild**, directly from the CISA KEV catalog.")
    
    # Let the user filter by how recent the exploits are
    days_back = st.radio("Show CVEs added in the last:", ["7 Days", "30 Days", "All Time (Archive)"], horizontal=True)
    
    query = session.query(CveItem)
    if days_back == "7 Days":
        query = query.filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=7))
    elif days_back == "30 Days":
        query = query.filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30))
        
    cves = query.order_by(CveItem.date_added.desc()).all()
    
    if not cves:
        st.success("No new exploited vulnerabilities added in this timeframe.")
    else:
        st.caption(f"Showing {len(cves)} exploited vulnerabilities.")
        for cve in cves:
            with st.expander(f"🚨 {cve.cve_id} | {cve.vendor} {cve.product}"):
                c1, c2 = st.columns([3, 1])
                c1.markdown(f"**Vulnerability:** {cve.vulnerability_name}")
                c1.write(cve.description)
                c1.info(f"**Required Action:** {cve.required_action}")
                
                c2.caption(f"**Date Added:** {cve.date_added.strftime('%Y-%m-%d')}")
                c2.caption(f"**CISA Due Date:** {cve.due_date}")
                c2.markdown(f"[View on NVD](https://nvd.nist.gov/vuln/detail/{cve.cve_id})")

# ================= 5. REGIONAL INFRASTRUCTURE =================
elif page == "🗺️ Regional Infrastructure":
    col_title, col_btn = st.columns([3, 1])
    col_title.title("🗺️ Regional Hazards & Infrastructure")
    
    if col_btn.button("🔄 Sync Regional Telemetry"):
        with st.spinner("Pulling latest state & regional telemetry..."):
            from src.infra_worker import fetch_regional_hazards
            fetch_regional_hazards()
            time.sleep(1)
            st.rerun()

    st.markdown("Live physical threat tracking covering the immediate operational footprint.")
    
    st.subheader("📡 Live Radar Timeline")
    # Coordinates 34.8, -92.2 center the map over Arkansas with Zoom 7 to capture the whole state.
    # The URL parameters force an auto-playing timeline of the last 30 minutes of radar imagery.
    radar_html = """
    <iframe 
        src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,7&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" 
        width="100%" 
        height="500" 
        frameborder="0" 
        style="border-radius: 8px;"
        allowfullscreen>
    </iframe>
    """
    components.html(radar_html, height=500)
    st.divider()
    
    hazards = session.query(RegionalHazard).order_by(RegionalHazard.updated_at.desc()).all()
    
    if not hazards:
        st.success("The grid is clear. No active regional hazards reported.")
    else:
        st.caption(f"Tracking {len(hazards)} active alerts.")
        for haz in hazards:
            sev_color = "red" if haz.severity in ["Extreme", "Severe"] else "orange" if haz.severity == "Moderate" else "blue"
            with st.expander(f":{sev_color}[{haz.severity}] {haz.title}"):
                st.markdown(f"**Affected Area:** {haz.location}")
                st.info(haz.description)
                st.caption(f"Alert ID: {haz.hazard_id} | Updated: {haz.updated_at.strftime('%Y-%m-%d %H:%M')}")
                
# ================= 6. CLOUD SERVICES STATUS =================
elif page == "☁️ Cloud Services Status":
    col_title, col_btn = st.columns([3, 1])
    col_title.title("☁️ Cloud Services Status")
    
    if col_btn.button("🔄 Sync Cloud Status"):
        with st.spinner("Pulling latest status from AWS, GCP, Azure, and Cisco..."):
            from src.cloud_worker import fetch_cloud_outages
            fetch_cloud_outages()
            time.sleep(1)
            st.rerun()

    st.markdown("Live infrastructure tracking broken down by major cloud provider.")
    
    # --- NEW DEDICATED TABS ---
    tab_aws, tab_gcp, tab_azure, tab_cisco = st.tabs(["AWS", "Google Cloud", "Microsoft Azure", "Cisco Systems"])
    
    def render_provider_tab(provider_filter, tab_obj):
        with tab_obj:
            if "%" in provider_filter:
                outages = session.query(CloudOutage).filter(CloudOutage.provider.like(provider_filter)).order_by(CloudOutage.is_resolved.asc(), CloudOutage.updated_at.desc()).all()
                display_name = "Cisco"
            else:
                outages = session.query(CloudOutage).filter(CloudOutage.provider == provider_filter).order_by(CloudOutage.is_resolved.asc(), CloudOutage.updated_at.desc()).all()
                display_name = provider_filter
                
            if not outages:
                st.success(f"All monitored {display_name} systems are currently operational.")
            else:
                for out in outages:
                    status_color = "green" if out.is_resolved else "red"
                    status_icon = "✅ RESOLVED" if out.is_resolved else "🚨 ACTIVE"
                    with st.expander(f":{status_color}[{status_icon}] {out.service} ({format_local_time(out.updated_at)})"):
                        st.markdown(f"**Issue:** [{out.title}]({out.link})")
                        st.write(out.description)
                        
    render_provider_tab("AWS", tab_aws)
    render_provider_tab("Google Cloud", tab_gcp)
    render_provider_tab("Azure", tab_azure)
    render_provider_tab("Cisco%", tab_cisco)
    
# ================= 7. REPORT BUILDER =================
elif page == "📝 Report Builder":
    st.title("📝 Custom Intelligence Report Builder")
    st.markdown("Search active and archived intelligence, select relevant articles, and instruct the AI to synthesize a targeted brief.")
    
    # Initialize session state for the persistent report
    if "generated_report" not in st.session_state:
        st.session_state.generated_report = None
    
    # --- 1. SEARCH & FILTER ---
    st.subheader("1. Gather Intelligence")
    col_search, col_limit = st.columns([3, 1])
    search_query = col_search.text_input("🔍 Keyword Search (Scans Titles and Summaries)")
    search_limit = col_limit.selectbox("Max Results", [20, 50, 100])
    
    query = session.query(Article)
    if search_query:
        query = query.filter(Article.title.ilike(f"%{search_query}%") | Article.summary.ilike(f"%{search_query}%"))
        
    search_results = query.order_by(Article.published_date.desc()).limit(search_limit).all()
    
    # --- 2. SELECTION & MANUAL INPUTS ---
    if not search_results:
        st.warning("No articles match your search query.")
    else:
        article_map = {f"[{a.published_date.strftime('%Y-%m-%d')}] {a.title} ({a.source})": a for a in search_results}
        
        selected_titles = st.multiselect(
            "Select Articles to Include in the Report:",
            options=list(article_map.keys()),
            help="Select up to 10 articles to ensure the AI's context window is not overwhelmed."
        )
        
        st.divider()
        st.subheader("2. Report Metadata & Manual Overrides")
        
        col_m1, col_m2 = st.columns(2)
        analyst_name = col_m1.text_input("Analyst Name", placeholder="e.g., Preston")
        contact_info = col_m2.text_input("NOC Contact Info", placeholder="Phone number or email")
        
        manual_systems = st.text_area(
            "Manually Identified Internal Systems (Optional)", 
            placeholder="List any internal AECC systems, IP addresses, or hardware known to be affected by this threat...",
            height=100
        )
        
        # --- 3. SYNTHESIS ---
        st.subheader("3. Define the AI Objective")
        objective = st.text_area(
            "What should the AI focus on?",
            value="Generate an exhaustive, detailed technical intelligence report. Extract every possible technical artifact, system version, IOC, and remediation step from the provided text.",
            height=100
        )
        
        if st.button("🚀 Generate AECC Intel Report", type="primary"):
            if not selected_titles:
                st.error("Please select at least one article.")
            else:
                selected_articles = [article_map[title] for title in selected_titles]
                
                with st.spinner(f"Synthesizing {len(selected_articles)} intelligence reports... This may take a moment."):
                    ai_markdown = build_custom_intel_report(selected_articles, objective, session)
                    
                    if ai_markdown:
                        # Construct the Master AECC Header
                        now_str = datetime.now(LOCAL_TZ).strftime("%A, %B %d, %Y at %I:%M %p %Z")
                        
                        master_report = f"""# 🛡️ AECC Network Operations Center - Intelligence Report
**Date/Time Generated:** {now_str}
**Lead Analyst:** {analyst_name if analyst_name else 'Unspecified'}
**Contact:** {contact_info if contact_info else 'Unspecified'}

---

"""
                        # Inject Manual Systems if provided
                        if manual_systems.strip():
                            master_report += f"## 🎯 Internally Identified Affected Systems (Manual Entry)\n{manual_systems}\n\n---\n\n"
                            
                        # Append the AI generated content
                        master_report += ai_markdown
                        
                        # Save to session state so it survives UI refreshes
                        st.session_state.generated_report = master_report
                        st.success("Report Generation Complete!")
                    else:
                        st.error("AI failed to generate the report. Check the worker logs.")

    # --- 4. DISPLAY & EXPORT (Outside the button logic so it persists) ---
    if st.session_state.generated_report:
        st.divider()
        
        with st.container(border=True):
            st.markdown(st.session_state.generated_report)
            
        st.divider()
        st.subheader("Export Report")
        
        filename = f"AECC_Intel_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
        
        col_d1, col_d2 = st.columns([1, 4])
        col_d1.download_button(
            label="💾 Download as Markdown (.md)",
            data=st.session_state.generated_report,
            file_name=filename,
            mime="text/markdown",
            use_container_width=True
        )
        
        if col_d2.button("🗑️ Clear Report", type="secondary"):
            st.session_state.generated_report = None
            st.rerun()

# ================= 6. SETTINGS & TRAINING =================
elif page == "⚙️ Settings & Training":
    st.title("⚙️ Settings & Engine Room")
    
    tab_rss, tab_ml, tab_ai, tab_danger = st.tabs(["📡 RSS Sources & Keywords", "🧠 ML Training Data", "🤖 AI Engine", "⚠️ Danger Zone"])
    
    with tab_rss:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Manage Keywords")
            with st.form("bulk_kw"):
                raw_text = st.text_area("Bulk Add Keywords (word, weight)", placeholder="infrastructure, 80\npower grid, 50")
                if st.form_submit_button("Add Keywords"):
                    lines = raw_text.split('\n')
                    for line in lines:
                        if not line.strip(): continue
                        parts = line.split(',')
                        word = parts[0].strip().lower()
                        weight = int(parts[1].strip()) if len(parts) > 1 and parts[1].strip().isdigit() else 10
                        if not session.query(Keyword).filter_by(word=word).first():
                            session.add(Keyword(word=word, weight=weight))
                    session.commit()
                    st.rerun()
            
            with st.expander("Active Keywords"):
                for k in session.query(Keyword).order_by(Keyword.weight.desc()).all():
                    c_a, c_b, c_c = st.columns([3, 1, 1])
                    c_a.code(k.word)
                    c_b.write(f"**{k.weight}**")
                    if c_c.button("🗑️", key=f"del_kw_{k.id}"):
                        session.delete(k)
                        session.commit()
                        st.rerun()

        with col2:
            st.subheader("Manage RSS Feeds")
            with st.form("bulk_feed"):
                raw_text = st.text_area("Bulk Add Feeds (URL, Name)", placeholder="https://site.com/feed, Tech News")
                if st.form_submit_button("Add Sources"):
                    lines = raw_text.split('\n')
                    for line in lines:
                        if not line.strip(): continue
                        parts = line.split(',')
                        url = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else "New Feed"
                        if not session.query(FeedSource).filter_by(url=url).first():
                            session.add(FeedSource(url=url, name=name))
                    session.commit()
                    st.rerun()

            with st.expander("Active Feeds"):
                for s in session.query(FeedSource).all():
                    st.text(s.name)
                    st.caption(s.url)
                    if st.button("Delete", key=f"del_src_{s.id}"):
                        session.delete(s)
                        session.commit()
                        st.rerun()
                        
    with tab_ml:
        st.subheader("Smart Filter Training")
        count_pos = session.query(Article).filter(Article.human_feedback == 2).count()
        count_neg = session.query(Article).filter(Article.human_feedback == 1).count()
        total = count_pos + count_neg
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Samples", total)
        c2.metric("Positives (Keep)", count_pos)
        c3.metric("Negatives (Dismiss)", count_neg)
        
        if st.button("🚀 Retrain Model Now", type="primary"):
            if total < 10: st.error("Not enough data! Please review at least 10 articles.")
            else:
                with st.spinner("Training neural pathways..."):
                    try:
                        train() 
                        st.success("Model retrained successfully!")
                    except Exception as e: st.error(f"Training failed: {e}")
        
        st.write("Labeled Dataset")
        df = pd.read_sql(session.query(Article).filter(Article.human_feedback != 0).statement, session.bind)
        st.dataframe(df)
        
    with tab_ai:
        st.subheader("Universal LLM Integration")
        config = session.query(SystemConfig).first() or SystemConfig()
        if not config.id: session.add(config); session.commit()
        
        with st.form("llm_config"):
            endpoint = st.text_input("Endpoint URL", value=config.llm_endpoint)
            api_key = st.text_input("API Key", value=config.llm_api_key, type="password")
            model_name = st.text_input("Model Name", value=config.llm_model_name)
            
            st.divider()
            st.write("**NOC Tech Stack Definition**")
            st.caption("List the software, hardware, and protocols running in your environment. The AI will cross-reference this list against active CVEs.")
            
            # --- NEW: UI Field for the Tech Stack ---
            current_stack = config.tech_stack if config.tech_stack else "SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco"
            tech_stack_input = st.text_area("Internal Tech Stack", value=current_stack, height=100)
            
            is_active = st.checkbox("Enable AI Features", value=config.is_active)
            
            if st.form_submit_button("Save AI Config"):
                config.llm_endpoint = endpoint
                config.llm_api_key = api_key
                config.llm_model_name = model_name
                config.tech_stack = tech_stack_input
                config.is_active = is_active
                session.commit()
                st.success("✅ AI Configuration Saved!")
                time.sleep(1)
                st.rerun()
                
    with tab_danger:
        st.error("These actions are irreversible!")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Clear History** (Keeps Feeds/Keywords)")
            if st.button("🗑️ Delete All Articles"):
                session.execute(text("TRUNCATE TABLE articles RESTART IDENTITY CASCADE;"))
                session.commit()
                st.rerun()
        with col2:
            st.write("**Factory Reset** (Wipes EVERYTHING)")
            if st.button("☢️ FULL RESET"):
                session.execute(text("TRUNCATE TABLE articles, feed_sources, keywords RESTART IDENTITY CASCADE;"))
                session.commit()
                st.rerun()

session.close()